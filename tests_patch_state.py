"""Tests for the patch-state sidecar: version reporting and lost-patch hints.

Run: python3 tests_patch_state.py
No network, no real Antigravity install, no codesign - everything is built
from throwaway fake .app bundles under a temp directory.
"""

import importlib.util
import json
import os
import plistlib
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "antigravity_patcher", os.path.join(HERE, "antigravity_patcher.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_app(root, version, binary=b"not a real executable"):
    app = os.path.join(root, "Foo.app")
    bindir = os.path.join(app, "Contents", "Resources", "bin")
    os.makedirs(bindir, exist_ok=True)
    with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump({"CFBundleShortVersionString": version,
                       "CFBundleExecutable": "Foo"}, f)
    path = os.path.join(bindir, "language_server")
    with open(path, "wb") as f:
        f.write(binary)
    return path


def _set_version(path, version):
    app = path.split("/Contents/")[0]
    with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump({"CFBundleShortVersionString": version,
                       "CFBundleExecutable": "Foo"}, f)


def test_bundle_version_read():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        assert m.target_version("manager", path) == "2.33.0"
        assert m.target_version("ide", path) is None
        assert m.target_version("cli", path) is None
    finally:
        shutil.rmtree(root)


def test_state_file_lives_outside_bundle():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        st = m._state_path("manager", path)
        # _mac_app_bundle() resolves symlinks (/var -> /private/var on macOS).
        expected = os.path.join(os.path.realpath(root), "Foo.app" + m.PATCH_STATE)
        assert st == expected, st
        assert not st.startswith(os.path.join(root, "Foo.app") + os.sep), \
            "state file must not live inside the bundle (an update wipes it)"
    finally:
        shutil.rmtree(root)


def test_record_then_status_is_quiet():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        m.record_patch_state("manager", path)
        rec = json.load(open(m._state_path("manager", path)))["manager"]
        assert rec["version"] == "2.33.0"
        assert rec["binary"] == "language_server"
        assert len(rec["sha256"]) == 64
        # A patched target never warns, whatever the note says.
        assert m.patch_state_warning("manager", path, "patched") is None
    finally:
        shutil.rmtree(root)


def test_update_after_patch_is_reported():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        m.record_patch_state("manager", path)
        _set_version(path, "2.40.0")
        msg = m.patch_state_warning("manager", path, "unpatched")
        assert msg and "2.33.0" in msg and "2.40.0" in msg, msg
        assert "re-run patch" in msg
    finally:
        shutil.rmtree(root)


def test_same_version_different_bytes_is_reported():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        m.record_patch_state("manager", path)
        with open(path, "wb") as f:
            f.write(b"replaced by an update that kept the version")
        msg = m.patch_state_warning("manager", path, "unpatched")
        assert msg and "binary changed" in msg, msg
    finally:
        shutil.rmtree(root)


def test_no_state_file_means_no_noise():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        assert m.patch_state_warning("manager", path, "unpatched") is None
    finally:
        shutil.rmtree(root)


def test_forget_removes_entry_and_file():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        st = m._state_path("manager", path)
        m.record_patch_state("manager", path)
        assert os.path.exists(st)
        m.forget_patch_state("manager", path)
        assert not os.path.exists(st), "single-entry state file should be removed"
        # Idempotent on a missing file.
        m.forget_patch_state("manager", path)
    finally:
        shutil.rmtree(root)


def test_forget_keeps_other_targets():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        path = _fake_app(root, "2.33.0")
        st = m._state_path("manager", path)
        m.record_patch_state("manager", path)
        data = json.load(open(st))
        data["ide"] = {"version": "2.6.0"}
        json.dump(data, open(st, "w"))
        m.forget_patch_state("manager", path)
        left = json.load(open(st))
        assert "manager" not in left and left["ide"]["version"] == "2.6.0"
    finally:
        shutil.rmtree(root)


def test_macos_eperm_mentions_app_management():
    """EPERM inside a .app is TCC, not file permissions - say so."""
    if sys.platform != "darwin":
        return
    import errno as _errno
    from unittest import mock

    m = _load()
    app = "/Applications/X.app"
    target = os.path.join(app, "Contents", "Resources", "bin", "language_server")
    captured = []
    denied = PermissionError(_errno.EPERM, "Operation not permitted")
    with mock.patch.object(m, "warn", captured.append), \
            mock.patch("builtins.open", side_effect=denied), \
            mock.patch("tempfile.mkstemp", side_effect=denied):
        locked = m.is_locked(target, app)
    assert locked is True
    joined = " ".join(captured)
    assert "App Management" in joined, joined
    assert "System Settings" in joined, joined
    # The old advice is actively wrong here: it sent users to sudo/ownership.
    assert "sudo / Administrator" not in joined, joined


def test_gate_status_keeps_the_reason():
    m = _load()
    root = tempfile.mkdtemp()
    try:
        bogus = os.path.join(root, "not-an-executable")
        with open(bogus, "wb") as f:
            f.write(b"\x00" * 64)
        state, reason = m.gate_status(bogus, m.MANAGER_GATE)
        assert state == "unknown"
        assert reason, "the reason must not be swallowed - 'unknown' alone "\
                       "tells the user nothing"
    finally:
        shutil.rmtree(root)


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as e:
            failed += 1
            print(f"  [FAIL] {name}: {e}")
        except Exception as e:  # noqa: BLE001 - report, keep going
            failed += 1
            print(f"  [ERR ] {name}: {type(e).__name__}: {e}")
        else:
            print(f"  [ok  ] {name}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
