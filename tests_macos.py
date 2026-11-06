#!/usr/bin/env python3
"""macOS signing tests for antigravity_patcher, runnable on any platform.

codesign is mocked; the .app bundle, signature snapshots and patch/restore
flows are real files in a temp directory.
"""
import contextlib
import io
import os
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import antigravity_patcher as ap

IDE_GATE = b"before;resetIsTierGCPTos(),this._productService.isGoogleInternal;after"


def make_app(root):
    """Create a minimal fake Antigravity IDE.app bundle; return (app, main_js)."""
    app = os.path.join(root, "Antigravity IDE.app")
    macos = os.path.join(app, "Contents", "MacOS")
    out = os.path.join(app, "Contents", "Resources", "app", "out")
    sig = os.path.join(app, "Contents", "_CodeSignature")
    for d in (macos, out, sig):
        os.makedirs(d)
    with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump({"CFBundleExecutable": "Antigravity IDE",
                       "CFBundleIdentifier": "com.google.antigravity-ide"}, f)
    with open(os.path.join(macos, "Antigravity IDE"), "wb") as f:
        f.write(b"\xcf\xfa\xed\xfe" + b"MAIN-BINARY-v1")
    main_js = os.path.join(out, "main.js")
    with open(main_js, "wb") as f:
        f.write(IDE_GATE)
    with open(os.path.join(sig, "CodeResources"), "wb") as f:
        f.write(b"SEAL-v1")
    with open(os.path.join(app, "Contents", "CodeResources"), "wb") as f:
        f.write(b"LEGACY-SEAL-v1")
    return app, main_js


def ok_result(*args, **kwargs):
    return mock.Mock(returncode=0, stdout="", stderr="")


class SnapshotTests(unittest.TestCase):
    def test_snapshot_roundtrip_restores_signature_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = make_app(tmp)
            snap = os.path.join(tmp, "snap")
            os.makedirs(snap)
            ap._mac_write_signature_snapshot(app, snap)
            # simulate re-signing damage
            main = ap._mac_bundle_main(app)
            with open(main, "wb") as f:
                f.write(b"RESIGNED")
            with open(os.path.join(app, "Contents", "_CodeSignature", "CodeResources"), "wb") as f:
                f.write(b"SEAL-v2")
            ap._mac_restore_signature_snapshot(snap, app)
            with open(main, "rb") as f:
                self.assertEqual(f.read(), b"\xcf\xfa\xed\xfe" + b"MAIN-BINARY-v1")
            with open(os.path.join(app, "Contents", "_CodeSignature", "CodeResources"), "rb") as f:
                self.assertEqual(f.read(), b"SEAL-v1")

    def test_prepare_backup_creates_agysignbak(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = make_app(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                backup = ap._mac_prepare_signature_backup(app)
            self.assertEqual(backup, app + ap.MAC_SIGNATURE_BAK)
            self.assertTrue(os.path.isfile(os.path.join(backup, "manifest.json")))


class SignTransactionTests(unittest.TestCase):
    def test_signs_binary_then_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, main_js = make_app(tmp)
            calls = []
            def fake_codesign(path, bundle=False, entitlements=None, identifier=None):
                calls.append((path, bundle))
            with mock.patch.object(ap, "_mac_codesign", side_effect=fake_codesign), \
                 contextlib.redirect_stdout(io.StringIO()):
                ap._mac_sign_transaction({"ide": main_js})
            self.assertEqual(calls, [(app, True)])

    def test_sign_failure_restores_binary_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "agy")
            with open(binary, "wb") as f:
                f.write(b"PATCHED-BYTES")
            def boom(path, bundle=False, entitlements=None, identifier=None):
                with open(path, "wb") as out:
                    out.write(b"CORRUPTED-BY-SIGN")
                raise OSError("codesign failed")
            with mock.patch.object(ap, "_mac_codesign", side_effect=boom), \
                 mock.patch.object(ap.sys, "platform", "darwin"), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    ap._mac_sign_transaction({"agy": binary})
            with open(binary, "rb") as f:
                self.assertEqual(f.read(), b"PATCHED-BYTES")


class LibraryValidationTests(unittest.TestCase):
    def _app_with_framework(self, tmp):
        app, _ = make_app(tmp)
        os.makedirs(os.path.join(app, "Contents", "Frameworks",
                                 "Electron Framework.framework"))
        return app

    def _command(self, app):
        def fake(args, check=True):
            path = args[-1]
            if "Electron Framework" in path:
                return mock.Mock(returncode=0, stdout="TeamIdentifier=TEAM123\n", stderr="")
            return mock.Mock(returncode=0, stdout="flags=0x10000 (runtime)\n", stderr="")
        return fake

    def test_lv_blocks_without_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self._app_with_framework(tmp)
            with mock.patch.object(ap, "_mac_command", side_effect=self._command(app)), \
                 mock.patch.object(ap, "_mac_entitlements", return_value={}):
                with self.assertRaises(OSError) as ctx:
                    ap._mac_library_validation_entitlements(app, allow_disable=False)
            self.assertIn("--macos-disable-library-validation", str(ctx.exception))

    def test_lv_exception_with_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self._app_with_framework(tmp)
            with mock.patch.object(ap, "_mac_command", side_effect=self._command(app)), \
                 mock.patch.object(ap, "_mac_entitlements", return_value={}):
                result = ap._mac_library_validation_entitlements(app, allow_disable=True)
            self.assertEqual(result, {ap.MAC_DISABLE_LIBRARY_VALIDATION: True})


class DarwinFlowTests(unittest.TestCase):
    def test_full_patch_sign_restore_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, main_js = make_app(tmp)
            original = open(main_js, "rb").read()
            signed = []
            def fake_codesign(path, bundle=False, entitlements=None, identifier=None):
                signed.append((path, bundle))
            with mock.patch.object(ap.sys, "platform", "darwin"), \
                 mock.patch.object(ap, "_mac_command", side_effect=ok_result), \
                 mock.patch.object(ap, "_mac_codesign", side_effect=fake_codesign), \
                 mock.patch.object(ap, "_mac_codesign_verify", return_value=None), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = ap.run("patch", ["ide"], {"ide": main_js})
                self.assertEqual(rc, 0)
                self.assertEqual(ap.ide_status(main_js)[0], "patched")
                self.assertTrue(os.path.isdir(app + ap.MAC_SIGNATURE_BAK))
                self.assertIn((app, True), signed)
                rc = ap.run("restore", ["ide"], {"ide": main_js})
                self.assertEqual(rc, 0)
                self.assertEqual(ap.ide_status(main_js)[0], "unpatched")
            self.assertEqual(open(main_js, "rb").read(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
