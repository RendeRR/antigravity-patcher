#!/usr/bin/env python3
"""CLI parsing regression tests.

`status` with no target must work on every Python version: argparse's
matching of an optional positional followed by a `*` positional is
version-dependent and broke on macOS (a lone `status` was eaten by the
targets positional). The patcher therefore splits positionals by hand;
these tests pin the behaviour via real subprocess calls.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PATCHER = os.path.join(HERE, "antigravity_patcher.py")
sys.path.insert(0, HERE)
from tests_multi_gate import build_macho  # noqa: E402


def run_cli(args, cwd):
    return subprocess.run([sys.executable, PATCHER] + args,
                          capture_output=True, text=True, cwd=cwd)


def main():
    tmp = tempfile.mkdtemp(prefix="agy-cli-")
    try:
        fixture = os.path.join(tmp, "agy")
        build_macho(fixture)

        r = run_cli(["status", "--path-agy", fixture], tmp)
        assert r.returncode == 0 and "unpatched" in r.stdout, (r.returncode, r.stdout, r.stderr)
        r = run_cli(["--path-agy", fixture, "status"], tmp)
        assert r.returncode == 0 and "unpatched" in r.stdout, (r.returncode, r.stdout, r.stderr)
        r = run_cli(["status", "agy", "--path-agy", fixture], tmp)
        assert r.returncode == 0 and "unpatched" in r.stdout, (r.returncode, r.stdout, r.stderr)
        r = run_cli(["--path-agy", fixture], tmp)  # no action -> status
        assert r.returncode == 0 and "unpatched" in r.stdout, (r.returncode, r.stdout, r.stderr)
        r = run_cli(["--json", "--path-agy", fixture], tmp)
        assert r.returncode == 0 and '"agy"' in r.stdout, (r.returncode, r.stdout, r.stderr)

        r = run_cli(["patch", "--path-agy", fixture], tmp)  # no targets -> all
        assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
        r = run_cli(["status", "--path-agy", fixture], tmp)
        assert "patched" in r.stdout and "partial" not in r.stdout, r.stdout
        r = run_cli(["restore", "agy", "--path-agy", fixture], tmp)
        assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
        r = run_cli(["status", "--path-agy", fixture], tmp)
        assert "unpatched" in r.stdout, r.stdout

        r = run_cli(["status", "bogus"], tmp)
        assert r.returncode == 2 and "invalid target" in r.stderr, (r.returncode, r.stderr)
        print("CLI TESTS PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
