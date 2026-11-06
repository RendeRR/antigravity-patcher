#!/usr/bin/env python3
"""Multi-gate agy tests: both gate families (CLI screen + hub validator)
must patch together; a half-patched file (the state the old patcher left
on macOS ARM64) must upgrade without touching the pristine backup.

Fixtures are synthetic Mach-O arm64 and PE x64 binaries carrying the exact
gate byte patterns in executable ranges. Run: python3 tests_multi_gate.py
"""
import importlib.util
import os
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "ap", os.path.join(HERE, "antigravity_patcher.py"))
ap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ap)

CLI64 = (b"\x48\x85\xc9\x0f\x84\x11\x11\x11\x11\x80\x79\x08\x00\x0f\x85\x22\x22\x22\x22"
         b"\x48\x89\xc8\x90\xe8\x33\x33\x33\x33\x48\x89\x84\x24\xe0\x00\x00\x00"
         b"\x48\x89\x9c\x24\xe8\x00\x00\x00\x48\x89\x8c\x24\xf0\x00\x00\x00")
HUB64 = b"\x80\x78\x08\x00\x74\x10\x48\x8b\x54\x24\x70\x48\x89\x50\x60"
CLIARM_CTX = struct.pack("<II", 0xB5000021, 0xB4000040)
CLIARM = (b"\x02\x20\x40\x39\x02\xaa\x05\x37\xbb\xbb\xbb\x95"
          b"\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9")
HUBARM = b"\x03\x20\x40\x39\x03\xaa\x05\x36\xe3\x13\x48\xa9\x03\x10\x06\xa9"


def build_pe(path):
    code = bytearray(b"\x90" * 512)
    code[0x40:0x40 + len(CLI64)] = CLI64
    code[0x100:0x100 + len(HUB64)] = HUB64
    hdr = bytearray(0x200)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x8664, 1, 0, 0, 0, 0, 0)
    sec = 0x80 + 24
    hdr[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<II", hdr, sec + 16, len(code), 0x200)
    struct.pack_into("<I", hdr, sec + 36, 0x20000000)
    with open(path, "wb") as f:
        f.write(hdr + code)
    return 0x200 + 0x40 + 9, 0x200 + 0x100  # cli fix off, hub fix off


def build_macho(path):
    code_off = 0x200
    code = bytearray(b"\x00" * 512)
    code[0x40:0x40 + 8] = CLIARM_CTX
    code[0x48:0x48 + len(CLIARM)] = CLIARM
    code[0x100:0x100 + len(HUBARM)] = HUBARM
    total = code_off + len(code)
    seg = bytearray()
    seg += struct.pack("<II", 0x19, 72 + 80)
    seg += b"__TEXT\0\0\0\0\0\0\0\0\0\0"
    seg += struct.pack("<QQQQiiII", 0, total, 0, total, 7, 5, 1, 0)
    sect = bytearray()
    sect += b"__text\0\0\0\0\0\0\0\0\0\0"
    sect += b"__TEXT\0\0\0\0\0\0\0\0\0\0"
    sect += struct.pack("<QQ", 0, len(code))
    sect += struct.pack("<I", code_off)
    sect += struct.pack("<IIIIIIII", 2, 0, 0, 0x80000400, 0, 0, 0, 0)
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(seg), 0, 0)
    blob = bytearray(total)
    blob[0:32] = hdr
    blob[32:32 + len(seg)] = seg + sect
    blob[code_off:code_off + len(code)] = code
    with open(path, "wb") as f:
        f.write(blob)
    return code_off + 0x48, code_off + 0x100


def lifecycle(path, cli_off, hub_off, cli_fix, hub_fix):
    orig = open(path, "rb").read()
    st = lambda: ap.gate_status(path, ap.AGY_GATES)[0]
    assert st() == "unpatched", st()
    # full patch: both families at once
    assert ap.gate_patch(path, ap.AGY_GATES, "agy-test"), "patch failed"
    data = open(path, "rb").read()
    assert data[cli_off:cli_off + len(cli_fix)] == cli_fix, "cli gate not written"
    assert data[hub_off:hub_off + len(hub_fix)] == hub_fix, "hub gate not written"
    assert st() == "patched", st()
    assert open(path + ap.BAK, "rb").read() == orig, "backup is not pristine"
    # restore is byte-identical
    assert ap.restore_file(path, lambda p: ap.gate_status(p, ap.AGY_GATES))
    assert open(path, "rb").read() == orig, "restore mismatch"
    assert st() == "unpatched", st()
    os.unlink(path + ap.BAK)

    # partial state (old patcher: CLI gate only) + pristine backup present
    with open(path, "r+b") as f:
        f.seek(cli_off)
        f.write(cli_fix)
    shutil.copy2(path, path + ".tmp")
    with open(path + ap.BAK, "wb") as f:
        f.write(orig)
    os.unlink(path + ".tmp")
    assert st() == "partial", st()
    assert ap.gate_patch(path, ap.AGY_GATES, "agy-test"), "partial upgrade failed"
    data = open(path, "rb").read()
    assert data[hub_off:hub_off + len(hub_fix)] == hub_fix, "hub gate not added"
    assert open(path + ap.BAK, "rb").read() == orig, "pristine backup overwritten!"
    assert st() == "patched", st()
    assert ap.restore_file(path, lambda p: ap.gate_status(p, ap.AGY_GATES))
    assert open(path, "rb").read() == orig
    os.unlink(path + ap.BAK)


def main():
    tmp = tempfile.mkdtemp(prefix="agy-multi-")
    try:
        pe = os.path.join(tmp, "agy.exe")
        cli_off, hub_off = build_pe(pe)
        lifecycle(pe, cli_off, hub_off,
                  ap.CLI_GATE_X64.fix, ap.MANAGER_GATE_X64.fix)
        print("PE x64: full patch / restore / partial upgrade OK")
        mo = os.path.join(tmp, "agy")
        cli_off, hub_off = build_macho(mo)
        lifecycle(mo, cli_off, hub_off,
                  ap.CLI_GATE_ARM64.fix, ap.MANAGER_GATE_ARM64.fix)
        print("Mach-O arm64: full patch / restore / partial upgrade OK")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("ALL MULTI-GATE TESTS PASSED")


if __name__ == "__main__":
    sys.exit(main())
