#!/usr/bin/env python3
"""Antigravity regional-restriction (eligibility) patcher.

Disables the *local* eligibility gates in Google Antigravity clients so the
apps stop showing "not available in your location" on machines/accounts whose
region is not on Google's rollout list. It does NOT create server-side
entitlements, bypass server authentication, or unlock paid features: model
and feature availability is still decided by Google's servers.

Targets
-------
ide       Antigravity IDE (VS Code fork) — patches the auth gate in
          resources/app/out/main.js:
              ...resetIsTierGCPTos(),this.<svc>.isGoogleInternal
          becomes
              ...resetIsTierGCPTos(),true
          Verified on the real IDE 2.6.0 build (see VERIFIED_IDE below).
agy       The language-server binary the IDE 2.6.0 extension downloads on
          first launch into ~/.gemini/bin/agy[.exe] (IDE 2.6.0 no longer
          ships a language server inside the IDE folder). It carries two
          independent gates - the CLI eligibility screen and the hub
          hasValidAuth validator the IDE actually uses via `agy --hub` -
          and every gate family present is patched (each must still match
          unambiguously).
cli       Standalone Antigravity CLI (agy / agy.exe) found in PATH.
manager   Antigravity 2.0 desktop app — its Go backend
          resources/bin/language_server[.exe].

Safety model (inherited from the upstream project, see credits):
  * signatures are regexes over machine code / minified JS, never fixed
    file offsets; a gate is patched only when it matches exactly once;
  * binary signatures are searched only inside executable PE/ELF/Mach-O
    sections/segments;
  * mixed patched+unpatched states and duplicate matches are refused;
  * a pristine backup <file>.agybak is created and verified before any
    write; the target is re-scanned right before writing; the result is
    verified after writing; any failure rolls back automatically;
  * restore accepts a backup only if the backup itself scans as a clean,
    unpatched original.

Usage
-----
  python3 antigravity_patcher.py status            # all targets
  python3 antigravity_patcher.py patch             # all found targets
  python3 antigravity_patcher.py patch ide agy     # selected targets
  python3 antigravity_patcher.py restore ide
  python3 antigravity_patcher.py --path-ide /path/to/main.js patch ide
  python3 antigravity_patcher.py --path-agy ~/.gemini/bin/agy patch agy

Options: --json (machine-readable status), --dry-run (patch: report only).

Close Antigravity before patching. Python 3.8+, standard library only.

macOS: signing is handled automatically. Before the first patch inside a
.app bundle, the bundle's original signature state is saved to a sibling
<App>.app.agysignbak snapshot; after patching, changed binaries are ad-hoc
signed inside-out and then the bundle itself (metadata preserved), the
result is verified with codesign, and quarantine is removed. On restore,
the original bundle signature is restored from the snapshot once the last
patched target in the bundle is restored. If Electron Library Validation
would reject the ad-hoc bundle, patching stops; rerun with
--macos-disable-library-validation to add the exception entitlement to the
app's main executable only. Standalone binaries (agy, cli) are ad-hoc
signed in place; restoring their pristine bytes restores their signature.

Credits: based on QNIX-Dev/eligibility-antigravity-patcher (MIT) —
gate signatures, executable-range scanning and the backup/rollback model
come from that project. IDE 2.6.0 support was verified against the official
2.6.0-5526304964083712 build for this patcher. The structural note that
IDE 2.6.0 downloads its language server into ~/.gemini/bin was first
documented by the confeden/Antigravity unlocker release v2.28.2.
"""
from __future__ import annotations

import argparse
import contextlib
import errno
import glob
import hashlib
import json
import mmap
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from xml.parsers.expat import ExpatError

BAK = ".agybak"
MAC_SIGNATURE_BAK = ".agysignbak"
MAC_DISABLE_LIBRARY_VALIDATION = "com.apple.security.cs.disable-library-validation"
TARGETS = ("ide", "agy", "cli", "manager")

# --------------------------------------------------------------------------
# small output helpers
# --------------------------------------------------------------------------

def _say(tag, msg): print(f"  [{tag}] {msg}")
def ok(m):   _say("ok", m)
def info(m): _say("..", m)
def warn(m): _say("!!", m)


def _files_equal(first, second):
    with open(first, "rb") as a, open(second, "rb") as b:
        while True:
            chunk = a.read(1024 * 1024)
            if chunk != b.read(1024 * 1024):
                return False
            if not chunk:
                return True


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_locked(path, app=None):
    """True when the file cannot be opened for writing (app running, perms)."""
    try:
        with open(path, "r+b"):
            return False
    except OSError as e:
        # macOS can deny opening a signed executable for in-place writes even
        # when its owner may replace it (the patcher replaces via a staged
        # sibling on darwin). Probe the directory without touching the file.
        if sys.platform == "darwin" and e.errno == errno.EPERM:
            try:
                actual = os.path.realpath(path)
                fd, probe = tempfile.mkstemp(prefix=".agy-write-",
                                             dir=os.path.dirname(actual))
                os.close(fd)
                os.unlink(probe)
                return False
            except OSError:
                pass
        if app:
            if e.errno == errno.ETXTBSY or getattr(e, "winerror", None) in (32, 33):
                warn(f"{os.path.basename(path)} is in use - close {app} first")
            elif e.errno in (errno.EACCES, errno.EPERM):
                warn(f"permission denied writing {path} - use an account with "
                     "write access to the installation (sudo / Administrator)")
            else:
                warn(f"cannot open {path} for writing: {e}")
        return True


# --------------------------------------------------------------------------
# executable format parsing: executable ranges + arch for PE / ELF / Mach-O
# (adapted from QNIX-Dev/eligibility-antigravity-patcher, MIT)
# --------------------------------------------------------------------------

def _read_exact(f, offset, size):
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError("truncated executable header")
    return data


def _normalized_ranges(ranges, file_size):
    clean = []
    for start, end in ranges:
        start, end = max(0, start), min(file_size, end)
        if start < end:
            clean.append((start, end))
    out = []
    for start, end in sorted(clean):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return tuple(out)


def _machine_arch(machine):
    return {0x8664: "x64", 0xAA64: "arm64", 0x3E: "x64", 0xB7: "arm64",
            0x01000007: "x64", 0x0100000C: "arm64"}.get(machine)


def _pe_executable_info(f, file_size):
    pe = struct.unpack("<I", _read_exact(f, 0x3C, 4))[0]
    if _read_exact(f, pe, 4) != b"PE\0\0":
        raise ValueError("invalid PE signature")
    coff = _read_exact(f, pe + 4, 20)
    arch = _machine_arch(struct.unpack_from("<H", coff, 0)[0])
    section_count = struct.unpack_from("<H", coff, 2)[0]
    optional_size = struct.unpack_from("<H", coff, 16)[0]
    section_table = pe + 24 + optional_size
    ranges = []
    for i in range(section_count):
        section = _read_exact(f, section_table + i * 40, 40)
        raw_size, raw_offset = struct.unpack_from("<II", section, 16)
        characteristics = struct.unpack_from("<I", section, 36)[0]
        if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            ranges.append((raw_offset, raw_offset + raw_size))
    return _normalized_ranges(ranges, file_size), arch


def _elf_executable_info(f, file_size):
    ident = _read_exact(f, 0, 16)
    elf_class, data_order = ident[4], ident[5]
    endian = "<" if data_order == 1 else ">" if data_order == 2 else None
    if endian is None:
        raise ValueError("unknown ELF byte order")
    machine = struct.unpack(endian + "H", _read_exact(f, 18, 2))[0]
    if elf_class == 2:
        header = _read_exact(f, 0, 64)
        phoff = struct.unpack_from(endian + "Q", header, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", header, 54)
        layout = (0, 4, 8, 32, "I", "I", "Q", "Q")
    elif elf_class == 1:
        header = _read_exact(f, 0, 52)
        phoff = struct.unpack_from(endian + "I", header, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", header, 42)
        layout = (0, 24, 4, 16, "I", "I", "I", "I")
    else:
        raise ValueError("unknown ELF class")
    type_off, flags_off, file_off, size_off, type_fmt, flags_fmt, off_fmt, size_fmt = layout
    ranges = []
    for i in range(phnum):
        entry = _read_exact(f, phoff + i * phentsize, phentsize)
        p_type = struct.unpack_from(endian + type_fmt, entry, type_off)[0]
        flags = struct.unpack_from(endian + flags_fmt, entry, flags_off)[0]
        offset = struct.unpack_from(endian + off_fmt, entry, file_off)[0]
        size = struct.unpack_from(endian + size_fmt, entry, size_off)[0]
        if p_type == 1 and flags & 1:  # PT_LOAD + PF_X
            ranges.append((offset, offset + size))
    return _normalized_ranges(ranges, file_size), _machine_arch(machine)


def _macho_slice_info(f, file_size, base, slice_size):
    magic = _read_exact(f, base, 4)
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise ValueError("unsupported Mach-O slice")
    header = _read_exact(f, base, 32)
    arch = _machine_arch(struct.unpack_from(endian + "I", header, 4)[0])
    command_count = struct.unpack_from(endian + "I", header, 16)[0]
    pos, ranges = base + 32, []
    for _ in range(command_count):
        command_header = _read_exact(f, pos, 8)
        command, command_size = struct.unpack(endian + "II", command_header)
        if command_size < 8 or pos + command_size > base + slice_size:
            raise ValueError("invalid Mach-O load command")
        if command == 0x19:  # LC_SEGMENT_64
            segment = _read_exact(f, pos, command_size)
            section_count = struct.unpack_from(endian + "I", segment, 64)[0]
            if 72 + section_count * 80 > command_size:
                raise ValueError("invalid Mach-O section table")
            section_pos = 72
            for _ in range(section_count):
                section = segment[section_pos:section_pos + 80]
                section_name = section[:16].split(b"\0", 1)[0]
                segment_name = section[16:32].split(b"\0", 1)[0]
                size = struct.unpack_from(endian + "Q", section, 40)[0]
                offset = struct.unpack_from(endian + "I", section, 48)[0]
                flags = struct.unpack_from(endian + "I", section, 64)[0]
                is_code = ((segment_name, section_name) == (b"__TEXT", b"__text") or
                           flags & (0x80000000 | 0x00000400))
                if is_code:
                    ranges.append((base + offset, base + offset + size))
                section_pos += 80
        pos += command_size
    return _normalized_ranges(ranges, file_size), arch


def _macho_executable_info(f, file_size):
    magic = _read_exact(f, 0, 4)
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return _macho_slice_info(f, file_size, 0, file_size)
    fat = {
        b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True),
    }.get(magic)
    if not fat:
        raise ValueError("unsupported Mach-O header")
    endian, is_64 = fat
    count = struct.unpack(endian + "I", _read_exact(f, 4, 4))[0]
    entry_size = 32 if is_64 else 20
    ranges, arches = [], []
    for i in range(count):
        entry = _read_exact(f, 8 + i * entry_size, entry_size)
        if is_64:
            offset, size = struct.unpack_from(endian + "QQ", entry, 8)
        else:
            offset, size = struct.unpack_from(endian + "II", entry, 8)
        slice_ranges, arch = _macho_slice_info(f, file_size, offset, size)
        ranges += slice_ranges
        arches.append(arch)
    known_arch = arches[0] if arches and arches[0] and all(a == arches[0] for a in arches) else None
    return _normalized_ranges(ranges, file_size), known_arch


def executable_info(path):
    """Return (executable ranges, arch) for a PE, ELF or Mach-O file."""
    with open(path, "rb") as f:
        file_size = os.fstat(f.fileno()).st_size
        magic = _read_exact(f, 0, min(4, file_size))
        if magic[:2] == b"MZ":
            ranges, arch = _pe_executable_info(f, file_size)
        elif magic == b"\x7fELF":
            ranges, arch = _elf_executable_info(f, file_size)
        else:
            ranges, arch = _macho_executable_info(f, file_size)
    if not ranges:
        raise ValueError("no executable code ranges found")
    return ranges, arch


@contextlib.contextmanager
def mapped(path):
    with open(path, "rb") as f:
        if sys.platform == "darwin":
            yield f.read()
            return
        if os.fstat(f.fileno()).st_size == 0:
            yield b""
            return
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            yield mm
        finally:
            mm.close()


# --------------------------------------------------------------------------
# binary gates (signatures from QNIX-Dev/eligibility-antigravity-patcher, MIT)
# --------------------------------------------------------------------------

class SignatureNotFound(LookupError):
    pass


class SignatureAmbiguous(LookupError):
    pass


def _unique_match(pattern, data, ranges, label, accept=None):
    found = None
    for start, end in ranges:
        pos = start
        while pos < end:
            match = pattern.search(data, pos, end)
            if not match:
                break
            if accept is not None and not accept(data, match, start, end):
                pos = max(match.end(), match.start() + 1)
                continue
            if found is not None:
                raise SignatureAmbiguous(f"{label} signature is not unique - refusing to guess")
            found = match
            pos = max(match.end(), match.start() + 1)
    return found


class Gate:
    def __init__(self, sig, patched, fix, offset=0, desc="", arch=None, accept=None):
        self.sig, self.patched = re.compile(sig, re.S), re.compile(patched, re.S)
        self.fix, self.offset, self.desc, self.arch, self.accept = fix, offset, desc, arch, accept

    def find(self, data, ranges=None):
        search_ranges = ranges or ((0, len(data)),)
        original = _unique_match(self.sig, data, search_ranges, "unpatched gate", self.accept)
        patched = _unique_match(self.patched, data, search_ranges, "patched gate", self.accept)
        if original and patched:
            raise SignatureAmbiguous("both patched and unpatched gate signatures are present")
        if patched:
            return ("patched", patched.start() + self.offset)
        if original:
            return ("unpatched", original.start() + self.offset)
        raise SignatureNotFound("gate signature not found (unsupported version?)")

    def resolve(self, data, ranges=None, arch=None):
        kind, off = self.find(data, ranges)
        return kind, off, self


class MultiGate:
    """Select one architecture-specific gate."""
    def __init__(self, *gates, desc=""):
        self.gates, self.desc = gates, desc

    def resolve(self, data, ranges=None, arch=None):
        matches = []
        gates = [g for g in self.gates
                 if arch is None or getattr(g, "arch", None) is None or g.arch == arch]
        for g in gates:
            try:
                matches.append(g.resolve(data, ranges, arch))
            except SignatureNotFound:
                pass
        if len(matches) > 1:
            raise SignatureAmbiguous("multiple architecture gate signatures matched")
        if matches:
            return matches[0]
        raise SignatureNotFound("no architecture gate signature matched (unsupported version?)")


# CLI eligibility screen, agy 1.4.0 x64 handleAuthResult:
# test rcx,rcx ; je ; cmp byte[rcx+8],0 ; jne eligible ; ... call IneligibilityFromResult
# Repeating test rcx,rcx keeps ZF=0, so jne selects eligible.
CLI_GATE_X64 = Gate(
    rb"\x48\x85\xc9\x0f\x84....\x80\x79\x08\x00\x0f\x85....\x48\x89\xc8\x90"
    rb"\xe8....\x48\x89\x84\x24\xe0\x00\x00\x00"
    rb"\x48\x89\x9c\x24\xe8\x00\x00\x00\x48\x89\x8c\x24\xf0\x00\x00\x00",
    rb"\x48\x85\xc9\x0f\x84....\x48\x85\xc9\x90\x0f\x85....\x48\x89\xc8\x90"
    rb"\xe8....\x48\x89\x84\x24\xe0\x00\x00\x00"
    rb"\x48\x89\x9c\x24\xe8\x00\x00\x00\x48\x89\x8c\x24\xf0\x00\x00\x00",
    b"\x48\x85\xc9\x90", offset=9, desc="eligibility screen off (x64)", arch="x64")


def _cli_arm64_context(data, match, start, end):
    off = match.start()
    if off - 8 < start:
        return False
    cbnz_x1, cbz_x0 = struct.unpack_from("<II", data, off - 8)
    return ((cbnz_x1 & 0xFF00001F) == 0xB5000001 and
            (cbz_x0 & 0xFF00001F) == 0xB4000000)


# CLI 1.4.0 arm64: ldrb w2,[x0,#8] ; tbnz w2,#0,eligible ; bl IneligibilityFromResult
# mov w2,#1 selects the existing eligible branch.
CLI_GATE_ARM64 = Gate(
    rb"\x02\x20\x40\x39[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37"
    rb"...[\x94-\x97]\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9",
    rb"\x22\x00\x80\x52[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37"
    rb"...[\x94-\x97]\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9",
    b"\x22\x00\x80\x52", desc="eligibility screen off (arm64)",
    arch="arm64", accept=_cli_arm64_context)

CLI_GATE = MultiGate(CLI_GATE_X64, CLI_GATE_ARM64, desc="eligibility screen off")

# Manager / hub auth result, 2.19.1 x64: force hasValidAuth.
# cmp byte[rax+8],0 ; je ; mov rdx,[rsp+0x70] ; mov [rax+0x60],rdx
# Replacing cmp/je with mov byte[rax+8],1 ; nop*2 selects the success path.
MANAGER_GATE_X64 = Gate(
    rb"\x80\x78\x08\x00\x74.\x48\x8b\x54\x24\x70\x48\x89\x50\x60",
    rb"\xc6\x40\x08\x01\x90\x90\x48\x8b\x54\x24\x70\x48\x89\x50\x60",
    b"\xc6\x40\x08\x01\x90\x90", desc="hasValidAuth=true", arch="x64")

# Manager 2.19.1 Linux arm64: ldrb w3,[x0,#8] ; tbz w3,#0,skip
#   -> mov w3,#1 ; strb w3,[x0,#8]
MANAGER_GATE_ARM64 = Gate(
    rb"\x03\x20\x40\x39[\x03\x23\x43\x63\x83\xa3\xc3\xe3]."
    rb"[\x00-\x07]\x36\xe3\x13\x48\xa9\x03\x10\x06\xa9",
    rb"\x23\x00\x80\x52\x03\x20\x00\x39\xe3\x13\x48\xa9"
    rb"\x03\x10\x06\xa9",
    b"\x23\x00\x80\x52\x03\x20\x00\x39", desc="hasValidAuth=true (arm64)",
    arch="arm64")

MANAGER_GATE = MultiGate(MANAGER_GATE_X64, MANAGER_GATE_ARM64, desc="hasValidAuth=true")

# The agy binary in ~/.gemini/bin is two things at once: the standalone
# CLI (its own eligibility-screen gate, handleAuthResult) and the IDE
# extension's language server, launched as `agy --hub`, whose Login /
# GetAuthStatus verdict comes from a different code site - the
# PersonalAuthValidator hasValidAuth check. The two gates are independent:
# patching only the CLI screen leaves the IDE's hub check fully live
# (observed on macOS ARM64 with IDE 2.6.0: "patched", yet the IDE still
# showed the regional ineligible error right after browser sign-in).
# Both families are therefore resolved and patched whenever present.
# The hub ARM64 signature is the validator build upstream verified for
# the Manager's arm64 language_server - the same validator code; upstream
# ships its extension target as x64-only, so on agy/ARM64 this gate is
# same-code-inferred rather than upstream-verified for agy itself.
HUB_GATE = MultiGate(MANAGER_GATE_X64, MANAGER_GATE_ARM64,
                     desc="hub hasValidAuth=true")
AGY_GATES = (CLI_GATE, HUB_GATE)


def _resolve_all_gates(gates, data, ranges, arch):
    """Resolve every gate family that matches; at least one must match.

    Ambiguity inside one family still raises - only a family with no
    signature at all is skipped.
    """
    resolved = []
    for gate in gates:
        try:
            resolved.append(gate.resolve(data, ranges, arch))
        except SignatureNotFound:
            pass
    if not resolved:
        raise SignatureNotFound("no gate signature matched (unsupported version?)")
    return resolved


def _multi_state(resolved):
    kinds = {kind for kind, _off, _g in resolved}
    if kinds == {"patched"}:
        return "patched"
    if kinds == {"unpatched"}:
        return "unpatched"
    return "partial"


# --------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------

def make_backup(path, status_fn):
    """Create/refresh a verified clean backup; return its path.

    status_fn(path) -> (state, ...) where state is 'unpatched' for a clean
    original. A backup that itself contains a patch is never (re)used as an
    original.
    """
    bak = path + BAK
    if os.path.exists(bak):
        if _files_equal(path, bak):
            if status_fn(bak)[0] == "patched":
                raise OSError("backup already contains a patch; restore a pristine "
                              "original before patching again")
            return bak
        if status_fn(path)[0] in ("patched", "partial"):
            # current file is (partly) patched and differs from backup:
            # backup must be the pristine original - verify before trusting it.
            if status_fn(bak)[0] != "unpatched":
                raise OSError("existing backup is not a recognized clean original - "
                              "refusing to patch on top of it")
            return bak
        info(f"backup is stale (app updated) - refreshing {os.path.basename(bak)}")
    else:
        info(f"backup -> {os.path.basename(bak)}")
    shutil.copy2(path, bak)
    if not _files_equal(path, bak):
        raise OSError("backup verification failed")
    if status_fn(bak)[0] != "unpatched":
        raise OSError("backup does not scan as a clean original - refusing to continue")
    return bak


def restore_file(path, status_fn):
    bak = path + BAK
    if not os.path.exists(bak):
        warn(f"no backup for {os.path.basename(path)} (nothing to restore)")
        return False
    if is_locked(path, "the app"):
        return False
    try:
        if status_fn(bak)[0] != "unpatched":
            warn("backup is not a recognized clean build - refusing to restore")
            return False
    except Exception as e:
        warn(f"could not validate backup: {e}")
        return False
    # atomic replace, preserving the backup itself
    fd, tmp = tempfile.mkstemp(prefix=".agy-restore-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "wb") as out, open(bak, "rb") as src:
            shutil.copyfileobj(src, out)
            out.flush()
            os.fsync(out.fileno())
        shutil.copystat(bak, tmp)
        os.replace(tmp, path)
    except Exception as e:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        warn(f"restore failed: {e}")
        return False
    if status_fn(path)[0] != "unpatched":
        warn("restore verification failed")
        return False
    ok(f"restored {os.path.basename(path)}")
    return True


# --------------------------------------------------------------------------
# generic binary patching (CLI / agy / manager)
# --------------------------------------------------------------------------

def gate_status(path, gates):
    try:
        ranges, arch = executable_info(path)
        with mapped(path) as d:
            if isinstance(gates, (Gate, MultiGate)):
                return (gates.resolve(d, ranges, arch)[0], None)
            return (_multi_state(_resolve_all_gates(gates, d, ranges, arch)), None)
    except (LookupError, OSError, ValueError):
        return ("unknown", None)


def gate_patch(path, gates, app):
    if is_locked(path, app):
        return False
    multi = not isinstance(gates, (Gate, MultiGate))
    try:
        ranges, arch = executable_info(path)
        with mapped(path) as d:
            if multi:
                resolved = _resolve_all_gates(gates, d, ranges, arch)
            else:
                resolved = [gates.resolve(d, ranges, arch)]
    except (LookupError, OSError, ValueError) as e:
        warn(str(e))
        return False
    if all(kind == "patched" for kind, _off, _g in resolved):
        ok(f"{app} already patched")
        return True
    todo = [(off, g) for kind, off, g in resolved if kind == "unpatched"]
    status_fn = lambda p: gate_status(p, gates)
    try:
        bak = make_backup(path, status_fn)
    except OSError as e:
        warn(f"{app} patch failed: {e}")
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="agy-patch-") as temp:
            before = os.path.join(temp, "before")
            shutil.copy2(path, before)
            if not _files_equal(path, before):
                raise OSError("target changed after backup")
            # re-scan the snapshot we are about to patch: the same gate set
            # at the same offsets, with the same per-gate states.
            ranges, arch = executable_info(before)
            with mapped(before) as d:
                if multi:
                    cur = _resolve_all_gates(gates, d, ranges, arch)
                else:
                    cur = [gates.resolve(d, ranges, arch)]
            if [(k, o, g.desc) for k, o, g in cur] != \
                    [(k, o, g.desc) for k, o, g in resolved]:
                raise OSError("target changed before patch write")
            if not _files_equal(path, before):
                raise OSError("target changed before patch write")
            if sys.platform == "darwin":
                # Never write in place into a signed Mach-O: build the patched
                # copy on a sibling inode and atomically replace. The binary
                # fixes are length-preserving, so the offsets stay valid.
                with open(before, "rb") as f:
                    patched_bytes = bytearray(f.read())
                for off, g in todo:
                    patched_bytes[off:off + len(g.fix)] = g.fix
                _mac_replace_file(path, bytes(patched_bytes), before)
            else:
                with open(path, "r+b") as f:
                    for off, g in todo:
                        f.seek(off)
                        f.write(g.fix)
                    f.flush()
                    os.fsync(f.fileno())
    except Exception as e:
        try:
            if sys.platform == "darwin":
                _mac_copy_binary(bak, path)
            else:
                shutil.copy2(bak, path)
            rolled_back = _files_equal(path, bak)
        except Exception:
            rolled_back = False
        warn(f"{app} patch failed: {e}")
        warn("original restored from backup" if rolled_back else
             f"automatic rollback failed - restore {os.path.basename(path) + BAK} manually")
        return False
    if gate_status(path, gates)[0] != "patched":
        try:
            if sys.platform == "darwin":
                _mac_copy_binary(bak, path)
            else:
                shutil.copy2(bak, path)
        except Exception:
            pass
        warn(f"{app} patch failed: post-write signature verification failed")
        return False
    for off, g in todo:
        ok(f"{app} patched ({g.desc} @ file 0x{off:x})")
    return True


@contextlib.contextmanager
def _mac_staged_binary(path):
    """Create a private sibling inode; leave the installed binary untouched."""
    fd, staged = tempfile.mkstemp(prefix=".agy-write-", dir=os.path.dirname(path))
    os.close(fd)
    try:
        yield staged
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def _mac_copy_binary(src, dst):
    """Copy a binary onto dst via a staged sibling + atomic replace (macOS)."""
    if sys.platform != "darwin":
        shutil.copy2(src, dst)
        return
    dst = os.path.realpath(dst)
    with _mac_staged_binary(dst) as staged:
        shutil.copy2(src, staged)
        if not _files_equal(src, staged):
            raise OSError("replacement copy verification failed")
        with open(staged, "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
        os.replace(staged, dst)


def _mac_replace_file(path, data, expected_current):
    """Atomically replace path with data, verifying it still equals expected."""
    real = os.path.realpath(path)
    with _mac_staged_binary(real) as staged:
        with open(staged, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.copystat(expected_current, staged)
        if not _files_equal(real, expected_current):
            raise OSError("target changed while staging patch")
        os.replace(staged, real)


# --------------------------------------------------------------------------
# IDE target (main.js)
# --------------------------------------------------------------------------

# IDE auth gate, verified on IDE 2.5.5 (upstream, macOS arm64 build) and on
# IDE 2.6.0 (this patcher, Linux x64 build 2.6.0-5526304964083712):
#   if(this._authActor.send({type:...}),this._cloudCodeMainService
#       .resetIsTierGCPTos(),this._productService.isGoogleInternal){...}
# Replace this.<field>.isGoogleInternal with true after resetIsTierGCPTos().
IDE_RE = re.compile(rb"(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal")
IDE_DONE = b"resetIsTierGCPTos(),true"
IDE_DONE_RE = re.compile(re.escape(IDE_DONE))

# Builds this patcher was verified against on the real files.
VERIFIED_IDE = {
    # linux-x64: main.js 12,946,363 bytes, gate at file offset 0xbf13cb,
    # exactly one IDE_RE match, not present in product.json checksums.
    "2.6.0": {"build": "5526304964083712",
              "main_js_sha256_linux_x64":
                  "d84ad79f5634d3ba544a939533e75ec197240a21047e3a01b9160cfd980e04ff"},
    # reported verified by the upstream project (issue #8, macOS arm64).
    "2.5.5": {"build": "4923483625488384"},
}


def _ide_gate_state(data):
    ranges = ((0, len(data)),)
    original = _unique_match(IDE_RE, data, ranges, "unpatched IDE gate")
    patched = _unique_match(IDE_DONE_RE, data, ranges, "patched IDE gate")
    if original and patched:
        raise SignatureAmbiguous("both patched and unpatched IDE gates are present")
    if original:
        return "unpatched"
    if patched:
        return "patched"
    raise SignatureNotFound("IDE auth-gate pattern not found (unsupported version?)")


def ide_status(path):
    try:
        with mapped(path) as d:
            return (_ide_gate_state(d), None)
    except (LookupError, OSError, ValueError):
        return ("unknown", None)


def ide_version(main_js_path):
    """IDE version from product.json (ideVersion) next to main.js, or None."""
    app_dir = os.path.dirname(os.path.dirname(main_js_path))  # out/ -> app/
    for name in ("product.json",):
        p = os.path.join(app_dir, name)
        try:
            with open(p, "r", encoding="utf-8") as f:
                product = json.load(f)
            return product.get("ideVersion") or product.get("version")
        except (OSError, ValueError):
            continue
    return None


def _ide_cache_dirs():
    home = os.path.expanduser("~")
    if os.name == "nt":
        bases = [os.path.expandvars(p) for p in
                 (r"%USERPROFILE%\scoop\persist\antigravity-ide\data\user-data",
                  r"%APPDATA%\Antigravity IDE")]
    elif sys.platform == "darwin":
        bases = [os.path.join(home, "Library", "Application Support", "Antigravity IDE")]
    else:
        cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        bases = [os.path.join(cfg, "Antigravity IDE")]
    dirs = []
    for base in bases:
        dirs += [os.path.join(base, "CachedData"),
                 os.path.join(base, "Code Cache", "js")]
    return dirs


def ide_patch(path, dry_run=False):
    if is_locked(path, "Antigravity IDE"):
        return False
    with open(path, "rb") as f:
        d = f.read()
    try:
        kind = _ide_gate_state(d)
    except LookupError as e:
        warn(str(e))
        return False
    if kind == "patched":
        ok("IDE already patched")
        return True
    version = ide_version(path)
    if version and version not in VERIFIED_IDE:
        info(f"IDE version {version} is not in the verified list "
             f"({', '.join(sorted(VERIFIED_IDE))}); the signature matched "
             "exactly once, so patching is still safe to apply")
    elif version:
        info(f"IDE version {version} (verified build)")
    off = IDE_RE.search(d).end(1)
    if dry_run:
        ok(f"IDE would be patched (isGoogleInternal=true @ file 0x{off:x}) [dry-run]")
        return True
    try:
        bak = make_backup(path, ide_status)
    except OSError as e:
        warn(f"IDE patch failed: {e}")
        return False
    try:
        with open(path, "rb") as f:
            current = f.read()
        if current != d or _ide_gate_state(current) != "unpatched":
            raise OSError("target changed before patch write")
        patched, count = IDE_RE.subn(rb"\1true", current, count=1)
        if count != 1:
            raise OSError(f"expected one IDE gate replacement, got {count}")
        # atomic write: temp file in the same directory + os.replace
        fd, tmp = tempfile.mkstemp(prefix=".agy-ide-", dir=os.path.dirname(path) or ".")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(patched)
                f.flush()
                os.fsync(f.fileno())
            shutil.copystat(path, tmp)
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        with mapped(path) as verified:
            if _ide_gate_state(verified) != "patched":
                raise OSError("post-write IDE signature verification failed")
    except Exception as e:
        try:
            shutil.copy2(bak, path)
            rolled_back = _files_equal(path, bak)
        except Exception:
            rolled_back = False
        warn(f"IDE patch failed: {e}")
        warn("original restored from backup" if rolled_back else
             f"automatic rollback failed - restore {os.path.basename(bak)} manually")
        return False
    for c in _ide_cache_dirs():
        try:
            if os.path.isdir(c):
                shutil.rmtree(c, ignore_errors=True)
        except OSError:
            pass
    ok(f"IDE patched (isGoogleInternal=true @ file 0x{off:x})")
    return True


# --------------------------------------------------------------------------
# macOS code signing (adapted from QNIX-Dev/eligibility-antigravity-patcher)
#
# Patching any file inside a signed .app bundle (or a standalone signed
# Mach-O) invalidates its signature. The flow mirrors the upstream project:
#   1. Before the first patch inside a bundle, the bundle's original
#      signature state (main executable, Contents/_CodeSignature,
#      Contents/CodeResources) is snapshotted to a sibling directory
#      <App>.app.agysignbak with a digest manifest.
#   2. Electron Library Validation is preflighted: if it is enabled and no
#      exception entitlement exists, patching stops unless the user passes
#      --macos-disable-library-validation (adds the exception to the main
#      executable only).
#   3. After patching, changed binaries are ad-hoc signed first, then the
#      bundle itself (inside-out), preserving identifier / entitlements /
#      flags / runtime, and verified with codesign --verify. Quarantine is
#      removed from signed targets.
#   4. A signing failure rolls the patched files back from their backups.
#   5. On restore, when the last patched target inside a bundle is restored,
#      the bundle's original signature is restored from the snapshot and
#      verified; if other targets remain patched, the bundle is re-signed
#      around them instead. Standalone binaries need no signature backup:
#      restoring the pristine file bytes restores the original signature.
# --------------------------------------------------------------------------

def _mac_app_bundle(path):
    """Return the enclosing .app bundle, if path is inside one."""
    cur = os.path.realpath(path)
    if not os.path.isdir(cur):
        cur = os.path.dirname(cur)
    while True:
        if cur.endswith(".app") and os.path.isdir(os.path.join(cur, "Contents")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _mac_bundle_main(app):
    info_path = os.path.join(app, "Contents", "Info.plist")
    with open(info_path, "rb") as f:
        executable = plistlib.load(f).get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable or os.path.basename(executable) != executable:
        raise ValueError("invalid CFBundleExecutable in macOS app bundle")
    path = os.path.join(app, "Contents", "MacOS", executable)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"app bundle executable not found: {path}")
    return path


def _mac_command(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise OSError(detail[-1] if detail else f"command failed ({result.returncode}): {args[0]}")
    return result


def _mac_entry_kind(path):
    if os.path.islink(path):
        return "symlink"
    if os.path.isdir(path):
        return "dir"
    if os.path.isfile(path):
        return "file"
    return "missing"


def _mac_entry_digest(path):
    h = hashlib.sha256()

    def add(cur, rel):
        kind = _mac_entry_kind(cur)
        h.update(kind.encode() + b"\0" + rel.encode("utf-8", "surrogateescape") + b"\0")
        if kind == "symlink":
            h.update(os.readlink(cur).encode("utf-8", "surrogateescape"))
        elif kind == "file":
            h.update(str(os.stat(cur, follow_symlinks=False).st_mode & 0o7777).encode())
            with open(cur, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        elif kind == "dir":
            for name in sorted(os.listdir(cur)):
                add(os.path.join(cur, name), rel + "/" + name if rel else name)

    add(path, "")
    return h.hexdigest()


def _mac_remove_entry(path):
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def _mac_copy_entry(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    kind = _mac_entry_kind(src)
    if kind == "symlink":
        os.symlink(os.readlink(src), dst)
    elif kind == "dir":
        shutil.copytree(src, dst, symlinks=True, copy_function=shutil.copy2)
    elif kind == "file":
        shutil.copy2(src, dst)


def _mac_signature_relpaths(app):
    main = os.path.relpath(_mac_bundle_main(app), app)
    return (main, os.path.join("Contents", "_CodeSignature"),
            os.path.join("Contents", "CodeResources"))


def _mac_write_signature_snapshot(app, snapshot):
    app = os.path.abspath(app)
    payload = os.path.join(snapshot, "payload")
    os.makedirs(payload, exist_ok=True)
    items = []
    for rel in _mac_signature_relpaths(app):
        src = os.path.join(app, rel)
        kind = _mac_entry_kind(src)
        if kind != "missing":
            _mac_copy_entry(src, os.path.join(payload, rel))
        items.append({"path": rel.replace(os.sep, "/"), "kind": kind,
                      "digest": _mac_entry_digest(src)})
    manifest = {"version": 1, "app": app, "items": items}
    with open(os.path.join(snapshot, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    _mac_validate_signature_snapshot(snapshot, app)


def _mac_load_signature_snapshot(snapshot, app):
    with open(os.path.join(snapshot, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    app = os.path.abspath(app)
    if manifest.get("version") != 1 or os.path.abspath(manifest.get("app", "")) != app:
        raise OSError("macOS signature backup belongs to a different app bundle")
    items = manifest.get("items")
    if not isinstance(items, list) or not items:
        raise OSError("invalid macOS signature backup manifest")
    for item in items:
        rel = item.get("path", "").replace("/", os.sep)
        dst = os.path.abspath(os.path.join(app, rel))
        if (not rel or os.path.isabs(rel) or
                os.path.normcase(os.path.commonpath((app, dst))) != os.path.normcase(app)):
            raise OSError("unsafe path in macOS signature backup")
    return manifest


def _mac_validate_signature_snapshot(snapshot, app):
    manifest = _mac_load_signature_snapshot(snapshot, app)
    for item in manifest["items"]:
        rel = item["path"].replace("/", os.sep)
        saved = os.path.join(snapshot, "payload", rel)
        if _mac_entry_kind(saved) != item["kind"]:
            raise OSError("macOS signature backup type verification failed")
        if _mac_entry_digest(saved) != item["digest"]:
            raise OSError("macOS signature backup content verification failed")
    return manifest


def _mac_restore_signature_snapshot(snapshot, app):
    manifest = _mac_validate_signature_snapshot(snapshot, app)
    app = os.path.abspath(app)
    for item in manifest["items"]:
        rel = item["path"].replace("/", os.sep)
        dst = os.path.join(app, rel)
        _mac_remove_entry(dst)
        if item["kind"] != "missing":
            _mac_copy_entry(os.path.join(snapshot, "payload", rel), dst)
            if _mac_entry_digest(dst) != item["digest"]:
                raise OSError("restored macOS signature state failed verification")


def _mac_bundle_patch_states(app):
    candidates = {
        "manager": os.path.join(app, "Contents", "Resources", "bin", "language_server"),
        "ide": os.path.join(app, "Contents", "Resources", "app", "out", "main.js"),
    }
    states = {}
    for target, path in candidates.items():
        if os.path.isfile(path):
            try:
                states[target] = (SPEC[target]["status"](path)[0], path)
            except Exception:
                states[target] = ("unknown", path)
    return states


def _mac_prepare_signature_backup(app):
    backup = app + MAC_SIGNATURE_BAK
    states = _mac_bundle_patch_states(app)
    clean = bool(states) and all(state == "unpatched" for state, _ in states.values())
    if sys.platform == "darwin":
        verify = _mac_command(["/usr/bin/codesign", "--verify", "--deep", "--strict",
                               "--verbose=2", app], check=False)
        display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=2", app], check=False)
        details = (display.stdout + display.stderr).lower()
        clean = clean and verify.returncode == 0 and "signature=adhoc" not in details
    if os.path.isdir(backup) and not clean:
        _mac_validate_signature_snapshot(backup, app)
        return backup
    parent = os.path.dirname(app)
    temp = tempfile.mkdtemp(prefix=os.path.basename(app) + MAC_SIGNATURE_BAK + ".", dir=parent)
    old = None
    try:
        _mac_write_signature_snapshot(app, temp)
        if os.path.lexists(backup):
            old = backup + f".old-{os.getpid()}-{time.time_ns()}"
            os.replace(backup, old)
        try:
            os.replace(temp, backup)
            temp = None
        except Exception:
            if old is not None:
                os.replace(old, backup)
                old = None
            raise
        if old is not None:
            _mac_remove_entry(old)
        info(f"macOS signature backup -> {os.path.basename(backup)}")
        return backup
    finally:
        if temp and os.path.isdir(temp):
            shutil.rmtree(temp, ignore_errors=True)


def _mac_entitlements(path):
    result = _mac_command(["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", path])
    if not result.stdout.strip():
        return {}
    try:
        entitlements = plistlib.loads(result.stdout.encode("utf-8"))
    except (ValueError, ExpatError):
        raise OSError("cannot parse macOS signing entitlements") from None
    if not isinstance(entitlements, dict):
        raise OSError("macOS signing entitlements must be a dictionary")
    return entitlements


def _mac_library_validation_entitlements(app, allow_disable=False):
    """Plan an explicit Electron signing exception before any patch writes."""
    framework = os.path.join(app, "Contents", "Frameworks", "Electron Framework.framework")
    if not os.path.isdir(framework):
        return None
    _mac_bundle_main(app)  # validate the executable covered by the bundle signature
    display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=4", app])
    details = display.stdout + display.stderr
    flags = re.search(r"\bflags=0x([0-9a-fA-F]+)\b", details)
    if not flags:
        raise OSError("cannot determine Electron code-signing flags before patching")
    # CS_RUNTIME enables Library Validation; CS_REQUIRE_LV requests it explicitly.
    if not int(flags[1], 16) & (0x10000 | 0x2000):
        return None
    entitlements = _mac_entitlements(app)
    exception = entitlements.get(MAC_DISABLE_LIBRARY_VALIDATION, False)
    if not isinstance(exception, bool):
        raise OSError("invalid Electron disable-library-validation entitlement")
    if exception:
        return None
    framework_display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=4", framework])
    framework_details = framework_display.stdout + framework_display.stderr
    team = re.search(r"^TeamIdentifier=(.*)$", framework_details, re.M)
    if not team:
        raise OSError("cannot determine Electron Framework Team ID before patching")
    if not allow_disable:
        raise OSError(
            "Electron Library Validation would reject bundled frameworks after ad-hoc "
            f"signing (Electron Framework Team ID: {team[1].strip()}; ad-hoc Team ID: none). "
            "No patch was applied. To permit other/unsigned libraries in this app's main "
            "executable only, rerun patch with --macos-disable-library-validation")
    return {**entitlements, MAC_DISABLE_LIBRARY_VALIDATION: True}


def _mac_codesign_verify(path, bundle=False):
    args = ["/usr/bin/codesign", "--verify"]
    if bundle:
        args.append("--deep")
    args += ["--strict", "--verbose=2", path]
    _mac_command(args)


def _mac_codesign(path, bundle=False, entitlements=None, identifier=None):
    display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=2", path], check=False)
    if entitlements is not None and display.returncode:
        raise OSError("cannot preserve Electron signing metadata before applying "
                      "the Library Validation exception")
    args = ["/usr/bin/codesign", "--force", "--sign", "-"]
    if identifier is not None:
        args += ["--identifier", identifier]
    if display.returncode == 0:
        metadata = ("identifier,flags,runtime" if entitlements is not None
                    else "identifier,entitlements,flags,runtime")
        if identifier is not None:
            metadata = metadata.replace("identifier,", "")
        args.append("--preserve-metadata=" + metadata)
    with tempfile.TemporaryDirectory(prefix="agy-macos-entitlements-") as temp:
        if entitlements is not None:
            if not bundle:
                raise ValueError("Library Validation exceptions are limited to the "
                                 "app bundle's main executable")
            plist = os.path.join(temp, "entitlements.plist")
            with open(plist, "wb") as f:
                plistlib.dump(entitlements, f)
            args += ["--entitlements", plist]
            warn(f"disabling Library Validation for {os.path.basename(path)} main "
                 "executable only; this permits libraries with other or no signatures")
        _mac_command(args + [path])
        _mac_codesign_verify(path, bundle=bundle)
        if entitlements is not None and _mac_entitlements(path) != entitlements:
            raise OSError("signed macOS entitlements do not match the requested entitlements")


def _mac_sign_transaction(entries, bundle_entitlements=None):
    """Ad-hoc sign patched binaries (inside-out), then their bundles.

    entries: {target: path}. On any failure the pre-signing bytes/signature
    state are restored before the error propagates.
    """
    binaries = []
    bundles = []
    for target, path in entries.items():
        actual = os.path.realpath(path)
        if target in ("agy", "cli", "manager") and actual not in binaries:
            binaries.append(actual)
        app = _mac_app_bundle(path)
        if app and app not in bundles:
            bundles.append(app)
    if not binaries and not bundles:
        return
    with tempfile.TemporaryDirectory(prefix="agy-macos-sign-") as temp:
        binary_copies = []
        bundle_copies = []
        for i, path in enumerate(binaries):
            saved = os.path.join(temp, f"binary-{i}")
            shutil.copy2(path, saved)
            if not _files_equal(path, saved):
                raise OSError("temporary macOS signing backup verification failed")
            binary_copies.append((path, saved))
        for i, app in enumerate(bundles):
            saved = os.path.join(temp, f"bundle-{i}")
            os.makedirs(saved)
            _mac_write_signature_snapshot(app, saved)
            bundle_copies.append((app, saved))
        try:
            for path in binaries:
                _mac_codesign(path)
            for app in bundles:
                entitlements = (bundle_entitlements or {}).get(app)
                if entitlements is None:
                    _mac_codesign(app, bundle=True)
                else:
                    _mac_codesign(app, bundle=True, entitlements=entitlements)
            for path in binaries:
                ok(f"ad-hoc signed {os.path.basename(path)}")
            for app in bundles:
                ok(f"ad-hoc signed {os.path.basename(app)}")
        except Exception:
            restore_errors = []
            for path, saved in binary_copies:
                try:
                    _mac_copy_binary(saved, path)
                except Exception as e:
                    restore_errors.append(str(e))
            for app, saved in bundle_copies:
                try:
                    _mac_restore_signature_snapshot(saved, app)
                except Exception as e:
                    restore_errors.append(str(e))
            if restore_errors:
                raise OSError("macOS signing failed and its temporary state could not "
                              "be restored: " + "; ".join(restore_errors))
            raise


def _mac_restore_bundle_signature(app):
    backup = app + MAC_SIGNATURE_BAK
    if not os.path.isdir(backup):
        raise OSError(f"macOS signature backup not found: {backup}")
    with tempfile.TemporaryDirectory(prefix="agy-macos-restore-") as temp:
        _mac_write_signature_snapshot(app, temp)
        try:
            _mac_restore_signature_snapshot(backup, app)
            _mac_codesign_verify(app, bundle=True)
        except Exception:
            _mac_restore_signature_snapshot(temp, app)
            raise


def _mac_xattr(action, path, attribute=None, value=None):
    native = getattr(os, action + "xattr", None)
    if native is not None:
        args = [path]
        if attribute is not None:
            args.append(attribute)
        if value is not None:
            args.append(value)
        return native(*args, follow_symlinks=False)
    args = ["/usr/bin/xattr", "-s"]
    if action == "get":
        args += ["-p", "-x", attribute]
    elif action == "remove":
        args += ["-d", attribute]
    elif action == "set":
        args += ["-w", "-x", attribute, value.hex()]
    elif action != "list":
        raise ValueError("unsupported xattr operation")
    result = _mac_command(args + [os.path.abspath(path)])
    if action == "list":
        return result.stdout.splitlines()
    if action == "get":
        return bytes.fromhex(result.stdout)


def _mac_remove_quarantine(entries):
    roots = []
    for path in entries.values():
        root = _mac_app_bundle(path) or os.path.realpath(path)
        if root not in roots:
            roots.append(root)
    attribute = "com.apple.quarantine"
    found = []
    counts = {root: 0 for root in roots}

    def walk_error(error):
        raise error

    for root in roots:
        candidates = [root]
        if root.endswith(".app"):
            for base, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
                candidates += [os.path.join(base, name) for name in dirs + files
                               if not os.path.islink(os.path.join(base, name))]
        for path in candidates:
            attrs = _mac_xattr("list", path)
            if attribute in attrs:
                found.append((root, path, _mac_xattr("get", path, attribute)))
    removed = []
    try:
        for root, path, value in found:
            _mac_xattr("remove", path, attribute)
            removed.append((path, value))
            counts[root] += 1
    except Exception:
        restore_errors = []
        for path, value in reversed(removed):
            try:
                _mac_xattr("set", path, attribute, value)
            except Exception as e:
                restore_errors.append(str(e))
        if restore_errors:
            raise OSError("quarantine removal failed and could not be rolled back: " +
                          "; ".join(restore_errors))
        raise
    for root, count in counts.items():
        if count:
            ok(f"quarantine removed from {os.path.basename(root)} ({count} item(s))")


def _mac_prepare_apps(paths, signing_entitlements=None, disable_library_validation=False):
    failures = {}
    seen = set()
    for path in paths.values():
        if not path:
            continue
        app = _mac_app_bundle(path)
        if not app or app in seen:
            continue
        seen.add(app)
        try:
            entitlements = None
            if signing_entitlements is not None:
                entitlements = _mac_library_validation_entitlements(
                    app, disable_library_validation)
            _mac_prepare_signature_backup(app)
            if entitlements is not None:
                signing_entitlements[app] = entitlements
        except Exception as e:
            failures[app] = str(e)
    return failures


def _mac_run_patch(targets, overrides, disable_library_validation=False):
    rc = 0
    paths = {t: resolve(t, overrides.get(t)) for t in targets}
    signing_entitlements = {}
    app_failures = _mac_prepare_apps(paths, signing_entitlements,
                                     disable_library_validation)
    successful = {}
    changed = []
    for t in targets:
        spec = SPEC[t]
        path = paths[t]
        if not path:
            if t == "agy":
                warn("agy language server not found in ~/.gemini/bin - IDE 2.6.0 "
                     "downloads it on first launch; start the IDE once, then re-run patch")
            else:
                warn(f"{spec['name']} not found - skipping")
            continue
        app = _mac_app_bundle(path)
        if app in app_failures:
            warn(f"macOS signing preparation failed: {app_failures[app]}")
            rc = 1
            continue
        try:
            before = spec["status"](path)[0]
            fn = spec["patch"]
            success = fn(path, dry_run=False) if t == "ide" else fn(path)
            if not success:
                rc = 1
                continue
            successful[t] = path
            if before == "unpatched" and spec["status"](path)[0] == "patched":
                changed.append((t, path))
        except Exception as e:
            warn(f"error: {e}")
            rc = 1
    if successful:
        try:
            if signing_entitlements:
                _mac_sign_transaction(successful, bundle_entitlements=signing_entitlements)
            else:
                _mac_sign_transaction(successful)
        except Exception as e:
            warn(f"macOS code signing failed: {e}")
            for target, path in reversed(changed):
                if not restore_file(path, SPEC[target]["status"]):
                    warn(f"automatic rollback failed for {path}")
            return 1
        try:
            _mac_remove_quarantine(successful)
        except Exception as e:
            warn(f"couldn't remove macOS quarantine: {e}")
            rc = 1
    return rc


def _mac_run_restore(targets, overrides):
    rc = 0
    paths = {t: resolve(t, overrides.get(t)) for t in targets}
    app_failures = _mac_prepare_apps(paths)
    restored = {}
    touched_apps = []
    for t in targets:
        spec = SPEC[t]
        path = paths[t]
        if not path:
            warn(f"{spec['name']} not found - skipping")
            continue
        app = _mac_app_bundle(path)
        if app in app_failures:
            warn(f"macOS signature backup failed: {app_failures[app]}")
            rc = 1
            continue
        try:
            if spec["status"](path)[0] == "patched":
                if not restore_file(path, spec["status"]):
                    rc = 1
                    continue
                if app and app not in touched_apps:
                    touched_apps.append(app)
                if app:
                    restored.setdefault(app, {})[t] = path
            else:
                warn(f"{spec['name']} not patched - skipping restore")
        except Exception as e:
            warn(f"error: {e}")
            rc = 1
    for app in touched_apps:
        states = _mac_bundle_patch_states(app)
        remaining = {target: path for target, (state, path) in states.items()
                     if state == "patched"}
        try:
            if remaining:
                _mac_sign_transaction(remaining)
            else:
                _mac_restore_bundle_signature(app)
                ok(f"original signature restored for {os.path.basename(app)}")
        except Exception as e:
            warn(f"macOS signature restore failed: {e}")
            rc = 1
    return rc


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def _dedup_newest(paths):
    seen, out = set(), []
    for p in sorted({p for p in paths if p and os.path.exists(p)},
                    key=lambda x: os.path.getmtime(x), reverse=True):
        k = os.path.normcase(os.path.realpath(p))
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def _win_roots():
    out = []
    for v in ("LOCALAPPDATA", "ProgramW6432", "PROGRAMFILES", "PROGRAMFILES(X86)",
              "ProgramData", "APPDATA"):
        p = os.environ.get(v)
        if p:
            out += [p, os.path.join(p, "Programs")]
    up = os.environ.get("USERPROFILE", "")
    out += [os.path.join(up, "scoop", "apps"),
            os.path.join(os.environ.get("SCOOP", ""), "apps")]
    try:
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = winreg.OpenKey(
                    hive, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            except OSError:
                continue
            try:
                count = winreg.QueryInfoKey(key)[0]
            except OSError:
                count = 0
            for i in range(count):
                try:
                    sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                    name = str(winreg.QueryValueEx(sub, "DisplayName")[0])
                    if "antigravity" in name.lower():
                        loc = winreg.QueryValueEx(sub, "InstallLocation")[0]
                        if loc:
                            out.append(loc)
                except OSError:
                    pass
    except Exception:
        pass
    seen, roots = set(), []
    for r in out:
        if r and os.path.isdir(r):
            k = os.path.normcase(os.path.realpath(r))
            if k not in seen:
                seen.add(k)
                roots.append(r)
    return roots


def _find_marker_windows(rel):
    hits = []
    for root in _win_roots():
        hits += glob.glob(os.path.join(root, "*ntigravity*", rel))
        hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
        direct = os.path.join(root, rel)
        if os.path.isfile(direct):
            hits.append(direct)
    return _dedup_newest(hits)


def _posix_roots(*launchers):
    home = os.path.expanduser("~")
    roots = ["/opt", "/usr/share", "/usr/lib", "/usr/local/share", "/usr/local/lib",
             "/Applications",
             os.path.join(home, ".local", "share"),
             os.path.join(home, "Applications"),
             os.path.join(home, "Downloads"), home]
    for launcher in launchers:
        w = shutil.which(launcher)
        if w:
            roots.append(os.path.dirname(os.path.realpath(w)))
    return roots


def _posix_find(rel, *launchers):
    hits = []
    for root in _posix_roots(*launchers):
        hits += glob.glob(os.path.join(root, "*ntigravity*", rel))
        hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
        direct = os.path.join(root, rel)
        if os.path.isfile(direct):
            hits.append(direct)
    return _dedup_newest(hits)


def ide_default_mains():
    if os.name == "nt":
        return _find_marker_windows(os.path.join("resources", "app", "out", "main.js"))
    rel = (os.path.join("Contents", "Resources", "app", "out", "main.js")
           if sys.platform == "darwin"
           else os.path.join("resources", "app", "out", "main.js"))
    return _posix_find(rel, "antigravity-ide", "antigravity")


def agy_default_paths():
    return _dedup_newest([os.path.join(os.path.expanduser("~"), ".gemini", "bin",
                                       "agy.exe" if os.name == "nt" else "agy")])


def cli_default_paths():
    cands = []
    w = shutil.which("agy")
    if w:
        cands.append(w)
    if os.name != "nt":
        home = os.path.expanduser("~")
        cands += [os.path.join(d, "agy") for d in
                  (os.path.join(home, ".local", "bin"), os.path.join(home, "bin"),
                   "/usr/local/bin", "/usr/bin", "/opt/homebrew/bin")]
    return _dedup_newest(cands)


def manager_default_bins():
    fname = "language_server.exe" if os.name == "nt" else "language_server"
    if os.name == "nt":
        return _find_marker_windows(os.path.join("resources", "bin", fname))
    rel = (os.path.join("Contents", "Resources", "bin", fname)
           if sys.platform == "darwin"
           else os.path.join("resources", "bin", fname))
    return _posix_find(rel, "antigravity")


SPEC = {
    "ide": dict(name="Antigravity IDE", find=ide_default_mains,
                status=ide_status, patch=ide_patch),
    "agy": dict(name="IDE language server (~/.gemini/bin/agy)", find=agy_default_paths,
                status=lambda p: gate_status(p, AGY_GATES),
                patch=lambda p: gate_patch(p, AGY_GATES, "agy language server")),
    "cli": dict(name="Antigravity CLI", find=cli_default_paths,
                status=lambda p: gate_status(p, CLI_GATE),
                patch=lambda p: gate_patch(p, CLI_GATE, "Antigravity CLI")),
    "manager": dict(name="Antigravity Manager (2.0 app)", find=manager_default_bins,
                    status=lambda p: gate_status(p, MANAGER_GATE),
                    patch=lambda p: gate_patch(p, MANAGER_GATE, "Antigravity Manager")),
}


def resolve(target, override):
    if override:
        return override if os.path.exists(override) else None
    found = SPEC[target]["find"]()
    return found[0] if found else None


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def run(action, targets, overrides, dry_run=False, macos_disable_library_validation=False):
    if sys.platform == "darwin" and not dry_run:
        if action == "patch":
            return _mac_run_patch(targets, overrides,
                                  disable_library_validation=macos_disable_library_validation)
        if action == "restore":
            return _mac_run_restore(targets, overrides)
    rc = 0
    for t in targets:
        spec = SPEC[t]
        path = resolve(t, overrides.get(t))
        if action == "status":
            if not path:
                print(f"  {spec['name']:<42} not found")
                continue
            state, _ = spec["status"](path)
            extra = ""
            if t == "ide":
                v = ide_version(path)
                if v:
                    extra = f" (IDE {v})"
            print(f"  {spec['name']:<42} {state:<10} {path}{extra}")
            continue
        if not path:
            if t == "agy" and action == "patch":
                warn("agy language server not found in ~/.gemini/bin - IDE 2.6.0 "
                     "downloads it on first launch; start the IDE once, then re-run patch")
            else:
                warn(f"{spec['name']} not found - skipping")
            if action == "patch":
                rc = rc or 0  # a missing optional target is not a failure by itself
            continue
        if action == "patch":
            fn = spec["patch"]
            success = fn(path, dry_run=dry_run) if t == "ide" else fn(path)
            if not success:
                rc = 1
        elif action == "restore":
            if not restore_file(path, spec["status"]):
                rc = 1
    return rc


def status_json(targets, overrides):
    out = {}
    for t in targets:
        spec = SPEC[t]
        path = resolve(t, overrides.get(t))
        if not path:
            out[t] = {"name": spec["name"], "found": False}
            continue
        state, _ = spec["status"](path)
        entry = {"name": spec["name"], "found": True, "path": path, "state": state,
                 "sha256": _sha256(path)}
        if t == "ide":
            entry["ide_version"] = ide_version(path)
            entry["verified"] = entry["ide_version"] in VERIFIED_IDE
        out[t] = entry
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Antigravity eligibility patcher (IDE 2.6.0 supported)")
    ap.add_argument("action", nargs="?", choices=("status", "patch", "restore"),
                    help="default: interactive-less status when omitted")
    ap.add_argument("targets", nargs="*", choices=TARGETS,
                    help="subset of targets (default: all)")
    ap.add_argument("--path-ide", dest="path_ide")
    ap.add_argument("--path-agy", dest="path_agy")
    ap.add_argument("--path-cli", dest="path_cli")
    ap.add_argument("--path-manager", dest="path_manager")
    ap.add_argument("--json", action="store_true", help="JSON status output")
    ap.add_argument("--dry-run", action="store_true",
                    help="patch: only report what would change (IDE target)")
    ap.add_argument("--macos-disable-library-validation", action="store_true",
                    help="macOS patch only: if Electron Library Validation would "
                         "reject the ad-hoc re-signed bundle, add the "
                         "disable-library-validation entitlement to the app's "
                         "main executable only")
    args = ap.parse_args(argv)
    overrides = {t: getattr(args, f"path_{t}") for t in TARGETS}
    targets = args.targets or list(TARGETS)
    if args.json or not args.action:
        if args.json:
            print(json.dumps(status_json(targets, overrides), indent=2, ensure_ascii=False))
            return 0
        return run("status", targets, overrides)
    return run(args.action, targets, overrides, dry_run=args.dry_run,
               macos_disable_library_validation=args.macos_disable_library_validation)


if __name__ == "__main__":
    sys.exit(main())
