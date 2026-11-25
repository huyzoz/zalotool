#!/usr/bin/env python3
"""Fail if any two touched binaries share an identical CodeDirectory.

Background (the old 261002 build's instant-crash lesson): all four
injected/patched binaries carried the SAME template CodeDirectory
(byte-identical, ident com.icraze.gtatracker, 805 slots). On a
non-jailbroken TrollStore device the kernel kills the process when it
faults in a page whose hash does not match the binary's own CodeDirectory,
so a shared template signature crashes on tap, before any tweak code runs.

`ldid -S` re-signs each binary with its own real per-page hashes, so
after correct signing every touched binary must have a DIFFERENT
CodeDirectory blob. This script parses LC_CODE_SIGNATURE of each given
binary, hashes its CodeDirectory blob (SHA-256) and FAILS if:
  - a binary has no LC_CODE_SIGNATURE / no CodeDirectory blob, or
  - any two binaries share an identical CodeDirectory hash.

Usage:
    python3 scripts/verify_signatures.py <binary1> [binary2 ...]

Requires only the Python standard library. Exits nonzero on failure.
"""
import hashlib
import struct
import sys

LC_CODE_SIGNATURE = 0x1D
SUPERBLOB_MAGIC = 0xFADE0CC0
CODEDIRECTORY_MAGIC = 0xFADE0C02
# Superblob index entry types (cs_blobs.h): 0 = CodeDirectory.
INDEX_TYPE_CODEDIRECTORY = 0


def code_directory_hash(path):
    """Return (sha256_hex, ident, nslots) of a binary's CodeDirectory."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
        raise ValueError("%s: not a Mach-O 64-bit binary" % path)
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    sig_off = sig_size = None
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, size = struct.unpack_from("<2I", data, off)
        if cmd == LC_CODE_SIGNATURE:
            sig_off, sig_size = struct.unpack_from("<2I", data, off + 8)
            break
        off += size
    if sig_off is None:
        raise ValueError("%s: no LC_CODE_SIGNATURE" % path)
    if sig_off + sig_size > len(data) or sig_size < 16:
        raise ValueError("%s: LC_CODE_SIGNATURE out of range" % path)
    blob = data[sig_off:sig_off + sig_size]
    magic, length, count = struct.unpack_from(">3I", blob, 0)
    if magic != SUPERBLOB_MAGIC:
        raise ValueError("%s: bad superblob magic 0x%x" % (path, magic))
    cd_blob = None
    for i in range(count):
        entry_off = 12 + i * 8
        if entry_off + 8 > len(blob):
            break
        etype, eoff = struct.unpack_from(">2I", blob, entry_off)
        if etype != INDEX_TYPE_CODEDIRECTORY:
            continue
        if eoff + 12 > len(blob):
            break
        cmagic, clength = struct.unpack_from(">2I", blob, eoff)
        if cmagic != CODEDIRECTORY_MAGIC:
            raise ValueError("%s: CodeDirectory blob has bad magic 0x%x"
                             % (path, cmagic))
        cd_blob = blob[eoff:eoff + clength]
        break
    if cd_blob is None:
        raise ValueError("%s: no CodeDirectory blob in superblob" % path)
    # CodeDirectory header (cs_blobs.h, big-endian):
    # magic(0) length(4) version(8) flags(12) hashOffset(16)
    # identOffset(20) nSpecialSlots(24) nCodeSlots(28) codeLimit(32)
    ident_off = struct.unpack_from(">I", cd_blob, 20)[0]
    n_code_slots = struct.unpack_from(">I", cd_blob, 28)[0]
    ident_end = cd_blob.find(b"\x00", ident_off)
    ident = cd_blob[ident_off:ident_end].decode(errors="replace")
    return hashlib.sha256(cd_blob).hexdigest(), ident, n_code_slots


def main():
    paths = sys.argv[1:]
    if not paths:
        print("usage: verify_signatures.py <binary1> [binary2 ...]")
        return 2
    seen = {}
    failures = []
    for path in paths:
        try:
            digest, ident, nslots = code_directory_hash(path)
        except (OSError, ValueError) as e:
            print("FAIL: %s" % e)
            failures.append(str(e))
            continue
        print("%s\n  CodeDirectory SHA-256: %s\n  ident: %s, code slots: %d"
              % (path, digest, ident, nslots))
        if digest in seen:
            failures.append(
                "identical CodeDirectory hash for %s and %s (%s) — "
                "shared template signature, will crash on TrollStore"
                % (seen[digest], path, digest))
        else:
            seen[digest] = path
    if failures:
        print("FAIL:")
        for f in failures:
            print("  - %s" % f)
        return 1
    print("OK: %d binaries, all CodeDirectory hashes distinct" % len(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
