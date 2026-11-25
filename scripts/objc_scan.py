#!/usr/bin/env python3
"""Static ObjC method-list scanner for the Zalo main binary.

Adapted from ~/workspace/zalo-ipa2/scratch/objc_scan.py so CI is
self-contained: the original imported its MachO parser from
~/workspace/zalo-ipa/scratch/resolve_all.py (which needs capstone) and
hard-coded the binary path and output directory. This copy embeds a
minimal stdlib-only MachO parser (header + LC_SEGMENT_64 section table)
and takes the binary path + output directory as arguments.

Parsing (unchanged from the original, verified against 26.11.02.1):
- class list from __objc_classlist (chained-pointer targets = file offsets)
- method lists handling BOTH 24-byte absolute and 12-byte relative lists
  (relative: name/types/imp are int32 offsets from the field's own VA)
- empirical quirk of this binary: a relative name pointer lands on a
  __objc_selrefs slot holding a chained pointer to the real
  __objc_methname string — follow one indirection, fall back to reading
  the string directly at the target
- instance methods (class_ro baseMethods) + class methods (metaclass baseMethods)
- dumps the __objc_methname string pool (authoritative selector pool)

Usage:
    objc_scan.py <binary> [--out DIR] [ClassName ...]
    No class names: only the class list + methname pool are written.
    With class names: methods-<Class>.inst.txt / .meta.txt are written too.

Outputs go to --out (default: current working directory).
Requires only the Python standard library.
"""
import argparse
import os
import struct
import sys


def chained(v):
    """Strip a dyld chained pointer to its target (file offset)."""
    return ((v >> 36) & 0xFF) << 32 | (v & 0xFFFFFFFFF)


class MachO:
    """Minimal Mach-O 64-bit reader: segments, sections, va_to_off."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        magic = struct.unpack_from("<I", d, 0)[0]
        if magic != 0xFEEDFACF:
            raise ValueError("%s: not a Mach-O 64-bit binary (magic 0x%x)"
                             % (path, magic))
        (cputype, cpusub, ftype, ncmds, sizeofcmds, flags,
         reserved) = struct.unpack_from("<7I", d, 4)
        self.segs = {}   # segname -> (vmaddr, vmsize, fileoff, filesize)
        self.sects = {}  # (segname, sectname) -> (addr, size, offset, res1)
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<2I", d, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = d[off + 8:off + 24].split(b"\x00")[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", d, off + 24)
                nsects = struct.unpack_from("<I", d, off + 64)[0]
                self.segs[segname] = (vmaddr, vmsize, fileoff, filesize)
                soff = off + 72
                for _i in range(nsects):
                    sname = d[soff:soff + 16].split(b"\x00")[0].decode()
                    sseg = d[soff + 16:soff + 32].split(b"\x00")[0].decode()
                    addr, sz = struct.unpack_from("<QQ", d, soff + 32)
                    s_off = struct.unpack_from("<I", d, soff + 48)[0]
                    res1 = struct.unpack_from("<I", d, soff + 68)[0]
                    self.sects[(sseg, sname)] = (addr, sz, s_off, res1)
                    soff += 80
            off += size

    def va_to_off(self, va):
        for vmaddr, vmsize, fileoff, filesize in self.segs.values():
            if vmaddr <= va < vmaddr + filesize:
                return va - vmaddr + fileoff
        return None

    def off_to_va(self, off):
        for vmaddr, vmsize, fileoff, filesize in self.segs.values():
            if fileoff <= off < fileoff + filesize:
                return off - fileoff + vmaddr
        return None


class ObjCScan:
    def __init__(self, binary_path):
        self.m = MachO(binary_path)
        self.d = self.m.data
        self.classes = self._scan_classes()
        self.methnames = self._scan_methnames()

    def _cstr_at_off(self, off):
        if off is None or off < 0 or off >= len(self.d):
            return None
        end = self.d.find(b"\x00", off)
        if end == -1:
            return None
        try:
            s = self.d[off:end].decode()
        except UnicodeDecodeError:
            return None
        return s if s and all(32 <= ord(c) < 127 for c in s) else None

    def _read_u64(self, off):
        if off is None or off + 8 > len(self.d):
            return 0
        return struct.unpack_from("<Q", self.d, off)[0]

    def _scan_classes(self):
        key = [k for k in self.m.sects if k[1] == "__objc_classlist"]
        if not key:
            return {}
        _, size, off, _ = self.m.sects[key[0]]
        classes = {}
        for i in range(size // 8):
            v = struct.unpack_from("<Q", self.d, off + i * 8)[0]
            cfo = chained(v)
            if cfo + 40 > len(self.d):
                continue
            datap = self._read_u64(cfo + 32)
            dp = chained(datap)
            if dp + 40 > len(self.d):
                continue
            name = self._cstr_at_off(chained(self._read_u64(dp + 24)))
            if not name:
                continue
            isa_raw = self._read_u64(cfo)
            meta_off = chained(isa_raw)
            meta_ro_off = None
            if meta_off and meta_off + 40 <= len(self.d):
                mdatap = self._read_u64(meta_off + 32)
                meta_ro_off = chained(mdatap)
            classes[name] = dict(class_off=cfo, ro_off=dp,
                                 meta_off=meta_off, meta_ro_off=meta_ro_off)
        return classes

    def _scan_methnames(self):
        methnames = set()
        for (seg, sname) in list(self.m.sects):
            if sname == "__objc_methname":
                _, sz, soff, _ = self.m.sects[(seg, sname)]
                buf = self.d[soff:soff + sz]
                for part in buf.split(b"\x00"):
                    try:
                        s = part.decode()
                    except UnicodeDecodeError:
                        continue
                    if s:
                        methnames.add(s)
        return methnames

    def _parse_method_list(self, bm_off):
        """Return list of selector names, or [] if none."""
        d = self.d
        if not bm_off or bm_off + 8 > len(d):
            return []
        entsize_flags, count = struct.unpack_from("<2I", d, bm_off)
        entsize = entsize_flags & 0xFFFF
        is_relative = bool(entsize_flags & 0x80000000)
        if count > 10000 or entsize not in (12, 24):
            return ["<UNPARSEABLE entsize_flags=0x%x count=%d>"
                    % (entsize_flags, count)]
        sels = []
        bm_va = self.m.off_to_va(bm_off)
        for i in range(count):
            eoff = bm_off + 8 + i * entsize
            if is_relative:
                name_rel, = struct.unpack_from("<i", d, eoff)
                if bm_va is None:
                    sels.append("<NO-VA>")
                    continue
                name_va = bm_va + 8 + i * entsize + name_rel
                name_off = self.m.va_to_off(name_va)
                s = None
                if name_off is not None and name_off + 8 <= len(d):
                    slot = struct.unpack_from("<Q", d, name_off)[0]
                    s = self._cstr_at_off(chained(slot))
                if s is None:
                    s = self._cstr_at_off(name_off)
                sels.append(s or "<BAD-NAME va=0x%x>" % name_va)
            else:
                name_raw = self._read_u64(eoff)
                np = chained(name_raw)
                sels.append(self._cstr_at_off(np)
                            or "<BAD-NAME off=0x%x>" % np)
        return sels

    def methods_of(self, name, meta=False):
        """Selector list for a class (None if the class is not found)."""
        info = self.classes.get(name)
        if info is None:
            return None
        ro = info["meta_ro_off"] if meta else info["ro_off"]
        if not ro or ro + 40 > len(self.d):
            return []
        bm = chained(self._read_u64(ro + 32))
        if bm == 0:
            return []
        return self._parse_method_list(bm)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary", help="Mach-O binary to scan (Zalo main binary)")
    ap.add_argument("--out", default=".",
                    help="output directory (default: current directory)")
    ap.add_argument("classes", nargs="*", help="class names to dump")
    args = ap.parse_args(argv)
    scan = ObjCScan(args.binary)
    os.makedirs(args.out, exist_ok=True)
    print("%d classes" % len(scan.classes))
    with open(os.path.join(args.out, "Zalo.classes.txt"), "w") as f:
        f.write("\n".join(sorted(scan.classes)))
    print("%d __objc_methname strings" % len(scan.methnames))
    with open(os.path.join(args.out, "Zalo.methnames.txt"), "w") as f:
        f.write("\n".join(sorted(scan.methnames)))
    for name in args.classes:
        for meta in (False, True):
            tag = "meta" if meta else "inst"
            sels = scan.methods_of(name, meta=meta)
            if sels is None:
                print("%s [%s]: CLASS NOT FOUND" % (name, tag))
                continue
            print("%s [%s]: %d methods" % (name, tag, len(sels)))
            with open(os.path.join(args.out,
                                   "methods-%s.%s.txt" % (name, tag)), "w") as f:
                f.write("\n".join(sorted(s for s in sels if s)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
