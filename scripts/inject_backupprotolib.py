#!/usr/bin/env python3
"""Patch the BackupProtoLib COPY inside an extracted .app so the ZaloTool
dylib loads at launch — without touching the main Zalo binary.

Adds, idempotently:
  - LC_LOAD_WEAK_DYLIB @rpath/ZaloTool.dylib   (weak: the app still launches
    if the dylib is ever missing)
  - LC_RPATH @executable_path/Frameworks      (so @rpath resolves into the
    app's Frameworks/ directory; deduped — never added twice)

Records + verifies the main Zalo binary SHA-256: pass --main-sha <sha> or
--main-sha-file <file with the hash>. The hash is checked BEFORE patching
and AFTER patching; any change fails the job. The main binary itself is
never opened for writing by this script.

Usage:
    python3 scripts/inject_backupprotolib.py <path/to/Zalo.app>
        [--main-sha SHA256] [--main-sha-file FILE]

Requires LIEF (pip install lief). Exits nonzero with a clear message on
any failure — the workflow then fails instead of shipping a bad IPA.

Enum-spelling note (ForgeTax lesson): LIEF 1.0.0 reports load-command
enum names WITHOUT the LC_ prefix (e.g. "LOAD_WEAK_DYLIB", "RPATH");
other versions report "LC_LOAD_WEAK_DYLIB" / "LC_RPATH". All checks
below accept both spellings so idempotency works across LIEF versions.
"""
import argparse
import hashlib
import os
import plistlib
import sys

DYLIB_LOAD_PATH = "@rpath/ZaloTool.dylib"
RPATH_VALUE = "@executable_path/Frameworks"

WEAK_DYLIB_NAMES = ("LC_LOAD_WEAK_DYLIB", "LOAD_WEAK_DYLIB")
RPATH_NAMES = ("LC_RPATH", "RPATH")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_main_binary(app_dir):
    plist_path = os.path.join(app_dir, "Info.plist")
    exe = None
    if os.path.isfile(plist_path):
        with open(plist_path, "rb") as f:
            exe = plistlib.load(f).get("CFBundleExecutable")
    if exe:
        cand = os.path.join(app_dir, exe)
        if os.path.isfile(cand):
            return cand
    app_name = os.path.basename(app_dir.rstrip("/"))
    exe_name = app_name[:-4] if app_name.endswith(".app") else app_name
    cand = os.path.join(app_dir, exe_name)
    if os.path.isfile(cand):
        return cand
    raise ValueError("no main executable found in %s" % app_dir)


def cmd_name(cmd):
    try:
        return cmd.command.name
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app_dir", help="extracted .app directory")
    ap.add_argument("--main-sha", default=None,
                    help="expected SHA-256 of the main binary")
    ap.add_argument("--main-sha-file", default=None,
                    help="file containing the expected main-binary SHA-256")
    args = ap.parse_args()

    expected_sha = args.main_sha
    if args.main_sha_file:
        with open(args.main_sha_file, "r") as f:
            expected_sha = f.read().strip().split()[0]

    app_dir = args.app_dir.rstrip("/")
    proto_path = os.path.join(app_dir, "Frameworks",
                              "BackupProtoLib.framework", "BackupProtoLib")
    if not os.path.isfile(proto_path):
        print("FAIL: BackupProtoLib not found at %s" % proto_path)
        return 1
    main_path = find_main_binary(app_dir)
    main_before = sha256_file(main_path)
    print("Main binary SHA-256 before: %s" % main_before)
    if expected_sha and main_before != expected_sha:
        print("FAIL: main binary SHA-256 mismatch before patching: "
              "got %s, expected %s" % (main_before, expected_sha))
        return 1
    proto_before = sha256_file(proto_path)
    print("BackupProtoLib SHA-256 before: %s" % proto_before)

    try:
        import lief
    except ImportError:
        print("FAIL: LIEF is not installed (pip install lief)")
        return 1
    binary = lief.parse(proto_path)
    if binary is None:
        print("FAIL: LIEF could not parse %s" % proto_path)
        return 1

    have_weak = False
    have_rpath = False
    for cmd in binary.commands:
        name = cmd_name(cmd)
        if name in WEAK_DYLIB_NAMES:
            try:
                if DYLIB_LOAD_PATH in str(cmd.name):
                    have_weak = True
            except Exception:
                pass
        elif name in RPATH_NAMES:
            try:
                if RPATH_VALUE in str(cmd.path):
                    have_rpath = True
            except Exception:
                pass

    changed = False
    if not have_weak:
        # LIEF 1.0.0 names the factory weak_lib(); some versions expose
        # load_weak_dylib() instead. Try both.
        weak_cmd = None
        for factory in ("weak_lib", "load_weak_dylib"):
            fn = getattr(lief.MachO.DylibCommand, factory, None)
            if fn is None:
                continue
            try:
                weak_cmd = fn(DYLIB_LOAD_PATH)
                break
            except Exception:
                continue
        if weak_cmd is None:
            print("FAIL: this LIEF version has no weak-dylib factory "
                  "(tried weak_lib, load_weak_dylib)")
            return 1
        binary.add(weak_cmd)
        print("Added LC_LOAD_WEAK_DYLIB %s" % DYLIB_LOAD_PATH)
        changed = True
    else:
        print("LC_LOAD_WEAK_DYLIB %s already present, skipping" % DYLIB_LOAD_PATH)

    if not have_rpath:
        # LIEF 1.0.0: RPathCommand.create(path) (no public constructor).
        rpath_cmd = None
        create = getattr(lief.MachO.RPathCommand, "create", None)
        if create is not None:
            try:
                rpath_cmd = create(RPATH_VALUE)
            except Exception:
                rpath_cmd = None
        if rpath_cmd is None:
            try:
                rpath_cmd = lief.MachO.RPathCommand(RPATH_VALUE)
            except Exception:
                rpath_cmd = None
        if rpath_cmd is None:
            print("FAIL: this LIEF version cannot create an RPathCommand "
                  "(tried create, constructor)")
            return 1
        binary.add(rpath_cmd)
        print("Added LC_RPATH %s" % RPATH_VALUE)
        changed = True
    else:
        print("LC_RPATH %s already present, skipping" % RPATH_VALUE)

    if changed:
        binary.write(proto_path)
        print("Wrote patched %s" % proto_path)
    else:
        print("No changes needed (idempotent re-run)")

    proto_after = sha256_file(proto_path)
    print("BackupProtoLib SHA-256 after: %s" % proto_after)
    if changed and proto_after == proto_before:
        print("FAIL: BackupProtoLib unchanged after patching?!")
        return 1

    main_after = sha256_file(main_path)
    print("Main binary SHA-256 after: %s" % main_after)
    if main_after != main_before:
        print("FAIL: main binary changed during injection! %s -> %s"
              % (main_before, main_after))
        return 1
    if expected_sha and main_after != expected_sha:
        print("FAIL: main binary SHA-256 mismatch after patching")
        return 1
    print("Main binary unchanged: %s" % main_after)
    return 0


if __name__ == "__main__":
    sys.exit(main())
