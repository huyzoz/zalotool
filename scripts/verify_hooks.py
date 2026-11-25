#!/usr/bin/env python3
"""Verify hook_table_verified.json against a base IPA.

Extracts the IPA to a temp dir, finds the main binary (CFBundleExecutable
from the app Info.plist), parses its ObjC method lists with objc_scan.py
(same directory, stdlib-only) and checks every hook entry:
  - the class exists in the binary's class list
  - the selector is in that class's instance (or metaclass) method list
Also checks every expected_absent entry: the selector must NOT appear in
the __objc_methname pool nor in the named class's method list.

Additionally verifies the settings-UI hook targets (NOT part of the
28-hook RE table, so they live here as a built-in list):
  - AccountSettingUI40ViewController exists (the "Tai khoan va Bao mat"
    screen) and is a subclass of BasicSettingUI40TableViewController ->
    BasicSettingTableViewController (checked via the class hierarchy
    recorded in the RE work; here we only assert class existence)
  - BasicSettingTableViewController implements the four table-view
    data-source methods the Tool-row injection hooks.

Exit 0 only if every check passes; otherwise prints each failure and
exits nonzero with a clear message. The workflow fails the job instead
of shipping an IPA whose hooks do not match the base binary.

Usage:
    python3 scripts/verify_hooks.py hook_table_verified.json --ipa base.ipa
"""
import argparse
import json
import os
import plistlib
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from objc_scan import ObjCScan  # noqa: E402

# Settings-UI hook targets (built-in; not part of hook_table_verified.json).
SETTINGS_CHECKS = [
    # (class, selector-or-None, kind) — kind "inst"/"meta"/"class-exists"
    ("AccountSettingUI40ViewController", None, "class-exists"),
    ("BasicSettingTableViewController", "tableView:numberOfRowsInSection:", "inst"),
    ("BasicSettingTableViewController", "tableView:cellForRowAtIndexPath:", "inst"),
    ("BasicSettingTableViewController", "tableView:didSelectRowAtIndexPath:", "inst"),
    ("BasicSettingTableViewController", "tableView:willDisplayCell:forRowAtIndexPath:", "inst"),
]


def find_main_binary(app_dir):
    plist_path = os.path.join(app_dir, "Info.plist")
    with open(plist_path, "rb") as f:
        info = plistlib.load(f)
    exe = info.get("CFBundleExecutable")
    if not exe:
        raise ValueError("Info.plist has no CFBundleExecutable in %s" % app_dir)
    exe_path = os.path.join(app_dir, exe)
    if not os.path.isfile(exe_path):
        raise ValueError("main executable not found: %s" % exe_path)
    return exe_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hook_table", help="hook_table_verified.json")
    ap.add_argument("--ipa", required=True, help="base IPA to check against")
    args = ap.parse_args()

    with open(args.hook_table, "r", encoding="utf-8") as f:
        table = json.load(f)
    hooks = table.get("hooks", [])
    expected_absent = table.get("expected_absent", [])
    if not hooks:
        print("FAIL: no hooks in %s" % args.hook_table)
        return 1
    # No duplicate (class, selector, kind) entries.
    seen = set()
    for h in hooks:
        key = (h["class"], h["selector"], h["kind"])
        if key in seen:
            print("FAIL: duplicate hook entry %s" % (key,))
            return 1
        seen.add(key)

    with tempfile.TemporaryDirectory(prefix="zalotool-verify-") as tmp:
        with zipfile.ZipFile(args.ipa) as z:
            z.extractall(tmp)
        payload = os.path.join(tmp, "Payload")
        apps = [d for d in os.listdir(payload) if d.endswith(".app")]
        if len(apps) != 1:
            print("FAIL: expected exactly one .app in Payload, found %s" % apps)
            return 1
        binary = find_main_binary(os.path.join(payload, apps[0]))
        print("Scanning %s ..." % binary)
        scan = ObjCScan(binary)
        print("%d classes, %d methname strings"
              % (len(scan.classes), len(scan.methnames)))

        failures = []
        checked = 0
        for h in hooks:
            checked += 1
            cls, sel, kind = h["class"], h["selector"], h["kind"]
            meta = (kind == "meta")
            methods = scan.methods_of(cls, meta=meta)
            if methods is None:
                failures.append("MISSING CLASS %s (hook %s %s)"
                                % (cls, kind, sel))
                print("FAIL [mod %s] %s %s %s: class not found"
                      % (h.get("mod", "?"), kind, cls, sel))
                continue
            if sel not in methods:
                failures.append("MISSING SELECTOR %s %s %s" % (kind, cls, sel))
                print("FAIL [mod %s] %s %s %s: selector not in %s method list"
                      % (h.get("mod", "?"), kind, cls, sel,
                         "meta" if meta else "inst"))
                continue
            print("PASS [mod %s] %s %s %s" % (h.get("mod", "?"), kind, cls, sel))

        for entry in expected_absent:
            cls, sel = entry["class"], entry["selector"]
            present = False
            if sel in scan.methnames:
                present = True
            methods = scan.methods_of(cls, meta=(entry.get("kind") == "meta"))
            if methods is not None and sel in methods:
                present = True
            if present:
                failures.append("EXPECTED-ABSENT but present: %s %s" % (cls, sel))
                print("FAIL [expected-absent] %s %s: selector EXISTS, "
                      "hook table must gain an entry" % (cls, sel))
            else:
                print("PASS [expected-absent] %s %s: confirmed absent"
                      % (cls, sel))

        print("--- settings-UI hook targets ---")
        for cls, sel, kind in SETTINGS_CHECKS:
            if kind == "class-exists":
                if cls not in scan.classes:
                    failures.append("MISSING SETTINGS CLASS %s" % cls)
                    print("FAIL [settings] class %s: not found" % cls)
                else:
                    print("PASS [settings] class %s exists" % cls)
                continue
            methods = scan.methods_of(cls, meta=(kind == "meta"))
            if methods is None:
                failures.append("MISSING SETTINGS CLASS %s" % cls)
                print("FAIL [settings] %s %s: class not found" % (cls, sel))
            elif sel not in methods:
                failures.append("MISSING SETTINGS SELECTOR %s %s" % (cls, sel))
                print("FAIL [settings] %s %s: selector not in method list"
                      % (cls, sel))
            else:
                print("PASS [settings] %s %s" % (cls, sel))

        print("Checked %d hooks + %d expected-absent + %d settings targets"
              % (checked, len(expected_absent), len(SETTINGS_CHECKS)))
        if failures:
            print("FAIL: %d check(s) failed:" % len(failures))
            for f in failures:
                print("  - %s" % f)
            return 1
        print("OK: all hook-table and settings-target checks passed")
        return 0


if __name__ == "__main__":
    sys.exit(main())
