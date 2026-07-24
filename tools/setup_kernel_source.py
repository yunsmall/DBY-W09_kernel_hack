#!/usr/bin/env python3
"""
Apply necessary fixes to the kernel source tree after submodule checkout.

Usage:
  python3 tools/setup_kernel_source.py

This patches the dby-w09-4.0 submodule with two fixes needed for compilation:

  1. scripts/mkcompile_h — fix multi-line clang version output
  2. drivers/qcacld/Kbuild — fix include paths for qca-wifi-host-cmn
"""

import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KERNEL = os.path.join(ROOT, 'dby-w09-4.0')

PATCHES = [
    {
        'name': 'mkcompile_h: fix multi-line clang version',
        'file': 'scripts/mkcompile_h',
        'old': "CC_VERSION=$($CC -v 2>&1 | grep ' version ' | sed 's/[[:space:]]*$//')",
        'new': "CC_VERSION=$($CC -v 2>&1 | grep ' version ' | head -n1 | sed 's/[[:space:]]*$//')",
    },
    {
        'name': 'qcacld/Kbuild: fix WLAN_COMMON_ROOT path',
        'file': 'drivers/qcacld/Kbuild',
        'old': 'WLAN_COMMON_ROOT := ../qca-wifi-host-cmn',
        'new': 'WLAN_COMMON_ROOT := $(srctree)/drivers/qca-wifi-host-cmn',
    },
    {
        'name': 'qcacld/Kbuild: fix WLAN_COMMON_INC path',
        'file': 'drivers/qcacld/Kbuild',
        'old': 'WLAN_COMMON_INC := qca-cmn',
        'new': 'WLAN_COMMON_INC := $(WLAN_COMMON_ROOT)',
    },
]


def apply_patch(patch):
    path = os.path.join(KERNEL, patch['file'])
    if not os.path.exists(path):
        print(f"  SKIP: {patch['file']} not found")
        return False

    with open(path, 'r') as f:
        content = f.read()

    if patch['new'] in content:
        print(f"  ALREADY APPLIED: {patch['name']}")
        return True

    if patch['old'] not in content:
        print(f"  SKIP: pattern not found in {patch['file']}")
        return False

    content = content.replace(patch['old'], patch['new'], 1)
    with open(path, 'w') as f:
        f.write(content)
    print(f"  PATCHED: {patch['name']}")
    return True


def main():
    if not os.path.isdir(KERNEL):
        print(f"ERROR: kernel source not found at {KERNEL}")
        print("Run: git submodule update --init")
        sys.exit(1)

    print(f"Patching kernel source at {KERNEL}\n")

    ok = 0
    fail = 0
    for p in PATCHES:
        if apply_patch(p):
            ok += 1
        else:
            fail += 1

    print(f"\n{ok} applied/skipped, {fail} failed")
    sys.exit(0 if fail == 0 else 1)


if __name__ == '__main__':
    main()
