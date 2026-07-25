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
        'name': 'Makefile: fix gcc-wrapper overriding CC=clang when LLVM=1',
        'file': 'Makefile',
        'old': '# Use the wrapper for the compiler.  This wrapper scans for new\n'
               '# warnings and causes the build to stop upon encountering them\n'
               'CC\t\t= $(PYTHON) $(srctree)/scripts/gcc-wrapper.py $(srctree)/../../prebuilts/misc/linux-x86/ccache/ccache $(REAL_CC)',
        'new': 'ifneq ($(LLVM),)\n'
               '# LLVM=1: CC=clang already set above, skip gcc-wrapper\n'
               'else\n'
               '# Use the wrapper for the compiler.  This wrapper scans for new\n'
               '# warnings and causes the build to stop upon encountering them\n'
               'CC\t\t= $(PYTHON) $(srctree)/scripts/gcc-wrapper.py $(srctree)/../../prebuilts/misc/linux-x86/ccache/ccache $(REAL_CC)\n'
               'endif',
    },
    {
        'name': 'mkcompile_h: fix multi-line clang version',
        'file': 'scripts/mkcompile_h',
        'old': "CC_VERSION=$($CC -v 2>&1 | grep ' version ' | sed 's/[[:space:]]*$//')",
        'new': "CC_VERSION=$($CC -v 2>&1 | grep ' version ' | head -n1 | sed 's/[[:space:]]*$//')",
    },
    {
        'name': 'qcacld/Kbuild: fix WLAN_ROOT to use srctree for out-of-tree build',
        'file': 'drivers/qcacld/Kbuild',
        'old': 'WLAN_ROOT := drivers/qcacld',
        'new': 'WLAN_ROOT := $(srctree)/drivers/qcacld',
    },
    {
        'name': 'qcacld/Kbuild: fix WLAN_COMMON_INC path for out-of-tree build',
        'file': 'drivers/qcacld/Kbuild',
        'old': 'WLAN_COMMON_INC := qca-cmn',
        'new': 'WLAN_COMMON_INC := $(srctree)/drivers/qca-wifi-host-cmn',
    },
]


def apply_patch(patch):
    path = os.path.join(KERNEL, patch['file'])
    print(f"\n── {patch['name']}")
    print(f"   文件: {patch['file']}")

    if not os.path.exists(path):
        print(f"   ✗ 文件不存在，跳过")
        return False

    with open(path, 'r') as f:
        content = f.read()

    if patch['new'] in content:
        print(f"   ✓ 已打过，跳过")
        return True

    if patch['old'] not in content:
        print(f"   ✗ 未找到匹配行，跳过")
        return False

    content = content.replace(patch['old'], patch['new'], 1)
    with open(path, 'w') as f:
        f.write(content)
    print(f"   ✓ 已 patch")
    print(f"     旧: {patch['old'].strip()}")
    print(f"     新: {patch['new'].strip()}")
    return True


def main():
    if not os.path.isdir(KERNEL):
        print(f"ERROR: kernel source not found at {KERNEL}")
        print("Run: git submodule update --init")
        sys.exit(1)

    print(f"内核源码: {KERNEL}")
    print(f"共 {len(PATCHES)} 个 patch\n")

    ok = 0
    fail = 0
    for p in PATCHES:
        if apply_patch(p):
            ok += 1
        else:
            fail += 1

    print(f"\n{'─' * 40}")
    print(f"结果: {ok} 个成功, {fail} 个失败")
    if fail:
        print("部分 patch 未应用，编译可能失败")
    sys.exit(0 if fail == 0 else 1)


if __name__ == '__main__':
    main()
