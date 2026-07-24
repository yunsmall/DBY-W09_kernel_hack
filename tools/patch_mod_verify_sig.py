#!/usr/bin/env python3
"""
Patch DBY-W09 kernel Image to bypass module signature verification.

Two essential patches (patch #2 is redundant — see below):
  1. mod_verify_sig          → printk trampoline + return 0
  3. sig_enforce LDRB in module_sig_check → MOV W8, WZR (always 0)

Flow in module_sig_check (HarmonyOS 4.2 kernel):
  ├─ [module has signature marker]
  │   → mod_verify_sig() → patch #1 always returns 0
  └─ [module has NO signature marker]
       → LDRB sig_enforce → patch #3 forces W8=0 → CBZ always taken
       → enforcement check skipped, module loads

Also patches is_module_sig_enforced (patch #2, REDUNDANT):
  - is_module_sig_enforced is only called from trace_event_raw_event_module_load,
    a trace event handler that records enforcement state for logging.
  - It is NOT called from the actual module load path.
  - Patch #3 makes this unreachable anyway (CBZ always branches over the call).
  - Kept as a safety net against OTA changes; can be removed to save 8 bytes.

Usage:
  python3 patch_mod_verify_sig.py stock/boot_extracted/kernel -o kernel_patched.gz
  python3 patch_mod_verify_sig.py stock/boot_extracted/kernel -o kernel_patched.gz --brand
"""

import struct
import gzip
import sys
import os

# ── Patch data ───────────────────────────────────────────────────────

# Simple MOV X0,XZR; RET (8 bytes)
MOV_RET = bytes.fromhex('e0031faac0035fd6')
# MOV W8, WZR (4 bytes) — replace LDRB sig_enforce, makes CBZ always branch
MOV_W8_WZR = bytes.fromhex('e8031f2a')
SIG_ENFORCE_LDRB_OFF = 0x130a34  # file offset where module_sig_check reads sig_enforce

# printk trampoline for mod_verify_sig:
# Layout at function entry:
#   +0: B +8              (jump to trampoline at +8)
#   +4: NOP               (padding)
#   +8: STP X29,X30,...   (save frame)
#  +12: ADR X0, msg       (point to string)
#  +16: BL printk         (call printk)
#  +20: LDP X29,X30,...   (restore frame)
#  +24: MOV X0, XZR       (return 0)
#  +28: RET
#  +32: "mod_verify_sig: bypassed by patch\n\0"

TRAMPOLINE_BYTES = bytes.fromhex(
    '02000014'   # B +8
    '1f2003d5'   # NOP
    'fd7bbfa9'   # STP X29, X30, [SP, #-16]!
    'a0000010'   # ADR X0, +0x14   → points to string at +32
    '32d8fe97'   # BL printk       → PC-relative to printk @ 0xffffff9391b6a8d8
    'fd7bc1a8'   # LDP X29, X30, [SP], #16
    'e0031faa'   # MOV X0, XZR
    'c0035fd6'   # RET
)
TRAMPOLINE_MSG = b'mod_verify_sig: bypassed by patch\n\x00'

# Version branding
VERSION_OLD = b'#1 SMP PREEMPT'
VERSION_NEW = b'BP SMP PREEMPT'
# Version branding: "#1 SMP PREEMPT" → "BP SMP PREEMPT" (shows in /proc/version)
BANNER_OFFSETS = [0x1d800a3, 0x24800c3, 0x339df6f]

# ── ARM64 instruction helpers ─────────────────────────────────────────

def is_b_cc(inst):
    return (inst & 0xFF00001F) == 0x54000003

def is_sub_imm(inst):
    return (inst >> 24) == 0xD1

def is_ldr_x_reg_offset(inst):
    return (inst & 0xFFC00000) == 0xF9400000

def get_ldr_rt(inst):
    return inst & 0x1F

def get_ldr_rn(inst):
    return (inst >> 5) & 0x1F

def get_ldr_offset(inst):
    return ((inst >> 10) & 0xFFF) << 3

def get_sub_rd(inst):
    return inst & 0x1F

def get_sub_rn(inst):
    return (inst >> 5) & 0x1F

def get_sub_imm(inst):
    return (inst >> 10) & 0xFFF

# ── Prologue detection ────────────────────────────────────────────────

def walk_to_prologue(data, known_offset):
    for off in range(known_offset, max(known_offset - 128, 0), -4):
        inst = struct.unpack('<I', data[off:off + 4])[0]
        if (inst & 0xFF0000FF) == 0xD10000FF:      # SUB SP, SP, #imm
            return off
        if (inst & 0xFFC07FFF) == 0xA9007BFD:       # STP X29, X30, [SP, #imm]
            if off >= 4:
                prev = struct.unpack('<I', data[off - 4:off])[0]
                if (prev & 0xFF0000FF) == 0xD10000FF:
                    return off - 4
            return off
    return known_offset

# ── Target finders ────────────────────────────────────────────────────

def find_mod_verify_sig(data):
    """Find mod_verify_sig by LDR [X1,#24] + CMP #13 + B.CC + SUB #12."""

    FINGERPRINTS = [
        bytes.fromhex('280c40f91f3500f143050054153100d1f40301aaf30300aa'),
        bytes.fromhex('280c40f91f3500f183040054083100d1000900088b'),
    ]
    for i, fp in enumerate(FINGERPRINTS):
        off = data.find(fp)
        if off != -1:
            prologue = walk_to_prologue(data, off)
            return prologue, f"fingerprint #{i+1} at +0x{off:x}"

    for rt in list(range(10)) + list(range(19, 29)):
        ldr_pat = struct.pack('<I', 0xF9400C20 | rt)
        pos = 0
        while pos < len(data) - 24:
            pos = data.find(ldr_pat, pos)
            if pos == -1:
                break
            if pos + 20 > len(data):
                break
            insts = [struct.unpack('<I', data[pos + i*4:pos + (i+1)*4])[0]
                     for i in range(5)]
            i0, i1, i2, i3 = insts[0], insts[1], insts[2], insts[3]
            if not (is_ldr_x_reg_offset(i0) and get_ldr_rn(i0) == 1 and get_ldr_offset(i0) == 24):
                pos += 4; continue
            if i1 != 0xF100351F:
                pos += 4; continue
            if not is_b_cc(i2):
                pos += 4; continue
            if not (is_sub_imm(i3) and get_sub_rn(i3) == rt and get_sub_imm(i3) == 12):
                pos += 4; continue
            prologue = walk_to_prologue(data, pos)
            return prologue, f"semantic LDR+CMP+SUB (X{rt}) at +0x{pos:x}"

    return None, "not found"


def find_is_module_sig_enforced(data):
    """Find is_module_sig_enforced: ADRP + LDRB W0 + RET (12 bytes)."""

    FINGERPRINTS = [
        bytes.fromhex('889401f000615339c0035fd6'),
    ]
    for i, fp in enumerate(FINGERPRINTS):
        off = data.find(fp)
        if off != -1 and off % 4 == 0:
            return off, f"fingerprint #{i+1} at +0x{off:x}"

    pos = 0
    while pos + 12 <= len(data):
        insts = struct.unpack('<III', data[pos:pos+12])
        i0, i1, i2 = insts
        if (i0 & 0x9F000000) != 0x90000000:
            pos += 4; continue
        adrp_rd = i0 & 0x1F
        if (i1 & 0xFFC00000) != 0x39400000:
            pos += 4; continue
        if (i1 & 0x1F) != 0:            # must be W0 (return reg)
            pos += 4; continue
        if ((i1 >> 5) & 0x1F) != adrp_rd:
            pos += 4; continue
        if i2 != 0xD65F03C0:             # RET
            pos += 4; continue
        return pos, f"semantic ADRP+LDRB+RET at +0x{pos:x}"

    return None, "not found"


def find_all_targets(data):
    results = []
    off, method = find_mod_verify_sig(data)
    if off is not None:
        results.append(('mod_verify_sig', off, method))
    off, method = find_is_module_sig_enforced(data)
    if off is not None:
        results.append(('is_module_sig_enforced', off, method))
    # 3. sig_enforce LDRB patch (fixed offset, verify fingerprint)
    fp = data[SIG_ENFORCE_LDRB_OFF:SIG_ENFORCE_LDRB_OFF+4]
    if (struct.unpack('<I', fp)[0] & 0xFFC003FF) == 0x39400108:
        results.append(('sig_enforce_LDRB', SIG_ENFORCE_LDRB_OFF, f'LDRB->MOV_W8_WZR at +0x{SIG_ENFORCE_LDRB_OFF:x}'))

    return results

# ── Patch application ─────────────────────────────────────────────────

def apply_patches(data, targets, brand=False):
    """Apply all patches to kernel data. Returns patched data + summary."""

    summary = []

    for name, offset, method in targets:
        if name == 'mod_verify_sig':
            # Apply trampoline: B+8 + NOP + trampoline code + string
            patch = TRAMPOLINE_BYTES + TRAMPOLINE_MSG
            orig = data[offset:offset + len(patch)]
            data = bytearray(data)
            data[offset:offset + len(patch)] = patch
            summary.append(
                f"  {name} @ 0x{offset:x}  ({method})\n"
                f"    trampoline: {len(TRAMPOLINE_BYTES)}b code + {len(TRAMPOLINE_MSG)}b string\n"
                f"    first 8 bytes: {orig[:8].hex(' ')} → {patch[:8].hex(' ')}"
            )
        elif name == 'sig_enforce_LDRB':
            orig = data[offset:offset + len(MOV_W8_WZR)]
            data = bytearray(data)
            data[offset:offset + len(MOV_W8_WZR)] = MOV_W8_WZR
            summary.append(
                f"  {name} @ 0x{offset:x}  ({method})\n"
                f"    {len(MOV_W8_WZR)} bytes: {orig.hex(' ')} → {MOV_W8_WZR.hex(' ')}"
            )
        else:  # is_module_sig_enforced: simple MOV,RET
            orig = data[offset:offset + len(MOV_RET)]
            data = bytearray(data)
            data[offset:offset + len(MOV_RET)] = MOV_RET
            summary.append(
                f"  {name} @ 0x{offset:x}  ({method})\n"
                f"    {len(MOV_RET)} bytes: {orig.hex(' ')} → {MOV_RET.hex(' ')}"
            )

    data = bytes(data)

    # Brand version string (UTS_VERSION, shows in /proc/version)
    if brand:
        pos = 0
        count = 0
        while True:
            pos = data.find(VERSION_OLD, pos)
            if pos == -1:
                break
            data = bytearray(data)
            data[pos:pos + len(VERSION_OLD)] = VERSION_NEW
            data = bytes(data)
            summary.append(f"  brand @ 0x{pos:x}: → {VERSION_NEW.decode()}")
            count += 1
            pos += 1
        if count == 0:
            summary.append(f"  brand: SKIP (VERSION_OLD not found)")

    return data, summary

# ── Verification ──────────────────────────────────────────────────────

def verify(data, targets, brand=False):
    """Verify patches are applied correctly."""
    ok = True

    for name, offset, _ in targets:
        if name == 'mod_verify_sig':
            expected_len = len(TRAMPOLINE_BYTES) + len(TRAMPOLINE_MSG)
            actual = data[offset:offset + expected_len]
            expected = TRAMPOLINE_BYTES + TRAMPOLINE_MSG
            if actual == expected:
                print(f"  ✓ {name} @ 0x{offset:x}: OK ({expected_len} bytes)")
            else:
                print(f"  ✗ {name} @ 0x{offset:x}: MISMATCH")
                ok = False
        elif name == 'sig_enforce_LDRB':
            if data[offset:offset + len(MOV_W8_WZR)] == MOV_W8_WZR:
                print(f"  ✓ {name} @ 0x{offset:x}: OK")
            else:
                print(f"  ✗ {name} @ 0x{offset:x}: MISMATCH")
                ok = False
        else:
            if data[offset:offset + len(MOV_RET)] == MOV_RET:
                print(f"  ✓ {name} @ 0x{offset:x}: OK")
            else:
                print(f"  ✗ {name} @ 0x{offset:x}: MISMATCH")
                ok = False

    if brand:
        pos = 0
        old_count = 0
        while True:
            pos = data.find(VERSION_OLD, pos)
            if pos == -1: break
            old_count += 1
            pos += 1
        pos = 0
        new_count = 0
        while True:
            pos = data.find(VERSION_NEW, pos)
            if pos == -1: break
            new_count += 1
            pos += 1
        if old_count == 0 and new_count >= 1:
            print(f"  ✓ brand: {new_count}x {VERSION_NEW.decode()}")
        else:
            print(f"  ✗ brand: {old_count} old, {new_count} new")
            ok = False

    return ok

# ── Main ──────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="Patch DBY-W09 kernel to bypass module signature verification")
    p.add_argument('input', help='Kernel Image (raw or gzipped)')
    p.add_argument('-o', '--output', required=True,
                   help='Output file (.img raw, else compressed)')
    p.add_argument('--brand', action='store_true',
                   help='Brand version string: 4.19.157-BYPS+ (banner only, vermagic intact)')
    p.add_argument('-v', '--verbose', action='store_true')
    args = p.parse_args()

    with open(args.input, 'rb') as f:
        data = f.read()

    is_gz = data[:2] == b'\x1f\x8b'
    if is_gz:
        data = gzip.decompress(data)

    print(f"Kernel: {len(data):,} bytes ({len(data)/1024**2:.1f} MiB)")

    # Find targets
    targets = find_all_targets(data)
    if not targets:
        print("ERROR: no patch targets found!")
        sys.exit(1)

    for name, offset, method in targets:
        print(f"Found {name} @ 0x{offset:x}  ({method})")

    # Apply patches
    print("\nApplying patches:")
    data, summary = apply_patches(data, targets, brand=args.brand)
    for s in summary:
        print(s)

    # Verify
    print("\nVerification:")
    if not verify(data, targets, brand=args.brand):
        print("\nERROR: verification failed!")
        sys.exit(1)

    # Compress & save
    do_gz = args.output.endswith('.gz') or (
        is_gz and not (args.output.endswith('.img') or args.output.endswith('.raw')))
    if do_gz:
        data = gzip.compress(data, compresslevel=9)

    with open(args.output, 'wb') as f:
        f.write(data)
    print(f"\nDone → {args.output} ({len(data):,} bytes)")


if __name__ == '__main__':
    main()
