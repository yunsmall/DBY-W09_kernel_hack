#!/usr/bin/env python3
"""
Patch DBY-W09 内核 Image，绕过模块签名验证。

通过 kallsyms 文件精确定位所有 patch 点，不依赖指纹或启发式搜索。
如果提供了 --timestamp 且匹配已知内核，还会打 is_module_sig_enforced 冗余补丁。

用法:
  python3 patch_mod_verify_sig.py 内核 Image -o 输出文件 --kallsyms tablet_kallsyms
  python3 patch_mod_verify_sig.py ... --timestamp "Mon Jun 24 13:57:05 CST 2024" --brand
"""

import struct, gzip, sys, os, json, re

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, 'kernel_patches.json')) as f:
    CONFIG = json.load(f)

# ── ARM64 指令 ────────────────────────────────────────────────────────

MOV_RET    = bytes.fromhex('e0031faac0035fd6')
MOV_W8_WZR = bytes.fromhex('e8031f2a')
TRAMPOLINE = bytes.fromhex(
    '02000014'  '1f2003d5'   # B +8; NOP
    'fd7bbfa9'  'a0000010'   # STP X29,X30; ADR X0,msg
    '32d8fe97'  'fd7bc1a8'   # BL printk; LDP X29,X30
    'e0031faa'  'c0035fd6'   # MOV X0,XZR; RET
) + b'mod_verify_sig: bypassed by patch\n\x00'

PATCH_BYTES = {
    'mod_verify_sig':         TRAMPOLINE,
    'is_module_sig_enforced': MOV_RET,
    'sig_enforce_LDRB':       MOV_W8_WZR,
}

def u32(data, off):
    return struct.unpack('<I', data[off:off+4])[0]

# ═══════════════════════════════════════════════════════════════════════
# kallsyms 解析
# ═══════════════════════════════════════════════════════════════════════

def parse_kallsyms(path):
    """解析 kallsyms，返回 {符号名: (地址, 类型)}"""
    syms = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                addr = int(parts[0], 16)
                ty = parts[1]
                name = parts[2]
                syms[name] = (addr, ty)
    return syms

def sym_file_off(syms, name, text_addr):
    """符号的虚拟地址 → 文件偏移"""
    if name not in syms:
        return None
    return syms[name][0] - text_addr

# ═══════════════════════════════════════════════════════════════════════
# 定位函数
# ═══════════════════════════════════════════════════════════════════════

def func_prologue(data, off):
    """从 off 往前找函数入口（SUB SP 或 STP X29,X30）"""
    for o in range(off, max(off - 4096, 0), -4):
        inst = u32(data, o)
        if (inst & 0xFF0000FF) == 0xD10000FF:          # SUB SP, SP, #imm
            return o
        if (inst & 0xFFC07FFF) == 0xA9007BFD:           # STP X29, X30, [SP, #imm]
            if o >= 4 and (u32(data, o - 4) & 0xFF0000FF) == 0xD10000FF:
                return o - 4
            return o
    return off

def find_bl_to(data, start, end, target):
    """在 [start,end) 找 BL target"""
    for o in range(start, end, 4):
        inst = u32(data, o)
        if (inst >> 26) != 0x25:
            continue
        off = inst & 0x03FFFFFF
        if off & 0x02000000: off |= 0xFC000000
        if o + (off << 2) == target:
            return o
    return None

# ═══════════════════════════════════════════════════════════════════════
# kallsyms 精确定位（所有模式共用）
# ═══════════════════════════════════════════════════════════════════════

def find_targets_by_kallsyms(data, syms, text_addr):
    """通过 kallsyms 精确定位所有 patch 点"""

    # 1. mod_verify_sig — 直接拿地址
    mv_off = sym_file_off(syms, 'mod_verify_sig', text_addr)
    if mv_off is None:
        print("错误: kallsyms 中未找到 mod_verify_sig"); sys.exit(1)
    mv_prologue = func_prologue(data, mv_off)
    results = [('mod_verify_sig', mv_prologue, 'kallsyms')]

    # 2. is_module_sig_enforced — 直接拿地址
    is_off = sym_file_off(syms, 'is_module_sig_enforced', text_addr)
    if is_off is not None:
        results.append(('is_module_sig_enforced', is_off, 'kallsyms'))

    # 3. sig_enforce LDRB — 需要找到引用 sig_enforce 变量的指令
    se_off = find_sig_enforce_ldrb_by_kallsyms(data, syms, text_addr, mv_prologue)
    if se_off is None:
        print("错误: 未找到 sig_enforce LDRB 指令"); sys.exit(1)
    results.append(('sig_enforce_LDRB', se_off, 'kallsyms'))

    return results

def find_sig_enforce_ldrb_by_kallsyms(data, syms, text_addr, mv_prologue):
    """通过 kallsyms 找到 sig_enforce LDRB 指令

    1. 从 kallsyms 获取 sig_enforce 变量地址
    2. 定位 module_sig_check（通过 BL mod_verify_sig）
    3. 在 module_sig_check 内找引用 sig_enforce 地址的 LDRB
    """
    se_addr = sym_file_off(syms, 'sig_enforce', text_addr)
    if se_addr is None:
        return None

    # 定位 module_sig_check = 包含 BL mod_verify_sig 的函数
    # module_sig_check 可能在 mod_verify_sig 之前或之后，两个方向都搜
    bl_off = find_bl_to(data, max(mv_prologue - 0x8000, 0),
                        min(mv_prologue + 0x1000, len(data)), mv_prologue)
    if bl_off is None:
        return None

    msc_prologue = func_prologue(data, bl_off)

    # sig_enforce 变量文件偏移 → ARM64 中通过 ADRP + LDRB 访问
    # ADRP 加载页地址，LDRB 加上页内偏移
    se_page = se_addr & ~0xFFF
    se_page_off = se_addr & 0xFFF

    # 扫描 module_sig_check 内的 ADRP 指令
    # ADRP Xd, #imm: imm21 << 12 = target_page - (PC & ~0xFFF)
    for o in range(msc_prologue, msc_prologue + 0x800, 4):
        inst = u32(data, o)
        if (inst & 0x9F000000) != 0x90000000:  # ADRP
            continue

        # 计算 ADRP 目标页
        imm21 = (((inst >> 5) & 0x7FFFF) << 2) | ((inst >> 29) & 0x3)
        if imm21 & 0x100000:
            imm21 |= 0xFFE00000  # sign-extend 21-bit
        target_page = (o & ~0xFFF) + (imm21 << 12)

        if target_page != se_page:
            continue

        adrp_rd = inst & 0x1F

        # 找到对应的 LDRB Wx, [Xd, #off]
        for l in range(o + 4, min(o + 24, msc_prologue + 0x800), 4):
            ldrb = u32(data, l)
            if ((ldrb & 0xFFC00000) == 0x39400000 and        # LDRB
                ((ldrb >> 5) & 0x1F) == adrp_rd and          # [ADRP reg]
                ((ldrb >> 10) & 0xFFF) == se_page_off):      # 偏移匹配
                return l

    return None

# ═══════════════════════════════════════════════════════════════════════
# 品牌和验证
# ═══════════════════════════════════════════════════════════════════════

def apply_branding(data, cfg):
    old_b = cfg['banner_old'].encode()
    new_b = cfg['banner_new'].encode()
    lines = []
    for o_str in cfg.get('banner_offsets', []):
        o = int(o_str, 16)
        if data[o:o+len(old_b)] == old_b:
            data = bytearray(data); data[o:o+len(old_b)] = new_b; data = bytes(data)
            lines.append(f"  brand @ 0x{o:x}: → {cfg['banner_new']}")
    return data, lines

def apply_patches(data, targets):
    lines = []
    for name, off, method in targets:
        if name not in PATCH_BYTES:
            continue
        b = PATCH_BYTES[name]
        old = data[off:off+len(b)].hex(' ')
        data = bytearray(data); data[off:off+len(b)] = b; data = bytes(data)
        lines.append(f"  {name} @ 0x{off:x}  ({method})\n"
                     f"    {len(b)}B: {old} → {b[:8].hex(' ')}")
    return data, lines

def verify_patches(data, targets, cfg, brand):
    ok = True
    for name, off, _ in targets:
        if name not in PATCH_BYTES: continue
        b = PATCH_BYTES[name]
        good = data[off:off+len(b)] == b
        print(f"  {'✓' if good else '✗'} {name}")
        ok = ok and good
    if brand and cfg:
        n = data.count(cfg['banner_new'].encode())
        print(f"  {'✓' if n else '✗'} brand: {n} 处")
        ok = ok and n > 0
    return ok

# ═══════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description='Patch DBY-W09 内核，绕过模块签名验证')
    p.add_argument('input')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--kallsyms', required=True, help='kallsyms 符号表文件（必须）')
    p.add_argument('--brand', action='store_true', help='改 /proc/version 标记')
    p.add_argument('--timestamp', help='编译时间戳如 "Mon Jun 24 13:57:05 CST 2024"，匹配后开启品牌')
    args = p.parse_args()

    # ── 加载内核 ──
    with open(args.input, 'rb') as f:
        data = f.read()
    is_gz = data[:2] == b'\x1f\x8b'
    ftype = 'gzip 压缩' if is_gz else ('原始 Image' if data[:4] == b'\x00\x00\x00\x00' else '未知格式')
    if is_gz:
        data = gzip.decompress(data)
    print(f"内核: {len(data):,} 字节 ({len(data)/1024**2:.1f} MiB)  输入格式: {ftype}")

    # ── 解析 kallsyms ──
    syms = parse_kallsyms(args.kallsyms)
    text_addr = syms.get('_text', (0,))[0]
    if text_addr == 0:
        print("错误: kallsyms 中未找到 _text"); sys.exit(1)
    print(f"_text: 0x{text_addr:x}")

    # ── 时间戳检查 ──
    cfg = None
    if args.timestamp:
        for ts, c in CONFIG['known_kernels'].items():
            if args.timestamp == ts:
                cfg = c
                print(f"时间戳匹配: {ts[:40]}...\n")
                break
        if cfg is None:
            print(f"WARNING: 时间戳 '{args.timestamp}' 不在配置中\n")
    else:
        found = [ts for ts in CONFIG['known_kernels'] if ts.encode() in data]
        if found:
            print(f"内核匹配配置: [{found[0][:40]}...]  (可加 --timestamp 开启品牌)\n")

    # ── 定位 ──
    targets = find_targets_by_kallsyms(data, syms, text_addr)


    for name, off, method in targets:
        print(f"找到 {name} @ 0x{off:x}  ({method})")

    # ── 应用 ──
    print("\n应用 patch:")
    data, lines = apply_patches(data, targets)
    if args.brand and cfg:
        data, blines = apply_branding(data, cfg)
        lines.extend(blines)
    for line in lines: print(line)

    # ── 验证 ──
    print("\n验证:")
    if not verify_patches(data, targets, cfg, args.brand):
        print("\n错误: 验证失败!"); sys.exit(1)

    # ── 保存 ──
    do_gz = args.output.endswith('.gz') or (is_gz and not args.output.endswith(('.img','.raw')))
    if do_gz:
        raw_size = len(data)
        data = gzip.compress(data, compresslevel=9)
        print(f"\n完成 → {args.output}  ({len(data):,} 字节, gzip 压缩, 原始 {raw_size:,} 字节)")
    else:
        print(f"\n完成 → {args.output}  ({len(data):,} 字节, 原始 Image)")

if __name__ == '__main__':
    main()
