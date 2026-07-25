#!/usr/bin/env python3
"""Check known patches present in boot.img kernel (patch_mod_verify_sig.py output)."""
import struct, gzip, sys

def rip_kernel(path):
    with open(path, 'rb') as f:
        d = f.read()
    h = struct.unpack('<8I', d[8:40])
    ks, ps = h[0], h[7]
    kp = (ks + ps - 1) // ps * ps
    return gzip.decompress(d[ps:ps + ks])

bk = rip_kernel(sys.argv[1])

PATCHES = [
    ('mod_verify_sig', 0x134800,
     bytes.fromhex('020000141f2003d5fd7bbfa9a000001032d8fe97fd7bc1a8e0031faac0035fd6')
     + b'mod_verify_sig: bypassed by patch\n\x00'),
    ('is_module_sig_enforced', 0x12da30, bytes.fromhex('e0031faac0035fd6')),
    ('brand /proc/version', 0x1d800a3, b'BP SMP PREEMPT'),
    ('brand /proc/version', 0x24800c3, b'BP SMP PREEMPT'),
    ('brand /proc/version', 0x339df6f, b'BP SMP PREEMPT'),
]

all_ok = True
for name, off, expect in PATCHES:
    actual = bk[off:off + len(expect)]
    ok = actual == expect
    tag = 'OK' if ok else 'FAIL'
    if not ok:
        all_ok = False
    print(f'{name}: {tag}')
    if not ok:
        for i in range(min(len(actual), len(expect))):
            if actual[i] != expect[i]:
                print(f'  0x{off + i:x}: got 0x{actual[i]:02x} want 0x{expect[i]:02x}')

sys.exit(0 if all_ok else 1)
