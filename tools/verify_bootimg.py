#!/usr/bin/env python3
"""Check: does patched boot.img only differ from original in the kernel?"""
import struct, gzip, sys

def rip(path):
    with open(path,'rb') as f: d = f.read()
    h = struct.unpack('<8I', d[8:40])
    ks,rds,s2s,ps = h[0],h[2],h[4],h[7]
    hv = struct.unpack('<I', d[40:44])[0]
    dts = struct.unpack('<I', d[1648:1652])[0] if hv>=2 else 0
    kp = (ks+ps-1)//ps*ps; rp = (rds+ps-1)//ps*ps
    return {
        'hdr': {
            'kernel_addr':h[1], 'ramdisk_addr':h[3], 'second_addr':h[5],
            'tags_addr':h[6], 'page_size':ps, 'header_version':hv,
            'os_version': struct.unpack('<I', d[44:48])[0],
            'name': d[48:64], 'cmdline': d[64:576], 'extra_cmdline': d[608:1184],
            'second_size': s2s, 'dtb_size': dts, 'kernel_size': ks, 'ramdisk_size': rds,
        },
        'ramdisk': d[ps+kp:ps+kp+rds],
        'dtb': d[ps+kp+rp:ps+kp+rp+dts],
        'kernel_gz': d[ps:ps+ks],
    }

a = rip(sys.argv[1])
b = rip(sys.argv[2])

expected_diff = {'kernel_size', 'os_version'}
hdrs_ok = all(a['hdr'][k] == b['hdr'][k] for k in a['hdr'] if k not in expected_diff)
rd_ok = a['ramdisk'] == b['ramdisk']
dtb_ok = a['dtb'] == b['dtb']

ak = gzip.decompress(a['kernel_gz'])
bk = gzip.decompress(b['kernel_gz'])
min_len = min(len(ak), len(bk))
ker_diff = sum(1 for i in range(min_len) if ak[i] != bk[i])
ker_size_diff = abs(len(ak) - len(bk))

print(f'ramdisk:          {"OK" if rd_ok else "DIFFER"}  ({len(a["ramdisk"]):,} b)')
print(f'dtb:              {"OK" if dtb_ok else "DIFFER"}  ({len(a["dtb"]):,} b)')
print(f'cmdline:          {"OK" if a["hdr"]["cmdline"]==b["hdr"]["cmdline"] else "DIFFER"}')
print(f'kernel differ:    {ker_diff} bytes / {min_len:,} comparable')
if ker_size_diff:
    print(f'kernel size diff: {ker_size_diff:,} bytes (A: {len(ak):,}, B: {len(bk):,})')
all_ok = hdrs_ok and rd_ok and dtb_ok
print(f'only kernel diff: {"YES" if all_ok else "NO"}')
sys.exit(0 if all_ok else 1)
