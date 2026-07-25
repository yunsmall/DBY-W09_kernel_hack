# DBY-W09 内核模块签名绕过 — 完整教程

本教程假设你有一台 **Huawei MatePad 11 2021 (DBY-W09)**，已解锁 bootloader、已 root。

每一步都有**可复制粘贴的命令**。

> Root 教程可参考 B 站 [BV1HLVa68EUv](https://www.bilibili.com/video/BV1HLVa68EUv)。

> **不想自己 Patch？** 直接从 [Releases](https://github.com/yunsmall/DBY-W09_kernel_hack/releases)
> 下载 `kernel_patched.gz`，跳到[第 5 步](#5-重新打包-bootimg)。

---

## 目录

1. [准备工作](#1-准备工作)
2. [从平板提取原版 boot.img](#2-从平板提取原版-bootimg)
3. [解包 boot.img](#3-解包-bootimg)
4. [Patch 内核](#4-patch-内核)
5. [重新打包 boot.img](#5-重新打包-bootimg)
6. [刷入平板并验证](#6-刷入平板并验证)
7. [（可选）编译内核模块](#7-可选编译内核模块)
8. [（可选）关闭 SELinux](#8-可选关闭-selinux)
9. [恢复原版](#9-恢复原版)

---

## 1. 准备工作

### 1.1 克隆仓库

```bash
git clone --recurse-submodules https://github.com/yunsmall/DBY-W09_kernel_hack.git
cd DBY-W09_kernel_hack
```

### 1.2 编译 mkbootimg 和 unpackbootimg

这两个工具是 [osm0sis/mkbootimg](https://github.com/osm0sis/mkbootimg) 提供的 C 程序。
**不要用系统自带的 Python 版 `mkbootimg`，有兼容性问题。**

```bash
git clone https://github.com/osm0sis/mkbootimg /tmp/mkbootimg-src
make -C /tmp/mkbootimg-src -j$(nproc)
```

安装到 `~/.local/bin`：

```bash
mkdir -p ~/.local/bin
cp /tmp/mkbootimg-src/mkbootimg /tmp/mkbootimg-src/unpackbootimg ~/.local/bin/
```

确认 `~/.local/bin` 在 PATH 里：

```bash
echo $PATH | tr ':' '\n' | grep .local/bin
# 如果没有输出，加到 ~/.bashrc 或 ~/.zshrc：
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 1.3 确认平板连接

```bash
adb devices
# 应看到设备
```

---

## 2. 从平板提取原版 boot.img

```bash
mkdir -p stock

# 提取 boot 分区
adb shell su -c "dd if=/dev/block/by-name/boot of=/sdcard/boot.img"
adb pull /sdcard/boot.img stock/boot.img

# 备份 kallsyms（必须，patch 脚本定位函数用）
adb shell cat /proc/kallsyms > stock/tablet_kallsyms
```

---

## 3. 解包 boot.img

用 `unpackbootimg` 一键解包，同时它会输出所有需要的打包参数：

```bash
mkdir -p /tmp/unpacked
unpackbootimg -i stock/boot.img -o /tmp/unpacked
```

解包后 `/tmp/unpacked/` 里的文件：

```
boot.img-kernel           ← 压缩的内核镜像（Image.gz），这就是我们要 patch 的
boot.img-ramdisk           ← ramdisk
boot.img-dtb               ← 设备树
boot.img-cmdline            ← 内核命令行（文本文件，直接 cat 查看）
boot.img-base
boot.img-kernel_offset
boot.img-ramdisk_offset
boot.img-tags_offset
boot.img-pagesize
boot.img-header_version
boot.img-hashtype
boot.img-os_version
boot.img-os_patch_level
...
```

把需要保留的文件移到项目目录：

```bash
mkdir -p stock/boot_extracted
cp /tmp/unpacked/boot.img-kernel   stock/boot_extracted/kernel
cp /tmp/unpacked/boot.img-ramdisk  stock/boot_extracted/ramdisk
cp /tmp/unpacked/boot.img-dtb      stock/boot_extracted/dtb
```

---

## 4. Patch 内核

patch 脚本通过 **kallsyms**（第 2 步已备份）精确定位每个 patch 点，
根据 `/proc/version` 中的内核编译时间戳匹配配置：

### 情况 A：内核时间戳在配置中（推荐）

`tools/kernel_patches.json` 里记录了已知内核的精确偏移。如果时间戳匹配，
加上 `--timestamp` 走精确模式，还会打品牌标记（`/proc/version` 显示 `BP` 而非 `#1`）。

先从 `/proc/version` 获取时间戳（平板开机状态）：

```bash
adb shell cat /proc/version
# 输出: Linux version 4.19.157-perf+ ... #1 SMP PREEMPT Mon Jun 24 13:57:05 CST 2024
# 时间戳部分：Mon Jun 24 13:57:05 CST 2024
```

```bash
python3 tools/patch_mod_verify_sig.py stock/boot_extracted/kernel \
    -o kernel_patched.gz \
    --kallsyms stock/tablet_kallsyms \
    --timestamp "Mon Jun 24 13:57:05 CST 2024" \
    --brand
```

### 情况 B：内核时间戳不在配置中

如果时间戳不在 `kernel_patches.json` 里，不加 `--timestamp` 即可。
脚本仍然通过 kallsyms 精确定位（不依赖启发式搜索），只是不打品牌标记。

```bash
python3 tools/patch_mod_verify_sig.py stock/boot_extracted/kernel \
    -o kernel_patched.gz \
    --kallsyms stock/tablet_kallsyms
```

> **如果时间戳不在配置中**，脚本会打印 WARNING。建议把时间戳和偏移加入
> `tools/kernel_patches.json`（添加方式见 [常见问题](#常见问题)），方便下次直接用精确模式。

### 正常输出：

```
内核: 57,xxx,xxx 字节 (54.x MiB)  输入格式: gzip 压缩
找到 mod_verify_sig @ 0x134800  (kallsyms)
找到 is_module_sig_enforced @ 0x12da30  (kallsyms)
找到 sig_enforce_LDRB @ 0x130a34  (kallsyms)

应用 patch:
  mod_verify_sig @ 0x134800  (kallsyms)
    67B: ff 43 01 d1 ... → 02 00 00 14 ...
  is_module_sig_enforced @ 0x12da30  (kallsyms)
    8B: 88 94 01 f0 ... → e0 03 1f aa ...
  sig_enforce_LDRB @ 0x130a34  (kallsyms)
    4B: 08 61 53 39 → e8 03 1f 2a
  brand @ 0x1d800a3: → BP SMP PREEMPT
  brand @ 0x24800c3: → BP SMP PREEMPT
  brand @ 0x339df6f: → BP SMP PREEMPT

验证:
  ✓ mod_verify_sig
  ✓ is_module_sig_enforced
  ✓ sig_enforce_LDRB
  ✓ brand: 3 处

完成 → kernel_patched.gz (22,xxx,xxx 字节, gzip 压缩)
```

**如果时间戳不在配置中**，脚本会用 WARNING 提示，但仍然通过 kallsyms 精确定位。
建议将时间戳加入配置以便下次精确匹配。

---

## 5. 重新打包 boot.img

`unpackbootimg` 把每个参数都写成了单独文件，直接用 `cat` 读取即可：

```bash
mkdir -p output
UNPACKED=/tmp/unpacked

mkbootimg \
  --kernel kernel_patched.gz \
  --ramdisk stock/boot_extracted/ramdisk \
  --dtb stock/boot_extracted/dtb \
  --base $(cat $UNPACKED/boot.img-base) \
  --second_offset $(cat $UNPACKED/boot.img-second_offset) \
  --kernel_offset $(cat $UNPACKED/boot.img-kernel_offset) \
  --ramdisk_offset $(cat $UNPACKED/boot.img-ramdisk_offset) \
  --tags_offset $(cat $UNPACKED/boot.img-tags_offset) \
  --pagesize $(cat $UNPACKED/boot.img-pagesize) \
  --header_version $(cat $UNPACKED/boot.img-header_version) \
  --hashtype $(cat $UNPACKED/boot.img-hashtype) \
  --os_version $(cat $UNPACKED/boot.img-os_version) \
  --os_patch_level $(cat $UNPACKED/boot.img-os_patch_level) \
  --cmdline "$(cat $UNPACKED/boot.img-cmdline)" \
  -o output/kernel_patched_boot.img

mkdir -p output
mv kernel_patched.gz output/  # 可选，保留 patch 后的内核
```

### 验证打包（可选）

```bash
python3 tools/verify_bootimg.py stock/boot.img output/kernel_patched_boot.img
# 成功: ramdisk: OK, dtb: OK, cmdline: OK, only kernel diff: YES
```

---

## 6. 刷入平板并验证

```bash
# 进 fastboot（关机 → 按住音量下 + 电源，或用 adb）
adb reboot bootloader

# 刷入
fastboot flash boot output/kernel_patched_boot.img
fastboot reboot
```

**如果刷完不开机，不要慌：**

```bash
# 长按电源键关机，进 fastboot，刷回原版：
fastboot flash boot stock/boot.img
fastboot reboot
```

开机后验证：

```bash
# 版本字符串应显示 "BP SMP PREEMPT" 而非 "#1 SMP PREEMPT"
cat /proc/version

# 加载任意 .ko 模块
insmod /path/to/some_module.ko

# 日志确认
dmesg | grep bypassed
# 输出: mod_verify_sig: bypassed by patch
```

---

## 7.（可选）编译内核模块

如果内核提供的模块不够用，可以从源码编译 `.ko`。

### 7.1 安装交叉编译工具链

```bash
# Debian/Ubuntu
sudo apt install clang-22 gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
```

把 llvm-22 的 bin 目录加到 PATH：

```bash
export PATH="/usr/lib/llvm-22/bin:$PATH"
```

### 7.2 编译

> `kmake` 定义在 `env.sh`，`source env.sh` 后即可使用。

```bash
source env.sh

# 应用必要的内核源码 patch（gcc-wrapper、mkcompile_h 等）
python3 tools/setup_kernel_source.py

mkdir -p output/kernel_build
cp analysis/my_tablet_origin_config output/kernel_build/.config
cd dby-w09-4.0
make O=../output/kernel_build olddefconfig

# 调整配置
scripts/config --file ../output/kernel_build/.config --disable MODULE_SIG
scripts/config --file ../output/kernel_build/.config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --file ../output/kernel_build/.config --set-str MODULE_SIG_KEY ""
scripts/config --file ../output/kernel_build/.config --disable QCA_CLD_WLAN
scripts/config --file ../output/kernel_build/.config -e MODVERSIONS

kmake O=../output/kernel_build modules_prepare
kmake O=../output/kernel_build modules
```

产物在 `dby-w09-4.0/` 下各子目录。

> **注意**: 源码编译的完整内核（vmlinux/Image.gz）**不要刷入平板**——华为
> 有大量闭源驱动和 vendor patch，自编内核会卡在开机 logo。编译仅用于生成
> `Module.symvers`（符号 CRC 表），以便编译与平板内核匹配的 `.ko` 模块。

---

## 8.（可选）关闭 SELinux

平板内核禁用了 SELinux 运行时开关（`CONFIG_SECURITY_SELINUX_DEVELOP=n`），
本仓库提供的内核模块可以绕过。

### 8.1 编译

```bash
source env.sh && cd dby-w09-4.0
kmake O=../output/kernel_build M=../selinux_module modules
```

产物：`../selinux_module/selinux_permissive.ko`

> 模块通过 `init_utsname()->version` 中的时间戳匹配已知内核配置表。
> 如果时间戳不在 `known_kernels[]` 中，insmod 会拒绝加载。
> 添加新内核支持见[常见问题](#常见问题)。

### 8.2 使用

> **警告**: 此模块直接修改内核代码，有死机/重启风险。建议**重启平板后单独测试**，
> 确认稳定后再搭配其他内核模块（如 vhci-hcd）使用。若 `echo 1` 后死机，
> 长按**音量下 + 电源键**强制重启。

```bash
# 推送并加载
adb push selinux_module/selinux_permissive.ko /sdcard/
adb shell su -c "insmod /sdcard/selinux_permissive.ko"

# 关闭 SELinux（permissive）
adb shell su -c "echo 1 > /sys/kernel/selinux_permissive/selinux_permissive"

# 恢复 SELinux（enforcing）
adb shell su -c "echo 0 > /sys/kernel/selinux_permissive/selinux_permissive"

# 卸载（自动恢复 enforcing）
adb shell su -c "rmmod selinux_permissive"
```

---

## 9. 恢复原版

```bash
adb reboot bootloader
fastboot flash boot stock/boot.img
fastboot reboot
```

---

## 常见问题

**Q: 怎么在内核配置和模块里添加新内核支持？**

A: 以时间戳 `Mon Jul 01 12:00:00 CST 2025` 为例，两步：

1. `tools/kernel_patches.json` 的 `known_kernels` 里加一条：
```json
"Mon Jul 01 12:00:00 CST 2025": {
  "sig_enforce_ldrb_off": "0x???",
  "banner_offsets": ["0x???", "0x???", "0x???"],
  "fingerprint_mod_verify_sig": ["..."],
  ...
}
```

2. `selinux_module/selinux_permissive.c` 的 `known_kernels[]` 里加一条：
```c
{ .timestamp = "Mon Jul 01 12:00:00 CST 2025",
  .avc_denied_off = 0x??, .compute_sid_off = 0x???, .sid_mls_copy_off = 0x??? },
```
三个偏移需用 IDA 在新内核上逆向找到（与当前内核相同位置的 MOV 指令）。

**Q: 脚本报 `sig_enforce LDRB 未找到`**

A: 很可能是 kallsyms 文件不对（跟内核不是同一次开机的）。重新 `adb shell cat /proc/kallsyms > stock/tablet_kallsyms`。

**Q: 刷完不开机**

A: 常见原因是 mkbootimg 参数不对。确保使用 `unpackbootimg` 输出的所有参数。
`fastboot flash boot stock/boot.img` 可随时恢复。

**Q: insmod 报 `Exec format error`**

A: vermagic 不匹配。在 `.config` 里开 `CONFIG_MODVERSIONS` 重新编译。
如果已刷 patched kernel，也可以用 `insmod --force`。
