# DBY-W09 内核模块签名绕过 — 完整教程

本教程假设你有一台 **Huawei MatePad 11 2021 (DBY-W09)**，已解锁 bootloader、已 root。

每一步都有**可复制粘贴的命令**。

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

# 备份 kallsyms（可选，patch 脚本定位函数时参考）
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

```bash
python3 tools/patch_mod_verify_sig.py stock/boot_extracted/kernel \
    -o kernel_patched.gz --brand
```

正常输出：

```
Kernel: 57,xxx,xxx bytes (54.x MiB)
Found mod_verify_sig @ 0x134800  (fingerprint #1 at +0x1348dc)
Found sig_enforce_LDRB @ 0x130a34  (LDRB->MOV_W8_WZR at +0x130a34)

Applying patches:
  mod_verify_sig @ 0x134800  ...
  sig_enforce_LDRB @ 0x130a34  ...
  brand @ 0x1d800a3: → BP SMP PREEMPT
  brand @ 0x24800c3: → BP SMP PREEMPT
  brand @ 0x339df6f: → BP SMP PREEMPT

Verification:
  ✓ mod_verify_sig @ 0x134800: OK
  ✓ sig_enforce_LDRB @ 0x130a34: OK
  ✓ brand: 3x BP SMP PREEMPT

Done → kernel_patched.gz
```

**如果报 `no patch targets found`：** 你的内核版本和本教程不一致。本教程针对：

```
Linux version 4.19.157-perf+ (HarmonyOS@localhost)
#1 SMP PREEMPT Mon Jun 24 13:57:05 CST 2024
```

脚本有语义搜索能力（跨编译器），不同版本可能仍有效，但不保证。

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
sudo apt install clang-22 lld-22 gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
```

### 7.2 编译

```bash
source env.sh
cd dby-w09-4.0
cp ../analysis/my_config .config
make olddefconfig

# 开启 MODVERSIONS（平板内核开启了，必须匹配 CRC）
scripts/config -e MODVERSIONS

make modules_prepare
kmake modules
```

产物在 `dby-w09-4.0/` 下各子目录。

> **已知问题**: WiFi 驱动 `qcacld` 缺 `athdefs.h` 等头文件，无法编译。

---

## 8.（可选）关闭 SELinux

平板内核禁用了 SELinux 运行时开关（`CONFIG_SECURITY_SELINUX_DEVELOP=n`），
本仓库提供的内核模块可以绕过。

### 8.1 编译

```bash
source env.sh && cd dby-w09-4.0
kmake M=../selinux_module modules
```

产物：`../selinux_module/selinux_permissive.ko`

### 8.2 使用

```bash
# 推送并加载
adb push selinux_module/selinux_permissive.ko /sdcard/
adb shell su -c "insmod /sdcard/selinux_permissive.ko"

# 关闭 SELinux
adb shell su -c "echo 1 > /sys/kernel/selinux_permissive/selinux_permissive"

# 恢复 SELinux
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

**Q: 脚本报 `no patch targets found`**

A: 内核版本不匹配。脚本搜索的是 HarmonyOS 4.2 的 4.19.157-perf+ 内核，
但保留了语义搜索能力（跨编译器 ADRP+LDRB+RET 指令模式匹配），
可能仍有效。如果完全搜不到，需要在新内核上手动逆向。

**Q: 刷完不开机**

A: 常见原因是 mkbootimg 参数不对。确保使用 `unpackbootimg` 输出的所有参数。
`fastboot flash boot stock/boot.img` 可随时恢复。

**Q: insmod 报 `Exec format error`**

A: vermagic 不匹配。在 `.config` 里开 `CONFIG_MODVERSIONS` 重新编译。
如果已刷 patched kernel，也可以用 `insmod --force`。
