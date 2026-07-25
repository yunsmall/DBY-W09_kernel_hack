# DBY-W09 内核模块签名绕过

Huawei MatePad 11 2021 (DBY-W09) HarmonyOS 4.2 / Linux 4.19.157-perf+

通过 binary patch 原版内核，绕过模块签名验证，加载任意 `.ko` 模块。
包含一个运行时关闭 SELinux 的内核模块。

> **[→ 完整教程看这里 ←](TUTORIAL.md)**

## 目标内核

```
Linux version 4.19.157-perf+ (HarmonyOS@localhost)
#1 SMP PREEMPT Mon Jun 24 13:57:05 CST 2024
```

> 不同编译时间的同一版本内核，patch 脚本通过 kallsyms 精确定位。

## 做了什么

Patch 原版内核的两个关键点（第三个是冗余安全网）：

| Patch | 函数 | 改动 | 必要性 |
|-------|------|------|--------|
| #1 | `mod_verify_sig` | 签名验证函数 → 直接返回 0 | **必须** |
| #3 | `module_sig_check` 读取 `sig_enforce` | LDRB → MOV W8, WZR | **必须** |
| #2 | `is_module_sig_enforced` | MOV X0,#0; RET | 冗余（仅 trace event 调用） |

`tools/patch_mod_verify_sig.py` 通过 kallsyms 精确定位，偏移配置在 `tools/kernel_patches.json`。

SELinux 模块在运行时 patch 6 个内核执行点，绕过 `CONFIG_SECURITY_SELINUX_DEVELOP=n`
导致的硬编码 enforcing。通过 `kallsyms_lookup_name()` 解析地址，用内核自带的
`aarch64_insn_patch_text`（stop_machine）原子切换。控制接口：
`/sys/kernel/selinux_permissive/selinux_permissive`（echo 1 → permissive，echo 0 → enforcing）。

## 编译模块

CI 手动触发编译：[Actions](../../actions/workflows/build-modules.yml)，输入平板内核 `.config` 的下载链接即可。
产物：`all-modules.tar.gz`（全部模块）+ `selinux_permissive.ko`。

本地编译见 [完整教程](TUTORIAL.md#7可选编译内核模块)。

## 目录

```
README.md
TUTORIAL.md              ← 完整教程
env.sh                   ← 内核编译环境
.github/workflows/       ← CI（手动触发编译模块）
tools/                   ← patch_mod_verify_sig.py, verify_bootimg.py, verify_patches.py, setup_kernel_source.py
selinux_module/           ← SELinux permissive 模块
analysis/                ← 平板内核配置
dby-w09-4.0/             ← 内核源码 (submodule → yunsmall/dby-w09-4.0 fork)
```

## 设备

- **设备**: Huawei MatePad 11 2021 (DBY-W09)
- **SoC**: Snapdragon 865 (Kona, SM8250)
- **系统**: HarmonyOS 4.2
- **内核**: 4.19.157-perf+ (ARM64)
- **配置**: `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_SECURITY_SELINUX_DEVELOP=n`

> 以上流程略繁琐。如果你用 [Claude Code](https://claude.com/claude-code) 等 AI 工具，
> 可以直接把 `stock/` 下的文件给它，让它全自动完成 patch、打包、刷入一条龙。

## 注意事项

- 刷入补丁内核不影响 Magisk（ramdisk 没动）
- OTA 更新后内核可能变化，需重新 patch
- 更新内核前先备份 kallsyms：`adb shell cat /proc/kallsyms > stock/tablet_kallsyms`
- **编译模块用 `make`，编译完整内核用 `kmake`**。`kmake` 定义在 `env.sh`，将 LD 覆盖为 `aarch64-linux-gnu-ld --noinhibit-exec`，绕过 MSM 驱动 `R_AARCH64_ABS32` 重定位硬错误
- **源码编译的完整内核不能刷入平板**——华为有大量闭源驱动和 vendor patch，自编内核会导致卡 logo。编译内核仅用于获取 `Module.symvers` 来编译 `.ko` 模块
