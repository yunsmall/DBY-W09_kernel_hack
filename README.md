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

> 不同版本/编译器的内核，补丁脚本的指纹匹配可能失败，语义搜索可能仍有效。

## 做了什么

Patch 原版内核的两个关键点（第三个是冗余安全网）：

| Patch | 函数 | 改动 | 必要性 |
|-------|------|------|--------|
| #1 | `mod_verify_sig` | 签名验证函数 → 直接返回 0 | **必须** |
| #3 | `module_sig_check` 读取 `sig_enforce` | LDRB → MOV W8, WZR | **必须** |
| #2 | `is_module_sig_enforced` | MOV X0,#0; RET | 冗余（仅 trace event 调用） |

`tools/patch_mod_verify_sig.py` 自动定位并 patch，支持指纹+语义搜索。

SELinux 关闭模块通过 `kallsyms_lookup_name()` 动态解析地址（KASLR 安全），
用内核自己的 `aarch64_insn_patch_text_nosync`（ftrace 同款机制）patch `avc_denied`
使其永远返回 0。SELinux 其余功能（文件标签、安全上下文等）保持正常。

## 目录

```
README.md
TUTORIAL.md              ← 完整教程
env.sh                   ← 内核编译环境变量
tools/                   ← patch_mod_verify_sig.py, verify_bootimg.py
selinux_module/           ← SELinux 关闭模块
analysis/                ← 平板内核配置
dby-w09-4.0/             ← 内核源码 (submodule)
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
