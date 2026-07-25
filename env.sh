# Source this script before building kernel/modules for DBY-W09
#   source env.sh && cd dby-w09-4.0
#   kmake modules
#   kmake M=../selinux_module modules
#
# 前提: /usr/lib/llvm-22/bin 已在 PATH 中，这样内核 Makefile 的 "CC = clang"
# 自动选中 llvm-22 版本。LD 由 kmake 覆盖为 GNU ld（lld 的 --noinhibit-exec
# 对 R_AARCH64_ABS32 无效）。

export ARCH=arm64
export LLVM=1
export CROSS_COMPILE=aarch64-linux-gnu-
export HOSTCC=clang
export CLANG_TRIPLE=aarch64-linux-gnu-
export HOSTCFLAGS=-fcommon
export KCFLAGS="-Wno-error -fno-builtin-wcslen"
# lld --noinhibit-exec 对 R_AARCH64_ABS32 无效，GNU ld 可以
kmake() { make LD="aarch64-linux-gnu-ld --noinhibit-exec" "$@"; }
