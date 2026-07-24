# Source this script before building kernel/modules for DBY-W09
#   source env.sh && cd dby-w09-4.0
#   kmake modules
#   kmake M=../selinux_module modules
#
# CC and LD must be on the command line (not just environment) because the
# kernel Makefile has "CC = clang" / "LD = ld.lld" which overrides environment.

export ARCH=arm64
export LLVM=1
export CROSS_COMPILE=aarch64-linux-gnu-
export HOSTCC=clang-22
export CLANG_TRIPLE=aarch64-linux-gnu-
export HOSTCFLAGS=-fcommon
export KCFLAGS="-Wno-error -fno-builtin-wcslen"

kmake() {
	make CC=clang-22 LD=aarch64-linux-gnu-ld "$@"
}
