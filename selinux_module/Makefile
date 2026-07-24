# Makefile for selinux_permissive kernel module
#
# Build from kernel source tree:
#   cd ../dby-w09-4.0
#   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- M=../selinux_module modules
#
# Or with clang:
#   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=clang LD=aarch64-linux-gnu-ld \
#     M=../selinux_module modules

obj-m := selinux_permissive.o
