#!/bin/bash

build_ebpf() {
ARCH=$1
case ${ARCH} in
arm64)
CROSS_COMPILE=aarch64-linux-gnu-
TARGET=bpf
;;
arm)
CROSS_COMPILE=arm-linux-gnueabi-
TARGET=arm-linux-gnueabi
;;
*)
CROSS_COMPILE=x86_64-linux-gnu-
TARGET=bpf
ARCH=x86
;;
esac
SRC=$2
BIN=$3
ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} \
clang \
    -target ${TARGET} \
    -D__TARGET_ARCH_${ARCH} \
    -D__KERNEL__ -D__BPF_TRACING__ \
    -Wno-implicit-int \
    -Wno-int-conversion \
    -fno-stack-protector \
    -Wno-int-to-pointer-cast \
    -Wno-incompatible-pointer-types \
    -Wno-unknown-attributes \
    -Wno-visibility \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-address-of-packed-member \
    -Wno-unused -Wall -Werror \
    -O2 -emit-llvm -c ${SRC} \
    -I vmlinux/${ARCH} \
    -o - | llc -march=bpf -filetype=obj -o ${BIN}
}

if [ $# -ne 3 ]; then
    echo "Usage: $0 <arch> <src> <bin>"
    exit 1
fi
build_ebpf $@
