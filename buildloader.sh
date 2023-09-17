#!/bin/sh
build_loader() {
ARCH=$1
SRC=$2
BIN=$3
case ${ARCH} in
arm64)
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc \
go build -ldflags '-linkmode "external" -extldflags "-static"' -o ${BIN} ${SRC}
;;
arm)
GOOS=linux GOARCH=arm CGO_ENABLED=1 CC=arm-linux-gnueabi-gcc \
go build -ldflags '-linkmode "external" -extldflags "-static"' -o ${BIN} ${SRC}
;;
*)
GOOS=linux \
go build -ldflags '-linkmode "external" -extldflags "-static"' -o ${BIN} ${SRC}
;;
esac
}

if [ $# -ne 3 ]; then
    echo "Usage: $0 <arch> <src> <bin>"
    exit 1
fi
build_loader $@
