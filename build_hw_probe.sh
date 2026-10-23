#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${ZIG:=zig}"
mkdir -p build
"$ZIG" cc -target arm-linux-musleabi -mcpu=cortex_a9 \
  -marm -mfloat-abi=soft -Os -ffreestanding -fno-builtin \
  -fno-vectorize -fno-slp-vectorize -fno-stack-protector \
  -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -nostdlib -static -fno-pie -no-pie \
  -Wl,-e,_start -Wl,--build-id=none -Wl,-z,noexecstack \
  src/ca01_hw_probe.c -o build/ca01-hw-probe-arm
printf '%s\n' 'Built build/ca01-hw-probe-arm (read-only ARM diagnostic ELF; NOT firmware).'
