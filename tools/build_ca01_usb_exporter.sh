#!/bin/sh
# Offline research build only; not firmware/USB autorun, no radio connection.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${CA01_BUILD_OUT:-"$ROOT/../system-audit/ca01-service-access-assessment-20261023"}
mkdir -p "$OUT"
: "${ARM_CC:=arm-linux-gnueabi-gcc}"
"$ARM_CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -march=armv5te -marm -mfloat-abi=soft \
    -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-pie -no-pie -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -nostdlib -static -Wl,-e,_start -Wl,--build-id=none \
    -Wl,-z,noexecstack -DCA01_LEGACY_ARM \
    "$ROOT/tools/ca01_usb_exporter.c" -lgcc -o "$OUT/ca01_usb_exporter_armel_nolibc"
printf '%s\n' "Built offline-only Linux ARM EABI no-libc exporter: $OUT/ca01_usb_exporter_armel_nolibc"
file "$OUT/ca01_usb_exporter_armel_nolibc"
readelf -n "$OUT/ca01_usb_exporter_armel_nolibc" || true
if readelf -d "$OUT/ca01_usb_exporter_armel_nolibc" | grep -q 'NEEDED'; then
    echo "Refusing dynamically linked build" >&2
    exit 1
fi
if nm -u "$OUT/ca01_usb_exporter_armel_nolibc" | grep -v 'no symbols'; then
    echo "Unresolved imported symbols detected" >&2
    exit 1
fi
