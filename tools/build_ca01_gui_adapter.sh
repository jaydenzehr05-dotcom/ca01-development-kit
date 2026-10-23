#!/bin/sh
# Compile the synthetic CA01 ARMEL GUI adapter. No recovered Toyota ELF is linked or executed.
set -eu
REPO=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ROOT=$(dirname "$REPO")
ARMEL="$ROOT/system-audit/gui-emulation/armel-rootfs"
DEST="$ROOT/system-audit/ca01-hmi-adapter/ca01_adapter_armel"
mkdir -p "$(dirname "$DEST")"
command -v arm-linux-gnueabi-gcc >/dev/null
test -f "$ARMEL/usr/include/EGL/egl.h"
test -f "$ARMEL/usr/include/GLES/gl.h"
test -e "$ARMEL/usr/lib/arm-linux-gnueabi/libEGL.so"
test -e "$ARMEL/usr/lib/arm-linux-gnueabi/libGLESv1_CM.so"
arm-linux-gnueabi-gcc -std=c11 -O2 -Wall -Wextra -Werror \
 -pthread -march=armv7-a -mfloat-abi=soft \
 -I"$REPO/src" -I"$ARMEL/usr/include" \
 -L"$ARMEL/usr/lib/arm-linux-gnueabi" \
 -Wl,-rpath-link,"$ARMEL/usr/lib/arm-linux-gnueabi" \
 "$REPO/src/ca01_hmi_ipc.c" \
 "$REPO/src/ca01_gui_compat.c" \
 "$REPO/src/ca01_gui_egl_bridge.c" \
 "$REPO/tools/ca01_gui_adapter_demo.c" \
 -lEGL -lGLESv1_CM -o "$DEST"
file "$DEST"
arm-linux-gnueabi-readelf -l "$DEST" | grep 'Requesting program interpreter: /lib/ld-linux.so.3'
echo "CA01_ARMEL_ADAPTER_BUILT=$DEST"
