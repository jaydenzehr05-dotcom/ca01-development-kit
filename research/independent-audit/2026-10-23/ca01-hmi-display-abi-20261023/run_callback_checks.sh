#!/usr/bin/env bash
# Synthetic ARMEL graphics callback test; no original Toyota executable launch.
set -euo pipefail
cd "$(dirname "$0")"
SYSROOT=/home/starlight/projects/rav4-radio/system-audit/gui-emulation/armel-rootfs
PREVIOUS=/home/starlight/projects/rav4-radio/system-audit/ca01-hmi-egl-bridge-20261023
INC=(-I"$SYSROOT/usr/include" -I"$SYSROOT/usr/include/arm-linux-gnueabi")
LIB=(-L"$SYSROOT/usr/lib/arm-linux-gnueabi" "-Wl,-rpath-link,$SYSROOT/usr/lib/arm-linux-gnueabi")
COMMON=(-std=c11 -O2 -Wall -Wextra -Werror)
mkdir -p results/800x480 results/480x480
arm-linux-gnueabi-gcc "${COMMON[@]}" "${INC[@]}" "${LIB[@]}" -shared -fPIC \
  -o libca01_window_callback_v2.so egl_window_to_pbuffer_bridge_v2.c -ldl
for spec in 800x480 480x480; do
  w="${spec%x*}"; h="${spec#*x}"
  arm-linux-gnueabi-gcc "${COMMON[@]}" "${INC[@]}" "${LIB[@]}" \
    "-DCA01_TEST_WIDTH=$w" "-DCA01_TEST_HEIGHT=$h" \
    -o "callback-probe-$spec" armel_callback_probe.c -lEGL -lGLESv1_CM
  env EGL_PLATFORM=surfaceless GALLIUM_DRIVER=softpipe LIBGL_ALWAYS_SOFTWARE=1 \
    CA01_PROBE_NATIVE_WINDOW=1 \
    timeout 30s qemu-arm -L "$SYSROOT" \
    -E CA01_EGL_BRIDGE=1 -E "LD_PRELOAD=$(pwd)/libca01_window_callback_v2.so" \
    "./callback-probe-$spec" "results/$spec/v2" \
    > "results/$spec/v2.log" 2>&1
  grep -q "callback_frame=2" "results/$spec/v2.log"
  grep -q "callback_wrap_handle=0xca010001" "results/$spec/v2.log"
  grep -q "PASS armel-egl-gles1-window-bridge-3frames" "results/$spec/v2.log"
  for i in 00 01 02; do
    cmp "$PREVIOUS/results/$spec/bridged-$i.ppm" "results/$spec/v2-$i.ppm"
  done
  echo "PASS original-shaped +0x1c callback, three handles cycle, pixel parity $spec"
done
# v1 did not install a callback, so new probe should exit 23.
set +e
env EGL_PLATFORM=surfaceless GALLIUM_DRIVER=softpipe LIBGL_ALWAYS_SOFTWARE=1 \
  CA01_PROBE_NATIVE_WINDOW=1 \
  timeout 30s qemu-arm -L "$SYSROOT" \
  -E CA01_EGL_BRIDGE=1 -E "LD_PRELOAD=$PREVIOUS/libca01_egl_bridge.so" \
  "./callback-probe-800x480" results/800x480/v1-rejection \
  > results/800x480/v1-rejection.log 2>&1
previous_status=$?
# A malformed window with v2 must remain a hard failure.
env EGL_PLATFORM=surfaceless GALLIUM_DRIVER=softpipe LIBGL_ALWAYS_SOFTWARE=1 \
  CA01_PROBE_NATIVE_WINDOW=1 CA01_PROBE_INVALID_WINDOW=1 \
  timeout 30s qemu-arm -L "$SYSROOT" \
  -E CA01_EGL_BRIDGE=1 -E "LD_PRELOAD=$(pwd)/libca01_window_callback_v2.so" \
  "./callback-probe-800x480" results/800x480/malformed-rejection \
  > results/800x480/malformed-rejection.log 2>&1
bad_status=$?
set -e
test "$previous_status" -eq 23
test "$bad_status" -eq 15
echo "PASS old interposer lacks original callback; malformed window rejected"
sha256sum libca01_window_callback_v2.so callback-probe-800x480 callback-probe-480x480 \
  > results/bridge-v2-sha256.txt
echo "PASS isolated ARMEL graphics-callback bridge tests"
