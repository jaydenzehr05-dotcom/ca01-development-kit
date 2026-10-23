#!/usr/bin/env bash
# Reproducible, isolated, no root privileges or real Toyota execution.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=/home/starlight/projects/rav4-radio/system-audit/gui-emulation/armel-rootfs
INC=(-I"$ROOT/usr/include" -I"$ROOT/usr/include/arm-linux-gnueabi")
LIB=(-L"$ROOT/usr/lib/arm-linux-gnueabi" "-Wl,-rpath-link,$ROOT/usr/lib/arm-linux-gnueabi")
CC=arm-linux-gnueabi-gcc
COMMON=(-std=c11 -O2 -Wall -Wextra -Werror)
mkdir -p results/800x480 results/480x480
python3 extract_hmi_display_profiles.py > results/display-profile-extraction.log
"$CC" "${COMMON[@]}" "${INC[@]}" "${LIB[@]}" -fPIC -shared \
  -o libca01_egl_bridge.so egl_window_to_pbuffer_bridge.c -ldl
for spec in 800x480 480x480; do
    w="${spec%x*}"
    h="${spec#*x}"
    binary="./probe-$spec"
    target="results/$spec"
    "$CC" "${COMMON[@]}" "${INC[@]}" "${LIB[@]}" \
      "-DCA01_TEST_WIDTH=$w" "-DCA01_TEST_HEIGHT=$h" \
      -o "$binary" armel_egl_pbuffer_probe.c -lEGL -lGLESv1_CM
    env EGL_PLATFORM=surfaceless LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=softpipe \
      timeout 30s qemu-arm -L "$ROOT" "$binary" "$target/direct" \
      > "$target/direct.log" 2>&1
    env EGL_PLATFORM=surfaceless LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=softpipe \
      CA01_PROBE_NATIVE_WINDOW=1 timeout 30s qemu-arm -L "$ROOT" \
      -E CA01_EGL_BRIDGE=1 -E "LD_PRELOAD=$(pwd)/libca01_egl_bridge.so" \
      "$binary" "$target/bridged" > "$target/bridged.log" 2>&1
    for number in 00 01 02; do
        cmp "$target/direct-$number.ppm" "$target/bridged-$number.ppm"
    done
    echo "PASS $spec : pixel-exact pbuffer vs window bridge"
done
# Expected failures validate that the unmodified Mesa window path has no config
# and that malformed native window metadata is rejected by the adapter.
if env EGL_PLATFORM=surfaceless LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=softpipe \
    CA01_PROBE_NATIVE_WINDOW=1 timeout 30s qemu-arm -L "$ROOT" \
    ./probe-800x480 results/800x480/no-bridge \
    > results/800x480/no-bridge.log 2>&1; then
    echo "FAIL window path unexpectedly worked without interception" >&2
    exit 1
else
    status=$?
    test "$status" -eq 13 || { echo "FAIL unexpected baseline exit: $status" >&2; exit 1; }
    echo "PASS expected unbridged window failure (code 13)"
fi
if env EGL_PLATFORM=surfaceless LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=softpipe \
    CA01_PROBE_NATIVE_WINDOW=1 CA01_PROBE_INVALID_WINDOW=1 \
    timeout 30s qemu-arm -L "$ROOT" -E CA01_EGL_BRIDGE=1 \
    -E "LD_PRELOAD=$(pwd)/libca01_egl_bridge.so" \
    ./probe-800x480 results/800x480/invalid-window \
    > results/800x480/invalid-window.log 2>&1; then
    echo "FAIL adapter accepted malformed native-window structure" >&2
    exit 1
else
    status=$?
    test "$status" -eq 15 || { echo "FAIL unexpected invalid-window exit: $status" >&2; exit 1; }
    echo "PASS malformed window rejected (code 15)"
fi
python3 verify_outputs.py
sha256sum probe-800x480 probe-480x480 libca01_egl_bridge.so \
    > results/build-sha256.txt
printf "PASS all local ARMEL EGL bridge checks; Toyota GUI not executed.\n"
