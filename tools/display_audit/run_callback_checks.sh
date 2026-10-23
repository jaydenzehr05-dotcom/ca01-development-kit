#!/usr/bin/env bash
# Self-authored ARMEL fixtures only: offline Bubblewrap, read-only guest rootfs.
set -euo pipefail
cd "$(dirname "$0")"
SYSROOT=/home/starlight/projects/rav4-radio/system-audit/gui-emulation/armel-rootfs
INC=(-I"$SYSROOT/usr/include" -I"$SYSROOT/usr/include/arm-linux-gnueabi")
LIB=(-L"$SYSROOT/usr/lib/arm-linux-gnueabi" "-Wl,-rpath-link,$SYSROOT/usr/lib/arm-linux-gnueabi")
COMMON=(-std=c11 -O2 -Wall -Wextra -Werror)
mkdir -p results/800x480 results/480x480
arm-linux-gnueabi-gcc "${COMMON[@]}" "${INC[@]}" "${LIB[@]}" -shared -fPIC \
  -o libca01_window_callback_v2.so egl_window_to_pbuffer_bridge_v2.c -ldl
arm-linux-gnueabi-gcc "${COMMON[@]}" "${INC[@]}" "${LIB[@]}" -shared -fPIC \
  -o libca01_window_control_v1.so egl_window_to_pbuffer_bridge.c -ldl
run_guest() {
  local executable=$1 mode=$2 bridge=$3 prefix=$4
  local -a env_args=()
  if [[ "$mode" == window ]]; then env_args+=(--setenv CA01_PROBE_NATIVE_WINDOW 1); fi
  if [[ "$mode" == invalid ]]; then
    env_args+=(--setenv CA01_PROBE_NATIVE_WINDOW 1 --setenv CA01_PROBE_INVALID_WINDOW 1)
  fi
  if [[ "$bridge" != none ]]; then env_args+=(--setenv CA01_EGL_BRIDGE 1 --setenv LD_PRELOAD "/tmp/audit/$bridge"); fi
  timeout 30 /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv --cap-drop ALL \
    --ro-bind "$SYSROOT" / --proc /proc --dev /dev --tmpfs /tmp \
    --dir /tmp/audit --ro-bind "$PWD" /tmp/audit --dir /tmp/output --bind "$PWD/results" /tmp/output \
    --setenv PATH /usr/bin:/bin --setenv HOME /tmp --setenv LC_ALL C \
    --setenv XDG_RUNTIME_DIR /tmp --setenv EGL_PLATFORM surfaceless \
    --setenv GALLIUM_DRIVER softpipe --setenv LIBGL_ALWAYS_SOFTWARE 1 \
    "${env_args[@]}" --chdir /tmp \
    /usr/bin/qemu-arm-static "/tmp/audit/$executable" "/tmp/output/$prefix"
}
for spec in 800x480 480x480; do
  w="${spec%x*}"; h="${spec#*x}"
  arm-linux-gnueabi-gcc "${COMMON[@]}" "${INC[@]}" "${LIB[@]}" \
    "-DCA01_TEST_WIDTH=$w" "-DCA01_TEST_HEIGHT=$h" \
    -o "callback-probe-$spec" armel_callback_probe.c -lEGL -lGLESv1_CM
  run_guest "callback-probe-$spec" pbuffer none "$spec/direct" > "results/$spec/direct.log" 2>&1
  run_guest "callback-probe-$spec" window libca01_window_callback_v2.so "$spec/v2" > "results/$spec/v2.log" 2>&1
  grep -q "callback_frame=2" "results/$spec/v2.log"
  grep -q "callback_wrap_handle=0xca010001" "results/$spec/v2.log"
  grep -q "PASS armel-egl-gles1-window-bridge-3frames" "results/$spec/v2.log"
  for i in 00 01 02; do cmp "results/$spec/direct-$i.ppm" "results/$spec/v2-$i.ppm"; done
  echo "PASS original-shaped +0x1c callback, three handles cycle, pixel parity $spec"
done
set +e
run_guest callback-probe-800x480 window libca01_window_control_v1.so 800x480/v1-rejection > results/800x480/v1-rejection.log 2>&1
previous_status=$?
run_guest callback-probe-800x480 invalid libca01_window_callback_v2.so 800x480/malformed-rejection > results/800x480/malformed-rejection.log 2>&1
bad_status=$?
set -e
test "$previous_status" -eq 23
test "$bad_status" -eq 15
echo "PASS old interposer lacks original callback; malformed window rejected"
sha256sum libca01_window_callback_v2.so callback-probe-800x480 callback-probe-480x480 > results/bridge-v2-sha256.txt
echo "PASS isolated ARMEL graphics-callback bridge tests"
