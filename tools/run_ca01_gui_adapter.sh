#!/bin/sh
# Isolated synthetic ARM diagnostic. NEVER launches recovered Toyota applications.
# Writes to a new timestamped diagnostic folder; no output files are overwritten.
set -eu
ROOT=/home/starlight/projects/rav4-radio
ARMEL="$ROOT/system-audit/gui-emulation/armel-rootfs"
OUT="$ROOT/system-audit/ca01-hmi-adapter/output-$(date -u +%Y%m%dT%H%M%SZ)"
BIN="$ROOT/system-audit/ca01-hmi-adapter/ca01_adapter_armel"
test ! -e "$OUT"
mkdir -p "$OUT"
test -f "$BIN"
test -f "$ARMEL/usr/bin/qemu-arm-static"
test -e "$ARMEL/lib/ld-linux.so.3"
ulimit -c 0
timeout 35 /usr/bin/bwrap \
 --unshare-all --die-with-parent --new-session --clearenv --cap-drop ALL \
 --ro-bind "$ARMEL" / \
 --proc /proc --dev /dev --tmpfs /tmp \
 --tmpfs /opt --ro-bind "$BIN" /opt/ca01-demo \
 --bind "$OUT" /tmp/output \
 --setenv PATH /usr/bin:/bin --setenv LC_ALL C \
 --setenv HOME /tmp --setenv XDG_RUNTIME_DIR /tmp \
 --setenv LIBGL_ALWAYS_SOFTWARE 1 \
 --setenv GALLIUM_DRIVER softpipe --setenv EGL_PLATFORM surfaceless \
 --chdir /tmp \
 /usr/bin/qemu-arm-static /opt/ca01-demo /tmp/output/adapter-frame0.ppm \
 > "$OUT/adapter-runtime.stdout.log" 2> "$OUT/adapter-runtime.stderr.log"
grep -q CA01_SYNTHETIC_ADAPTER_OK "$OUT/adapter-runtime.stdout.log"
test -s "$OUT/adapter-frame0.ppm"
printf 'DIAGNOSTIC_OUTPUT=%s\n' "$OUT"
cat "$OUT/adapter-runtime.stdout.log"
cat "$OUT/adapter-runtime.stderr.log"
