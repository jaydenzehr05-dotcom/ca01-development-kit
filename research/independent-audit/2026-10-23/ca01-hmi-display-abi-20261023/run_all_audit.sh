#!/usr/bin/env bash
# Reproduce independent CA01 display ABI findings. Does not execute the full
# Toyota application, access hardware, flash firmware, or modify Git.
set -euo pipefail
cd "$(dirname "$0")"
PY=/home/starlight/projects/rav4-radio/ca01-development-kit/.venv/bin/python
mkdir -p results
"$PY" probe_original_window.py > results/original-arm-window.log
"$PY" probe_original_frame_path.py > results/original-arm-frame.log
python3 validate_embedded_asset_signatures.py > results/asset-header-check.log
python3 audit_gui_assets.py > results/asset-inventory-check.log
bash run_callback_checks.sh > results/callback-checks.log
grep -q "PASS original-bounded-arm-display-boundaries" results/original-arm-window.log
grep -q "PASS original-bounded-arm-frame-submission" results/original-arm-frame.log
grep -q "Verified 59 recovered CA01 file hashes" results/asset-inventory-check.log
grep -q "PASS magic signatures rejected" results/asset-header-check.log
grep -q "PASS isolated ARMEL graphics-callback bridge tests" results/callback-checks.log
sha256sum probe_original_window.py probe_original_frame_path.py \
  egl_window_to_pbuffer_bridge_v2.c armel_callback_probe.c \
  audit_gui_assets.py validate_embedded_asset_signatures.py > results/scripts-sha256.txt
echo "PASS verified original ARM construction, frame flow, display-plane service arguments"
echo "PASS 59 recovered files, 7 false embedded-asset candidates"
echo "PASS ARMEL callback bridge at 800x480 and 480x480, with negative tests"
echo "NO original Toyota GUI rendering claimed. No Git commit/push."
