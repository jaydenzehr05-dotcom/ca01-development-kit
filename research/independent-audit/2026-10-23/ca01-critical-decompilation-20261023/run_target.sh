#!/bin/bash
set -euo pipefail
root=/home/starlight/projects/rav4-radio
repo=$root/ca01-development-kit
out=$root/system-audit/ca01-critical-decompilation-20261023
label=$1
case "$label" in
 display1134) input=$root/system-audit/ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered/01116817-PROC_DISPLAY;;
 system1127) input=$root/system-audit/ca01-updater-independent-20261022/06-PROC_SYSTEM;;
 sysc1127) input=$root/system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so;;
 *) exit 2;;
esac
export JAVA_HOME=$root/tools/jdk-21.0.13+9
export GHIDRA_HEADLESS_MAXMEM=3G
export PATH=$JAVA_HOME/bin:/usr/bin:/bin
sha256sum "$input" > "$out/$label.input.sha256"
timeout 900 "$root/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" "$out/projects" "$label" \
 -import "$input" -scriptPath "$repo/tools/ghidra" \
 -postScript CA01DecompileBatch.java "$out/$label" 420 \
 -analysisTimeoutPerFile 360 -max-cpu 2 \
 -log "$out/$label.ghidra.log" -scriptlog "$out/$label.script.log" \
 > "$out/$label.console.log" 2>&1
sha256sum -c "$out/$label.input.sha256"
tail -4 "$out/$label.script.log"
