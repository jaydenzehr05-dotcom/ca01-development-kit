#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/starlight/projects/rav4-radio
BASE=$ROOT/system-audit/ca01-1134-firmware-analysis-20261023
export JAVA_HOME=$ROOT/tools/jdk-21.0.13+9
export GHIDRA_HEADLESS_MAXMEM=2G
export PATH=$JAVA_HOME/bin:/usr/bin:/bin
NEW=$BASE/recovered-1134-06-audio/recovered/01116817-PROC_DISPLAY
OLD=$ROOT/system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY
for label in 1134 1127; do
  if [ "$label" = "1134" ];then INPUT=$NEW;else INPUT=$OLD;fi
  $ROOT/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless $BASE GhidraDisplay$label \
   -import "$INPUT" -scriptPath "$BASE" \
   -postScript CA01DisplaySurvey.java "$BASE/ghidra-$label" \
   -analysisTimeoutPerFile 160 -max-cpu 4 -deleteProject \
   -log "$BASE/ghidra-$label-log.txt" -scriptlog "$BASE/ghidra-$label-scriptlog.txt" \
   > "$BASE/ghidra-$label-console.log" 2>&1
  test -s "$BASE/ghidra-$label/ghidra-display-survey.txt"
  tail -4 "$BASE/ghidra-$label/ghidra-display-survey.txt"
done
echo "PASS Ghidra compared 1127/1134 PROC_DISPLAY in isolated projects"
