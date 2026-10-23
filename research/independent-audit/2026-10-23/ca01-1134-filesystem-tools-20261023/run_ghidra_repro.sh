#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/starlight/projects/rav4-radio
AUD=$ROOT/system-audit/ca01-1134-filesystem-tools-20261023
BIN=$ROOT/system-audit/ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered
SOURCE=$(find "$BIN" -maxdepth 1 -name '*-PROC_REPRO' | head -n 1)
test -n "$SOURCE"
export JAVA_HOME=$ROOT/tools/jdk-21.0.13+9
export PATH=$JAVA_HOME/bin:/usr/bin:/bin
"$ROOT/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" "$AUD" ReproPartitions_1134 \
  -import "$SOURCE" -scriptPath "$AUD" -postScript CA01ReproPartitionSurvey.java "$AUD/ghidra-repro" \
  -analysisTimeoutPerFile 90 -max-cpu 2 -deleteProject \
  -log "$AUD/ghidra-repro-headless.log" -scriptlog "$AUD/ghidra-repro-script.log" \
  > "$AUD/ghidra-repro-console.log" 2>&1
test -s "$AUD/ghidra-repro/partition-survey.txt"
tail -12 "$AUD/ghidra-repro/partition-survey.txt"
