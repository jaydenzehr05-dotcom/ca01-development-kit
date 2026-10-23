#!/bin/sh
# Read-only Ghidra raw ARM survey. No known entry point is assumed.
set -eu
REPO=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
WS=$(dirname "$REPO")
GH="$WS/tools/ghidra_12.1.4_PUBLIC"
JAVA_HOME="$WS/tools/jdk-21.0.13+9"
export JAVA_HOME
PATH="$JAVA_HOME/bin:/usr/bin:/bin"
export PATH
OUT="$WS/system-audit"
mkdir -p "$OUT/ghidra-temp-projects"
"$GH/support/analyzeHeadless" "$OUT/ghidra-temp-projects" CA01_Boot_Raw \
 -import "$WS/stock-firmware/components/09-boot.bin" \
 -processor ARM:LE:32:v7 -cspec default \
 -scriptPath "$REPO/tools/ghidra" \
 -postScript CA01BootSurvey.java "$OUT/ghidra-boot-survey.txt" \
 -analysisTimeoutPerFile 150 -max-cpu 4 -deleteProject \
 -log "$OUT/ghidra-boot-log.txt" -scriptlog "$OUT/ghidra-boot-script-log.txt"
