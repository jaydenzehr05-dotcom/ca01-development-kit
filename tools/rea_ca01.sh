#!/bin/sh
# Run the checked-out REA CLI with verified, isolated CA01 Ghidra + Java.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORKSPACE=$(dirname "$REPO")
NODE_HOME="$WORKSPACE/tools/node-v24.18.0-linux-x64"
JAVA_HOME="$WORKSPACE/tools/jdk-21.0.13+9"
GHIDRA_INSTALL_DIR="$WORKSPACE/tools/ghidra_12.1.4_PUBLIC"
if [ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ] || [ ! -x "$JAVA_HOME/bin/javac" ]; then
  echo "Missing CA01 Ghidra/JDK installation in $WORKSPACE/tools" >&2
  exit 2
fi
export JAVA_HOME GHIDRA_INSTALL_DIR
export GHIDRA_HEADLESS_MAXMEM="${GHIDRA_HEADLESS_MAXMEM:-2G}"
export REA_ANALYSIS_PROVIDER=ghidra
PATH="$JAVA_HOME/bin:$NODE_HOME/bin:/usr/bin:/bin"
export PATH
exec "$NODE_HOME/bin/node" "$WORKSPACE/rea-reference/scripts/rea.mjs" "$@"
