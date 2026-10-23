#!/usr/bin/env bash
# Reproduce research in a NEW external output directory, preserving the source.
set -euo pipefail
REPO=$(cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$(dirname "$REPO")/system-audit/ca01-display-release-$(date -u +%Y%m%dT%H%M%SZ)"}
if [[ -e "$OUT" || -L "$OUT" ]]; then
  echo "Output must not exist: $OUT" >&2; exit 2
fi
mkdir -p -- "$OUT"
cp -- "$REPO"/tools/display_audit/*.py "$REPO"/tools/display_audit/*.c "$REPO"/tools/display_audit/*.sh "$OUT/"
export CA01_AUDIT_PYTHON="$REPO/.venv/bin/python"
bash "$OUT/run_all_audit.sh"
printf 'AUDIT_OUTPUT=%s\n' "$OUT"
