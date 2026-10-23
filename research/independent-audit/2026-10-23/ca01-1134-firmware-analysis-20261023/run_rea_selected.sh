#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/starlight/projects/rav4-radio
OUT=$ROOT/system-audit/ca01-1134-firmware-analysis-20261023
export REA_UNBLOB_COMMAND=$ROOT/ca01-development-kit/.venv/bin/unblob
for kind in 07-gui 06-audio; do
  INPUT=$OUT/inner-1134/$kind.payload.bin
  DEST=$OUT/rea-$kind
  RESULT=$OUT/rea-$kind.json
  "$ROOT/ca01-development-kit/tools/rea_ca01.sh" extract-firmware "$INPUT" "$DEST" --format json > "$RESULT"
  python3 -c 'import sys,json; x=json.load(open(sys.argv[1])); rr=x.get("raw_result",{}).get("report",[]); print(sys.argv[1],"provider",x.get("provider",{}).get("id"),"subtasks",sum(len(y.get("subtasks",[])) for y in rr),"code",x.get("code"))' "$RESULT"
done
