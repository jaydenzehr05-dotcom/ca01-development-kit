#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/starlight/projects/rav4-radio
OUT=$ROOT/system-audit/ca01-1134-filesystem-tools-20261023
BIN=$ROOT/stock-firmware/15TBDANA-CA01_1134.kwi
GUI=$ROOT/system-audit/ca01-1134-firmware-analysis-20261023/inner-1134/07-gui.payload.bin
KERNEL=$ROOT/system-audit/ca01-1134-firmware-analysis-20261023/inner-1134/03-kernel.payload.bin
AUDIO=$ROOT/system-audit/ca01-1134-firmware-analysis-20261023/inner-1134/06-audio.payload.bin
UNBLOB=$ROOT/ca01-development-kit/.venv/bin/unblob
mkdir -p "$OUT"
for entry in package gui kernel audio; do
  case "$entry" in
    package) INPUT=$BIN;;
    gui) INPUT=$GUI;;
    kernel) INPUT=$KERNEL;;
    audio) INPUT=$AUDIO;;
  esac
  sha256sum "$INPUT" > "$OUT/$entry.input.sha256"
  echo "SCANNING $entry $INPUT"
  timeout 45s binwalk -y 'squashfs|cramfs|jffs2|ubifs|UBI|ROMFS|Linux EXT filesystem|gzip|tar archive|cpio' "$INPUT" > "$OUT/$entry.binwalk-fs.txt" 2>&1 || echo "binwalk exit was nonzero" >> "$OUT/$entry.binwalk-fs.txt"
  timeout 80s "$UNBLOB" --skip-extraction --process-num 2 --randomness-depth 0 --depth 1 \
    --extract-dir "$OUT/$entry-carve" --report "$OUT/$entry.unblob.json" \
    --log "$OUT/$entry.unblob.log" "$INPUT" > "$OUT/$entry.unblob-output.txt" 2>&1 || echo "unblob exit was nonzero" >> "$OUT/$entry.unblob-output.txt"
  echo "SCAN_DONE $entry $(wc -l < "$OUT/$entry.binwalk-fs.txt") binwalk lines"
done
echo "COMPLETE checked package, gui, kernel, audio (all read-only)"
