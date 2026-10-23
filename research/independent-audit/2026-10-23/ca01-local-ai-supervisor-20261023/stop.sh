#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
/usr/bin/python3 ./supervisor.py stop
echo "Stop flag saved. Current bounded research job will finish before loop exits."
