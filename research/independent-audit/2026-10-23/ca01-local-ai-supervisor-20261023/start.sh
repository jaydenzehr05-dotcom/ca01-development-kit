#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if test -e stop.flag; then echo "Stopped by operator. Run reset-stop command before starting."; exit 2; fi
if test -e /mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag; then
  echo "Local AI manual-off flag present. No model or supervisor process started."; exit 3
fi
if test -s supervisor.pid; then
  prior=$(cat supervisor.pid)
  if [[ "$prior" =~ ^[0-9]+$ ]] && kill -0 "$prior" 2>/dev/null &&
      tr '\0' ' ' < "/proc/$prior/cmdline" | grep -Fq 'supervisor.py loop'; then
     echo "Already running: PID $prior"
     exit 0
  fi
fi
umask 077
nohup /usr/bin/python3 "$(pwd)/supervisor.py" loop >> "$(pwd)/activity.log" 2>&1 </dev/null &
candidate=$!
sleep 3
if kill -0 "$candidate" 2>/dev/null; then
  echo "Started CA01 local AI supervisor PID=$candidate"
  /usr/bin/python3 "$(pwd)/supervisor.py" status
else
  echo "Supervisor startup failed; check activity.log"
  tail -n 25 activity.log
  exit 1
fi
