#!/usr/bin/env python3
"""After DISPLAY resume completes, retry only that older DISPLAY's failed functions."""
import datetime as dt
import json
import sys
import time
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
sys.path.insert(0,str(ROOT))
import manual_retries as task
SHA="4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004"
DISPLAY_REPORT=ROOT/"manual-display-recovery-20261023.json"
task.REPORT=ROOT/"manual-old-display-retries-20261023.json"
task.BASE={"started":dt.datetime.now(dt.timezone.utc).isoformat(),
           "runner":"direct Ghidra old DISPLAY targeted retries",
           "local_ai_used":False,"codex_used":False,
           "source_firmware_modified":False,"events":[]}
start=time.monotonic()
while time.monotonic()-start<3900:
    if DISPLAY_REPORT.exists():
        try:
            progress=json.loads(DISPLAY_REPORT.read_text())
            events=[x["event"] for x in progress.get("events",[])]
            if "completed_display_phase" in events:
                break
            if "fatal" in events:
                raise RuntimeError("Display base recovery fatal; no safe targeted retries")
        except json.JSONDecodeError:
            pass
    time.sleep(10)
else:
    raise TimeoutError("Display merged recovery not completed within 65 min")
original=task.retry_failed.pending

def only_old(cx,sha):
    if sha != SHA:
        return None
    return original(cx,sha)
task.retry_failed.pending=only_old
task.report("starting_old_display_failed_entry_retries")
task.process()
