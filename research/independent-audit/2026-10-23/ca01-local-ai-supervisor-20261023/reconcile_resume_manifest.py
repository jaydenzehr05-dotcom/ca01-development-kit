#!/usr/bin/env python3
"""Non-destructive correction: one attempted-but-failed HMI function remains."""
import json
import sqlite3
from pathlib import Path
import resume_decompile,supervisor
sha="64f5d905a42aa844d60fcf2a3aed752ce5fd9df04e54a1a565d81b64307af62b"
if supervisor.PID.is_file():
    p=Path("/proc")/supervisor.PID.read_text().strip()
    if p.exists():raise SystemExit("Refuse to update checkpoint while supervisor is active")
root=supervisor.OUTPUT/sha[:16]/"ghidra"
initial=root/"decomp"
part=root/"resume-1/isolated"
corrected=root/"merged-resume-1-reconciled"
result=resume_decompile.build_combined(initial,part,corrected,sha)
assert result==dict(improved=2064,new_total=8354,still_not_attempted=0,failed=1),result
cx=supervisor.connect()
row=cx.execute("SELECT result_path FROM jobs WHERE key=?",("decompile:"+sha,)).fetchone()
assert row is not None and row["result_path"].endswith("/merged-resume-1"),row
cx.execute("UPDATE jobs SET result_path=? WHERE key=?",(str(corrected),"decompile:"+sha))
cx.execute("UPDATE jobs SET status='queued',attempts=0 WHERE key=? AND status='done'",("index:"+sha,))
cx.commit()
report=dict(binary_sha256=sha,corrected=str(corrected),stats=result,
  original_resume_output_preserved=True,
  note="One supplemental function had status failed, not merely unattempted")
(root/"resume-1-reconciliation.json").write_text(json.dumps(report,indent=2)+"\n")
print("PASS CORRECTED",report)
