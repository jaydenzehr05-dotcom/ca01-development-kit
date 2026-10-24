#!/usr/bin/env python3
"""Merge verified same-binary older PROC_DISPLAY independent Ghidra success."""
from pathlib import Path
import sqlite3
import json
import hashlib
from datetime import datetime,timezone
import sys
ROOT=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
sys.path.insert(0,str(ROOT))
import retry_failed,coverage_index
sha="4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004"
supp=ROOT/"results"/sha[:16]/"ghidra"/"manual-predication-long-01"/"targeted"
dest=ROOT/"results"/sha[:16]/"ghidra"/"manual-predication-long-merged-01"
cx=sqlite3.connect(ROOT/"progress.sqlite3",timeout=60)
cx.row_factory=sqlite3.Row
cx.execute("PRAGMA busy_timeout=60000")
row=cx.execute("SELECT i.path,j.result_path FROM inputs i JOIN jobs j ON j.key='decompile:'||i.sha256 WHERE i.sha256=?",(sha,)).fetchone()
if not row:raise RuntimeError("Source ELF absent")
path=Path(row["path"])
with path.open("rb") as f:assert hashlib.file_digest(f,"sha256").hexdigest()==sha
part=json.loads((supp/"manifest.json").read_text())
assert part["sha256"]==sha
assert part["decompiled"]==1 and part["failed"]==0 and part["not_attempted"]==0
assert len(part["functions"])==1 and part["functions"][0]["address"]=="00023968"
current=Path(row["result_path"])
base=json.loads((current/"manifest.json").read_text())
assert base["sha256"]==sha
existing=next(x for x in base["functions"] if x["address"]=="00023968")
if existing["status"]=="decompiled":
    print(json.dumps({"status":"already_complete","source":str(current),"failed":base["failed"]}))
    sys.exit(0)
assert existing["status"]=="failed"
assert not dest.exists()
new,errors=retry_failed.merge_success(current,supp,dest,sha,["00023968"])
assert new==dest and not errors
merged=json.loads((dest/"manifest.json").read_text())
assert merged["failed"]==0 and merged["not_attempted"]==0
assert merged["decompiled"]==merged["functions_catalogued"]==5575
cx.execute("UPDATE jobs SET result_path=? WHERE key=?",(str(dest),"decompile:"+sha))
cx.commit()
index=coverage_index.index_binary(sha,dest,"./opt/ftl/apl/PROC_DISPLAY")
indexfile=ROOT/"results"/sha[:16]/"function-index.json"
indexfile.write_text(json.dumps(index,indent=2)+"\n")
cx.execute("UPDATE jobs SET status='done',result_path=?,error=NULL,finished=? WHERE key=?",(str(indexfile),datetime.now(timezone.utc).isoformat(),"index:"+sha))
cx.commit()
cx.close()
print(json.dumps({"status":"verified_merged","sha":sha,"address":"00023968","failed":0,"index":index,"path":str(dest)}),flush=True)
