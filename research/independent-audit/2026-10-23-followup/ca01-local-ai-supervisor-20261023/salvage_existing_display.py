#!/usr/bin/env python3
"""One-time restore for original UU.11.27 PROC_DISPLAY partially decompiled Ghidra export.

The prior job 'failed' due to a *second* Ghidra project-lock collision even
though the primary process emitted a validated partial manifest and source.
Recover it as an initial 'done' export so the existing pending-only resume
machinery can finish the skipped functions. No original binary or old artifact
is modified, and no fresh Ghidra process is launched here.
"""
import fcntl,hashlib,json,sqlite3
from pathlib import Path
import datetime as dt
P=Path(__file__).resolve().parent
sha="4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004"
source=P/"results"/sha[:16]/"ghidra/decomp"
assert (source/"manifest.json").is_file()
assert (source/"decompiled.c").is_file()
m=json.loads((source/"manifest.json").read_text())
assert m["sha256"].lower()==sha
assert m["decompiled"]==3019 and m["not_attempted"]==2552
assert m["failed"]==4 and m["functions_catalogued"]==5575
con=sqlite3.connect(P/"progress.sqlite3",timeout=30)
con.row_factory=sqlite3.Row
with (P/"supervisor.lock").open("a+") as hold:
    fcntl.flock(hold,fcntl.LOCK_EX|fcntl.LOCK_NB)
    item=con.execute("SELECT * FROM jobs WHERE key=?",("decompile:"+sha,)).fetchone()
    inp=con.execute("SELECT * FROM inputs WHERE sha256=?",(sha,)).fetchone()
    assert item and inp and inp["version"]=="1127" and inp["elf"]==1
    with open(inp["path"],"rb") as stream:
        assert hashlib.file_digest(stream,"sha256").hexdigest()==sha
    if item["status"]=="failed":
        con.execute("""UPDATE jobs SET status='done',error=NULL,finished=?,
                  result_path=? WHERE key=?""",
            (dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            str(source),"decompile:"+sha))
        con.execute("""INSERT INTO events(time,key,event,message)
              VALUES(?,?,?,?)""",(dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "decompile:"+sha,"salvaged_partial",
            "Primary partial Ghidra export 3019 decompiled 4 failed 2552 pending recovered, secondary process failed on project lock; schedule isolated pending-only resume."))
        con.commit()
        print("RECOVERED partial prior decompilation without rerunning the whole file")
    elif item["status"]=="done" and Path(item["result_path"])==source:
        print("ALREADY_RESTORED")
    else:
        raise RuntimeError("Unexpected job state; refusing change: "+str(item["status"]))
print("PENDING_FUNCTIONS_TO_RESUME",m["not_attempted"])
