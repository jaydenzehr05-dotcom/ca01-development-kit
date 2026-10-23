#!/usr/bin/env python3
"""Requeue only false-negative 'no_decompiled_c' reviews after manifest fix.

Requires the main supervisor to be stopped. Retains all old evidence files.
"""
from pathlib import Path
import json,sqlite3
import model_review,supervisor
if supervisor.PID.exists():
    pid=int(supervisor.PID.read_text().strip())
    if Path("/proc") .joinpath(str(pid)).exists():
        raise SystemExit("Refusing queue migration while supervisor runs")
cx=supervisor.connect()
rows=cx.execute("""SELECT jobs.key,jobs.sha256,jobs.result_path
     FROM jobs WHERE jobs.kind='review' AND jobs.status='done'""").fetchall()
requeued=[]
for row in rows:
    stored=Path(row["result_path"] or "")
    if not stored.is_file():continue
    try:doc=json.loads(stored.read_text())
    except ValueError:continue
    if doc.get("kind")!="no_decompiled_c":continue
    dep=cx.execute("SELECT result_path FROM jobs WHERE key=?",
           ("decompile:"+row["sha256"],)).fetchone()
    if not dep or not dep["result_path"]:continue
    source=Path(dep["result_path"])/"decompiled.c"
    if not source.is_file():continue
    if not model_review.extract_excerpts(source):continue
    cx.execute("""UPDATE jobs SET status='queued',attempts=0,result_path=NULL,
        error='Requeued after original manifest .text fix'
        WHERE key=?""",(row["key"],))
    requeued.append(row["key"])
cx.commit()
print("REQUEUED_VERIFIED_FALSE_NEGATIVES",len(requeued))
for x in requeued:print(" ",x)
