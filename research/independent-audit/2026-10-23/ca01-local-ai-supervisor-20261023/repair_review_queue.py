#!/usr/bin/env python3
"""Correct only earlier empty notes caused by an excerpt-regex mismatch."""
import json
from pathlib import Path
from model_review import extract_excerpts
from supervisor import connect, OUTPUT
with connect() as db:
    rows=db.execute("SELECT * FROM jobs WHERE kind='review' AND status='done'").fetchall()
    changed=[]
    for row in rows:
        artifact=OUTPUT/row['sha256'][:16]/'model-review.json'
        if not artifact.is_file():continue
        info=json.loads(artifact.read_text())
        if info.get('kind')!='no_decompiled_c':continue
        src=db.execute("SELECT result_path FROM jobs WHERE key=?",('decompile:'+row['sha256'],)).fetchone()
        if not src or not src['result_path']:continue
        decomp=Path(src['result_path'])/'decompiled.c'
        if not decomp.is_file() or not extract_excerpts(decomp):continue
        db.execute("UPDATE jobs SET status='queued',finished=NULL,error=NULL WHERE key=?",(row['key'],))
        changed.append(row['key'])
    db.commit()
print("REQUEUED_EXCERPT_REPAIR",changed)
