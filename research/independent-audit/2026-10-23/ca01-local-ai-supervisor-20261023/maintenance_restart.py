#!/usr/bin/env python3
"""Controlled restart after prompt fix. Only terminates THIS CA01 manager children."""
import os,psutil,sqlite3,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
pid=int((HERE/'supervisor.pid').read_text().strip())
process=psutil.Process(pid)
argv=process.cmdline()
must=str(HERE/'supervisor.py')
if must not in argv or 'loop' not in argv:
    raise SystemExit("Refusing non-CA01 supervisor PID")
if not (HERE/'stop.flag').exists():
    raise SystemExit("Stop flag required before maintenance restart")
children=process.children(recursive=True)
if any('analyzeHeadless' in ' '.join(x.cmdline()) or 'Ghidra-Headless' in ' '.join(x.cmdline()) or 'ghidra.GhidraClassLoader' in ' '.join(x.cmdline()) for x in children):
    raise SystemExit("Ghidra is still processing: restart only after binary completes")
for child in reversed(children):
    cmd=' '.join(child.cmdline())
    if ('bridge.ps1' not in cmd and 'WindowsPowerShell' not in cmd):
        raise SystemExit("Unknown child; refusing "+cmd[:250])
for child in reversed(children):
    try:child.terminate()
    except psutil.NoSuchProcess:pass
gone,alive=psutil.wait_procs(children,timeout=4)
for child in alive:
    try:child.kill()
    except psutil.NoSuchProcess:pass
process.terminate()
try:process.wait(timeout=7)
except psutil.TimeoutExpired:process.kill();process.wait(timeout=5)
db=sqlite3.connect(HERE/'progress.sqlite3')
db.execute("UPDATE jobs SET status='queued',attempts=CASE WHEN attempts>0 THEN attempts-1 ELSE 0 END,error='Restarted after local-model prompt correction' WHERE status='running'")
db.execute("UPDATE jobs SET status='queued',attempts=0,error='Retrying after shorter verified prompt' WHERE kind='review' AND status='failed'")
db.execute("INSERT INTO events(time,key,event,message) VALUES(datetime('now'),NULL,'maintenance','Restart for evidence-only prompt length/JSON recovery')")
db.commit()
print("CA01_RESTART_PREP_OK old_manager",pid,"terminated_children",len(children))
(HERE/'stop.flag').unlink(missing_ok=True)
