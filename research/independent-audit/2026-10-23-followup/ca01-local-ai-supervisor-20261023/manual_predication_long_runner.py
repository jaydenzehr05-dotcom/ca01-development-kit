#!/usr/bin/env python3
"""Retry remaining Ghidra timeouts, with predicated-code optimization disabled.
Original ELF hashes verified; new outputs only; local AI and Codex not invoked.
"""
import datetime as dt
import hashlib
import json
import os
import sqlite3
import subprocess
import traceback
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio")
HERE=ROOT/"system-audit"/"ca01-local-ai-supervisor-20261023"
GH=ROOT/"tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
JDK=ROOT/"tools/jdk-21.0.13+9"
OUT=HERE/"manual-predication-long-results.json"
PRIORITY={"4755da50d4396cb2":0,"ed6c8180598afb2f":1,
          "0ef37be31e5002eb":2,"cdc2f7a613e5a9a9":3,
          "c826857156b51869":4}
report={"started":dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_modified":False,"local_ai_used":False,"codex_used":False,"events":[]}
def note(event,**details):
    entry={"time":dt.datetime.now(dt.timezone.utc).isoformat(),
           "event":event,**details}
    report["events"].append(entry)
    OUT.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(entry),flush=True)
def sha256(path):
    with open(path,"rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def main():
    if not (HERE/"stop.flag").exists():raise RuntimeError("Supervisor not stopped")
    if not Path("/mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag").is_file():
        raise RuntimeError("Local AI manual OFF not detected")
    cx=sqlite3.connect(HERE/"progress.sqlite3",timeout=60)
    cx.row_factory=sqlite3.Row
    inputs=[dict(row) for row in cx.execute("""SELECT i.sha256,i.path,i.archive_path,j.result_path
        FROM inputs i JOIN jobs j ON j.key='decompile:' || i.sha256
        WHERE j.status='done' AND i.elf=1""")]
    eligible=[]
    for inp in inputs:
        try:
            manifest=json.loads((Path(inp["result_path"])/"manifest.json").read_text())
            failed=[r["address"] for r in manifest["functions"] if r["status"]=="failed"]
            if failed and inp["sha256"][:16] in PRIORITY:
                eligible.append((inp,failed))
        except (FileNotFoundError,ValueError):pass
    eligible.sort(key=lambda t:PRIORITY[t[0]["sha256"][:16]])
    note("inventory",count=len(eligible),targets=[dict(binary=i["archive_path"],
         sha=i["sha256"][:16],addresses=f) for i,f in eligible])
    env=os.environ.copy()
    env.update(JAVA_HOME=str(JDK),PATH=str(JDK/"bin")+":/usr/bin:/bin",
               GHIDRA_HEADLESS_MAXMEM="3G")
    for inp,old_failed in eligible:
        sha=inp["sha256"]
        if sha256(inp["path"])!=sha:
            note("hash_mismatch",sha=sha[:16]);continue
        # Use current manifest, since another independent Ghidra job might have
        # recovered some entries since the initial inventory.
        value=cx.execute("SELECT result_path FROM jobs WHERE key=?",("decompile:"+sha,)).fetchone()
        manifest=json.loads((Path(value[0])/"manifest.json").read_text())
        targets=[r["address"] for r in manifest["functions"] if r["status"]=="failed"]
        if not targets:continue
        folder=HERE/"results"/sha[:16]/"ghidra"/"manual-predication-long-01"
        if folder.exists():
            note("existing_output_not_overwritten",sha=sha[:16]);continue
        folder.mkdir(parents=True)
        (folder/"projects").mkdir()
        (folder/"addresses.txt").write_text("\n".join(targets)+"\n")
        args=[str(GH),str(folder/"projects"),"CA01_MANLONG_"+sha[:12],
            "-import",inp["path"],"-scriptPath",str(HERE),
            "-postScript","CA01PredicationOffLong.java",
            str(folder/"targeted"),"1600",str(folder/"addresses.txt"),
            "-analysisTimeoutPerFile","360","-max-cpu","2","-deleteProject",
            "-log",str(folder/"ghidra.log"),"-scriptlog",str(folder/"script.log")]
        note("started",sha=sha[:16],binary=inp["archive_path"],targets=targets)
        try:
            with (folder/"console.log").open("w") as out:
                p=subprocess.run(args,cwd=str(HERE),env=env,
                    stdin=subprocess.DEVNULL,stdout=out,
                    stderr=subprocess.STDOUT,timeout=2100)
            manifest_path=folder/"targeted"/"manifest.json"
            if not manifest_path.exists():
                note("failed_no_manifest",sha=sha[:16],exit=p.returncode)
                continue
            result=json.loads(manifest_path.read_text())
            if result["sha256"].lower()!=sha:raise ValueError("Wrong Ghidra SHA")
            note("finished_case",sha=sha[:16],exit=p.returncode,
                success=[r["address"] for r in result["functions"] if r["status"]=="decompiled"],
                failed=[r["address"] for r in result["functions"] if r["status"]=="failed"],
                pending=result["not_attempted"])
        except Exception as exc:
            note("error",sha=sha[:16],message=repr(exc),
                 traceback=traceback.format_exc()[-1000:])
    note("all_attempts_done")
    cx.close()
if __name__=="__main__":main()
