#!/usr/bin/env python3
"""Isolated alternative Ghidra decompilation on ARM conditional errors, no AI."""
import datetime as dt
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import traceback
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio")
HERE=ROOT/"system-audit"/"ca01-local-ai-supervisor-20261023"
GHIDRA=ROOT/"tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
JDK=ROOT/"tools/jdk-21.0.13+9"
OUT=HERE/"manual-alternate-outcomes.json"
SHAS=("1a526239fbe5b3b72d9fb871fed9db3523c76125522a9addf0a99f6281b5e115",
      "28e8b7d000b0d764c3bdadb1f2ff0e28d16dbd6d64946967e527597d3ddd51c8")
result={"created":dt.datetime.now(dt.timezone.utc).isoformat(),
        "kind":"model_free_ghidra_alternate_styles",
        "source_modified":False,"cases":[]}

def log(event,**kwargs):
    row=dict(time=dt.datetime.now(dt.timezone.utc).isoformat(),
             event=event,**kwargs)
    result["cases"].append(row)
    OUT.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(row),flush=True)

def main():
    if not (HERE/"stop.flag").exists():
        raise RuntimeError("Supervisor is not stopped")
    if not Path("/mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag").exists():
        raise RuntimeError("Local AI not off")
    cx=sqlite3.connect(HERE/"progress.sqlite3",timeout=35)
    cx.row_factory=sqlite3.Row
    env=os.environ.copy()
    env.update(JAVA_HOME=str(JDK),PATH=str(JDK/"bin")+":/usr/bin:/bin",
               GHIDRA_HEADLESS_MAXMEM="3G")
    for sha in SHAS:
        entry=cx.execute("""SELECT i.path, i.archive_path, j.result_path
            FROM inputs i JOIN jobs j ON j.key='decompile:'||i.sha256
            WHERE i.sha256=?""",(sha,)).fetchone()
        if not entry:
            log("input_not_found",sha=sha[:16])
            continue
        path=Path(entry["path"])
        with path.open("rb") as stream:
            if hashlib.file_digest(stream,"sha256").hexdigest()!=sha:
                log("hash_mismatch",sha=sha[:16])
                continue
        base=Path(entry["result_path"])
        manifest=json.loads((base/"manifest.json").read_text())
        targets=[x["address"] for x in manifest["functions"]
             if x["status"]=="failed" and "Illegal op" in x.get("error","")]
        if not targets:
            log("no_conditional_failures",sha=sha[:16],name=entry["archive_path"])
            continue
        dest=HERE/"results"/sha[:16]/"ghidra"/"manual-alt-01"
        if dest.exists():
            log("output_already_exists",sha=sha[:16],path=str(dest))
            continue
        dest.mkdir(parents=True)
        (dest/"addresses.txt").write_text("\n".join(targets)+"\n")
        (dest/"projects").mkdir()
        run=[str(GHIDRA),str(dest/"projects"),"CA01_ALT_"+sha[:12],
             "-import",str(path),"-scriptPath",str(HERE),
             "-postScript","CA01ManualAlternate.java",
             str(dest/"targeted"),str(dest/"addresses.txt"),
             "-analysisTimeoutPerFile","480","-max-cpu","2",
             "-deleteProject","-log",str(dest/"ghidra.log"),
             "-scriptlog",str(dest/"script.log")]
        log("start",sha=sha[:16],name=entry["archive_path"],targets=targets)
        try:
            with (dest/"console.log").open("w") as stream:
                ret=subprocess.run(run,cwd=str(HERE),env=env,
                    stdin=subprocess.DEVNULL,stdout=stream,
                    stderr=subprocess.STDOUT,timeout=1500)
            status="process_exit_"+str(ret.returncode)
            obj=json.loads((dest/"targeted"/"manifest.json").read_text())
            if obj["sha256"].lower()!=sha:
                raise ValueError("wrong source hash in alternate export")
            log("result",sha=sha[:16],name=entry["archive_path"],
                process_status=status,done=obj["decompiled"],
                failed=obj["failed"],output=str(dest/"targeted"))
        except Exception as exc:
            log("error",sha=sha[:16],name=entry["archive_path"],
                error=repr(exc),traceback=traceback.format_exc()[-1000:])
    cx.close()
    log("finished")

if __name__=="__main__":
    main()
