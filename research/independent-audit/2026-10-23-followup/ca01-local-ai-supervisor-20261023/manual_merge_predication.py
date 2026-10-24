#!/usr/bin/env python3
"""After both direct Ghidra streams stop, merge validated alternative-style successes."""
import collections
import datetime as dt
import hashlib
import json
import sqlite3
import subprocess
import time
import traceback
from pathlib import Path
import sys

HERE=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
sys.path.insert(0,str(HERE))
import coverage_index
SOURCE=HERE/"manual-predication-off-outcomes.json"
NORMAL=HERE/"manual-ghidra-recovery-20261023.json"
OUT=HERE/"manual-predication-merge.json"
SOURCES=("1a526239fbe5b3b72d9fb871fed9db3523c76125522a9addf0a99f6281b5e115",
         "28e8b7d000b0d764c3bdadb1f2ff0e28d16dbd6d64946967e527597d3ddd51c8")
events=[]

def log(event,**kwargs):
    x={"time":dt.datetime.now(dt.timezone.utc).isoformat(),"event":event,**kwargs}
    events.append(x)
    OUT.write_text(json.dumps({"local_ai_used":False,"codex_used":False,"events":events},indent=2)+"\n")
    print(json.dumps(x),flush=True)

def finished(path):
    try:
        x=json.loads(path.read_text())
        return any(e["event"]=="finished" for e in x.get("cases",x.get("events",[])))
    except (OSError,ValueError,KeyError):
        return False

def main():
    if not (HERE/"stop.flag").exists():raise RuntimeError("supervisor must stay stopped")
    until=time.monotonic()+7200
    log("waiting_for_independent_ghidra_pipelines")
    while not finished(SOURCE):
        if time.monotonic()>until:
            log("wait_timeout",alternates_done=finished(SOURCE),main_done=finished(NORMAL))
            return
        time.sleep(10)
    cx=sqlite3.connect(HERE/"progress.sqlite3",timeout=50)
    cx.row_factory=sqlite3.Row
    for sha in SOURCES:
        supplement=HERE/"results"/sha[:16]/"ghidra"/"manual-predication-off-01"/"targeted"
        if not (supplement/"manifest.json").is_file():
            log("no_alternate_manifest",sha=sha[:16])
            continue
        try:
            p=json.loads((supplement/"manifest.json").read_text())
            assert p["sha256"].lower()==sha
            successes=[r for r in p["functions"] if r["status"]=="decompiled"]
            if not successes:
                log("no_alternate_success",sha=sha[:16],attempts=len(p["functions"]))
                continue
            row=cx.execute("""SELECT i.archive_path,j.result_path FROM inputs i
                JOIN jobs j ON j.key='decompile:'||i.sha256 WHERE i.sha256=?""",
                (sha,)).fetchone()
            if not row:raise RuntimeError("ELF input no longer indexed")
            base=Path(row["result_path"])
            source=json.loads((base/"manifest.json").read_text())
            assert source["sha256"].lower()==sha
            current={x["address"].lower():x for x in source["functions"]}
            improve=[r for r in successes if
                     current.get(r["address"].lower(),{}).get("status")=="failed"]
            if not improve:
                log("already_recovered_by_main_pipeline",sha=sha[:16])
                continue
            raw=(supplement/"decompiled.c").read_text()
            for r in improve:
                if "/* FUNCTION "+r["address"] not in raw:
                    raise RuntimeError("Alternate output missing actual C body "+r["address"])
                old=current[r["address"].lower()]
                old["status"]="decompiled"
                old.pop("error",None)
                old["decompile_source"]="manual_Ghidra_"+r.get("decompile_style","unknown")
                old["calls"]=r.get("calls",old.get("calls",[]))
            counts=collections.Counter(x["status"] for x in source["functions"])
            source["decompiled"]=counts["decompiled"]
            source["failed"]=counts["failed"]
            source["not_attempted"]=counts["not_attempted_budget"]
            source.setdefault("manual_alternate_evidence",[]).append({
                "sha256":sha,"supplement":str(supplement),
                "functions":[x["address"] for x in improve],
                "input_sha256":hashlib.sha256((supplement/"manifest.json").read_bytes()).hexdigest()})
            output=HERE/"results"/sha[:16]/"ghidra"/"manual-predication-merged-01"
            if output.exists():raise FileExistsError(output)
            output.mkdir(parents=True)
            (output/"decompiled.c").write_text(
                (base/"decompiled.c").read_text()+"\n/* VERIFIED SAME-SHA ALTERNATE GHIDRA STYLE */\n"+raw)
            (output/"manifest.json").write_text(json.dumps(source,indent=2)+"\n")
            with (output/"functions.tsv").open("w") as tsv:
                tsv.write("address\tname\tbytes\tstatus\n")
                for x in source["functions"]:
                    tsv.write(f"{x['address']}\t{x['name']}\t{x['bytes']}\t{x['status']}\n")
            (output/"alternate-proof.json").write_text(json.dumps({
                "original_sha":sha,
                "source_manifest_hash":hashlib.sha256((base/"manifest.json").read_bytes()).hexdigest(),
                "supplement_manifest_hash":hashlib.sha256((supplement/"manifest.json").read_bytes()).hexdigest(),
                "recovered":[x["address"] for x in improve],
                "original_binary_unchanged":True},indent=2)+"\n")
            cx.execute("UPDATE jobs SET result_path=? WHERE key=?",(str(output),"decompile:"+sha))
            cx.commit()
            stats=coverage_index.index_binary(sha,output,row["archive_path"])
            index=HERE/"results"/sha[:16]/"function-index.json"
            index.write_text(json.dumps(stats,indent=2)+"\n")
            cx.execute("""UPDATE jobs SET status='done',result_path=?,finished=? WHERE key=?""",
                (str(index),dt.datetime.now(dt.timezone.utc).isoformat(),"index:"+sha))
            cx.commit()
            log("merged",sha=sha[:16],recovered=[x["address"] for x in improve],
                remaining=source["failed"])
        except Exception as e:
            log("merge_error",sha=sha[:16],error=repr(e),
                traceback=traceback.format_exc()[-1500:])
    cx.close()
    verify=subprocess.run(["python3",str(HERE/"manual_verify.py")],
                          stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=90)
    log("finished",verification=verify.stdout.strip(),
        verification_error=verify.stderr.strip()[-600:])

if __name__=="__main__":
    try:main()
    except Exception as e:
        log("fatal",error=repr(e),traceback=traceback.format_exc()[-1500:])
        raise
