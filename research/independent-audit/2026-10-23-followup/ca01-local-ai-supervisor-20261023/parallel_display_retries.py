#!/usr/bin/env python3
"""Run the last two 11.34 PROC_DISPLAY Ghidra retries CONCURRENTLY.
Operator requested parallel execution. Independent immutable output projects;
no model, no Codex, no original firmware or Git modifications.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import traceback

HERE=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
ROOT=HERE.parent.parent
GHIDRA=ROOT/"tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
JDK=ROOT/"tools/jdk-21.0.13+9"
SHA="ed6c8180598afb2f3d0ddd74793add46bfa012bc387516229726ee5f776e303f"
ADDRESSES=("00023968","002059cc")
GH_DIR=HERE/"results"/SHA[:16]/"ghidra"
REPORT=HERE/"manual-parallel-display-20261023.json"
OUTCOME={"started":datetime.now(timezone.utc).isoformat(),"strategy":"2 independent Ghidra processes each Xmx 3G plus existing 1127 worker","no_local_ai":True,"no_codex":True,"firmware_unchanged":True,"events":[]}

def record(event,**info):
    row=dict(at=datetime.now(timezone.utc).isoformat(),event=event,**info)
    OUTCOME["events"].append(row)
    REPORT.write_text(json.dumps(OUTCOME,indent=2)+"\n")
    print(json.dumps(row),flush=True)

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()

def get_db():
    cx=sqlite3.connect(str(HERE/"progress.sqlite3"),timeout=120)
    cx.row_factory=sqlite3.Row
    cx.execute("PRAGMA busy_timeout=120000")
    return cx

def run_independent(original,addr):
    folder=GH_DIR/f"manual-parallel-20261023-{addr}"
    if folder.exists():
        return {"addr":addr,"state":"existing_directory_no_overwrite","folder":str(folder)}
    folder.mkdir(parents=True,exist_ok=False)
    (folder/"projects").mkdir()
    (folder/"addresses.txt").write_text(addr+"\n")
    targeted=folder/"targeted"
    env=os.environ.copy()
    env.update(JAVA_HOME=str(JDK),PATH=str(JDK/"bin")+":/usr/bin:/bin",GHIDRA_HEADLESS_MAXMEM="3G")
    cmd=[str(GHIDRA),str(folder/"projects"),"CA01_PAR_"+addr,
        "-import",str(original),"-scriptPath",str(HERE),
        "-postScript","CA01PredicationOffLong.java",str(targeted),
        "1200",str(folder/"addresses.txt"),
        "-analysisTimeoutPerFile","420","-max-cpu","2","-deleteProject",
        "-log",str(folder/"ghidra.log"),"-scriptlog",str(folder/"script.log")]
    record("ghidra_started",addr=addr,project=str(folder),java_heap_limit="3G")
    try:
        with (folder/"console.log").open("w") as out:
            process=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=out,
                  stderr=subprocess.STDOUT,timeout=1850,env=env,cwd=str(HERE))
        info={"addr":addr,"status_code":process.returncode,"folder":str(folder)}
        if (targeted/"manifest.json").is_file():
            manifest=json.loads((targeted/"manifest.json").read_text())
            info.update(manifest_sha=manifest.get("sha256"),
                        count=manifest.get("functions_catalogued"),
                        decompiled=manifest.get("decompiled"),
                        failed=manifest.get("failed"),
                        pending=manifest.get("not_attempted"))
        else:
            info["error"]="Ghidra produced no manifest"
        return info
    except Exception as ex:
        return {"addr":addr,"folder":str(folder),"error":repr(ex)}

def merge_one(cx,addr,folder):
    supplement=Path(folder)/"targeted"
    added=json.loads((supplement/"manifest.json").read_text())
    if added["sha256"].lower()!=SHA:raise RuntimeError("Ghidra supplemental hash mismatch")
    rows=added["functions"]
    if len(rows)!=1 or rows[0]["address"].lower()!=addr:raise RuntimeError("Wrong selected supplemental address")
    if rows[0]["status"]!="decompiled":
        return {"address":addr,"state":"failed_not_merged","error":rows[0].get("error")}
    current=cx.execute("SELECT result_path FROM jobs WHERE key=?",("decompile:"+SHA,)).fetchone()
    if not current or not current["result_path"]:raise RuntimeError("Active decompilation reference unavailable")
    main=Path(current["result_path"])
    data=json.loads((main/"manifest.json").read_text())
    if data["sha256"].lower()!=SHA:raise RuntimeError("Base manifest hash mismatch")
    target=[x for x in data["functions"] if x["address"].lower()==addr]
    if len(target)!=1:raise RuntimeError("Base function missing or duplicated")
    if target[0]["status"]=="decompiled":return {"address":addr,"state":"already_done"}
    if target[0]["status"]!="failed":raise RuntimeError("Only failed entries allowed")
    body=(supplement/"decompiled.c").read_text()
    if body.count("/* FUNCTION "+addr+" ")!=1:
        raise RuntimeError("Missing or duplicate supplemental function body")
    target[0]["status"]="decompiled"
    target[0]["calls"]=rows[0].get("calls",target[0].get("calls",[]))
    target[0].pop("error",None)
    target[0]["decompile_source"]="independent_parallel_Ghidra_predication_off_360s"
    data["decompiled"]+=1
    data["failed"]-=1
    assert data["decompiled"]+data["failed"]+data["not_attempted"]==data["functions_catalogued"]
    data.setdefault("parallel_recovery_evidence",[]).append(
       dict(address=addr,supplement=str(supplement),original_sha=SHA,
            source_manifest_sha=sha(main/"manifest.json"),supplement_manifest_sha=sha(supplement/"manifest.json"),
            verified_original_unmodified=True))
    targetfolder=GH_DIR/f"manual-parallel-merged-20261023-{addr}"
    targetfolder.mkdir(parents=True,exist_ok=False)
    (targetfolder/"decompiled.c").write_text(
         (main/"decompiled.c").read_text()+"\n/* SAME SHA VERIFIED PARALLEL TARGETED Ghidra OUTPUT */\n"+body)
    (targetfolder/"manifest.json").write_text(json.dumps(data,indent=2)+"\n")
    with (targetfolder/"functions.tsv").open("w") as tsv:
        tsv.write("address\tname\tbytes\tstatus\n")
        for row in data["functions"]:
            tsv.write(f"{row['address']}\t{row['name']}\t{row['bytes']}\t{row['status']}\n")
    (targetfolder/"proof.json").write_text(json.dumps({
       "original_sha":SHA,"base_manifest_sha":sha(main/"manifest.json"),
       "supplement_manifest_sha":sha(supplement/"manifest.json"),
       "successful_address":addr,"original_firmware_modified":False},indent=2)+"\n")
    cx.execute("UPDATE jobs SET result_path=? WHERE key=?", (str(targetfolder),"decompile:"+SHA))
    cx.commit()
    sys.path.insert(0,str(HERE))
    import coverage_index
    index=coverage_index.index_binary(SHA,targetfolder,"./opt/ftl/apl/PROC_DISPLAY")
    dest=HERE/"results"/SHA[:16]/"function-index.json"
    dest.write_text(json.dumps(index,indent=2)+"\n")
    cx.execute("UPDATE jobs SET status='done',result_path=?,finished=?,error=NULL WHERE key=?",
             (str(dest),datetime.now(timezone.utc).isoformat(),"index:"+SHA))
    cx.commit()
    return {"address":addr,"state":"merged","remaining":data["failed"],"location":str(targetfolder),"index":index}

def main():
    if not (HERE/"stop.flag").exists():raise RuntimeError("Original supervisor not stopped")
    if not Path("/mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag").exists():
        raise RuntimeError("Operator's local AI manual OFF flag not present")
    cx=get_db()
    row=cx.execute("""SELECT i.path, d.result_path FROM inputs AS i JOIN jobs AS d
                       ON d.key='decompile:'||i.sha256
                       WHERE i.sha256=?""",(SHA,)).fetchone()
    if row is None:raise RuntimeError("ELF binary not found in manifest")
    original=Path(row["path"])
    if sha(original)!=SHA:raise RuntimeError("Original executable SHA changed")
    current=json.loads((Path(row["result_path"])/"manifest.json").read_text())
    failed={f["address"].lower() for f in current["functions"] if f["status"]=="failed"}
    selected=[a for a in ADDRESSES if a in failed]
    record("verified",source=str(original),addresses=selected,existing_failed=sorted(failed))
    if not selected:return record("nothing_to_do")
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs=[pool.submit(run_independent,original,addr) for addr in selected]
        for job in as_completed(jobs):
            result=job.result()
            record("ghidra_completed",**result)
            if result.get("decompiled")==1 and result.get("status_code")==0:
                try:
                    merged=merge_one(cx,result["addr"],result["folder"])
                    record("verification_and_merge",**merged)
                except Exception as ex:
                    record("merge_error",addr=result["addr"],error=repr(ex),traceback=traceback.format_exc()[-1800:])
    cx.close()
    command=subprocess.run(["python3",str(HERE/"manual_verify.py")],capture_output=True,text=True,timeout=120)
    record("finished",coverage=command.stdout.strip(),coverage_error=command.stderr[-900:])
if __name__=="__main__":
    try:main()
    except Exception as exc:
        record("fatal",error=repr(exc),traceback=traceback.format_exc()[-2200:])
        raise
