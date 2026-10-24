#!/usr/bin/env python3
"""Resume only Ghidra entries omitted by the earlier bounded decompiler pass.

Produces a NEW aggregated decompile directory in the independent audit tree;
never touches, overwrites, or deletes original recovery and Git files.
Requires verified input SHA, and preserves unattempted status for failures.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio")
HERE=Path(__file__).resolve().parent
GHIDRA=ROOT/"tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
SCRIPT=HERE/"CA01DecompileBatch.java"
JDK=ROOT/"tools/jdk-21.0.13+9"
ANALYSIS_TIMEOUT=165
RUN_TIMEOUT=1800
RESUME_BUDGET=600

def pending_entries(folder):
    manifest=json.loads((Path(folder)/"manifest.json").read_text())
    pending=[str(r["address"]) for r in manifest["functions"]
             if r.get("status")=="not_attempted_budget"]
    return manifest,pending

def pending_count(folder):
    p=Path(folder)/"manifest.json"
    if not p.is_file():return 0
    report=json.loads(p.read_text())
    return int(report.get("not_attempted",0))

def build_combined(main,part,out,sha):
    m=json.loads((main/"manifest.json").read_text())
    p=json.loads((part/"manifest.json").read_text())
    if m["sha256"].lower()!=sha or p["sha256"].lower()!=sha:
        raise RuntimeError("Cannot stitch unrelated binaries")
    pending=set(x["address"] for x in m["functions"] if x["status"]=="not_attempted_budget")
    addresses=set()
    for x in p["functions"]:
        if x["address"] not in pending:
            raise RuntimeError("Unexpected supplemental address "+x["address"])
        addresses.add(x["address"])
    improved={}
    attempted_failed={}
    for x in p["functions"]:
        if x["status"]=="decompiled":improved[x["address"]]=x
        elif x["status"]=="failed":attempted_failed[x["address"]]=x
    existing=set()
    for x in m["functions"]:
        if x["address"] in existing:raise RuntimeError("Base manifest duplicate address")
        existing.add(x["address"])
        if x["address"] in improved:
            newer=improved[x["address"]]
            x["status"]="decompiled"
            x["decompile_source"]="isolated_pending_only_resume"
            x["calls"]=newer.get("calls",x.get("calls",[]))
        elif x["address"] in attempted_failed:
            newer=attempted_failed[x["address"]]
            x["status"]="failed"
            x["error"]=newer.get("error","Selected retry decompilation failed")
            x["decompile_source"]="isolated_pending_only_resume"
    outcomes={k:0 for k in ["decompiled","failed","not_attempted_budget"]}
    for row in m["functions"]:
        outcomes[row["status"]]=outcomes.get(row["status"],0)+1
    m["decompiled"]=outcomes["decompiled"]
    m["failed"]=outcomes["failed"]
    m["not_attempted"]=outcomes["not_attempted_budget"]
    m["selection"]="initial decompilation plus independent skipped-entry Ghidra pass"
    grouped={}
    for row in m["functions"]:
        clas=row.get("classification") or ("import_thunk" if row.get("memory_block")==".plt" else
              "text_body" if row.get("memory_block")==".text" else "other_executable")
        group=grouped.setdefault(clas,{})
        group[row["status"]]=group.get(row["status"],0)+1
    m["counts_by_kind"]=grouped
    m["resume_evidence"]=dict(original_complete_count=
         sum(1 for row in m["functions"] if row["status"]=="decompiled" and row.get("decompile_source")!="isolated_pending_only_resume"),
         additional_verified_entries=len(improved),all_original_entries_retained=len(m["functions"]),
         selected_requested=len(pending),selected_discovered=len(addresses),
         supplement_name=str(part),
         limitation="Still Ghidra pseudocode, not recovered original source; unavailable dependencies persist")
    if len(m["functions"])!=m["functions_catalogued"]:
        raise RuntimeError("Result lost catalogued functions")
    out.mkdir(parents=True,exist_ok=False)
    a=main.joinpath("decompiled.c").read_text()
    b=part.joinpath("decompiled.c").read_text()
    if b.count("/* FUNCTION ")!=len(improved):
        raise RuntimeError("Supplement source functions do not match validated success count")
    # Mark supplement original-code SHA; append only new entries.
    (out/"decompiled.c").write_text(a+"\n/* VERIFIED SAME-SHA PENDING-ONLY DECOMPILATION */\n"+b)
    (out/"manifest.json").write_text(json.dumps(m,indent=2)+"\n")
    with (out/"functions.tsv").open("w") as f:
        f.write("address\tname\tbytes\tstatus\n")
        for row in m["functions"]:
            f.write(f"{row['address']}\t{row['name']}\t{row['bytes']}\t{row['status']}\n")
    (out/"resume-proof.json").write_text(json.dumps(dict(
       original_binary_sha=sha,
       main_manifest_sha256=hashlib.sha256((main/"manifest.json").read_bytes()).hexdigest(),
       supplement_manifest_sha256=hashlib.sha256((part/"manifest.json").read_bytes()).hexdigest(),
       improved_functions=len(improved),outcomes=outcomes,
       base_file_unchanged=True),indent=2)+"\n")
    return dict(improved=len(improved),new_total=m["decompiled"],
                still_not_attempted=m["not_attempted"],failed=m["failed"])

def resume(sha,original_path,initial_path,run_number=1):
    original_path=Path(original_path).resolve(strict=True)
    initial=Path(initial_path).resolve(strict=True)
    root=HERE/"results"/sha[:16]/"ghidra"
    main_manifest,pending=pending_entries(initial)
    if main_manifest["sha256"].lower()!=sha:raise RuntimeError("Base manifest SHA mismatch")
    if not pending:return dict(status="already_complete",combined=str(initial))
    with original_path.open("rb") as stream:
        if hashlib.file_digest(stream,"sha256").hexdigest()!=sha:
            raise RuntimeError("Original ELF changed")
    folder=root/f"resume-{run_number}"
    if folder.exists():raise FileExistsError("Refusing to overwrite previous resume attempt")
    folder.mkdir(parents=True)
    selected=folder/"pending-entry-addresses.txt"
    selected.write_text("\n".join(pending)+"\n")
    outputs=folder/"isolated"
    projects=folder/"projects"
    projects.mkdir(parents=True)
    env=os.environ.copy()
    env.update(JAVA_HOME=str(JDK),PATH=str(JDK/"bin")+":/usr/bin:/bin",
               GHIDRA_HEADLESS_MAXMEM="3G")
    args=[str(GHIDRA),str(projects),"CA01_RESUME_"+sha[:12],
       "-import",str(original_path),"-scriptPath",str(HERE),
       "-postScript","CA01DecompileBatch.java",str(outputs),
       str(RESUME_BUDGET),str(selected),
       "-analysisTimeoutPerFile",str(ANALYSIS_TIMEOUT),"-max-cpu","2",
       "-deleteProject","-log",str(folder/"ghidra.log"),
       "-scriptlog",str(folder/"script.log")]
    with (folder/"console.log").open("w") as out:
        completed=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,
             stderr=subprocess.STDOUT,timeout=RUN_TIMEOUT,env=env,cwd=str(HERE))
    if completed.returncode!=0:
        raise RuntimeError(f"Ghidra resume returned {completed.returncode}; see {folder}/console.log")
    if not (outputs/"manifest.json").is_file():
        raise RuntimeError("Ghidra did not produce supplemental manifest")
    merged=root/f"merged-resume-{run_number}"
    stats=build_combined(initial,outputs,merged,sha)
    return dict(status="success",main=str(initial),supplement=str(outputs),
                combined=str(merged),stats=stats,
                original_source_sha256=sha,
                note="No original binaries or repository files changed")

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("sha")
    p.add_argument("binary")
    p.add_argument("decomp")
    p.add_argument("--attempt",type=int,default=1)
    a=p.parse_args()
    print(json.dumps(resume(a.sha,a.binary,a.decomp,a.attempt),indent=2))
