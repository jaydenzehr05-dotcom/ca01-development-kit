#!/usr/bin/env python3
"""Bounded, hash-verified re-decompilation of original Ghidra failed entries.

Every retry has a distinct project/output directory. No firmware writes,
no Git actions, and no fabricated success; source hashes and supplemental
function addresses are checked before merging immutable C-like output.
"""
from __future__ import annotations
import collections
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path("/home/starlight/projects/rav4-radio")
HERE=Path(__file__).resolve().parent
GHIDRA=ROOT/"tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
JDK=ROOT/"tools/jdk-21.0.13+9"
SCRIPT=HERE/"CA01DecompileRetry.java"
MAX_RETRIES_PER_ADDRESS=3
MAX_ADDRESSES_PER_PASS=2
MAX_ROUNDS_PER_ELF=24
ANALYSIS_TIMEOUT=155
JOB_TIMEOUT=335
SCRIPT_BUDGET=105

def sha256(path):
    with Path(path).open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()

def load_current(cx,sha):
    dep=cx.execute("SELECT status,result_path FROM jobs WHERE key=?",
                   ("decompile:"+sha,)).fetchone()
    if not dep or dep["status"]!="done" or not dep["result_path"]:
        return None,None,None
    folder=Path(dep["result_path"]).resolve(strict=True)
    if not folder.is_relative_to(HERE/"results"):
        # Reused prior validated Codex outputs are elsewhere in the audit tree.
        if not folder.is_relative_to(ROOT/"system-audit"):
            raise RuntimeError("Unsafe function manifest location")
    info=json.loads((folder/"manifest.json").read_text())
    if info["sha256"].lower()!=sha:
        raise RuntimeError("Ghidra source SHA mismatch in current function manifest")
    failures=[dict(x) for x in info["functions"] if x.get("status")=="failed"]
    return folder,info,failures

def prior_attempts(cx,sha):
    tally=collections.Counter()
    for row in cx.execute("""SELECT result_path FROM jobs
            WHERE sha256=? AND kind='repair' AND status='done'
              AND result_path IS NOT NULL""",(sha,)):
        p=Path(row["result_path"])
        if not p.is_file():continue
        try:
            data=json.loads(p.read_text())
            for entry in data.get("selected_addresses",[]):tally[str(entry).lower()]+=1
        except (ValueError,OSError):pass
    return tally

def latest_index(cx,sha):
    item=cx.execute("SELECT status,priority,archive_path,version FROM jobs JOIN inputs USING(sha256) WHERE key=?",
        ("decompile:"+sha,)).fetchone()
    if item is None:raise KeyError(sha)
    return dict(item)

def redundant_older_version(cx,sha):
    path=HERE/"version-preference-20261023.json"
    if not path.is_file():return False
    data=json.loads(path.read_text())
    return any(x["old_sha"]==sha and x["identical_text"]
        for x in data["comparisons"])

def pending(cx,sha):
    folder,info,fail=load_current(cx,sha)
    if not folder or not fail:return None
    if info.get("not_attempted",0):return None
    if redundant_older_version(cx,sha):return None
    attempts=prior_attempts(cx,sha)
    eligible=[e for e in fail if attempts[e["address"].lower()]<MAX_RETRIES_PER_ADDRESS]
    if not eligible:return None
    eligible.sort(key=lambda e:(attempts[e["address"].lower()], -int(e.get("bytes",0)),
                                e["address"]))
    return eligible[:MAX_ADDRESSES_PER_PASS]

def ensure(cx,sha,priority):
    selection=pending(cx,sha)
    if not selection:return None
    existing=list(cx.execute("""SELECT key,status FROM jobs
         WHERE sha256=? AND kind='repair' ORDER BY key""",(sha,)))
    if any(row["status"] in ("queued","running") for row in existing):return None
    round_num=len(existing)+1
    if round_num>MAX_ROUNDS_PER_ELF:return None
    key="repair:"+sha+":"+str(round_num).zfill(2)
    cx.execute("""INSERT OR IGNORE INTO jobs(key,sha256,kind,priority)
                    VALUES(?,?,?,?)""",(key,sha,"repair",max(0,priority)))
    cx.commit()
    return key

def merge_success(base:Path,supp:Path,output:Path,sha:str,selected):
    main=json.loads((base/"manifest.json").read_text())
    part=json.loads((supp/"manifest.json").read_text())
    if main["sha256"].lower()!=sha or part["sha256"].lower()!=sha:
        raise RuntimeError("Cannot merge functions from different ELF inputs")
    allowed={s.lower() for s in selected}
    original_failed={x["address"].lower() for x in main["functions"]
                     if x.get("status")=="failed"}
    success={}
    errors={}
    for row in part.get("functions",[]):
        address=row["address"].lower()
        if address not in allowed or address not in original_failed:
            raise RuntimeError("Supplement contains unapproved or already-decompiled entry "+address)
        if row.get("status")=="decompiled":success[address]=row
        else:errors[address]=row.get("error","Targeted Ghidra still failed")
    raw=(supp/"decompiled.c").read_text()
    for address in success:
        if not ("/* FUNCTION "+address) in raw:
            raise RuntimeError("Successful supplement missing actual C body "+address)
    if not success:return None,errors
    # Do not mutate the source manifest in place; create a new immutable copy.
    for old in main["functions"]:
        address=old["address"].lower()
        if address in success:
            newer=success[address]
            old["status"]="decompiled"
            old["calls"]=newer.get("calls",old.get("calls",[]))
            old.pop("error",None)
            old["decompile_source"]="isolated_failed_only_45s_retry"
    counts=collections.Counter(x["status"] for x in main["functions"])
    main["decompiled"]=counts["decompiled"]
    main["failed"]=counts["failed"]
    main["not_attempted"]=counts["not_attempted_budget"]
    main["selection"]="original Ghidra analysis plus SHA-verified failed-only targeted retries"
    main.setdefault("failed_retry_evidence",[]).append(dict(
        successes=sorted(success),supplement=str(supp),
        original_sha256=sha,time=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")))
    if len(main["functions"])!=main["functions_catalogued"]:
        raise RuntimeError("Original function inventory changed during retry")
    if output.exists():raise FileExistsError(output)
    output.mkdir(parents=True)
    (output/"manifest.json").write_text(json.dumps(main,indent=2)+"\n")
    # Keep original Ghidra output byte-for-byte as a prefix.
    c=(base/"decompiled.c").read_text()
    (output/"decompiled.c").write_text(c+"\n/* SAME-SHA FAILED-ENTRY RETRY */\n"+raw)
    with (output/"functions.tsv").open("w") as stream:
        stream.write("address\tname\tbytes\tstatus\n")
        for row in main["functions"]:
            stream.write(f"{row['address']}\t{row['name']}\t{row['bytes']}\t{row['status']}\n")
    evidence=dict(source_sha256=sha,main_manifest_sha256=sha256(base/"manifest.json"),
         supplement_manifest_sha256=sha256(supp/"manifest.json"),
         success_addresses=sorted(success),
         still_failed=main["failed"],not_attempted=main["not_attempted"],
         original_source_modified=False)
    (output/"repair-proof.json").write_text(json.dumps(evidence,indent=2)+"\n")
    return output,errors

def repair(cx,job,original):
    sha=job["sha256"]
    path=Path(original).resolve(strict=True)
    if sha256(path)!=sha:raise RuntimeError("Original ELF source SHA changed")
    source,info,fail=load_current(cx,sha)
    if source is None:raise RuntimeError("Missing successfully exported source to retry")
    targets=pending(cx,sha)
    if not targets:raise RuntimeError("No eligible failed original functions left")
    if not SCRIPT.is_file():raise FileNotFoundError(SCRIPT)
    number=int(job["key"].rsplit(":",1)[-1])
    folder=HERE/"results"/sha[:16]/"ghidra"/f"failed-retry-{number:02d}"
    if folder.exists():raise FileExistsError("Refusing to overwrite older retry evidence: "+str(folder))
    folder.mkdir(parents=True)
    selected=[t["address"] for t in targets]
    (folder/"addresses.txt").write_text("\n".join(selected)+"\n")
    temp=folder/"targeted"
    proj=folder/"projects"
    proj.mkdir()
    env=os.environ.copy()
    env.update(JAVA_HOME=str(JDK),PATH=str(JDK/"bin")+":/usr/bin:/bin",
               GHIDRA_HEADLESS_MAXMEM="3G")
    args=[str(GHIDRA),str(proj),"CA01_REPAIR_"+sha[:12]+"_"+str(number),
         "-import",str(path),"-scriptPath",str(HERE),"-postScript",
         "CA01DecompileRetry.java",str(temp),str(SCRIPT_BUDGET),
         str(folder/"addresses.txt"),"-analysisTimeoutPerFile",str(ANALYSIS_TIMEOUT),
         "-max-cpu","2","-deleteProject",
         "-log",str(folder/"ghidra.log"),
         "-scriptlog",str(folder/"script.log")]
    error=None
    try:
        with (folder/"console.log").open("w") as output:
            run=subprocess.run(args,cwd=str(HERE),env=env,stdin=subprocess.DEVNULL,
                 stdout=output,stderr=subprocess.STDOUT,timeout=JOB_TIMEOUT)
        if run.returncode:
            error=f"Ghidra process returned {run.returncode}"
    except subprocess.TimeoutExpired:
        error=f"Ghidra process exceeded {JOB_TIMEOUT}s"
    recovered=None
    reported={}
    if (temp/"manifest.json").is_file() and (temp/"decompiled.c").is_file():
        try:
            recovered,reported=merge_success(source,temp,
                folder/"merged-decomp",sha,selected)
        except Exception as exc:
            error=f"Supplement validation failed: {type(exc).__name__}: {exc}"
    else:
        error=error or "Targeted Ghidra produced no complete manifest"
    if recovered is not None:
        cx.execute("UPDATE jobs SET result_path=? WHERE key=?",
                   (str(recovered),"decompile:"+sha))
        cx.execute("""UPDATE jobs SET status='queued',attempts=0,error=NULL
                   WHERE key=? AND status='done'""",("index:"+sha,))
        cx.commit()
    result=dict(kind="targeted_failed_original_arm_entry_decompilation",
        sha256=sha,source=str(path),existing_manifest=str(source),
        selected_addresses=selected,error=error,
        merged_decomp=str(recovered) if recovered else None,
        improved_addresses=[x["address"] for x in targets if
            recovered and x["address"].lower() in {
                r["address"].lower() for r in json.loads(
                    (recovered/"manifest.json").read_text())["functions"]
                if r.get("decompile_source")=="isolated_failed_only_45s_retry"
            }],
        failed_detail=reported,
        requires_manual_review=error is not None,
        original_binary_mutated=False,firmware_executed=False,
        note="Original ARM binaries read-only. Even successful pseudocode is not verified original source.")
    dest=folder/"retry-outcome.json"
    dest.write_text(json.dumps(result,indent=2)+"\n")
    return dest
