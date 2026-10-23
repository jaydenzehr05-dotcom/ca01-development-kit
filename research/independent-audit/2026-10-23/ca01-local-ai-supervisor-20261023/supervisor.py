#!/usr/bin/env python3
"""Independent Toyota CA01 read-only, checkpointed Ghidra + local-Qwen runner.

Codex is NOT invoked; its active repository is never written to or modified.
The model receives bounded decompilation excerpts and can return JSON notes
ONLY. Ghidra jobs are hash-verified, isolated, rate- and time-bounded.
"""
from __future__ import annotations
import argparse
import collections
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from model_review import review_code, MANUAL_OFF
import coverage_index
import resume_decompile

ROOT=Path("/home/starlight/projects/rav4-radio")
REPO=ROOT/"ca01-development-kit"
AUDIT=ROOT/"system-audit"
HERE=Path(__file__).resolve().parent
DB=HERE/"progress.sqlite3"
STOP=HERE/"stop.flag"
LOCK=HERE/"supervisor.lock"
PID=HERE/"supervisor.pid"
LOG=HERE/"activity.log"
OUTPUT=HERE/"results"
GHIDRA=ROOT/"tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
JDK=ROOT/"tools/jdk-21.0.13+9"
GH_SOURCES=REPO/"tools/ghidra/CA01DecompileBatch.java"
GH_SCRIPT=HERE/"CA01DecompileBatch.java"
OLD=AUDIT/"ca01-updater-independent-20261022/recovery-manifest.json"
NEW=AUDIT/"ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered-manifest.json"
PREVIOUS=AUDIT/"ca01-critical-decompilation-20261023"
MAX_ATTEMPTS=2
GHIDRA_TIMEOUT=300
ANALYSIS_TIMEOUT=165
DECOMPILE_BUDGET=70
IDLE_SECONDS=240
CATEGORIES={"decompile","review","identify","index","focus","resume"}
RUNNING=False

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def connect():
    HERE.mkdir(parents=True,exist_ok=True)
    cx=sqlite3.connect(DB,timeout=30)
    cx.row_factory=sqlite3.Row
    cx.execute("PRAGMA journal_mode=WAL")
    cx.executescript("""
    CREATE TABLE IF NOT EXISTS inputs(
      sha256 TEXT PRIMARY KEY, path TEXT NOT NULL, filename TEXT NOT NULL,
      bytes INTEGER NOT NULL, archive_path TEXT NOT NULL,
      version TEXT NOT NULL, elf INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS jobs(
      key TEXT PRIMARY KEY, sha256 TEXT NOT NULL, kind TEXT NOT NULL,
      priority INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
      attempts INTEGER NOT NULL DEFAULT 0, result_path TEXT,
      started TEXT, finished TEXT, error TEXT,
      FOREIGN KEY(sha256) REFERENCES inputs(sha256));
    CREATE TABLE IF NOT EXISTS events(
      time TEXT NOT NULL, key TEXT, event TEXT NOT NULL, message TEXT);
    CREATE INDEX IF NOT EXISTS queue ON jobs(status,priority,key);
    """)
    return cx

def event(cx,key,kind,detail):
    msg=str(detail)[:900]
    cx.execute("INSERT INTO events(time,key,event,message) VALUES(?,?,?,?)",(utc(),key,kind,msg))
    cx.commit()
    print(utc(),kind,key or "-",msg[:300],flush=True)

def validated_path(row):
    path=Path(row["path"]).resolve(strict=True)
    if not path.is_relative_to(AUDIT):
        raise ValueError("Source outside read-only recovered firmware corpus")
    if path.stat().st_size!=row["bytes"]:
        raise RuntimeError("Source size changed: "+str(path))
    with path.open("rb") as fd:
        h=hashlib.file_digest(fd,"sha256").hexdigest()
    if h!=row["sha256"]:
        raise RuntimeError("Original ELF hash mismatch "+str(path))
    return path

def priority(name,elf,version):
    n=name.upper()
    if not elf:return 300
    rules=(
      ("LIBI2C_CM.SO",3),("PROC_REPRO",8),("LIBIPAS_GRP.SO",9),
      ("PROC_HMI",10),("PROC_UIEIF",12),("PROC_CDP",13),
      ("PROC_AUDIO",14),("PROC_DISPLAY",18),("PROC_SYSTEM",19),
      ("LIBIPAS_SYSC.SO",20),("LIBIPAS_SYSP.SO",21),
      ("PROC_VRS",25),("PROC_",35),(".SO",50))
    pos=next((p for pattern,p in rules if pattern in n),65)
    return pos+(0 if version=="1134" else 85)

def existing_ghidra():
    result={}
    for label,folder in [
        ("display",PREVIOUS/"display1134"),
        ("system",PREVIOUS/"system1127-verified"),
        ("sysc",PREVIOUS/"sysc1127-verified")]:
        manifest=folder/"manifest.json"
        if not (manifest.is_file() and (folder/"decompiled.c").is_file()):continue
        try:
            info=json.loads(manifest.read_text())
            sha=info.get("sha256","").lower()
            if len(sha)==64:result[sha]=folder
        except (ValueError,OSError):continue
    return result

def seed(cx):
    manifest_sources=[
      ("1134",json.loads(NEW.read_text())),
      ("1127",json.loads(OLD.read_text())["files"])
    ]
    count=0
    for version,items in manifest_sources:
        for file in items:
            path=Path(file.get("local_file") or file.get("local_path") or "")
            if not path.is_file():continue
            sha=file.get("sha256","").lower()
            if len(sha)!=64:continue
            elf=bool(file.get("elf",file.get("ELF",False)))
            record=(sha,str(path.resolve()),path.name,file["size"],
                    file["archive_path"],version,int(elf))
            cx.execute("""INSERT OR IGNORE INTO inputs
                          (sha256,path,filename,bytes,archive_path,version,elf)
                          VALUES(?,?,?,?,?,?,?)""",record)
            kind="decompile" if elf else "identify"
            key=kind+":"+sha
            cx.execute("""INSERT OR IGNORE INTO jobs(key,sha256,kind,priority)
                       VALUES(?,?,?,?)""",(key,sha,kind,priority(file["archive_path"],elf,version)))
            count+=1
    # Include the original encoded CA01 component slices in read-only inspection.
    # This does NOT assume they contain extractable complete filesystems.
    wrapped=AUDIT/"ca01-1134-firmware-analysis-20261023"
    partmeta=wrapped/"1134-inspection.json"
    if partmeta.is_file():
        for part in json.loads(partmeta.read_text()).get("components",[]):
            source=wrapped/"components-1134"/part["filename"]
            if not source.is_file():continue
            sha=part["sha256"].lower()
            cx.execute("""INSERT OR IGNORE INTO inputs
                    (sha256,path,filename,bytes,archive_path,version,elf)
                    VALUES(?,?,?,?,?,?,?)""",
                (sha,str(source.resolve()),source.name,part["size"],
                 "KWI component: "+part["name"],"1134-component",0))
            rank=({"03-kernel.bin":6,"07-gui.bin":7,
                   "02-middle-ware.bin":33,"04-device-driver.bin":34,
                   "06-audio.bin":35}).get(part["filename"],95)
            cx.execute("""INSERT OR IGNORE INTO jobs(key,sha256,kind,priority)
                          VALUES(?,?,?,?)""",("identify:"+sha,sha,"identify",rank))
            count+=1
    # Reuse existing completed Ghidra exports without running duplicated analysis.
    for sha,folder in existing_ghidra().items():
        row=cx.execute("SELECT * FROM jobs WHERE key=?",("decompile:"+sha,)).fetchone()
        if row and row["status"]=="queued":
            cx.execute("""UPDATE jobs SET status='done',finished=?,result_path=?
                         WHERE key=?""",(utc(),str(folder),"decompile:"+sha))
            ensure_review(cx,sha,folder,row["priority"]+1)
    # Keep an exact, searchable entry for every discovered function, including
    # Ghidra failures and budget omissions. This is evidence accounting,
    # not a declaration that a decompiled ELF has been reverse engineered.
    finished=cx.execute("""SELECT sha256,priority,result_path
        FROM jobs WHERE kind='decompile' AND status='done' AND result_path IS NOT NULL""").fetchall()
    for item in finished:
        ensure_resume(cx,item["sha256"],item["result_path"],item["priority"]+2)
        ensure_index(cx,item["sha256"],item["priority"]+5)
    cx.commit()
    return dict(manifest_records=count,
        sources=cx.execute("SELECT count(*) FROM inputs").fetchone()[0],
        jobs=cx.execute("SELECT count(*) FROM jobs").fetchone()[0],
        prior_ghidra_exports=len(existing_ghidra()))

def ensure_review(cx,sha,folder,priority):
    cx.execute("""INSERT OR IGNORE INTO jobs(key,sha256,kind,priority)
                  VALUES(?,?,?,?)""",("review:"+sha,sha,"review",priority))
    cx.commit()

def ensure_resume(cx,sha,source_folder,priority_value):
    if not source_folder:return
    if resume_decompile.pending_count(source_folder)<=0:return
    cx.execute("""INSERT OR IGNORE INTO jobs(key,sha256,kind,priority)
                  VALUES(?,?,?,?)""",("resume:"+sha,sha,"resume",priority_value))
    cx.commit()

def resume_job(cx,job,path):
    existing=cx.execute("SELECT result_path,status FROM jobs WHERE key=?",
                        ("decompile:"+job["sha256"],)).fetchone()
    if not existing or existing["status"]!="done" or not existing["result_path"]:
        raise RuntimeError("Resume requires completed initial Ghidra decompilation")
    attempt=int(job["attempts"])+1
    result=resume_decompile.resume(job["sha256"],path,existing["result_path"],
                                    run_number=attempt)
    if result.get("status")=="success":
        merged=result["combined"]
        cx.execute("UPDATE jobs SET result_path=? WHERE key=?",
                   (merged,"decompile:"+job["sha256"]))
        # A previous index based on the initial incomplete export is now stale.
        cx.execute("""UPDATE jobs SET status='queued',attempts=0,error=NULL
                  WHERE key=? AND status='done'""",("index:"+job["sha256"],))
        cx.commit()
    dest=OUTPUT/job["sha256"][:16]/"ghidra"/f"resume-{attempt}-result.json"
    write_json(dest,result)
    return dest

def ensure_index(cx,sha,priority_value):
    cx.execute("""INSERT OR IGNORE INTO jobs(key,sha256,kind,priority)
                   VALUES(?,?,?,?)""",("index:"+sha,sha,"index",priority_value))
    cx.commit()

def _prior_reviewed_addresses(sha):
    path=OUTPUT/sha[:16]/"model-review.json"
    if not path.is_file():return set()
    try:
        data=json.loads(path.read_text())
        return {coverage_index.norm(x) for x in data.get("examined_functions",[])}
    except Exception:
        return set()

def ensure_next_focus(cx,sha,priority_value):
    # One sequential, checkpointed batch per ELF. Avoid 20,000 queued model
    # calls and prioritize verified evidence, not speculative feature claims.
    dependent=cx.execute("SELECT status FROM jobs WHERE key=?",("index:"+sha,)).fetchone()
    if not dependent or dependent["status"]!="done":return
    prefix="focus:"+sha+":"
    existing=cx.execute("SELECT key,status FROM jobs WHERE key LIKE ? ORDER BY key",
                         (prefix+"%",)).fetchall()
    if any(x["status"] in ("queued","running") for x in existing):return
    index=len(existing)
    if index>=8:return   # 16 additional functions maximum per binary initially
    review_excluded=_prior_reviewed_addresses(sha)
    ordered=coverage_index.candidates(sha,limit=16+len(review_excluded),exclude=review_excluded)
    selected=ordered[index*2:index*2+2]
    if not selected:return
    key=prefix+f"{index:03d}"
    cx.execute("""INSERT OR IGNORE INTO jobs(key,sha256,kind,priority)
                  VALUES(?,?,?,?)""",(key,sha,"focus",priority_value+index*9))
    cx.commit()

def index_source_job(cx,job,path):
    dep=cx.execute("SELECT result_path,status FROM jobs WHERE key=?",
                   ("decompile:"+job["sha256"],)).fetchone()
    if not dep or dep["status"]!="done" or not dep["result_path"]:
        raise RuntimeError("Index requires complete Ghidra export")
    value=coverage_index.index_binary(job["sha256"],dep["result_path"],job["archive_path"])
    output=OUTPUT/job["sha256"][:16]/"function-index.json"
    write_json(output,dict(value,kind="complete_discovery_index",
              note="Every Ghidra-discovered function enumerated; no source-level or semantic verification implied",
              created=utc()))
    return output

def model_focus_job(cx,job,path):
    dep=cx.execute("SELECT result_path,status FROM jobs WHERE key=?",
                   ("decompile:"+job["sha256"],)).fetchone()
    idx=cx.execute("SELECT status FROM jobs WHERE key=?",("index:"+job["sha256"],)).fetchone()
    if not dep or dep["status"]!="done" or not dep["result_path"]:
        raise RuntimeError("Focused review needs Ghidra export")
    if not idx or idx["status"]!="done":
        raise RuntimeError("Focused review needs function index")
    batch=int(job["key"].rsplit(":",1)[-1])
    omit=_prior_reviewed_addresses(job["sha256"])
    ranked=coverage_index.candidates(job["sha256"],limit=16+len(omit),exclude=omit)
    targets=ranked[batch*2:batch*2+2]
    if not targets:
        raise RuntimeError("No remaining indexed targets in requested batch")
    excerpts=coverage_index.get_excerpts(job["sha256"],[x["address"] for x in targets])
    result=review_code(job["archive_path"],job["sha256"],
        Path(dep["result_path"])/"decompiled.c",excerpts=excerpts)
    result["review_stage"]="focused_candidate_review"
    result["selected_addresses"]=[x["address"] for x in targets]
    result["selection_evidence"]=[dict(address=x["address"],score=x["score"],
                                       tags=json.loads(x["tags"])) for x in targets]
    result["still_unreviewed"]="Other function entries remain in function_coverage.sqlite3"
    dest=OUTPUT/job["sha256"][:16]/"focus"/f"{batch:03d}.json"
    write_json(dest,result)
    return dest

def get_next(cx):
    return cx.execute("""SELECT jobs.*,inputs.filename,inputs.path,inputs.bytes,
                       inputs.archive_path FROM jobs JOIN inputs USING(sha256)
                       WHERE jobs.status='queued'
                       ORDER BY jobs.priority,jobs.key LIMIT 1""").fetchone()

def index_nonelf(cx,job,path):
    raw=path.read_bytes()
    words=[]
    for found in re.finditer(rb"[ -~]{7,240}",raw):
        s=found.group().decode("ascii","replace")
        if any(w in s.lower() for w in ("/opt/","/dev/mmc","ext3","rootfs",
             "mra","mui","mount","flash","kernel","version","uub", "sys")):
            words.append(dict(offset=hex(found.start()),value=s[:210]))
        if len(words)>=100:break
    dest=OUTPUT/job["sha256"][:16]/"identification.json"
    dest.parent.mkdir(parents=True,exist_ok=True)
    doc=dict(classification="filename/magic/string indicators only",
      binary=job["filename"],sha256=job["sha256"],bytes=len(raw),
      first32hex=raw[:32].hex(),possible_paths=words,
      note="No full filesystem extraction or firmware execution; text can be incidental.")
    write_json(dest,doc)
    return dest

def write_json(dest,doc):
    dest.parent.mkdir(parents=True,exist_ok=True)
    tmp=dest.with_name(dest.name+".partial")
    tmp.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    os.replace(tmp,dest)

def ghidra_export(cx,job,path):
    if not GHIDRA.is_file():raise FileNotFoundError(GHIDRA)
    if not GH_SCRIPT.is_file():raise FileNotFoundError(GH_SCRIPT)
    folder=OUTPUT/job["sha256"][:16]/"ghidra"
    expected=folder/"decomp/manifest.json"
    if expected.exists():
        data=json.loads(expected.read_text())
        if data.get("sha256","").lower()==job["sha256"]:
            return folder/"decomp"
        raise RuntimeError("Stale or mismatched Ghidra artifact: "+str(expected))
    folder.mkdir(parents=True,exist_ok=True)
    project=folder/"projects"
    project.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy()
    env.update(JAVA_HOME=str(JDK),PATH=str(JDK/"bin")+":/usr/bin:/bin",
               GHIDRA_HEADLESS_MAXMEM="3G")
    project_name="CA01_LocalAI_"+job["sha256"][:15]
    args=[
       str(GHIDRA),str(project),project_name,
       "-import",str(path),"-scriptPath",str(HERE),
       "-postScript","CA01DecompileBatch.java",
       str(folder/"decomp"),str(DECOMPILE_BUDGET),
       "-analysisTimeoutPerFile",str(ANALYSIS_TIMEOUT),
       "-max-cpu","2","-deleteProject",
       "-log",str(folder/"ghidra.log"),
       "-scriptlog",str(folder/"ghidra-script.log")]
    # The process can be killed externally by the operator; its output is
    # quarantined until source hash and manifest validation pass.
    with (folder/"console.log").open("w",encoding="utf-8") as output:
        try:
            run=subprocess.run(args,cwd=str(HERE),env=env,stdin=subprocess.DEVNULL,
                 stdout=output,stderr=subprocess.STDOUT,
                 timeout=GHIDRA_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise TimeoutError("Ghidra exceeded 300-second per-binary limit")
    if not expected.is_file():
        raise RuntimeError("Ghidra did not produce manifest, exit="+str(run.returncode))
    info=json.loads(expected.read_text())
    if info.get("sha256","").lower()!=job["sha256"]:
        raise RuntimeError("Generated decompilation references wrong ELF hash")
    stats={key:info.get(key) for key in ("functions_catalogued","decompiled","failed","not_attempted")}
    event(cx,job["key"],"ghidra_counts",stats)
    if run.returncode!=0:raise RuntimeError("Ghidra process returned "+str(run.returncode))
    return folder/"decomp"

def model_review_job(cx,job,path):
    dep=cx.execute("SELECT result_path,status FROM jobs WHERE key=?",
         ("decompile:"+job["sha256"],)).fetchone()
    if not dep or dep["status"]!="done" or not dep["result_path"]:
        raise RuntimeError("Model review requires completed Ghidra source manifest")
    source=Path(dep["result_path"])/"decompiled.c"
    if not source.is_file():
        raise FileNotFoundError(source)
    if MANUAL_OFF.exists():
        raise RuntimeError("Local AI manually OFF; no restart or inference allowed")
    result=review_code(job["archive_path"],job["sha256"],source)
    dest=OUTPUT/job["sha256"][:16]/"model-review.json"
    write_json(dest,result)
    return dest

def work_one(cx):
    job=get_next(cx)
    if not job:return False
    kind=job["kind"]
    if kind not in CATEGORIES:raise RuntimeError("Unsupported job kind")
    if MANUAL_OFF.exists():
        event(cx,None,"paused","Manual OFF flag; not starting further local work")
        return False
    key=job["key"]
    cx.execute("""UPDATE jobs SET status='running',attempts=attempts+1,
                started=?,error=NULL WHERE key=?""",(utc(),key))
    cx.commit()
    event(cx,key,"started",kind+" "+job["archive_path"])
    try:
        path=validated_path(job)
        if kind=="decompile":
            result=ghidra_export(cx,job,path)
        elif kind=="identify":
            result=index_nonelf(cx,job,path)
        elif kind=="resume":
            result=resume_job(cx,job,path)
        elif kind=="index":
            result=index_source_job(cx,job,path)
        elif kind=="focus":
            result=model_focus_job(cx,job,path)
        else:
            result=model_review_job(cx,job,path)
        cx.execute("""UPDATE jobs SET status='done',result_path=?,finished=?,error=NULL
                      WHERE key=?""",(str(result),utc(),key))
        if kind=="decompile":
            ensure_review(cx,job["sha256"],result,job["priority"]+1)
            ensure_resume(cx,job["sha256"],result,job["priority"]+2)
            ensure_index(cx,job["sha256"],job["priority"]+5)
        cx.commit()
        if kind in ("index","focus"):
            base=cx.execute("SELECT priority FROM jobs WHERE key=?",
                            ("decompile:"+job["sha256"],)).fetchone()
            ensure_next_focus(cx,job["sha256"],(base["priority"] if base else 70)+65)
        event(cx,key,"completed",result)
    except Exception as exc:
        # Fail bounded, retain previous artifacts and all logs for diagnosis.
        current=cx.execute("SELECT attempts FROM jobs WHERE key=?",(key,)).fetchone()[0]
        status="failed" if current>=MAX_ATTEMPTS else "queued"
        cx.execute("""UPDATE jobs SET status=?,error=?,finished=? WHERE key=?""",
            (status,str(exc)[:650],utc(),key))
        cx.commit()
        event(cx,key,"error",str(exc)[:650]+" status="+status)
    # Refresh a human-readable coverage/status report using fixed local code.
    # Model text is never executed. Reporting failure never invalidates work.
    try:
        subprocess.run([sys.executable,str(HERE/"research_report.py")],
                       stdin=subprocess.DEVNULL,capture_output=True,
                       text=True,timeout=12,check=True)
    except (OSError,subprocess.SubprocessError) as report_error:
        event(cx,None,"report_warning",str(report_error)[:250])
    return True

def print_status(cx):
    groups=dict(cx.execute("SELECT status,count(*) FROM jobs GROUP BY status").fetchall())
    latest=[dict(x) for x in cx.execute(
        "SELECT time,key,event,message FROM events ORDER BY rowid DESC LIMIT 8").fetchall()]
    cur=cx.execute("SELECT key,kind,status,attempts,error FROM jobs WHERE status='running' LIMIT 3").fetchall()
    doc=dict(now=utc(),root=str(HERE),local_ai_off=MANUAL_OFF.exists(),
       stop_requested=STOP.exists(),state_counts=groups,
       verified_inputs=cx.execute("SELECT count(*) FROM inputs").fetchone()[0],
       running=[dict(x) for x in cur],latest=latest,
       next=(dict(get_next(cx)) if get_next(cx) else None),
       git_checkout_modified_by_supervisor=False,
       codex_involved=False)
    print(json.dumps(doc,indent=2,default=str),flush=True)
    return doc

def lock():
    f=LOCK.open("a+")
    try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise RuntimeError("Supervisor already running")
    return f

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("command",choices=["seed","status","once","loop","stop","reset-stop","smoke"])
    args=parser.parse_args()
    if args.command=="stop":
        STOP.touch();print("STOP_FLAG_SET will stop after bounded current job");return
    if args.command=="reset-stop":
        STOP.unlink(missing_ok=True);print("STOP_FLAG_CLEARED");return
    if args.command=="smoke":
        from model_review import smoke
        smoke();return
    cx=connect()
    if args.command=="status":
        print_status(cx);return
    with lock() as lk:
        PID.write_text(str(os.getpid())+"\n")
        if args.command in ("seed","once","loop"):
            info=seed(cx)
            print("SEED",json.dumps(info),flush=True)
        if args.command=="seed":return
        # If killed mid-analysis, previous 'running' work is safe to retry.
        cx.execute("UPDATE jobs SET status='queued',error='interrupted; will retry' WHERE status='running'")
        cx.commit()
        if args.command=="once":
            work_one(cx);print_status(cx);return
        while not STOP.exists():
            if MANUAL_OFF.exists():
                event(cx,None,"paused","Local AI manually OFF; exiting loop")
                break
            if not work_one(cx):
                time.sleep(IDLE_SECONDS)
                info=seed(cx)
                if cx.execute("SELECT count(*) FROM jobs WHERE status='queued'").fetchone()[0]==0:
                    event(cx,None,"idle","No new verified local inputs; awaiting additional firmware")
            else:
                time.sleep(4)
        event(cx,None,"stopped","Gracefully stopped; artifacts retained")
if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("SUPERVISOR_ERROR",type(exc).__name__,str(exc)[:1000],file=sys.stderr)
        raise
