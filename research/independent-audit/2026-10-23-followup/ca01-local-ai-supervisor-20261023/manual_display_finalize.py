#!/usr/bin/env python3
"""Complete and index older CA01 PROC_DISPLAY recovery without AI or Codex."""
import datetime as dt
import hashlib
import json
import sqlite3
import sys
import time
import traceback
from pathlib import Path

ROOT = Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
sys.path.insert(0, str(ROOT))
import resume_decompile
import coverage_index

SHA = "4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004"
BIN = Path("/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY")
GH = ROOT / "results" / SHA[:16] / "ghidra"
PROGRESS = ROOT / "manual-display-recovery-20261023.json"
CHECK = ROOT / "results" / SHA[:16] / "function-index.json"
resume_decompile.RUN_TIMEOUT = 1800
resume_decompile.RESUME_BUDGET = 600
resume_decompile.ANALYSIS_TIMEOUT = 480
data = {"started":dt.datetime.now(dt.timezone.utc).isoformat(),
        "local_model_used":False,"codex_used":False,
        "original_firmware_modified":False, "events":[]}

def record(event, **kwargs):
    row={"when":dt.datetime.now(dt.timezone.utc).isoformat(),
         "event":event,**kwargs}
    data["events"].append(row)
    PROGRESS.write_text(json.dumps(data,indent=2)+"\n")
    print(json.dumps(row,default=str),flush=True)

def alive_attempt6():
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmd=(proc/"cmdline").read_bytes()
            if b"resume_decompile.py" in cmd and b"--attempt" in cmd and b"6" in cmd:
                return True
        except (OSError,PermissionError):
            continue
    return False

def validate(path):
    path=Path(path)
    obj=json.loads((path/"manifest.json").read_text())
    assert obj["sha256"].lower()==SHA
    assert obj["functions_catalogued"]==len(obj["functions"])
    assert obj["decompiled"] + obj["failed"] + obj["not_attempted"] == obj["functions_catalogued"]
    return obj

def save_coverage(cx, source, stage):
    obj=validate(source)
    cx.execute("UPDATE jobs SET result_path=? WHERE key=?", (str(source),"decompile:"+SHA))
    cx.commit()
    try:
        stats=coverage_index.index_binary(SHA,source,"./opt/ftl/apl/PROC_DISPLAY")
        CHECK.write_text(json.dumps(stats,indent=2)+"\n")
        cx.execute("""UPDATE jobs SET status='done', result_path=?,
                    finished=?,error=NULL WHERE key=?""",
                   (str(CHECK),dt.datetime.now(dt.timezone.utc).isoformat(),"index:"+SHA))
        cx.commit()
        record("checkpoint",stage=stage,dir=str(source),
               catalogued=obj["functions_catalogued"],decompiled=obj["decompiled"],
               failed=obj["failed"],unattempted=obj["not_attempted"],index=stats)
    except Exception as e:
        record("index_error",stage=stage,source=str(source),error=repr(e))
    return obj

def main():
    if not (ROOT/"stop.flag").exists():
        raise RuntimeError("Supervisor was not stopped.")
    if not Path("/mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag").is_file():
        raise RuntimeError("Local AI is not marked off.")
    with BIN.open("rb") as stream:
        assert hashlib.file_digest(stream,"sha256").hexdigest()==SHA
    cx=sqlite3.connect(ROOT/"progress.sqlite3",timeout=60)
    cx.row_factory=sqlite3.Row
    initial=Path(cx.execute("SELECT result_path FROM jobs WHERE key=?",("decompile:"+SHA,)).fetchone()[0])
    validate(initial)
    record("begin",source=str(initial))
    waited=0
    while not (GH/"merged-resume-6"/"resume-proof.json").is_file():
        if waited>=2400:
            record("timeout_waiting_for_attempt6",minutes=waited/60)
            break
        if waited>30 and not alive_attempt6():
            record("attempt6_exited_without_merged_proof")
            break
        time.sleep(10)
        waited+=10
    candidate=GH/"merged-resume-6"
    current=initial
    if (candidate/"resume-proof.json").is_file():
        obj=save_coverage(cx,candidate,"attempt6")
        current=candidate
        cx.execute("""UPDATE jobs SET status='done', result_path=?, error=NULL,
            finished=? WHERE key=?""",
            (str(candidate),dt.datetime.now(dt.timezone.utc).isoformat(),
             "resume:"+SHA+":06"))
        cx.commit()
    else:
        record("attempt6_no_merged_proof",note="Preserving partial prior output and trying a new run.")
    previous_unattempted=validate(current)["not_attempted"]
    for number in range(7,13):
        if previous_unattempted==0:
            break
        if (GH/f"resume-{number}").exists():
            record("attempt_path_collision",number=number)
            continue
        record("next_resume_start",round=number,pending=previous_unattempted)
        try:
            result=resume_decompile.resume(SHA,BIN,current,run_number=number)
            if result["status"]!="success":
                record("resume_noop",round=number,result=result)
                break
            current=Path(result["combined"])
            obj=save_coverage(cx,current,f"attempt{number}")
            new_pending=obj["not_attempted"]
            record("next_resume_result",round=number,
                   gained=previous_unattempted-new_pending,
                   remaining=new_pending,failed=obj["failed"])
            if new_pending>=previous_unattempted:
                record("no_further_discovery",round=number)
                break
            previous_unattempted=new_pending
        except Exception as exc:
            record("next_resume_error",round=number,error=repr(exc),
                   traceback=traceback.format_exc()[-2000:])
            break
    final=validate(current)
    record("completed_display_phase",source=str(current),
           total=final["functions_catalogued"],
           decompiled=final["decompiled"],failed=final["failed"],
           not_attempted=final["not_attempted"])
    cx.close()

if __name__=="__main__":
    try:main()
    except Exception as exc:
        record("fatal",error=repr(exc),traceback=traceback.format_exc()[-2000:])
        raise
