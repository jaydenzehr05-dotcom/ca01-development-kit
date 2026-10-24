#!/usr/bin/env python3
"""Manual, model-free CA01 failed-function recovery. Does not modify originals."""
import datetime as dt
import hashlib
import json
import sqlite3
import sys
import traceback
from pathlib import Path

ROOT = Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
sys.path.insert(0, str(ROOT))
import retry_failed
import coverage_index

retry_failed.MAX_ADDRESSES_PER_PASS = 20
retry_failed.JOB_TIMEOUT = 1500
retry_failed.SCRIPT_BUDGET = 1050
REPORT = ROOT / "manual-ghidra-recovery-20261023.json"
DB = ROOT / "progress.sqlite3"
BASE = {"started": dt.datetime.now(dt.timezone.utc).isoformat(),
        "runner": "direct-Ghidra-no-local-AI-no-Codex",
        "source_firmware_modified": False,
        "events": []}

def report(event, **details):
    line = {"time": dt.datetime.now(dt.timezone.utc).isoformat(),
            "event": event, **details}
    BASE["events"].append(line)
    REPORT.write_text(json.dumps(BASE, indent=2) + "\n")
    print(json.dumps(line, default=str), flush=True)

def connect():
    cx = sqlite3.connect(str(DB), timeout=60)
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA busy_timeout=60000")
    return cx

def reindex(cx, sha, archive):
    dep = cx.execute("SELECT result_path FROM jobs WHERE key=?", ("decompile:" + sha,)).fetchone()
    if dep is None or not dep["result_path"]:
        return
    info = coverage_index.index_binary(sha, dep["result_path"], archive)
    target = ROOT / "results" / sha[:16] / "function-index.json"
    target.write_text(json.dumps(info, indent=2) + "\n")
    cx.execute("UPDATE jobs SET status='done', result_path=?, finished=?, error=NULL WHERE key=?",
               (str(target), dt.datetime.now(dt.timezone.utc).isoformat(), "index:" + sha))
    cx.commit()
    report("reindexed", sha=sha[:16], result=info)

def process():
    if not (ROOT / "stop.flag").exists():
        raise RuntimeError("Supervisor stop.flag not present: do not run concurrently.")
    manual = Path("/mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag")
    if not manual.exists():
        raise RuntimeError("Operator has not disabled local AI; refusing ambiguous concurrent run.")
    cx = connect()
    rows = [dict(r) for r in cx.execute("""SELECT i.sha256,i.path,i.archive_path,
                   d.result_path FROM inputs AS i JOIN jobs AS d
                   ON d.key = 'decompile:' || i.sha256 WHERE d.status='done'
                   ORDER BY i.archive_path""")]
    candidates = []
    for r in rows:
        try:
            sel = retry_failed.pending(cx, r["sha256"])
        except Exception as exc:
            report("inventory_error", sha=r["sha256"][:16], error=str(exc))
            continue
        if sel:
            candidates.append((r, sel))
    candidates.sort(key=lambda item: (0 if "DISPLAY" in item[0]["archive_path"] else 1,
                                      -len(item[1]), item[0]["archive_path"]))
    report("candidates", files=[{"name":r["archive_path"],
                                "sha":r["sha256"][:16],
                                "failures_eligible":len(s)} for r,s in candidates])
    for r, _ in candidates:
        sha = r["sha256"]
        if retry_failed.sha256(r["path"]) != sha:
            report("binary_hash_mismatch", binary=r["archive_path"], sha=sha[:16])
            continue
        for trial in range(3):
            selected = retry_failed.pending(cx, sha)
            if not selected:
                break
            existing = [int(p.name.rsplit("-", 1)[-1]) for p in
                (ROOT / "results" / sha[:16] / "ghidra").glob("failed-retry-*")
                if p.name.rsplit("-", 1)[-1].isdigit()]
            number = max([49] + existing) + 1
            key = f"repair:{sha}:{number:02d}"
            cx.execute("""INSERT INTO jobs(key,sha256,kind,priority,status,attempts,started)
                VALUES(?,?,?,?,?,?,?)""",
                (key, sha, "repair", 15, "running", 1,
                 dt.datetime.now(dt.timezone.utc).isoformat()))
            cx.commit()
            targets = [t["address"] for t in selected]
            report("repair_start", binary=r["archive_path"], sha=sha[:16],
                   round=number, targets=targets)
            try:
                result = retry_failed.repair(cx, {"key":key,"sha256":sha}, r["path"])
                outcome = json.loads(Path(result).read_text())
                cx.execute("""UPDATE jobs SET status='done',result_path=?,
                    finished=?,error=NULL WHERE key=?""",
                    (str(result), dt.datetime.now(dt.timezone.utc).isoformat(),key))
                cx.commit()
                report("repair_result", binary=r["archive_path"], sha=sha[:16],
                       improved=outcome.get("improved_addresses",[]),
                       errors=outcome.get("failed_detail",{}),
                       process_error=outcome.get("error"),
                       output=str(result))
                if outcome.get("improved_addresses"):
                    try:
                        reindex(cx, sha, r["archive_path"])
                    except Exception as exc:
                        report("reindex_error", sha=sha[:16], error=str(exc))
            except Exception as exc:
                cx.execute("""UPDATE jobs SET status='failed',error=?,finished=?
                    WHERE key=?""",
                    (str(exc)[:650], dt.datetime.now(dt.timezone.utc).isoformat(),key))
                cx.commit()
                report("repair_exception", binary=r["archive_path"],
                       sha=sha[:16], error=repr(exc),
                       traceback=traceback.format_exc()[-1500:])
                break
    report("finished", note="Remaining failed functions are individually recorded, never relabeled successful")
    cx.close()

if __name__ == "__main__":
    try:
        process()
    except Exception as e:
        report("fatal", error=repr(e), traceback=traceback.format_exc()[-2500:])
        raise
