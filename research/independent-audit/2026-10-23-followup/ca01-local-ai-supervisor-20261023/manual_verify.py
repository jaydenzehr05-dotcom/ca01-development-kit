#!/usr/bin/env python3
"""Verified status report of all available CA01 ELF decompilation outputs."""
import collections
import datetime as dt
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
sys.path.insert(0,str(ROOT))
import coverage_index

cx=sqlite3.connect(ROOT/"progress.sqlite3",timeout=45)
cx.row_factory=sqlite3.Row
rows=[dict(x) for x in cx.execute("""SELECT i.sha256,i.filename,i.archive_path,i.version,
    i.path AS binary_path,d.status AS job_status,d.result_path
    FROM inputs i LEFT JOIN jobs d ON d.key='decompile:'||i.sha256
    WHERE i.elf=1 ORDER BY i.archive_path,i.version""")]
items=[]
for r in rows:
    o=dict(name=r["archive_path"], version=r["version"], sha=r["sha256"],
           status=r["job_status"], path=r["result_path"])
    if r["job_status"]=="done" and r["result_path"]:
        try:
            path=Path(r["result_path"])
            obj=json.loads((path/"manifest.json").read_text())
            if obj["sha256"].lower()!=r["sha256"]:
                raise ValueError("binary SHA mismatch")
            counts=collections.Counter(x["status"] for x in obj["functions"])
            if len(obj["functions"]) != obj["functions_catalogued"]:
                raise ValueError("catalogue count mismatch")
            if obj["decompiled"]!=counts["decompiled"] or obj["failed"]!=counts["failed"] or obj["not_attempted"]!=counts["not_attempted_budget"]:
                raise ValueError("status counts mismatch")
            o.update(catalogued=obj["functions_catalogued"],
                     decompiled=obj["decompiled"],failed=obj["failed"],
                     not_attempted=obj["not_attempted"],
                     failed_entries=[dict(address=x["address"], name=x["name"], error=x.get("error",""))
                         for x in obj["functions"] if x["status"]=="failed"])
        except Exception as e:
            o["validation_error"]=str(e)
    items.append(o)

sums=collections.Counter()
for x in items:
    if x["status"]=="done" and "validation_error" not in x:
        for c in ("catalogued","decompiled","failed","not_attempted"):
            sums[c]+=x.get(c,0)
report=dict(generated=dt.datetime.now(dt.timezone.utc).isoformat(),
            ai_enabled=not Path("/mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag").exists(),
            supervisor_stopped=(ROOT/"stop.flag").exists(),
            caveat="Only known extracted ELF files and Ghidra-discovered executable functions; not recovered original source.",
            totals=dict(sums),items=items)
dest=ROOT/"MANUAL_EXECUTABLE_COVERAGE.json"
dest.write_text(json.dumps(report,indent=2)+"\n")
lines=["# Toyota CA01 - manually verified executable-code coverage",
       "", "Generated: "+report["generated"],
       "", "Local AI enabled: "+str(report["ai_enabled"]),
       "", "Supervisor stopped: "+str(report["supervisor_stopped"]),
       "", "**Scope:** extracted ELF inputs and Ghidra-discovered executable functions only.",
       "These are machine-code-derived C-like outputs, not factory source code.",
       "",
       "## Totals",
       "",
       f"- Catalogue entries: **{sums['catalogued']:,}**",
       f"- Decompiled: **{sums['decompiled']:,}**",
       f"- Failed: **{sums['failed']}**",
       f"- Not attempted: **{sums['not_attempted']}**",
       "",
       "## Versioned ELF inputs",
       "",
       "| Version | ELF path | Decompiled | Failed | Not attempted | Status |",
       "|---|---|---:|---:|---:|---|"]
for x in items:
    st=x["status"]
    if "validation_error" in x:
        st+=" (INVALID: "+x["validation_error"]+")"
    elif x["status"]=="done":
        st="complete" if x.get("failed",0)==0 and x.get("not_attempted",0)==0 else "partial"
    lines.append(f"| {x['version']} | `{x['name']}` | {x.get('decompiled','-')} | {x.get('failed','-')} | {x.get('not_attempted','-')} | {st} |")
lines.extend(["","## Failed function addresses",""])
for x in items:
    if not x.get("failed_entries"): continue
    lines.append("### "+x["version"]+" "+x["name"]+" (SHA "+x["sha"][:16]+")")
    for failure in x["failed_entries"]:
        lines.append("- `"+failure["address"]+"` "+failure["name"]+": "+failure["error"].strip().replace("\n"," ")[:150])
    lines.append("")
(ROOT/"MANUAL_EXECUTABLE_COVERAGE.md").write_text("\n".join(lines)+"\n")
print(json.dumps({"total":dict(sums),"inputs":len(items),
    "full":sum(1 for x in items if x.get("failed")==0 and x.get("not_attempted")==0),
    "pending":sum(1 for x in items if x.get("failed",0)>0 or x.get("not_attempted",0)>0),
    "output":str(dest)}),flush=True)
