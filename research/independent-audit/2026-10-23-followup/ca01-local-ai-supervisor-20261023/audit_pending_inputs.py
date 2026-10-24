#!/usr/bin/env python3
"""Read-only audit of CA01 original SHA inputs vs actual decompilation exports."""
from pathlib import Path
import sqlite3, collections, json
base=Path(__file__).resolve().parent
def read_db(path):
    cx=sqlite3.connect(path.as_uri()+"?mode=ro",uri=True,timeout=15)
    cx.row_factory=sqlite3.Row
    return cx
pr=read_db(base/"progress.sqlite3")
cov=read_db(base/"function_coverage.sqlite3")
jobs={x["sha256"]:dict(x) for x in pr.execute(
    "SELECT sha256,status,result_path,error,attempts FROM jobs WHERE kind='decompile'")}
indexed={x["sha256"]:dict(x) for x in cov.execute(
    "SELECT sha256,binary_name,catalogued,decompiled,failed,unattempted,indexed_bodies,indexed_at FROM sources")}
rows=[dict(x) for x in pr.execute("SELECT * FROM inputs ORDER BY archive_path,version")]
unique_names=collections.defaultdict(list)
for row in rows:unique_names[row["archive_path"]].append(row)
print("OVERALL",json.dumps({
    "sha_inputs":len(rows),
    "elf_sha":sum(1 for x in rows if x["elf"]),
    "other_sha":sum(1 for x in rows if not x["elf"]),
    "version_distribution":dict(collections.Counter(x["version"] for x in rows)),
    "decompile_jobs":dict(collections.Counter(x["status"] for x in jobs.values())),
    "indexed_sources":len(indexed),
    "index_totals":{key:sum(v.get(key,0) or 0 for v in indexed.values())
               for key in ("catalogued","decompiled","failed","unattempted","indexed_bodies")}
},indent=2))
print("ELF ENTRIES | SHA | VERSION | KB | decompile job | index | Ghidra decompiled / catalogued, failed/not_attempted | file")
for name, group in sorted(unique_names.items()):
    for x in group:
        if not x["elf"]:continue
        j=jobs.get(x["sha256"],{})
        ix=indexed.get(x["sha256"],{})
        print("ELF",x["sha256"][:12],x["version"],round(x["bytes"]/1024),j.get("status","NO_JOB"),
              bool(ix),f"{ix.get('decompiled','?')}/{ix.get('catalogued','?')} fail={ix.get('failed','?')} omitted={ix.get('unattempted','?')}",
              name,"actual_file="+x["filename"])
print("PENDING_FULL_GHIDRA",json.dumps([
    dict(file=x["archive_path"],filename=x["filename"],version=x["version"],
         sha=x["sha256"],bytes=x["bytes"],job=jobs.get(x["sha256"],{}))
    for x in rows if x["elf"] and (jobs.get(x["sha256"],{}).get("status")!="done")
],indent=2))
print("INDEXED_PARTIAL_FAILURES",json.dumps([
    dict(name=x["binary_name"],sha=sha,completed=x["decompiled"],
         catalogued=x["catalogued"],failed=x["failed"],unattempted=x["unattempted"])
    for sha,x in indexed.items() if (x.get("failed",0)>0 or x.get("unattempted",0)>0)
],indent=2))
print("NON_ELF_JOBS",json.dumps(
    [dict(status=x["status"],n=x["n"]) for x in
       pr.execute("SELECT status,count(*) n FROM jobs WHERE kind='identify' GROUP BY status")]))
