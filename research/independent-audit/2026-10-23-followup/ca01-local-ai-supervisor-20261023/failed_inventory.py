#!/usr/bin/env python3
"""Read-only snapshot of failed Ghidra functions across indexed original ELFs."""
from pathlib import Path
import json,sqlite3,collections,datetime as dt
P=Path(__file__).resolve().parent
conn=sqlite3.connect("file:"+str(P/"function_coverage.sqlite3")+"?mode=ro",uri=True)
conn.row_factory=sqlite3.Row
records=[]
for row in conn.execute("""SELECT sha256,binary_name,manifest_file,source_file,
                   failed,decompiled,catalogued FROM sources WHERE failed>0
                   ORDER BY binary_name"""):
    manifest=json.loads(Path(row["manifest_file"]).read_text())
    entries=[e for e in manifest["functions"] if e.get("status")=="failed"]
    records.append(dict(
        sha=row["sha256"],binary=row["binary_name"],
        catalogued=row["catalogued"],completed=row["decompiled"],
        failed=len(entries),
        manifest_file=row["manifest_file"],
        entries=[dict(address=e["address"],name=e.get("name"),
                  bytes=e.get("bytes"),error=e.get("error","")[:500],
                  block=e.get("memory_block")) for e in entries]))
data=dict(date=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
          failures=records,failed_function_total=sum(x["failed"] for x in records))
(P/"failed-function-inventory-20261023.json").write_text(json.dumps(data,indent=2)+"\n")
for row in records:
    print(row["binary"],row["sha"][:12],row["completed"],"/",row["catalogued"])
    for e in row["entries"]:
        print(" ",e["address"],e["name"],"bytes",e["bytes"],repr(e["error"][:150]))
print("FAILED TOTAL",data["failed_function_total"])
