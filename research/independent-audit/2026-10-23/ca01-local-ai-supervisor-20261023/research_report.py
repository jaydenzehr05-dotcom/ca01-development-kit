#!/usr/bin/env python3
"""Write an honest local CA01 state/coverage snapshot from both SQLite indexes."""
from __future__ import annotations
import datetime as dt
import json
import sqlite3
from pathlib import Path
import coverage_index
import supervisor

HERE=Path(__file__).resolve().parent
OUT=HERE/"CURRENT_STATUS.md"
def execute():
    cx=supervisor.connect()
    counts={f"{x['kind']}_{x['status']}":x["n"] for x in cx.execute("""
      SELECT kind,status,count(*) n FROM jobs GROUP BY kind,status ORDER BY kind,status""")}
    errors=[dict(x) for x in cx.execute("""SELECT key,error FROM jobs
       WHERE status='failed' ORDER BY priority LIMIT 16""")]
    pending=[dict(x) for x in cx.execute("""SELECT inputs.archive_path,jobs.key,jobs.kind,jobs.started
        FROM jobs JOIN inputs USING(sha256) WHERE jobs.status='running' LIMIT 2""")]
    overall=coverage_index.status()
    source=coverage_index.connect()
    ranked=[dict(x) for x in source.execute("""SELECT binary_name,catalogued,decompiled,
        failed,unattempted,indexed_bodies FROM sources ORDER BY
        unattempted DESC,catalogued DESC LIMIT 14""")]
    completed_ai=cx.execute("""SELECT count(*) FROM jobs
            WHERE kind IN ('review','focus') AND status='done'""").fetchone()[0]
    focused=cx.execute("""SELECT count(*) FROM jobs
            WHERE kind='focus' AND status='done'""").fetchone()[0]
    # Total reviewed Ghidra functions are not equated to function bodies
    # indexed: only the small cited model excerpts count as reviewed.
    summaries=[]
    for row in cx.execute("""SELECT jobs.result_path FROM jobs WHERE
           status='done' AND kind IN ('review','focus') AND result_path IS NOT NULL"""):
        f=Path(row["result_path"])
        if not f.is_file():continue
        try:d=json.loads(f.read_text())
        except (ValueError,OSError):continue
        if d.get("kind")=="model_hypothesis_review":
            summaries.extend((d.get("source_sha256"),a) for a in d.get("examined_functions",[]))
    unique_reviewed=len(set(summaries))
    latest=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    total=sum(counts.values())
    done=sum(v for k,v in counts.items() if k.endswith("_done"))
    queued=sum(v for k,v in counts.items() if k.endswith("_queued"))
    running=sum(v for k,v in counts.items() if k.endswith("_running"))
    txt=[
      "# Toyota CA01 independent research — live generated status",
      f"Generated: {latest}",
      "",
      f"- Checkpointed jobs: **{done} done / {total} scheduled**, {queued} queued, {running} running.",
      f"- Indexed ELF inputs: **{overall['files_indexed']}**.",
      f"- Ghidra-discovered function candidates: **{overall['discovered_functions']}**, "
       f"decompiled: **{overall['decompiled_functions']}**, failed: "
       f"**{overall['failed_decompilations']}**, not attempted: "
       f"**{overall['not_attempted_functions']}**.",
      f"- Indexed searchable actual function bodies: **{overall['searchable_body_count']}**.",
      f"- AI review jobs completed: {completed_ai}; focused review batches completed: {focused}.",
      f"- Distinct exact source function addresses sent to the model: **{unique_reviewed}**.",
      f"- **Warning:** decompiled, indexed and AI-reviewed are different; none proves authentic original source reconstruction.",
      f"- Codex involvement: **none**; original firmware and repository were not modified by this research supervisor.",
      "",
      "## Tasks by kind/status",
      "",
      "| Type/status | Count |",
      "|---|---:|",
    ]
    txt.extend(f"| {k} | {v} |" for k,v in sorted(counts.items()))
    txt.extend(["","## Highest unattempted function counts","",
        "| Binary | Discovered | Decompiled | Not attempted | Failed | Searchable bodies |",
        "|---|---:|---:|---:|---:|---:|"])
    txt.extend(f"| {r['binary_name']} | {r['catalogued']} | {r['decompiled']} | "
       f"{r['unattempted']} | {r['failed']} | {r['indexed_bodies']} |" for r in ranked)
    txt.extend(["","## Currently running",""])
    txt.extend(f"- {r['kind']}: {r['archive_path']}" for r in pending)
    if not pending:txt.append("- Nothing is currently active.")
    txt.extend(["","## Failed jobs",""])
    txt.extend(f"- {r['key']}: {r['error']}" for r in errors)
    if not errors:txt.append("- No permanently failed jobs in the checkpoint database.")
    txt.extend(["","## Interpretation",
         "",
         "No full Toyota factory GUI has been rendered. Original proprietary driver implementations",
         "and menu assets remain missing. The known EXT3/eMMC layout clues do not",
         "amount to a recovered eMMC filesystem image.",
         "",
         "Research scripts run as separate, read-only userspace processes against",
         "SHA-256-verified archived binaries. The model's JSON observations are",
         "hypotheses, not validated original software behavior.",
         ""])
    temp=OUT.with_suffix(".md.tmp")
    temp.write_text("\n".join(txt))
    temp.replace(OUT)
    return dict(jobs_done=done,total_jobs=total,covered_functions=overall["decompiled_functions"],
                indexed_functions=overall["searchable_body_count"],model_seen=unique_reviewed,
                currently_running=pending,status_file=str(OUT))
if __name__=="__main__":
    print(json.dumps(execute(),indent=2))
