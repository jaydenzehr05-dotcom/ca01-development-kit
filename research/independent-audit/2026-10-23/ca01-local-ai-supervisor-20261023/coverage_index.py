#!/usr/bin/env python3
"""Indexed, hash-bound function-level evidence for recovered CA01 ARM binaries.

Every entry is a Ghidra *candidate* not original source. Stores ALL discovered
entries, including failed and unattempted, to prevent false "finished" claims.
Indexes bounded source bodies for FTS search and prioritized local-only review.
No Codex tools, firmware execution, Git operations or hardware access.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import re
import sqlite3
from pathlib import Path

HERE=Path(__file__).resolve().parent
DB=HERE/"function_coverage.sqlite3"
PATTERN=re.compile(r"/[*] FUNCTION ([0-9a-fA-F]+) +([A-Za-z0-9_.$-]+) +bytes=([0-9]+) [*]/")
TAGS={
  "missing_resources":(195,(r"/opt/ftl/gui",r"\.mra\b",r"\.mui\b",r"screenTrans",r"\/font\/",r"opening\.mra",r"\/MC\/")),
  "filesystem":(155,(r"mmcblk",r"mkfs\.ext",r"\bext[234]\b",r"\bfstab\b",r"\brootfs\b",r"\/proc\/mtd",r"\bmount\(",r"\/var\/verup",r"\/mnt\/usb")),
  "missing_libs":(210,(r"libipas_fls",r"libdismng_if",r"libdisplay_if",r"fs_mpl_Create",r"rq_fls_Open",r"sysDisMngInit")),
  "graphics":(160,(r"eglSwapBuffers",r"eglCreate",r"OpenVG",r"vgDraw",r"glDraw",r"glClear",r"sysDisMng",r"vram",r"framebuffer",r"shader")),
  "startup_ipc":(130,(r"rq_tsk_WaitInit",r"ipasz\.conf",r"pthread_self",r"rq_msg_Send",r"rq_tsk_Create",r"SysPowerOn",r"rq_tsk_BlockBegin")),
  "update_recovery":(92,(r"13PFBACKUPDB",r"\.kwi",r"\btar\s+zx",r"\bcrc32\b",r"\bsignature\b",r"FlashImage",r"\bupdater\b")),
  "paths":(38,(r"/opt/ftl/",r"/dev/",r"/etc/",r"\.conf\b",r"\bopen\(",r"\bread\(")),
}
COMPILED={tag:[re.compile(p,re.IGNORECASE) for p in patterns] for tag,(_,patterns) in TAGS.items()}
PREVIEW_CAP=21000
CANDIDATES_PER_BIN=16
FOCUS_BATCH_SIZE=2

def utc():return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
def norm(s):return (str(s).lower().replace("0x","").lstrip("0") or "0")
def connect():
    cx=sqlite3.connect(DB,timeout=35)
    cx.row_factory=sqlite3.Row
    cx.execute("PRAGMA journal_mode=WAL")
    cx.executescript("""
    CREATE TABLE IF NOT EXISTS sources(
      sha256 TEXT PRIMARY KEY, binary_name TEXT NOT NULL,
      source_file TEXT NOT NULL, source_sha256 TEXT NOT NULL,
      manifest_file TEXT NOT NULL, indexed_at TEXT,
      catalogued INTEGER, decompiled INTEGER, failed INTEGER, unattempted INTEGER,
      indexed_bodies INTEGER, index_version INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS functions(
      sha256 TEXT NOT NULL, address TEXT NOT NULL, name TEXT,
      status TEXT, class TEXT, score INTEGER NOT NULL,
      tags TEXT NOT NULL, calls_count INTEGER,
      body_start INTEGER, body_end INTEGER, body_sha256 TEXT,
      PRIMARY KEY(sha256,address));
    CREATE INDEX IF NOT EXISTS by_score ON functions(sha256,status,score DESC,address);
    CREATE VIRTUAL TABLE IF NOT EXISTS function_fts USING fts5(
      sha UNINDEXED, address UNINDEXED, excerpt, tokenize='unicode61');
    """)
    return cx

def classify(info):
    block=str(info.get("memory_block",""))
    return str(info.get("classification") or (("import_thunk" if block==".plt" else
        "text_body" if block==".text" else "other_executable")))

def priority(body,name,calls):
    evidence=body+"\n"+name+"\n"+" ".join(calls)
    matched=[]
    score=0
    for tag,(weight,_) in TAGS.items():
        patterns=COMPILED[tag]
        count=sum(min(3,len(p.findall(evidence))) for p in patterns)
        if count:
            matched.append(tag)
            score+=weight+min(85, count*6)
    if name.startswith(("main","SysPowerOn","FUN_000400c4")):score+=45
    if body.count("case ")>=3:score+=4
    return score,matched

def index_binary(sha, source_folder, binary_name):
    source_folder=Path(source_folder).resolve(strict=True)
    manifest_file=source_folder/"manifest.json"
    source_file=source_folder/"decompiled.c"
    manifest=json.loads(manifest_file.read_text())
    if manifest.get("sha256","").lower()!=sha:raise ValueError("Manifest SHA != indexed source SHA")
    raw=source_file.read_text(encoding="utf-8",errors="replace")
    source_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest()
    anchors=list(PATTERN.finditer(raw))
    bodies={}
    for i,m in enumerate(anchors):
        start=m.start()
        end=anchors[i+1].start() if i+1<len(anchors) else len(raw)
        addr=norm(m.group(1))
        if addr in bodies:raise ValueError("Duplicate function address "+addr)
        bodies[addr]=(start,end)
    cx=connect()
    previous=cx.execute("SELECT source_sha256,index_version FROM sources WHERE sha256=?",(sha,)).fetchone()
    if previous and previous["source_sha256"]==source_hash and previous["index_version"]==2:
        info=dict(cx.execute("SELECT count(*) as n FROM functions WHERE sha256=?",(sha,)).fetchone())
        return dict(skipped=True,entries=info["n"],binary=binary_name)
    cx.execute("BEGIN IMMEDIATE")
    try:
        cx.execute("DELETE FROM function_fts WHERE sha=?",(sha,))
        cx.execute("DELETE FROM functions WHERE sha256=?",(sha,))
        rows=[]
        ftrows=[]
        n=0
        for info in manifest.get("functions",[]):
            addr=norm(info["address"])
            status=info.get("status","unknown")
            clas=classify(info)
            region=bodies.get(addr)
            if region and clas=="text_body" and status=="decompiled":
                body=raw[region[0]:region[1]]
                score,tags=priority(body,info.get("name",""),info.get("calls",[]))
                # Store enough text for targeted FTS; original full body stays unmodified.
                excerpt=body[:PREVIEW_CAP]
                ftrows.append((sha,addr,excerpt))
                n+=1
                digest=hashlib.sha256(body.encode("utf-8")).hexdigest()
            else:
                region=None
                score,tags=0,[]
                digest=None
            rows.append((sha,addr,info.get("name",""),status,clas,score,
                json.dumps(tags),len(info.get("calls",[])),
                region[0] if region else None,region[1] if region else None,digest))
        cx.executemany("""INSERT INTO functions
          (sha256,address,name,status,class,score,tags,calls_count,body_start,body_end,body_sha256)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)""",rows)
        cx.executemany("INSERT INTO function_fts(sha,address,excerpt) VALUES(?,?,?)",ftrows)
        cx.execute("""INSERT INTO sources(sha256,binary_name,source_file,source_sha256,
             manifest_file,indexed_at,catalogued,decompiled,failed,unattempted,indexed_bodies,index_version)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,2)
             ON CONFLICT(sha256) DO UPDATE SET
             binary_name=excluded.binary_name,source_file=excluded.source_file,
             source_sha256=excluded.source_sha256,manifest_file=excluded.manifest_file,
             indexed_at=excluded.indexed_at,catalogued=excluded.catalogued,
             decompiled=excluded.decompiled,failed=excluded.failed,
             unattempted=excluded.unattempted,indexed_bodies=excluded.indexed_bodies,
             index_version=2""",
             (sha,binary_name,str(source_file),source_hash,str(manifest_file),utc(),
              manifest.get("functions_catalogued",len(rows)),
              manifest.get("decompiled",0),manifest.get("failed",0),
              manifest.get("not_attempted",0),n))
        cx.commit()
    except:
        cx.rollback()
        raise
    count=len(rows)
    return dict(skipped=False,entries=count,source_bodies_indexed=n,
                not_attempted=manifest.get("not_attempted",0),failed=manifest.get("failed",0),
                binary=binary_name)

def candidates(sha,limit=CANDIDATES_PER_BIN,exclude=None):
    cx=connect()
    omit={norm(x) for x in (exclude or [])}
    results=cx.execute("""SELECT address,name,score,tags FROM functions
                         WHERE sha256=? AND status='decompiled' AND class='text_body'
                           AND body_start IS NOT NULL
                         ORDER BY score DESC,address ASC""",(sha,)).fetchall()
    return [dict(x) for x in results if x["address"] not in omit][:limit]

def get_excerpts(sha,addresses,budget_chars=6000):
    cx=connect()
    info=cx.execute("SELECT source_file,source_sha256 FROM sources WHERE sha256=?",(sha,)).fetchone()
    if not info:raise FileNotFoundError("Missing indexed decompilation "+sha)
    raw=Path(info["source_file"]).read_text(encoding="utf-8",errors="replace")
    if hashlib.sha256(raw.encode("utf-8")).hexdigest()!=info["source_sha256"]:
        raise RuntimeError("Decompiled C hash changed after index")
    selected=[]
    used=0
    for addr in addresses:
        f=cx.execute("""SELECT * FROM functions WHERE sha256=? AND address=?""",(sha,norm(addr))).fetchone()
        if not f or f["status"]!="decompiled" or f["class"]!="text_body" or f["body_start"] is None:
            raise ValueError("Not a validated decompiled function "+str(addr))
        full=raw[f["body_start"]:f["body_end"]]
        if hashlib.sha256(full.encode("utf-8")).hexdigest()!=f["body_sha256"]:
            raise RuntimeError("Function contents changed after indexing")
        # Useful context around high-value tokens, while maintaining exact source snippets.
        budget=min(2400,budget_chars-used)
        if budget<300:break
        chosen=full[:budget]
        if len(full)>budget:
            first_hit=None
            for _,exprs in COMPILED.items():
                for pattern in exprs:
                    m=pattern.search(full)
                    if m and m.start()>budget:
                        first_hit=m.start();break
                if first_hit is not None:break
            if first_hit is not None:
                half=budget//2
                chosen=full[:half]+"\n/* EARLIER CODE OMITTED FOR CONTEXT */\n"+full[max(first_hit-120,half):max(first_hit-120,half)+half]
        selected.append(dict(address=f["address"].zfill(8),name=f["name"],source=chosen,
                             full_body_sha256=f["body_sha256"],score=f["score"],
                             tags=json.loads(f["tags"])))
        used+=len(chosen)
    return selected

def status():
    cx=connect()
    rows=cx.execute("SELECT * FROM sources ORDER BY indexed_at").fetchall()
    sums=dict(files_indexed=len(rows),
      discovered_functions=sum(r["catalogued"] for r in rows),
      decompiled_functions=sum(r["decompiled"] for r in rows),
      failed_decompilations=sum(r["failed"] for r in rows),
      not_attempted_functions=sum(r["unattempted"] for r in rows),
      searchable_body_count=sum(r["indexed_bodies"] for r in rows))
    return sums

def search(query,limit=15):
    cx=connect()
    rows=cx.execute("""SELECT s.binary_name AS binary,f.address,f.name,
       f.score,s.sha256 FROM function_fts ft
       JOIN functions f ON f.sha256=ft.sha AND f.address=ft.address
       JOIN sources s ON s.sha256=f.sha256
       WHERE function_fts MATCH ?
       ORDER BY f.score DESC LIMIT ?""",(query,limit)).fetchall()
    return [dict(x) for x in rows]

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("command",choices=["status","index","search"])
    p.add_argument("--sha")
    p.add_argument("--source")
    p.add_argument("--binary")
    p.add_argument("--query")
    a=p.parse_args()
    if a.command=="status":print(json.dumps(status(),indent=2))
    if a.command=="index":print(json.dumps(index_binary(a.sha,a.source,a.binary),indent=2))
    if a.command=="search":print(json.dumps(search(a.query),indent=2))
