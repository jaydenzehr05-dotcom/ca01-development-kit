#!/usr/bin/env python3
"""Hash-gated CA01 release preference: newest code first, retain all old artifacts.

Only suppresses *queued* repetitive work on old ELF versions with byte-identical
.text to UU.11.34. Does not remove source files, functions, reviews or exports.
Keeps older code with genuinely changed .text (DISPLAY/VRS) in scope.
"""
from __future__ import annotations
import datetime as dt
import fcntl
import hashlib
import json
import sqlite3
from pathlib import Path
from elftools.elf.elffile import ELFFile

HERE=Path(__file__).resolve().parent
ROOT=Path("/home/starlight/projects/rav4-radio")
DB=HERE/"progress.sqlite3"
STOP=HERE/"stop.flag"
LOCK=HERE/"supervisor.lock"
REASON="Old ELF executable code exactly matches newer UU.11.34 .text; preserve prior source/exports, prefer newer."

def digest(path,expected,size):
    p=Path(path).resolve(strict=True)
    if not p.is_relative_to(ROOT/"system-audit"):
        raise ValueError("ELF path outside recovered evidence")
    if p.stat().st_size!=size:raise RuntimeError("Original ELF size mismatch "+str(p))
    h=hashlib.sha256()
    with p.open("rb") as stream:
        for b in iter(lambda:stream.read(1048576),b""):h.update(b)
    if h.hexdigest()!=expected:raise RuntimeError("Original ELF SHA mismatch "+str(p))
    with p.open("rb") as stream:
        section=ELFFile(stream).get_section_by_name(".text")
        if section is None:raise RuntimeError("ELF has no .text "+str(p))
        body=section.data()
    return hashlib.sha256(body).hexdigest(),len(body)

def comparisons(cx):
    records=[dict(x) for x in cx.execute(
       "SELECT sha256,path,bytes,archive_path,version,elf FROM inputs WHERE elf=1")]
    groups={}
    for record in records:
        if record["version"] not in ("1127","1134"):continue
        groups.setdefault(record["archive_path"],{})[record["version"]]=record
    compared=[]
    for name,versions in sorted(groups.items()):
        if "1127" not in versions or "1134" not in versions:continue
        old,new=versions["1127"],versions["1134"]
        oh,olen=digest(old["path"],old["sha256"],old["bytes"])
        nh,nlen=digest(new["path"],new["sha256"],new["bytes"])
        compared.append(dict(
            archive_path=name,old_sha=old["sha256"],new_sha=new["sha256"],
            old_text_sha=oh,new_text_sha=nh,old_text_bytes=olen,
            new_text_bytes=nlen,identical_text=oh==nh,reason=REASON if oh==nh else
            "Executable code differs; retain both versions for analysis."))
    return compared

def apply(cx,*,dry_run=False):
    plans=comparisons(cx)
    actions=[]
    for p in plans:
        if not p["identical_text"]:continue
        old=p["old_sha"]
        rows=list(cx.execute("""SELECT key,kind,status FROM jobs WHERE sha256=?
                   AND status='queued' AND kind IN ('decompile','focus','review','resume','index')
                   ORDER BY key""",(old,)))
        for row in rows:
            actions.append(dict(key=row["key"],sha=old,new_sha=p["new_sha"],
                kind=row["kind"],prior_status=row["status"],status="skipped_identical_text"))
    if not dry_run:
        for a in actions:
            cx.execute("""UPDATE jobs SET status='skipped_identical_text',
                      finished=?,error=?
                      WHERE key=? AND status='queued'""",
                (dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                REASON+" Newer SHA: "+a["new_sha"][:16],a["key"]))
        cx.commit()
    result=dict(
        timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        archive_policy="NO DELETE; no Ghidra output, ELF, original file, or prior review is altered",
        release_primary="UU.11.34",
        comparisons=plans,
        identical_code_pairs=sum(p["identical_text"] for p in plans),
        different_code_pairs=[p["archive_path"] for p in plans if not p["identical_text"]],
        queued_work_skipped=actions,
        would_skip=len(actions),dry_run=dry_run)
    return result

def main():
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--apply",action="store_true")
    ap.add_argument("--lock-already-held",action="store_true")
    args=ap.parse_args()
    cx=sqlite3.connect(DB,timeout=30)
    cx.row_factory=sqlite3.Row
    if args.apply and not args.lock_already_held:
        with LOCK.open("a+") as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            report=apply(cx,dry_run=False)
    else:
        report=apply(cx,dry_run=not args.apply)
    if args.apply:
        out=HERE/"version-preference-20261023.json"
        if out.is_file():
            old=out.with_suffix(".json.previous")
            if not old.is_file():old.write_bytes(out.read_bytes())
        tmp=out.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(report,indent=2)+"\n")
        tmp.replace(out)
        print("SAVED",out)
    print(json.dumps({
       "release_primary":report["release_primary"],
       "identical_code_pairs":report["identical_code_pairs"],
       "different_code_pairs":report["different_code_pairs"],
       "jobs_skipped":len(report["queued_work_skipped"]),
       "names_skipped":sorted(set(a["key"].split(":")[0]+":"+next(
          x["archive_path"].split("/")[-1] for x in report["comparisons"] if x["old_sha"]==a["sha"])
          for a in report["queued_work_skipped"]))},indent=2))

if __name__=="__main__":
    main()
