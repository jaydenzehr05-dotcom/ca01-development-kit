#!/usr/bin/env python3
"""Conservatively reuse the already recovered UU.11.34 Ghidra result
for UU.11.27 PROC_HMI only when both original ELF .text sections are identical.
Does not modify either original executable, old exports or Git repository.
"""
import copy
import datetime as dt
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

HERE=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
sys.path.insert(0,str(HERE))
import coverage_index
OLD="cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503"
NEW="64f5d905a42aa844d60fcf2a3aed752ce5fd9df04e54a1a565d81b64307af62b"
ADDR="00186210"
OUT=HERE/"results"/OLD[:16]/"ghidra"/"verified-identical-executable-01"
POLICY=HERE/"version-preference-20261023.json"

def hash_file(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()

def section(path):
    lines=subprocess.run(["readelf","-W","-S",str(path)],
        check=True,capture_output=True,text=True).stdout
    row=re.search(r"\[\s*\d+\]\s+\.text\s+PROGBITS\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",lines)
    if row is None: raise ValueError(".text ELF section missing")
    addr,offset,length=[int(x,16) for x in row.groups()]
    with path.open("rb") as f:
        f.seek(offset)
        data=f.read(length)
    if len(data)!=length:raise ValueError("Truncated .text")
    return dict(address=addr,offset=offset,length=length,digest=hashlib.sha256(data).hexdigest())

def run():
    if not (HERE/"stop.flag").exists():raise RuntimeError("Stop the research supervisor before this one-time operation")
    if not Path("/mnt/c/Users/fathe/Documents/Codex/local-codex-worker/runtime/manual-off.flag").exists():
        raise RuntimeError("Operator's local-AI OFF was not detected")
    cx=sqlite3.connect(HERE/"progress.sqlite3",timeout=60)
    cx.row_factory=sqlite3.Row
    data={}
    for label,sha in [("old",OLD),("new",NEW)]:
        row=cx.execute("""SELECT i.path, i.archive_path, d.result_path FROM inputs AS i
              JOIN jobs AS d ON d.key='decompile:' || i.sha256
              WHERE i.sha256=? AND d.status='done'""",(sha,)).fetchone()
        if row is None:raise LookupError(label+" source not present")
        path=Path(row["path"])
        if hash_file(path)!=sha:raise RuntimeError(label+" whole input ELF SHA mismatch")
        result=Path(row["result_path"])
        manifest=json.loads((result/"manifest.json").read_text())
        if manifest["sha256"].lower()!=sha:raise RuntimeError(label+" manifest SHA mismatch")
        target=[x for x in manifest["functions"] if x["address"].lower()==ADDR]
        if len(target)!=1:raise RuntimeError(label+" function entry missing / non-unique")
        data[label]=dict(path=path,archive=row["archive_path"],result=result,manifest=manifest,
                         target=target[0],text=section(path),sha=sha)
    if data["old"]["target"]["status"]!="failed":raise RuntimeError("Old function is not failed; refusing duplicate")
    if data["new"]["target"]["status"]!="decompiled":raise RuntimeError("New function has not been Ghidra decompiled")
    if data["new"]["target"]["bytes"]!=data["old"]["target"]["bytes"]:
        raise RuntimeError("Function body byte counts differ")
    if data["new"]["target"]["memory_block"]!=".text" or data["old"]["target"]["memory_block"]!=".text":
        raise RuntimeError("Function is not in .text")
    comparison=[x for x in json.loads(POLICY.read_text())["comparisons"]
         if x["old_sha"]==OLD and x["new_sha"]==NEW and x["archive_path"]=="./opt/ftl/apl/PROC_HMI"]
    if len(comparison)!=1 or not comparison[0]["identical_text"]:
        raise RuntimeError("Version policy does not attest identical HMI executable text")
    if data["old"]["text"]["digest"]!=data["new"]["text"]["digest"] or \
       data["old"]["text"]["digest"]!=comparison[0]["old_text_sha"]:
        raise RuntimeError("Live original .text sections differ or no longer match stored provenance")
    if data["old"]["text"]["address"] != data["new"]["text"]["address"]:
        raise RuntimeError(".text load addresses differ")
    recovered=(data["new"]["result"]/"decompiled.c").read_text()
    marker="/* FUNCTION "+ADDR+" "
    start=recovered.find(marker)
    if start<0:raise RuntimeError("New-source C function body not found")
    end=recovered.find("/* FUNCTION ",start+len(marker))
    body=recovered[start:] if end<0 else recovered[start:end]
    if "FUN_"+ADDR+"(" not in body or len(body)<100:
        raise RuntimeError("C-like output invalid or incomplete")
    old=copy.deepcopy(data["old"]["manifest"])
    row=next(x for x in old["functions"] if x["address"].lower()==ADDR)
    row["status"]="decompiled"
    row.pop("error",None)
    row["calls"]=data["new"]["target"].get("calls",row.get("calls",[]))
    row["decompile_source"]="Ghidra_output_from_byte_identical_1134_PROC_HMI"
    old["decompiled"]+=1
    old["failed"]-=1
    old.setdefault("cross_version_equivalence",[]).append(dict(
        address=ADDR,original_sha256=OLD,donor_sha256=NEW,
        matching_text_sha256=data["old"]["text"]["digest"],
        function_bytes=row["bytes"],
        note="The old and new ARM executable .text bytes are identical; original decompiled function body produced by Ghidra on new version."))
    assert sum(1 for x in old["functions"] if x["status"]=="decompiled")==old["decompiled"]
    assert sum(1 for x in old["functions"] if x["status"]=="failed")==old["failed"]
    if OUT.exists():raise FileExistsError("Immutable output exists: "+str(OUT))
    OUT.mkdir(parents=True)
    source=(data["old"]["result"]/"decompiled.c").read_text()
    (OUT/"decompiled.c").write_text(source+
        "\n/* SAME-ARM-CODE CROSS-FIRMWARE VERIFIED SHA256: "+data["old"]["text"]["digest"]+" */\n"+body)
    (OUT/"manifest.json").write_text(json.dumps(old,indent=2)+"\n")
    with (OUT/"functions.tsv").open("w") as f:
        f.write("address\tname\tbytes\tstatus\n")
        for e in old["functions"]:
            f.write(f"{e['address']}\t{e['name']}\t{e['bytes']}\t{e['status']}\n")
    proof=dict(old_input_sha=OLD,new_input_sha=NEW,
        old_elf_text=data["old"]["text"],new_elf_text=data["new"]["text"],
        address=ADDR,function_bytes=row["bytes"],
        donor_genuine_ghidra_source_sha=hashlib.sha256(body.encode()).hexdigest(),
        old_manifest_sha=hash_file(data["old"]["result"]/"manifest.json"),
        new_manifest_sha=hash_file(data["new"]["result"]/"manifest.json"),
        original_firmware_modified=False,
        code_note="Relies on proven binary-equivalence of all .text including this function, not manual conjecture")
    (OUT/"transfer-proof.json").write_text(json.dumps(proof,indent=2)+"\n")
    cx.execute("UPDATE jobs SET result_path=? WHERE key=?",(str(OUT),"decompile:"+OLD))
    cx.commit()
    stats=coverage_index.index_binary(OLD,OUT,data["old"]["archive"])
    index=HERE/"results"/OLD[:16]/"function-index.json"
    index.write_text(json.dumps(stats,indent=2)+"\n")
    cx.execute("UPDATE jobs SET status='done',result_path=?,finished=? WHERE key=?",
               (str(index),dt.datetime.now(dt.timezone.utc).isoformat(),"index:"+OLD))
    cx.commit()
    print(json.dumps(dict(status="verified_equivalent_recovered",name="PROC_HMI",
           sha=OLD[:16],address=ADDR,new_failed=old["failed"],
           indexed=stats,output=str(OUT))),flush=True)
    cx.close()

if __name__=="__main__":run()
