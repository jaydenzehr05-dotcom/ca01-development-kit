#!/usr/bin/env python3
"""Read-only, hash-verified GUI resource inventory of locally recovered CA01.

Distinguishes strings/reference paths from actual matching resource files.
Does not assume an OSS package provides original proprietary GUI assets.
"""
from __future__ import annotations
import collections
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio")
INPUT=ROOT/"system-audit/ca01-updater-independent-20261022"
MANIFEST=INPUT/"recovery-manifest.json"
OUTPUT=Path(__file__).with_name("asset-inventory.json")
record=json.loads(MANIFEST.read_text())
files=record["files"]
expected_names=("MC/","/font/","ScreenTrans.mui","allwords_na.xml",
                "libdisplay_if.so","libdismng_if.so")
bytes_markers={
    "png":bytes.fromhex("89504e470d0a1a0a"),
    "jpeg":bytes.fromhex("ffd8ffe0"),
    "gif87a":b"GIF87a",
    "gif89a":b"GIF89a",
    "truetype":b"\x00\x01\x00\x00",
    "otf":b"OTTO",
    "webp":b"RIFF",
}
result=dict(scope="59 hash-checked recovered CA01 entries, limited related source archive names; not a full proprietary system image",
    references={}, files_checked=0,mismatches=[],resource_paths=[],
    unique_gui_files=[],interesting_embedded_signatures=[],
    repo_other_assets=[],archives={},
    limitation="KWI extraction is partial; lack of a recovered path is not proof that original radio lacks it.")
for f in files:
    local=Path(f["local_path"])
    if not local.is_file():
        result["mismatches"].append(dict(file=str(local),issue="not found"))
        continue
    data=local.read_bytes()
    h=hashlib.sha256(data).hexdigest()
    if h!=f["sha256"]:
        result["mismatches"].append(dict(file=str(local),issue="sha256 mismatch"))
        continue
    result["files_checked"]+=1
    name=f["archive_path"]
    low_name=name.lower()
    if "/opt/ftl/gui/" in low_name:
        result["resource_paths"].append(name)
        result["unique_gui_files"].append((name,h))
    if local.name.endswith("-PROC_HMI"):
        strings=[]
        for s in expected_names:
            found=[]
            at=data.find(s.encode())
            while at>=0 and len(found)<6:
                found.append(dict(file_offset=hex(at),context=data[max(at-80,0):at+100]
                   .split(b"\x00")[0].decode("latin1","replace")))
                at=data.find(s.encode(),at+len(s))
            if found:strings.append(dict(term=s,occurrences=found))
        result["references"]["PROC_HMI"]=strings
    # We scan magic signatures as candidates, NOT validated image/font assets.
    if local.name.endswith("-PROC_HMI") or name.endswith("07-gui.bin"):
        candidates=[]
        for kind,magic in bytes_markers.items():
            if kind in ("truetype","webp"):
                continue  # common false positives from ARM binary code/data
            offsets=[]; at=data.find(magic)
            while at>=0 and len(offsets)<8:
                offsets.append(hex(at));at=data.find(magic,at+len(magic))
            if offsets:candidates.append(dict(kind=kind,offsets=offsets))
        if candidates:result["interesting_embedded_signatures"].append(dict(file=name,signatures=candidates))
if result["mismatches"]:
    raise RuntimeError(f"Recovered-file integrity failed: {result['mismatches'][:3]}")
gui=sorted(set(result["unique_gui_files"]))
result["unique_gui_files"]=[{"path":n,"sha256":h} for n,h in gui]
assert result["files_checked"]==59,(result["files_checked"],"Expected 59 recoveries")
# Actual compressed GUI component is NOT in the recovered-file manifest.
gui_data=(ROOT/"stock-firmware/components/07-gui.bin").read_bytes()
result["raw_gui_component"]={
    "bytes":len(gui_data),
    "sha256":hashlib.sha256(gui_data).hexdigest(),
    "target_resource_names_found":{s: (s.encode() in gui_data) for s in expected_names},
    "tar_ustar_header_signature_count":gui_data.count(b"ustar"),
    "note":"This is a compressed/encrypted(?) vendor component. Negative raw string scan does not imply absent compressed content."
}
archives=[
    ROOT/"related-firmware/DENSO_TEN_17_OSS_SOFT_PACK.zip",
    ROOT/"vendor-source/OSS_SOFT_PACK.tgz",
    ROOT/"vendor-source/20130619_LE2355.tgz",
]
for archive in archives:
    matched=[]
    members=0
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            iterator=z.namelist()
            for name in iterator:
                members+=1
                low=name.lower()
                if any(q in low for q in
                       ("/opt/ftl/gui/","screentrans.mui",
                        "libdisplay_if.so","libdismng_if.so")):
                    matched.append(name)
    else:
        with tarfile.open(archive,"r:gz") as t:
            for member in t:
                members+=1
                low=member.name.lower()
                if any(q in low for q in
                       ("/opt/ftl/gui/","screentrans.mui",
                        "libdisplay_if.so","libdismng_if.so")):
                    if len(matched)<100:matched.append(member.name)
    result["archives"][archive.name]=dict(member_count=members,
        target_name_matches=matched,
        limitation="Source archive names only; source is not established as CA01 proprietary files")
OUTPUT.write_text(json.dumps(result,indent=2)+"\n")
print("Verified",result["files_checked"],"recovered CA01 file hashes")
print("GUI paths",len(result["resource_paths"]),"unique",len(gui))
for name in sorted(set(result["resource_paths"])):print(" ",name)
print("HMI target references:",{row["term"]:len(row["occurrences"]) for row in result["references"]["PROC_HMI"]})
for name,entry in result["archives"].items():
    print("Related",name,"members",entry["member_count"],"target filenames",len(entry["target_name_matches"]))
print("PASS saved",OUTPUT)
