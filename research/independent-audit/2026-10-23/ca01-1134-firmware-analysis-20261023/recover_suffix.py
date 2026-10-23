#!/usr/bin/env python3
"""Recover ONLY individually verified complete files from 1134 DEFLATE suffix.

Compressed prefix/initial history stays UNKNOWN, no full archive/authenticity
claim. Original input never modified. Recovered bytes stay outside Git.
"""
import collections, hashlib, json, sys
from pathlib import Path
ROOT=Path("/home/starlight/projects/rav4-radio")
BASE=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023"
sys.path.insert(0,str(ROOT/"ca01-development-kit/tools"))
from ca01_experimental_decode import inspect,export_artifacts
OLD=json.loads((ROOT/"system-audit/ca01-updater-independent-20261022/recovery-manifest.json").read_text())["files"]
CHOICES={
    "07-gui":(67613,6,12),
    "06-audio":(65702,5,12),
    "08-voice-recognition":(67958,5,12),
    "02-middle-ware":(69312,2,524),
    "04-device-driver":(90137,7,12),
    "05-bluetooth":(101606,6,12),
}
def recover(name):
    first,bit,prefix=CHOICES[name]
    comp=BASE/"components-1134"/(name+".bin")
    dest=BASE/("recovered-1134-"+name)
    if dest.exists():raise FileExistsError(f"Do not overwrite existing artifact directory {dest}")
    result,report=inspect(comp,prefix,first,bit,32*1024*1024)
    export_artifacts(dest,result,report)
    records=report["fully_known_tar_entries"]
    oldname=name+".bin"
    old=[x for x in OLD if x["component"]==oldname]
    oldmap=collections.defaultdict(list)
    for x in old:oldmap[x["archive_path"]].append(x["sha256"])
    newnames=set()
    changes=[]
    for x in records:
        file=x["archive_path"]
        newnames.add(file)
        hashes=oldmap.get(file,[])
        changed=not (x["sha256"] in hashes)
        changes.append(dict(name=file,size=x["size"],sha256=x["sha256"],
                            status=("new_file" if not hashes else "changed" if changed else "identical_to_1127")))
    prevnames=set(oldmap)
    grouped=collections.Counter(x["status"] for x in changes)
    missing=sorted(prevnames-newnames)
    suspicious=[x for x in changes if any(k in x["name"].lower() for k in
                ["mc/","/font/",".mui",".mra","libipas_fls.so","libdismng_if.so","libdisplay_if.so","libsecurity.so"])]
    outcome=dict(input_name=name,input_sha256=report["input_sha256"],
             start_bit=first*8+bit,report_end=report["end_bit"],
             output_size=report["output_size"],known_bytes=report["known_bytes"],
             unknown_bytes=report["unknown_bytes"],
             all_tar_entries_count=len(records),
             classification_counts=dict(grouped),missing_previous_names=missing,
             files=changes,new_target_names=suspicious,
             note="Only individually checksum-valid and history-independent file bytes counted; not a complete recovered firmware filesystem")
    (BASE/(name+"-comparison.json")).write_text(json.dumps(outcome,indent=2)+"\n")
    print("RECOVERED",name,"suffix bytes",report["output_size"],
          "known",report["known_bytes"],"unknown",report["unknown_bytes"],
          "validated files",len(records),"classes",dict(grouped),"old missing",len(missing),flush=True)
    for x in changes:
        if x["status"]!="identical_to_1127":
            print("DIFFERENCE",x["status"],x["name"],"bytes",x["size"],"sha256",x["sha256"][:16],flush=True)
    if missing:
        for x in missing[:20]: print("OLD FILE NOT RECOVERED",x,flush=True)
    for x in suspicious:print("TARGET RESOURCE HIT",x["name"],flush=True)
if __name__=="__main__":
    for name in sys.argv[1:] or CHOICES:
        recover(name)
