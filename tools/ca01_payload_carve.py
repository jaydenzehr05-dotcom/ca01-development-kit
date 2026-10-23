#!/usr/bin/env python3
"""Experimental, byte-preserving CA01 inner-payload carving from component files.

Hypothesis only: the little-endian field at byte 8 denotes a trailing payload
length. Output is a separate directory and never modifies source data.
"""
import argparse,hashlib,json,struct
from pathlib import Path
def sha(data):return hashlib.sha256(data).hexdigest()
def carve_component(path):
    data=path.read_bytes()
    if len(data)<12:raise ValueError("component too short")
    declared=struct.unpack_from("<I",data,8)[0]
    offset=len(data)-declared
    if declared==0 or offset<12 or offset>4096:
        raise ValueError(f"unexpected declared trailing length in {path.name}")
    return data[offset:],{"component":path.name,"component_size":len(data),
        "input_sha256":sha(data),"observed_prefix_bytes":offset,
        "inner_size":declared,"inner_sha256":sha(data[offset:]),
        "note":"Offset inferred from a length field, not independently decoded or validated."}
def run(components,output):
    if output.exists():raise FileExistsError("output directory must not exist")
    sources=sorted(components.glob("*.bin"))
    if not sources:raise ValueError("no component bins")
    decoded=[carve_component(f) for f in sources]
    output.mkdir(parents=True)
    manifest=[]
    for (payload,record),path in zip(decoded,sources):
        (output/(path.stem+".payload.bin")).write_bytes(payload)
        manifest.append(record)
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    return manifest
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("components",type=Path)
    p.add_argument("output",type=Path)
    a=p.parse_args()
    if not a.components.is_dir():p.error("components directory not found")
    for x in run(a.components,a.output):
        print(x["component"],"prefix",x["observed_prefix_bytes"],
              "payload",x["inner_size"])
if __name__=="__main__":main()
