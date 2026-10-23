#!/usr/bin/env python3
"""Inspect changing CA01 component wrappers and likely compressed suffix footers."""
import sys, json, hashlib, struct
from pathlib import Path
ROOT=Path("/home/starlight/projects/rav4-radio")
sys.path.insert(0,str(ROOT/"ca01-development-kit/tools"))
from ca01_inspect import inspect_bytes
from ca01_update_research import analyze_component
A=ROOT/"stock-firmware/15TBDANA-CA01_1127.kwi"
B=ROOT/"stock-firmware/15TBDANA-CA01_1134.kwi"
old=A.read_bytes();new=B.read_bytes()
oa=inspect_bytes(old);nb=inspect_bytes(new)
summary=[]
for o,n in zip(oa["components"],nb["components"]):
    bo=old[o["offset"]:o["offset"]+o["size"]]
    bn=new[n["offset"]:n["offset"]+n["size"]]
    prev=analyze_component(bo,o["offset"])
    curr=analyze_component(bn,n["offset"])
    print("COMPONENT",o["name"])
    for record,label in [(prev,"1127"),(curr,"1134")]:
        w=record["wrapper"]
        v=record["payload"]
        trailer=v["gzip_trailer_candidate"]
        print(label,"bytes",record["size"],"prefix",w["observed_prefix_size"],"fields",
              w["common_prefix_hex"],"flag",w["raw_u32_at_4"],
              "payload",v["size"],"payload_head",v["first_32_hex"][:24],
              "suffix",v["payload_sha256"] if "payload_sha256" in v else v["sha256"][:12])
        if trailer:print("  trailer candidate",trailer["candidate_gzip_crc32"],
              "ISIZE",trailer["candidate_gzip_isize"],"last256",trailer["following_opaque_sha256"][:16])
        if record["path_regions"]:
            print(" PATHS", [x["text"] for x in record["path_regions"]][:20])
    oldhead=bo[:prev["wrapper"]["observed_prefix_size"]]
    newhead=bn[:curr["wrapper"]["observed_prefix_size"]]
    v1=bo[prev["wrapper"]["observed_prefix_size"]:]
    v2=bn[curr["wrapper"]["observed_prefix_size"]:]
    x=min(len(v1),len(v2))
    matching_prefix=0
    while matching_prefix<x and v1[matching_prefix]==v2[matching_prefix]:matching_prefix+=1
    matching_suffix=0
    while matching_suffix<x and v1[-1-matching_suffix]==v2[-1-matching_suffix]:matching_suffix+=1
    print("  identical wrapper",oldhead==newhead,
          "identical first64K",v1[:65536]==v2[:65536],
          "equal gzip-tail-256",v1[-256:]==v2[-256:],
          "common prefix",matching_prefix,"suffix",matching_suffix,
          "suffix values",v1[-264:-256].hex(),v2[-264:-256].hex())
    summary.append(dict(component=o["name"],number=o["index"],
                        old_size=len(bo),new_size=len(bn),prefix_old=len(oldhead),prefix_new=len(newhead),
                        wrapper_equal=oldhead==newhead,
                        payload_first_64k_equal=v1[:65536]==v2[:65536],
                        bytes_common_prefix=matching_prefix,bytes_common_suffix=matching_suffix,
                        payload_trailer_last_256_equal=v1[-256:]==v2[-256:],
                        gzip_trailer_guess_1127=v1[-264:-256].hex(),
                        gzip_trailer_guess_1134=v2[-264:-256].hex(),
                        old_gzip_trailer=prev["payload"]["gzip_trailer_candidate"],
                        new_gzip_trailer=curr["payload"]["gzip_trailer_candidate"],
                        old_paths=[x["text"] for x in prev["path_regions"]],
                        new_paths=[x["text"] for x in curr["path_regions"]]))
(Path(__file__).with_name("wrapper-comparison.json")).write_text(json.dumps(summary,indent=2)+"\n")
