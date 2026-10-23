#!/usr/bin/env python3
"""Byte- and ELF-section-exact comparison of recovered 1127 and 1134 software.

Each matched original file is individually verified by the two provenance
manifests. Reading these binaries is safe; no code from the files executes.
"""
import hashlib,json,collections,itertools
from pathlib import Path
from elftools.elf.elffile import ELFFile
ROOT=Path("/home/starlight/projects/rav4-radio")
BASE=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023"
OLD=json.loads((ROOT/"system-audit/ca01-updater-independent-20261022/recovery-manifest.json").read_text())["files"]
NEW=json.loads((BASE/"recovered-1134-06-audio/recovered-manifest.json").read_text())
oldmap={x["archive_path"]:x for x in OLD if x["component"]=="06-audio.bin"}
newmap={x["archive_path"]:x for x in NEW}
report=[]
def sha(x):return hashlib.sha256(x).hexdigest()
for name,row in sorted(newmap.items()):
    older=oldmap[name]
    data1=Path(older["local_path"]).read_bytes()
    data2=Path(row["local_file"]).read_bytes()
    assert sha(data1)==older["sha256"] and sha(data2)==row["sha256"]
    assert len(data1)==older["size"] and len(data2)==row["size"]
    diff_count=sum(x!=y for x,y in zip(data1,data2))+abs(len(data1)-len(data2))
    changes=[i for i,(x,y) in enumerate(zip(data1,data2)) if x!=y]
    blocks=[]
    for _,ix in itertools.groupby(enumerate(changes), lambda z:z[1]-z[0]):
        v=[n for _,n in ix]
        blocks.append([v[0],v[-1]+1])
    result=dict(name=name,old_size=len(data1),new_size=len(data2),changed_bytes=diff_count,
                changed_fraction=round(diff_count/max(1,len(data1)),6),
                changed_runs=len(blocks),
                first_changed_offsets=blocks[:15],
                old_sha256=older["sha256"],new_sha256=row["sha256"])
    if data1.startswith(b"\x7fELF") and data2.startswith(b"\x7fELF"):
        with Path(older["local_path"]).open("rb") as f1,Path(row["local_file"]).open("rb") as f2:
            elf1,elf2=ELFFile(f1),ELFFile(f2)
            sections1={sec.name:sec for sec in elf1.iter_sections()}
            sections2={sec.name:sec for sec in elf2.iter_sections()}
            stats=[]
            for secname in sorted(set(sections1)|set(sections2)):
                s1,s2=sections1.get(secname),sections2.get(secname)
                if not s1 or not s2:continue
                if s1["sh_type"]=="SHT_NOBITS":continue
                try:b1,b2=s1.data(),s2.data()
                except Exception:continue
                same=b1==b2
                stats.append(dict(section=secname,old_bytes=len(b1),
                    new_bytes=len(b2),same=same,diff_bytes=sum(x!=y for x,y in zip(b1,b2))+abs(len(b1)-len(b2)),
                    old_offset=s1["sh_offset"],new_offset=s2["sh_offset"]))
            result["elf_sections"]=stats
            result["changed_sections"]=[x for x in stats if not x["same"]]
            result["text_identical"]=sections1.get(".text").data()==sections2.get(".text").data() if ".text" in sections1 and ".text" in sections2 else None
            result["plt_identical"]=sections1.get(".plt").data()==sections2.get(".plt").data() if ".plt" in sections1 and ".plt" in sections2 else None
    report.append(result)
    if diff_count:
        print(f'CHANGED {name:<43s} {len(data1)}->{len(data2)}, {diff_count:8d} mismatched bytes in {len(blocks):7d} runs, text_identical={result.get("text_identical")} sections={[(x["section"],x["diff_bytes"]) for x in result.get("changed_sections",[])]}',flush=True)
    else:
        print("UNCHANGED",name,flush=True)
out=dict(total=len(report),changed=sum(x["changed_bytes"]>0 for x in report),
         file_count_reconciled_with_1127=len(oldmap)==len(newmap),files=report)
assert out["total"]==len(oldmap)==47
(BASE/"elf-byte-diff.json").write_text(json.dumps(out,indent=2)+"\n")
print("DONE",out["total"],"changed",out["changed"])
