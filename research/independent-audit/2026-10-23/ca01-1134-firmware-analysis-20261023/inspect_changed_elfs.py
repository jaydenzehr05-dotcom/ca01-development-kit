#!/usr/bin/env python3
"""Structured comparison of CA01 HMI/DISPLAY and source import dependencies."""
import hashlib,json,re,collections
from pathlib import Path
from elftools.elf.elffile import ELFFile
ROOT=Path("/home/starlight/projects/rav4-radio")
BASE=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023"
old=json.loads((ROOT/"system-audit/ca01-updater-independent-20261022/recovery-manifest.json").read_text())["files"]
new=json.loads((BASE/"recovered-1134-06-audio/recovered-manifest.json").read_text())
M1={x["archive_path"]:Path(x["local_path"]) for x in old if x["component"]=="06-audio.bin"}
M2={x["archive_path"]:Path(x["local_file"]) for x in new}
interesting_names=("PROC_HMI","PROC_DISPLAY","PROC_SYSTEM","PROC_REPRO","PROC_VRS")
def extract(path):
    with path.open("rb") as fp:
        elf=ELFFile(fp)
        dyn=elf.get_section_by_name(".dynamic")
        needed=[t.needed for t in dyn.iter_tags() if t.entry.d_tag=="DT_NEEDED"] if dyn else []
        syms=elf.get_section_by_name(".dynsym")
        undef=sorted(set(x.name for x in syms.iter_symbols() if x["st_shndx"]=="SHN_UNDEF" and x.name)) if syms else []
        defined=sorted(set(x.name for x in syms.iter_symbols() if x["st_shndx"]!="SHN_UNDEF" and x.name)) if syms else []
        sections={}
        for n in (".text",".rodata",".data",".dynsym",".dynamic",".ARM.exidx",".plt"):
            sec=elf.get_section_by_name(n)
            if sec:
                data=sec.data()
                sections[n]=dict(offset=sec["sh_offset"],virtual_address=sec["sh_addr"],
                                 size=sec["sh_size"],sha256=hashlib.sha256(data).hexdigest())
        entire=path.read_bytes()
        strings=set(x.decode("ascii","replace") for x in re.findall(rb"[ -~]{7,}",entire))
        return dict(path=str(path),entry=elf.header["e_entry"],machine=str(elf.header["e_machine"]),
                    sha256=hashlib.sha256(entire).hexdigest(),size=len(entire),
                    needed=needed,import_symbols=undef,defined_symbols=defined,
                    sections=sections,strings=strings)
report=[]
for n in interesting_names:
    target=f"./opt/ftl/apl/{n}"
    a=extract(M1[target])
    b=extract(M2[target])
    newneed=sorted(set(b["needed"])-set(a["needed"]))
    gone=sorted(set(a["needed"])-set(b["needed"]))
    added=sorted(set(b["import_symbols"])-set(a["import_symbols"]))
    removed=sorted(set(a["import_symbols"])-set(b["import_symbols"]))
    nstrings=sorted(b["strings"]-a["strings"])
    ostrings=sorted(a["strings"]-b["strings"])
    atext=a["sections"].get(".text",{})
    btext=b["sections"].get(".text",{})
    result=dict(executable=n,
          old_sha256=a["sha256"],new_sha256=b["sha256"],
          entry_unchanged=a["entry"]==b["entry"],
          old_entry=hex(a["entry"]),new_entry=hex(b["entry"]),
          old_needed=a["needed"],new_needed=b["needed"],
          added_dependencies=newneed,removed_dependencies=gone,
          added_import_symbols=added,removed_import_symbols=removed,
          new_defined_symbols=sorted(set(b["defined_symbols"])-set(a["defined_symbols"])),
          removed_defined_symbols=sorted(set(a["defined_symbols"])-set(b["defined_symbols"])),
          old_sections=a["sections"],new_sections=b["sections"],
          text_sha_identical=atext.get("sha256")==btext.get("sha256"),
          old_str_count=len(a["strings"]),new_str_count=len(b["strings"]),
          new_strings_count=len(nstrings),removed_strings_count=len(ostrings),
          new_strings=nstrings[:800],removed_strings=ostrings[:800],
          target_new_strings=[x for x in nstrings if any(t in x.lower() for t in
                            ("gui","opt/ftl","sysdismng","mra",".mui","font","vg","texture","display"))][:120])
    report.append(result)
    print(n,"text unchanged",result["text_sha_identical"],"old/new strings",len(a["strings"]),len(b["strings"]),
          "new imports",len(added),"removed imports",len(removed),
          "added needed",newneed,"gone needed",gone,flush=True)
    print("  NEW IMPORTS",added[:70],"REMOVED",removed[:70])
    print("  NEW TARGET STRINGS",result["target_new_strings"][:50])
    print("  ELF SEC .text",atext.get("size"),btext.get("size"))
    # For HMI/version-only changes, emit exact byte offsets and nearby textual context.
    if n=="PROC_HMI":
        da,db=M1[target].read_bytes(),M2[target].read_bytes()
        offsets=[i for i,(x,y) in enumerate(zip(da,db)) if x!=y]
        print("  HMI BYTE DIFF",[(hex(i),da[i],db[i],
            repr(da[max(i-12,0):i+12]),repr(db[max(i-12,0):i+12])) for i in offsets],flush=True)
        result["exact_byte_differences"]=dict(offsets=[hex(i) for i in offsets],
              old=[da[i] for i in offsets],new=[db[i] for i in offsets])
(BASE/"key-elf-differences.json").write_text(json.dumps(report,indent=2)+"\n")
