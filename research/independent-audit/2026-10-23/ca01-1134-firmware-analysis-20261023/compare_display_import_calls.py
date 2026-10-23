#!/usr/bin/env python3
"""Read-only ARM32 branch-and-link imports/PLT callsite comparison for CA01.

Runs Capstone on ELF .text words, maps .rel.plt imports to 12-byte ARM PLT
stubs, and counts direct BL calls only. Does NOT establish dynamic calls,
callbacks, runtime reachability, or functional equivalence.
"""
import hashlib,json,collections,sys
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from capstone.arm import ARM_OP_IMM

ROOT=Path("/home/starlight/projects/rav4-radio")
WORK=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023"
OLD=ROOT/"system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY"
NEW=WORK/"recovered-1134-06-audio/recovered/01116817-PROC_DISPLAY"
old_manifest=json.loads((ROOT/"system-audit/ca01-updater-independent-20261022/recovery-manifest.json").read_text())["files"]
new_manifest=json.loads((WORK/"recovered-1134-06-audio/recovered-manifest.json").read_text())
oldhash=next(x["sha256"] for x in old_manifest if x["archive_path"]=="./opt/ftl/apl/PROC_DISPLAY")
newhash=next(x["sha256"] for x in new_manifest if x["archive_path"]=="./opt/ftl/apl/PROC_DISPLAY")
TARGET=("sysDisMng","rq_fls","fs_mpl","rq_tsk","rq_msg","rq_ipc","rq_sys",
        "uie","fs_sys","pthread","sys","Vcl","mra","mmp")
def inspect(path,expected):
    data=path.read_bytes()
    assert hashlib.sha256(data).hexdigest()==expected,("source mismatch",path)
    with path.open("rb") as f:
        elf=ELFFile(f)
        dynsym=elf.get_section_by_name(".dynsym")
        relplt=elf.get_section_by_name(".rel.plt")
        plt=elf.get_section_by_name(".plt")
        text=elf.get_section_by_name(".text")
        assert dynsym and relplt and plt and text
        n=len(list(relplt.iter_relocations()))
        assert plt["sh_size"]==0x14+n*12,(plt["sh_size"],n)
        names={}
        imports=collections.defaultdict(list)
        for i,r in enumerate(relplt.iter_relocations()):
            sym=dynsym.get_symbol(r["r_info_sym"]).name
            names[int(plt["sh_addr"])+0x14+i*12]=sym
        decoder=Cs(CS_ARCH_ARM,CS_MODE_ARM)
        decoder.detail=True
        found=0; bl_found=0
        code=text.data()
        vaddr=int(text["sh_addr"])
        for ins in decoder.disasm(code,vaddr):
            if ins.mnemonic not in ("bl","blx"):continue
            bl_found+=1
            if not ins.operands or ins.operands[0].type!=ARM_OP_IMM:continue
            dst=int(ins.operands[0].imm)
            symbol=names.get(dst)
            if symbol:
                imports[symbol].append(int(ins.address))
                found+=1
        return dict(file_sha256=expected,text_vaddr=hex(vaddr),text_size=len(code),
            plt_count=n,unique_imports_from_bl=len(imports),
            bl_instructions=bl_found,bl_to_import_stubs=found,
            imported_calls={name:[hex(x) for x in sorted(v)] for name,v in sorted(imports.items())},
            missing_plt_names=sorted(set(names.values())-set(imports)))
old=inspect(OLD,oldhash)
new=inspect(NEW,newhash)
rows=[]
for name in sorted(set(old["imported_calls"])|set(new["imported_calls"])):
    a=[int(x,16) for x in old["imported_calls"].get(name,[])]
    b=[int(x,16) for x in new["imported_calls"].get(name,[])]
    ro=dict(name=name,old_calls=len(a),new_calls=len(b),
           count_delta=len(b)-len(a),old_addresses=[hex(x) for x in a[:90]],
           new_addresses=[hex(x) for x in b[:90]],
           both_have_calls=bool(a and b),
           first_old=hex(a[0]) if a else None,first_new=hex(b[0]) if b else None)
    rows.append(ro)
focus=[x for x in rows if any(x["name"].startswith(k) or k.lower() in x["name"].lower() for k in TARGET)]
unmatched=[x for x in focus if x["count_delta"]!=0 or x["both_have_calls"]==False]
out=dict(method="Capstone ARM .text direct BL/BLX immediate to known ARM PLT slots",
         limitations=["Not a function-level equivalence proof; direct import callsite counts only.",
                      "Code interspersed with data or Thumb may be misinterpreted as ARM.",
                      "Indirect calls through GOT, callbacks and non-PLT branches not captured.",
                      "Display binary requires absent system libraries; this does not execute it."],
         older={k:v for k,v in old.items() if k!="imported_calls"},
         newer={k:v for k,v in new.items() if k!="imported_calls"},
         changed_import_call_counts=[x for x in rows if x["count_delta"]!=0],
         relevant_import_calls=focus,
         changed_relevant_call_counts=unmatched)
dest=WORK/"display-import-callsite-diff.json"
dest.write_text(json.dumps(out,indent=2)+"\n")
print("Old/new direct BL-to-PLT",old["bl_to_import_stubs"],new["bl_to_import_stubs"],flush=True)
print("Known ELF import callsite names",old["unique_imports_from_bl"],new["unique_imports_from_bl"],flush=True)
print("Relevant",len(focus),"changed count",len(unmatched),flush=True)
for x in focus:
    if x["name"].startswith(("sysDisMng","rq_fls","fs_mpl","rq_tsk","rq_msg","rq_sys")):
       print(f'{x["name"]:44s} {x["old_calls"]:4d} -> {x["new_calls"]:4d} old_first={x["first_old"]} new_first={x["first_new"]}',flush=True)
print("Saved",dest)
