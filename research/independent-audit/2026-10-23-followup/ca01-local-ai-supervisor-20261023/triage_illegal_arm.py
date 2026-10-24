#!/usr/bin/env python3
"""Original-byte ARM/Thumb disassembly near two Ghidra illegal-pcode errors.

Neither decoder result is claimed to be correct by itself. Captures both
possibilities and full provenance to guide code/data/function-boundary review.
"""
from __future__ import annotations
import hashlib,json,struct,datetime as dt
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
HERE=Path(__file__).resolve().parent
ROOT=Path("/home/starlight/projects/rav4-radio")
cases=[
 ("PROC_DTV","1134",0x15790, ROOT/"system-audit/ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered/006a2a17-PROC_DTV",
  "1a526239fbe5b3b72d9fb871fed9db3523c76125522a9addf0a99f6281b5e115"),
 ("PROC_TMD","1134",0x19520, ROOT/"system-audit/ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered/0160d017-PROC_TMD",
  "28e8b7d000b0d764c3bdadb1f2ff0e28d16dbd6d64946967e527597d3ddd51c8")
]
results=[]
for name,version,address,path,sha in cases:
    raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==sha
    with path.open("rb") as handle:
        elf=ELFFile(handle)
        sections=[dict(name=s.name,addr=int(s["sh_addr"]),size=int(s["sh_size"]))
              for s in elf.iter_sections() if s.name in (".text",".plt")]
        maps=[]
        for segment in elf.iter_segments():
            if segment["p_type"]=="PT_LOAD":
                lo=int(segment["p_vaddr"]);sz=int(segment["p_filesz"]);off=int(segment["p_offset"])
                if lo<=address<lo+sz:
                    maps.append((off+address-lo,lo,sz,off))
        if not maps:raise ValueError("Function address was not in backed ELF LOAD segment "+name)
        offset=maps[0][0]
        section=next((x for x in sections if x["addr"]<=address<x["addr"]+x["size"]),None)
    code=raw[offset:offset+160]
    decoders=[]
    for mode,label in [(CS_MODE_ARM,"ARM"),(CS_MODE_THUMB,"Thumb")]:
        engine=Cs(CS_ARCH_ARM,mode|CS_MODE_LITTLE_ENDIAN)
        instructions=[]
        for ins in engine.disasm(code,address):
            instructions.append(dict(address=hex(ins.address),size=ins.size,
                  bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str))
            if len(instructions)>=24:break
        decoders.append(dict(mode=label,decoded_entries=len(instructions),
                             instructions=instructions))
    results.append(dict(name=name,version=version,entry=hex(address),elf_offset=hex(offset),
        original_elf_sha256=sha,section=section,file_bytes_160=code.hex(),
        decodings=decoders,
        note="Raw Capstone disassembly alternative; no automatic proof of Ghidra function-boundary correctness."))
report=dict(generated=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            cause_classification="Ghidra p-code/conditional-execution error, not original input checksum failure",
            cases=results)
out=HERE/"illegal-arm-function-triage-20261023.json"
out.write_text(json.dumps(report,indent=2)+"\n")
print("WROTE",out)
for item in results:
    print("CASE",item["name"],item["entry"],"ELF",item["elf_offset"])
    for mode in item["decodings"]:
        print(" ",mode["mode"],mode["decoded_entries"],
              [(i["mnemonic"],i["operands"]) for i in mode["instructions"][:8]])
