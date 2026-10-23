#!/usr/bin/env python3
"""Bounded original Toyota ARM type.txt fallback; file OPEN always explicitly fails.

Executes real PROC_HMI instructions at 0x3ec98. Imported rq_fls_Open and memcpy
are explicit, fail-closed host boundaries. Neither original file library nor
the complete HMI runs. No fabricated success, assets, or file contents.
"""
from __future__ import annotations
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio")
TOOLS=ROOT/"ca01-development-kit/tools"
sys.path.insert(0,str(TOOLS))
from ca01_startup_trace import prepare,HMI_SHA256,SYSC_SHA256
from ca01_hmi_startup import ElfImage
from unicorn.arm_const import UC_ARM_REG_R1
HMI=ROOT/"system-audit/ca01-updater-independent-20261022/06-PROC_HMI"
SYSC=ROOT/"system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so"
OUT=Path(__file__).with_name("type-txt-original-arm-proof.json")
SCRATCH=0x70001000

def main():
    hmi=HMI.read_bytes()
    sysc=SYSC.read_bytes()
    assert hashlib.sha256(hmi).hexdigest()==HMI_SHA256
    assert hashlib.sha256(sysc).hexdigest()==SYSC_SHA256
    image=ElfImage(hmi)
    trace,unused=prepare(hmi,sysc)
    for seg in image.segments:
        if seg["p_flags"] & 1:
            trace.executable_ranges.append((seg["p_vaddr"],seg["p_vaddr"]+seg["p_memsz"]))
    trace.imports.update({
        sym["st_value"]:sym.name
        for sym in image.elf.get_section_by_name(".dynsym").iter_symbols()
        if sym["st_shndx"]=="SHN_UNDEF" and sym["st_value"]})
    seen=[]
    def file_open(uc,regs):
        def string(address):
            return bytes(uc.mem_read(address,128)).split(b"\x00")[0].decode("ascii")
        path,mode=string(regs[0]),string(regs[1])
        if path!="type.txt" or mode!="r":
            raise RuntimeError("Unexpected or unverified file opening "+repr((path,mode)))
        seen.append(dict(service="rq_fls_Open",path=path,mode=mode,result=1,
            meaning="Explicit nonzero open-failure fixture; NOT original library code"))
        return 1
    def guest_memcpy(uc,regs):
        dst,src,n=regs[:3]
        if dst!=SCRATCH or not 0<n<=32:
            raise RuntimeError(f"Refuse unexpected memcpy dest={dst:#x} bytes={n}")
        chunk=bytes(uc.mem_read(src,n))
        if chunk[:7]!=b"(none)\x00":
            raise RuntimeError("Recovered original fallback literal was not (none)")
        uc.mem_write(dst,chunk)
        seen.append(dict(service="memcpy",size=n,source=hex(src),
                         copied_first_7=chunk[:7].decode("ascii").rstrip("\x00")))
        return dst
    trace.services["rq_fls_Open"]=file_open
    trace.services["memcpy"]=guest_memcpy
    outputs=[]
    for length in (7,16):
        trace.uc.mem_write(SCRATCH,b"Z"*32)
        trace.uc.reg_write(UC_ARM_REG_R1,length)
        first=len(seen)
        run=trace.run(0x3ec98,SCRATCH,instruction_limit=9000,timeout_us=2000000)
        final=bytes(trace.uc.mem_read(SCRATCH,32))
        assert run["returned"],(length,run)
        assert final.startswith(b"(none)\x00"),repr(final)
        assert [x["service"] for x in seen[first:]]==["rq_fls_Open","memcpy"]
        assert not any(x["symbol"] in ("rq_fls_Read","rq_fls_Close") for x in run["service_calls"])
        outputs.append(dict(length=length,returned=True,output_prefix=repr(final[:length]),
                     path_failed=True,original_instruction_count=run["instructions"],
                     imported_services=seen[first:],
                     caveat="Original function, explicit failed file open and generic guest memcpy; not authentic file library"))
        print("PASS real ARM type.txt ENOENT-style fallback length",length,
              "instructions",run["instructions"])
    OUT.write_text(json.dumps(dict(hmi_sha256=HMI_SHA256,sysc_sha256=SYSC_SHA256,
          entry="0x3ec98",original_function_ran=True,file_service_genuine=False,
          input_file_exists=False,original_gui_rendered=False,results=outputs),indent=2)+"\n")
    print("PASS original-ARM file failure fallback",OUT)

if __name__=="__main__":
    main()
