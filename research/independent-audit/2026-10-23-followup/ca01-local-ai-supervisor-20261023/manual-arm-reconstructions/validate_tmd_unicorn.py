#!/usr/bin/env python3
"""Emulate byte-verified original ARM PROC_TMD function with stubbed external
calls, then compare state and call arguments to host-compiled manual C.
Offline unit-test harness; no vehicle, local AI or Codex access.
"""
import ctypes as C
import hashlib
import json
import os
import re
import struct
import subprocess
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP

ROOT=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023")
ELF=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered/0076e2b3-PROC_TMD")
EXPECTED_SHA="28e8b7d000b0d764c3bdadb1f2ff0e28d16dbd6d64946967e527597d3ddd51c8"
FILE=ROOT/"manual-arm-reconstructions"/"manual_tmd_00019520.c"
LIB=ROOT/"manual-arm-reconstructions"/"libmanual_tmd_00019520.so"
OUT=ROOT/"manual-arm-reconstructions"/"tmd_unicorn_validation.json"

def find_elf():
    # Source file name may vary across archive projections.
    obj=json.loads((ROOT/"MANUAL_EXECUTABLE_COVERAGE.json").read_text())
    row=next(r for r in obj["items"] if r["sha"]==EXPECTED_SHA)
    import sqlite3
    cx=sqlite3.connect(ROOT/"progress.sqlite3")
    value=cx.execute("SELECT path FROM inputs WHERE sha256=?",(EXPECTED_SHA,)).fetchone()
    assert value
    return Path(value[0])

def load_code(path):
    with path.open("rb") as f:
        assert hashlib.file_digest(f,"sha256").hexdigest()==EXPECTED_SHA
    out=subprocess.run(["readelf","-W","-S",str(path)],capture_output=True,text=True,check=True).stdout
    match=re.search(r"\[\s*\d+\]\s+\.text\s+PROGBITS\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",out)
    assert match
    va,off,length=(int(x,16) for x in match.groups())
    start=0x19520
    assert va<=start and start+428<=va+length
    with path.open("rb") as f:
        f.seek(off+(start-va))
        return f.read(428)

def prepare_state(width,height,prev_w,prev_h,existing=0x123400,flag=0,limit_w=700,limit_h=400):
    memory=bytearray(0x100000)
    def put32(p,v):struct.pack_into("<I",memory,p,v&0xffffffff)
    def put16(p,v):struct.pack_into("<H",memory,p,v&0xffff)
    put32(0x63184,existing)
    put32(0x6322c,prev_w)
    put32(0x63230,prev_h)
    put32(0x6321c,flag)
    put32(0x633e0,limit_w)
    put32(0x633e4,limit_h)
    put32(0x632c8,0x0BADF00D)
    put32(0x633d8,0xDEADBEEF)
    put32(0x633dc,0xCAFE1234)
    put16(0x63306,0x2222)
    put16(0x6330a,0x3333)
    put16(0x63308,0x4444)
    for p,v in [(0x63302,0x55),(0x63303,0x66),(0x63304,0x77),
                (0x6330c,0x88),(0x6330d,0x99),(0x6330e,0xAA)]:
        memory[p]=v
    return memory

def emulated(code,memory,width,height):
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    uc.mem_map(0,0x100000)
    uc.mem_map(0x200000,0x10000)
    uc.mem_write(0,bytes(memory))
    uc.mem_write(0x19520,code)
    uc.reg_write(UC_ARM_REG_R0,width)
    uc.reg_write(UC_ARM_REG_R1,height)
    uc.reg_write(UC_ARM_REG_SP,0x20e000)
    uc.reg_write(UC_ARM_REG_LR,0xff000)
    calls=[]
    targets={0x9a0c:"release",0x9970:"allocate",0x9acc:"configure",0x1cfa4:"apply"}
    def hook(uc,address,size,data):
        if address not in targets:return
        op=targets[address]
        r0=uc.reg_read(UC_ARM_REG_R0)
        r1=uc.reg_read(UC_ARM_REG_R1)
        r2=uc.reg_read(UC_ARM_REG_R2)
        if op=="release":calls.append([op,r0])
        elif op=="allocate":
            calls.append([op,r0,r1])
            uc.reg_write(UC_ARM_REG_R0,0x77000)
        elif op=="configure":calls.append([op,r0,r1,r2])
        elif op=="apply":calls.append([op,uc.mem_read(r0,17).hex()])
        uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(0x19520,0xff000,count=5000,timeout=2000000)
    return uc.mem_read(0x63000,0x500),calls

READ32=C.CFUNCTYPE(C.c_uint32,C.c_uint32)
READ16=C.CFUNCTYPE(C.c_uint16,C.c_uint32)
READ8=C.CFUNCTYPE(C.c_uint8,C.c_uint32)
WRITE32=C.CFUNCTYPE(None,C.c_uint32,C.c_uint32)
RELEASE=C.CFUNCTYPE(None,C.c_uint32)
ALLOC=C.CFUNCTYPE(C.c_uint32,C.c_uint32,C.c_uint32)
CONFIG=C.CFUNCTYPE(None,C.c_uint32,C.c_uint32,C.c_uint32)
APPLY=C.CFUNCTYPE(None,C.c_void_p)

class Ops(C.Structure):
    _fields_=[("read32",READ32),("read16",READ16),("read8",READ8),("write32",WRITE32),
              ("release_slot",RELEASE),("allocate",ALLOC),("configure_slot",CONFIG),
              ("apply_config",APPLY)]

def reconstructed(lib,memory,width,height):
    calls=[]
    def r32(p):return struct.unpack_from("<I",memory,p)[0]
    def r16(p):return struct.unpack_from("<H",memory,p)[0]
    def r8(p):return memory[p]
    def w32(p,v):struct.pack_into("<I",memory,p,v)
    def release(slot):calls.append(["release",slot])
    def allocate(slot,length):
        calls.append(["allocate",slot,length])
        return 0x77000
    def config(p,mode,length):calls.append(["configure",p,mode,length])
    def apply(p):calls.append(["apply",C.string_at(p,17).hex()])
    callback_refs=[READ32(r32),READ16(r16),READ8(r8),WRITE32(w32),RELEASE(release),
                   ALLOC(allocate),CONFIG(config),APPLY(apply)]
    ops=Ops(*callback_refs)
    lib.ca01_tmd_00019520_reconstructed(width,height,C.byref(ops))
    return bytes(memory[0x63000:0x63500]),calls

def main():
    original=find_elf()
    code=load_code(original)
    subprocess.run(["gcc","-std=c11","-O2","-fPIC","-shared",str(FILE),"-o",str(LIB)],check=True)
    lib=C.CDLL(str(LIB))
    lib.ca01_tmd_00019520_reconstructed.argtypes=[C.c_uint32,C.c_uint32,C.POINTER(Ops)]
    lib.ca01_tmd_00019520_reconstructed.restype=None
    cases=[
        ("initial-alloc-landscape",800,360,320,240,0,0,700,400),
        ("same-size",800,360,800,360,0x123400,0,700,400),
        ("landscape-override",800,360,320,240,0,1,700,400),
        ("portrait-alloc",320,900,160,100,0x123400,0,700,400),
        ("zero-width-fallback",0,400,800,360,0,0,700,400),
        ("zero-height-fallback",800,0,800,360,0x123400,1,700,400),
        ("negative-early-return",0xffffffff,400,800,360,0x123400,0,700,400),
    ]
    outcomes=[]
    for name,w,h,pw,ph,existing,flag,lw,lh in cases:
        first=prepare_state(w,h,pw,ph,existing,flag,lw,lh)
        arm_state,arm_calls=emulated(code,first,w,h)
        c_state,c_calls=reconstructed(lib,first.copy(),w,h)
        matched=(arm_state==c_state and arm_calls==c_calls)
        outcomes.append(dict(case=name,passed=matched,arm_calls=arm_calls,
                             host_calls=c_calls,global_bytes_match=arm_state==c_state))
        print(name,matched,arm_calls,flush=True)
    report=dict(date="2026-10-23", original_elf_sha=EXPECTED_SHA,
                original_function_start="0x19520",original_function_length=len(code),
                emulation_note="Function-level ARM CPU emulation; external firmware calls are stubbed.",
                tests=outcomes,passed=sum(x["passed"] for x in outcomes),
                total=len(outcomes))
    OUT.write_text(json.dumps(report,indent=2)+"\n")
    print("TEST_SUMMARY",report["passed"],"/",report["total"],flush=True)
    if report["passed"]!=report["total"]:raise AssertionError("Manual C differs from observed ARM emulation")

if __name__=="__main__":main()
