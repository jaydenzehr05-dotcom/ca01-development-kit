#!/usr/bin/env python3
"""Bounded CA01 ARM boot-code experiment, NOT an authenticated boot emulator.

Runs ONLY at caller-chosen 4-byte aligned offsets inside an explicitly selected
raw component, with an assumed RAM load base. No device writes are forwarded,
no file execution, no external IO. Unmapped MMIO reads are rejected and logged;
unmapped execution/read/write stops. All assumptions are included in report.
"""
import argparse, hashlib, json
from pathlib import Path
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0
PAGE=4096
RAM=0x20000000
RAM_SIZE=0x200000
STACK=0x30000000
STACK_SIZE=0x10000
SENTINEL=0x31000000

def align(x):return (x+PAGE-1)&~(PAGE-1)
def inspect(data,offset,load_base=RAM,max_instructions=5000,argument_mode="zero"):
    if offset<0 or offset>=len(data) or offset%4:raise ValueError("offset must be aligned and within component")
    if load_base%PAGE or load_base<0x10000 or load_base+align(len(data))>=0x100000000:
        raise ValueError("invalid load base")
    if max_instructions<1 or max_instructions>100000:raise ValueError("invalid instruction budget")
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    uc.mem_map(load_base,align(len(data)))
    uc.mem_write(load_base,data)
    uc.mem_map(STACK,STACK_SIZE)
    uc.mem_map(SENTINEL,PAGE)
    uc.mem_write(SENTINEL,b"\x00\x00\xa0\xe1") # mov r0,r0, non-executing sentinel
    uc.reg_write(UC_ARM_REG_SP,STACK+STACK_SIZE-16)
    uc.reg_write(UC_ARM_REG_LR,SENTINEL)
    if argument_mode not in ("zero", "stack-buffer"):
        raise ValueError("unknown argument mode")
    if argument_mode=="stack-buffer":
        uc.reg_write(UC_ARM_REG_R0,STACK+0x1000)
    trace=[]
    writes=[]
    faults=[]
    stop=[]
    def code_hook(engine,address,size,_):
        if address==SENTINEL:
            stop.append("returned_to_sentinel")
            engine.emu_stop()
            return
        if len(trace)<256:trace.append({"pc":hex(address),"bytes":bytes(engine.mem_read(address,size)).hex()})
    def mem_write(engine,access,address,size,value,_):
        if len(writes)<64:writes.append({"address":hex(address),"size":size,"value":hex(value)})
        # Prevent modifying loaded image and unknown hardware. Only stack is mutable.
        if not(STACK<=address and address+size<=STACK+STACK_SIZE):
            faults.append({"kind":"blocked_write","address":hex(address),"size":size})
            engine.emu_stop()
    def bad_mem(engine,access,address,size,value,_):
        faults.append({"kind":"unmapped_access","address":hex(address),"size":size,"access":access})
        return False
    uc.hook_add(UC_HOOK_CODE,code_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,mem_write)
    for kind in [UC_HOOK_MEM_READ_UNMAPPED,UC_HOOK_MEM_WRITE_UNMAPPED,UC_HOOK_MEM_FETCH_UNMAPPED]:
        uc.hook_add(kind,bad_mem)
    start=load_base+offset
    error=None
    try:uc.emu_start(start,0,count=max_instructions)
    except UcError as exc:error=str(exc)
    return {"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data),
      "entry_offset":hex(offset),"assumed_load_base":hex(load_base),
      "assumed_entry_address":hex(start),"instructions_budget":max_instructions,"argument_mode":argument_mode,
      "instructions_logged":len(trace),"sample_trace":trace,
      "writes_observed":writes,"faults":faults,"stop_reason":stop[0] if stop else (error or "budget_or_end"),
      "final_pc":hex(uc.reg_read(UC_ARM_REG_PC)),"final_r0":hex(uc.reg_read(UC_ARM_REG_R0)),
      "limitations":"No MMIO model, unknown entry/load mapping, no verified hardware calls; behavior cannot establish authentic boot. Image writes are blocked."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input",type=Path,required=True)
    p.add_argument("--offset",type=lambda s:int(s,0),required=True)
    p.add_argument("--base",type=lambda s:int(s,0),default=RAM)
    p.add_argument("--budget",type=int,default=5000)
    p.add_argument("--argument-mode",choices=("zero","stack-buffer"),default="zero")
    p.add_argument("--output",type=Path)
    a=p.parse_args()
    result=inspect(a.input.read_bytes(),a.offset,a.base,a.budget,a.argument_mode)
    text=json.dumps(result,indent=2)+"\n"
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(text)
    else:print(text)
if __name__=="__main__":main()
