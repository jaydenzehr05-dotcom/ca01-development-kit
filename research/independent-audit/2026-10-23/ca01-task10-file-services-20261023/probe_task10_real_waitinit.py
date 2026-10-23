#!/usr/bin/env python3
"""Bind the authentic recovered rq_tsk_WaitInit into group -> HMI task39 trace.

The original sysc code at ELF 0x20f04 is entered; no synthetic WaitInit
success is supplied. Task data, queue and pthread services remain fail-closed.
This probe does not claim original task10 or HMI startup completed.
"""
import hashlib,json,struct,sys
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio")
sys.path.insert(0,str(ROOT/"ca01-development-kit/tools"))
import ca01_group_binding
from ca01_scene_boundary import inspect_scene_boundary
from ca01_hmi_startup import ElfImage,HMI_SHA256
from ca01_startup_trace import BIAS,SYSC_SHA256
from ca01_group_binding import GROUP_SHA256

HMI=ROOT/"system-audit/ca01-updater-independent-20261022/06-PROC_HMI"
SYSC=ROOT/"system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so"
GROUP=ROOT/"system-audit/ca01-updater-independent-20261022/06-libipas_grp.so"
OUT=Path(__file__).with_name("original-task10-wait-boundary.json")
assert hashlib.sha256(HMI.read_bytes()).hexdigest()==HMI_SHA256
assert hashlib.sha256(SYSC.read_bytes()).hexdigest()==SYSC_SHA256
assert hashlib.sha256(GROUP.read_bytes()).hexdigest()==GROUP_SHA256
orig_bind=ca01_group_binding.bind_group
transition=[]
def original_sysc_wait(trace,image,group_path):
    result=orig_bind(trace,image,group_path)
    matching=[addr for addr,name in trace.imports.items() if name=="rq_tsk_WaitInit"]
    assert len(matching)==1,matching
    trap=matching[0]
    trace.imports.pop(trap)
    code=struct.pack("<3I",0xe59fc000,0xe12fff1c,BIAS+0x20f04)
    trace.uc.mem_write(trap,code)
    trace.executable_ranges.append((trap,trap+len(code)))
    for seg in ElfImage(SYSC.read_bytes()).segments:
        if seg["p_flags"]&1:
            start=BIAS+seg["p_vaddr"]
            trace.executable_ranges.append((start,start+seg["p_memsz"]))
    transition.append(dict(group_import_address=hex(trap),
                           bound_to_original_sysc=hex(BIAS+0x20f04),
                           original_sysc_function="rq_tsk_WaitInit",
                           synthetic_success=False))
    result["original_waitinit_bound"]=hex(BIAS+0x20f04)
    return result

def main():
    ca01_group_binding.bind_group=original_sysc_wait
    try:
        report=inspect_scene_boundary(HMI,provide_clock=True,provide_semaphores=True,
            system_library=SYSC,group_library=GROUP,instruction_limit=20000)
    finally:
        ca01_group_binding.bind_group=orig_bind
    task=report["task39_initialization"]
    assert transition,report
    assert task["halt_reason"]!="returned","Do not accept task readiness without actual services"
    report["original_task10_waitinit_probe"]={
        "link":transition,
        "original_sysc_binding_entered":any(
             int(addr,16)==BIAS+0x20f04 for addr in task["last_instruction_addresses"]),
        "result":"Stopped at first unresolved service or state; no WaitInit override or readiness signal",
        "task10_started":False,
        "full_task39_ready":False,
        "limitations":"Without true task creation and state tables, the original wait cannot complete"
    }
    if not report["original_task10_waitinit_probe"]["original_sysc_binding_entered"]:
        report["original_task10_waitinit_probe"]["original_sysc_binding_entered"]=(
            any(entry["address"]==hex(BIAS+0x20f04) for entry in task["function_entries"]))
    OUT.write_text(json.dumps(report,indent=2)+"\n")
    print("TASK10_BOUNDARY",task["halt_reason"],task["boundary"])
    print("ORIGINAL_SYSC_WAITINIT_ENTERED",report["original_task10_waitinit_probe"]["original_sysc_binding_entered"])
    assert report["original_task10_waitinit_probe"]["original_sysc_binding_entered"],(
        "Could not demonstrate original WaitInit execution")
    print("PASS real original task10 WaitInit reached; no readiness fabricated:",OUT)

if __name__=="__main__":
    main()
