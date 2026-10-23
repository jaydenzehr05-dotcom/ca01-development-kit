#!/usr/bin/env python3
"""Validate original ARM rq_tsk_WaitInit(10) request envelope without claiming ready.

Run original sysc WaitInit instructions with explicit synthetic TASK ID and
block-object inputs. Stop at the actual BlockBegin call BEFORE sending or
returning: no queue send, no task 10 readiness, no scene startup fabricated.
"""
import json,hashlib,struct,sys
from pathlib import Path
ROOT=Path("/home/starlight/projects/rav4-radio")
sys.path.insert(0,str(ROOT/"ca01-development-kit/tools"))
from ca01_startup_trace import prepare,BIAS,HMI_SHA256,SYSC_SHA256
from unicorn import UC_HOOK_MEM_WRITE
HMI=ROOT/"system-audit/ca01-updater-independent-20261022/06-PROC_HMI"
SYSC=ROOT/"system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so"
OUT=Path(__file__).with_name("waitinit-original-envelope.json")
assert hashlib.sha256(HMI.read_bytes()).hexdigest()==HMI_SHA256
assert hashlib.sha256(SYSC.read_bytes()).hexdigest()==SYSC_SHA256

def main():
    trace,addresses=prepare(HMI.read_bytes(),SYSC.read_bytes())
    write_log=[]
    def record_write(uc,access,address,size,value,data):
        if len(write_log)<64:write_log.append(dict(address=hex(address),size=size,value=hex(value)))
    trace.uc.hook_add(UC_HOOK_MEM_WRITE,record_write)
    # ONLY GetTid/GetBlockObj are test fixture inputs; BlockBegin is left
    # unimplemented to capture the precise original envelope at its callsite.
    tid_entry=addresses["rq_tsk_GetTid"]
    blockobj_entry=addresses["rq_tsk_GetBlockObj"]
    blockbegin_entry=addresses["rq_tsk_BlockBegin"]
    trace.imports[tid_entry]="TEST_GUEST_THREAD_ID"
    trace.imports[blockobj_entry]="TEST_BLOCK_OBJECT"
    trace.imports[blockbegin_entry]="rq_tsk_BlockBegin"
    trace.services["TEST_GUEST_THREAD_ID"]=lambda uc,a:39
    trace.services["TEST_BLOCK_OBJECT"]=lambda uc,a:64
    evidence={}
    # The original engine deliberately stops before BlockBegin executes.
    # Its trapped register arguments and still-mapped guest stack allow
    # independent reading of the actual 16-byte original message.
    res=trace.run(addresses["rq_tsk_WaitInit"],10,
                  instruction_limit=5000,timeout_us=2000000)
    assert res["boundary"].get("symbol")=="rq_tsk_BlockBegin",res
    regs=res["boundary"]["arguments"]
    evidence.update(queue_id=regs[0],size=regs[2],
        envelope=list(struct.unpack("<4I",trace.uc.mem_read(regs[1],16))),ready=False)
    assert evidence==dict(queue_id=1,size=16,envelope=[0,5,39,10],ready=False),evidence
    assert res["halt_reason"]=="unimplemented_import"
    assert res["boundary"]["symbol"]=="rq_tsk_BlockBegin"
    assert not res["returned"]
    assert [x["symbol"] for x in res["service_calls"]]==[
        "TEST_GUEST_THREAD_ID","TEST_BLOCK_OBJECT"]
    OUT.write_text(json.dumps(dict(source_sha256=HMI_SHA256,
      sysc_sha256=SYSC_SHA256,real_waitinit_executed=True,
      borrowed_thread_id_for_fixture=39,borrowed_block_object_for_fixture=64,
      task10_initialized=False,queue_send_performed=False,
      task39_initialized=False,original_callback_boundary=res["boundary"],
      envelope=evidence,original_instruction_count=res["instructions"],
      writes_during_original_waitinit=write_log,halt_reason=res["halt_reason"]),indent=2)+"\n")
    print("PASS original sysc WaitInit(10) built message",evidence)
    print("Next boundary",res["boundary"])
    print("NO queue send or real task readiness; file",OUT)

if __name__=="__main__":
    main()
