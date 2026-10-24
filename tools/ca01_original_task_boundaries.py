#!/usr/bin/env python3
"""Execute bounded original ARM task-start/queue-record code without launching it.

The canonical HMI and sysc binaries are SHA-256 gated before Unicorn execution.
All original pthread_create, process sync, watchdog and queue-service interfaces
remain blocked. Fixture callbacks only model pthread attribute return values
and an explicit, nonfunctional guest queue token for rq_msg_Create. This is not
a vendor implementation, a process launcher, or radio firmware.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from ca01_startup_trace import prepare,REGISTRY,BIAS,HMI_SHA256,SYSC_SHA256
from ca01_hmi_startup import ElfImage

TABLE=0x50000000
TLS=0x5000f000
RECORD_BYTES=0x50
THREAD_FIELD=0x40
QUEUETOKEN_FIELD=8
TASK_ENTRY_FIELD=0x14
TASK_PRIORITY_FIELD=0x18

def engine_for(hmi:bytes,sysc:bytes,task:int):
    trace,defined=prepare(hmi,sysc)  # Validates original SHA-256 inputs.
    image=ElfImage(hmi)
    setup_ptr=struct.unpack("<I",image.read(REGISTRY,4))[0]
    count=struct.unpack("<I",image.read(setup_ptr+28,4))[0]
    if not 1<=count<=256:
        raise ValueError("Unexpected source task-table count")
    if type(task) is not int or not 0<=task<count:
        raise ValueError("Task index outside original task table")
    uc=trace.uc
    uc.mem_map(TABLE,0x10000)
    uc.mem_write(defined["bf_sys_TskMng"]+4,struct.pack("<II",count,TABLE))
    return trace,defined,count

def probe_pthread_create_boundary(hmi:bytes,sysc:bytes,*,task=39,
                                   priority=0,guest_entry=0x33334444):
    """Run genuine rq_tsk_Start ARM instructions until pthread_create trap.

    Host pthreads are NOT created by this probe. pthread_attr functions only
    report calls and return an explicit fixture status 0; guest pthread_create
    is deliberately NOT implemented and watchdog startup is NOT reached.
    """
    if type(priority) is not int or not 0<=priority<=20:
        raise ValueError("Priority fixture must be between 0 and 20")
    if type(guest_entry) is not int or not 1<=guest_entry<=0xffffffff:
        raise ValueError("Invalid guest entry pointer fixture")
    trace,defined,count=engine_for(hmi,sysc,task)
    uc=trace.uc
    record=TABLE+task*RECORD_BYTES
    uc.mem_write(record+TASK_ENTRY_FIELD,struct.pack("<I",guest_entry))
    uc.mem_write(record+TASK_PRIORITY_FIELD,struct.pack("<I",priority))
    seen=[]
    def attribute(name):
        def callback(uc,args):
            observed=dict(service=name,args=list(args))
            if name=="pthread_attr_setschedparam":
                observed["priority_value"]=struct.unpack("<i",uc.mem_read(args[1],4))[0]
            seen.append(observed)
            return 0
        return callback
    for name in ("pthread_attr_init","pthread_attr_setschedpolicy",
                 "pthread_attr_setschedparam","pthread_attr_setinheritsched"):
        trace.services[name]=attribute(name)
    result=trace.run(defined["rq_tsk_Start"],task,instruction_limit=8000)
    boundary=result.get("boundary",{})
    expected=record+THREAD_FIELD
    args=boundary.get("arguments",[])
    if (result["halt_reason"]!="unimplemented_import" or
            boundary.get("symbol")!="pthread_create" or len(args)!=4 or
            args[0]!=expected or args[2]!=guest_entry or args[3]!=0):
        raise RuntimeError("Original pthread_create boundary not verified: "+
                           json.dumps({"reason":result["halt_reason"],"boundary":boundary}))
    return {
        "source":"original hash-verified ARM instructions in rq_tsk_Start",
        "original_address":"0x213a4",
        "task":task,"task_table_slots":count,"record_bytes":RECORD_BYTES,
        "task_record_address":hex(record),
        "pthread_output_slot":hex(expected),"entry_pointer":hex(guest_entry),
        "priority_fixture":priority,"attribute_calls":seen,
        "pthread_create_arguments":[hex(v) for v in args],
        "original_instructions_before_trap":result["instructions"],
        "original_pthread_create_executed":False,
        "original_watchdog_started":False,
        "halt_reason":result["halt_reason"],
        "full_startup":False
    }

def probe_block_queue_slot(hmi:bytes,sysc:bytes,*,task=39,
                           guest_pthread=0x5678,guest_queue_token=0x1234):
    """Run original GetTid and GetBlockObj with a *synthetic* queue service.

    Instead of calling real rq_msg_Create (which needs unprovided mutex
    services), intercept at its original defined entry; return a test-only
    guest token and verify the *original caller* writes record+8.
    """
    if (type(guest_pthread) is not int or not 0<guest_pthread<=0xffffffff or
        type(guest_queue_token) is not int or not 0<guest_queue_token<=0xffffffff):
        raise ValueError("Guest pthread and queue token must be positive 32-bit")
    trace,defined,count=engine_for(hmi,sysc,task)
    uc=trace.uc
    record=TABLE+task*RECORD_BYTES
    uc.mem_write(record+THREAD_FIELD,struct.pack("<I",guest_pthread))
    uc.mem_write(TLS,struct.pack("<i",-2))
    trace.services["pthread_self"]=lambda uc,args:guest_pthread
    def tls_lookup(uc,args):
        if not BIAS<=args[0]<BIAS+0x200000:
            raise ValueError("Unrecognized guest TLS relocation descriptor")
        return TLS
    trace.services["__tls_get_addr"]=tls_lookup
    # Mark the original internal code address as an explicit fixture trap.
    # No original pthread mutex or actual rq_msg_Create call is run.
    trace.imports[defined["rq_msg_Create"]]="fixture_rq_msg_Create"
    calls=[]
    def fixture_queue(uc,args):
        calls.append(list(args))
        if args[0]!=0xffffffff or args[1]!=1 or args[2]!=16:
            raise ValueError("Original block queue create shape changed")
        return guest_queue_token
    trace.services["fixture_rq_msg_Create"]=fixture_queue
    result=trace.run(defined["rq_tsk_GetBlockObj"],0,instruction_limit=9000)
    token=struct.unpack("<I",uc.mem_read(record+QUEUETOKEN_FIELD,4))[0]
    tls=struct.unpack("<i",uc.mem_read(TLS,4))[0]
    if (not result["returned"] or len(calls)!=1 or
            token!=guest_queue_token or tls!=task):
        raise RuntimeError("Original ARM block-queue slot contract not verified")
    symbols=[x["symbol"] for x in result["function_entries"]]
    if "rq_tsk_GetTid" not in symbols:
        raise RuntimeError("Original GetTid subroutine did not execute")
    return {
        "source":"original hash-verified ARM GetBlockObj and GetTid",
        "get_block_obj_address":"0x20e70",
        "get_tid_address":"0x20bf4",
        "task":task,"task_table_slots":count,"record_bytes":RECORD_BYTES,
        "queue_record_field":8,"queue_token":hex(guest_queue_token),
        "stored_queue_token":hex(token),"tls_after":tls,
        "requested_queue_shape":[hex(calls[0][0]),calls[0][1],calls[0][2]],
        "original_arm_instructions_executed":result["instructions"],
        "original_rq_msg_create_implemented":False,
        "host_queue1_created":False,
        "actual_block_wait_performed":False,
        "ready_flags_modified":False,
        "full_startup":False
    }

def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--hmi",type=Path,required=True)
    cli.add_argument("--sysc",type=Path,required=True)
    cli.add_argument("--output",type=Path,required=True)
    args=cli.parse_args()
    if args.output.exists() or args.output.is_symlink():
        cli.error("Output must be a new file")
    hmi=args.hmi.read_bytes()
    sysc=args.sysc.read_bytes()
    report=dict(input_hashes={"HMI":HMI_SHA256,"SYSC":SYSC_SHA256},
                start=probe_pthread_create_boundary(hmi,sysc),
                block_queue=probe_block_queue_slot(hmi,sysc),
                all_actions_offline=True,
                original_vendor_process_created=False)
    with args.output.open("x",encoding="utf-8") as stream:
        json.dump(report,stream,indent=2)
        stream.write("\n")
    print("Original pthread_create and guest block-queue slot verified;",
          "no native vendor services started.")

if __name__=="__main__":
    main()
