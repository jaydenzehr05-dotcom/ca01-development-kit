#!/usr/bin/env python3
"""Offline bridge: native host pthread identities -> original CA01 ARM GetTid.

The recovered rq_tsk_GetTid executes under Unicorn with a verified HMI+SYSC
pair. Host pthread identities are explicitly mapped to synthetic 32-bit guest
pthread_t aliases (never truncated from 64-bit pointers), then checked through
the original 80-byte record/TLS instruction path. On successful identity
validation a self-authored queue-1 status transport carries 16-byte messages
into the existing synthetic startup state machine.

NO original pthread_create/queue-1 implementation, parent IPC, ipasz.conf,
kernel boot, display initialization or Toyota GUI is claimed. Original
missing-service barriers remain required.
"""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import queue
import threading

from ca01_startup_trace import verify_inputs
from ca01_task_identity import run_identity_probe
from ca01_hmi_startup import HmiHarness, Message, StartupBlocked

MODEL_TASKS=(3,10,39,40,41)
QUEUE1_EVENT=Message(0,3,0,0)

class ThreadedStartupBridge:
    """Native host threading + bounded original guest lookup, fail-closed.

    The source HMI and SYSC bytes are checked before any native threads start.
    The task-status channel is a host-only queue; it is not rq_msg_Create and
    has no asserted CA01 capacity or scheduling semantics.
    """

    def __init__(self,hmi:bytes,sysc:bytes,*,runtime_library:Path,
                 task_ids=MODEL_TASKS,status_queue_capacity=16):
        verify_inputs(hmi,sysc)
        tasks=tuple(task_ids)
        if not tasks or len(tasks)!=len(set(tasks)) or not set(tasks).issubset(MODEL_TASKS):
            raise ValueError("Only distinct modeled task IDs 3,10,39,40,41 allowed")
        if type(status_queue_capacity) is not int or not 1<=status_queue_capacity<=16:
            raise ValueError("Host-only status queue capacity must be 1..16")
        self.hmi,self.sysc=hmi,sysc
        self.task_ids=tasks
        self.aliases={task:0x5000+index*0x100 for index,task in enumerate(tasks)}
        self.status_queue=queue.Queue(maxsize=status_queue_capacity)
        self.status_source={}
        self.results={}
        self.errors=[]
        self._reg_lock=threading.Lock()
        self._guest_engine_lock=threading.Lock()
        self._has_run=False
        self.callbacks=[]
        self.h=HmiHarness(runtime_library=runtime_library,
            heartbeat=lambda m:self.callbacks.append(("heartbeat",m.event)),
            command=lambda m:self.callbacks.append(("command",m.subcommand)),
            diagnostic=lambda m:self.callbacks.append(("diagnostic",m.code)),
            release_payload=lambda pool,pointer:self.callbacks.append(("release",pool,pointer)))

    def _worker(self,task:int,barrier:threading.Barrier,
                overrides:dict[int,int]):
        try:
            libc=ctypes.CDLL(None)
            libc.pthread_self.argtypes=[]
            libc.pthread_self.restype=ctypes.c_ulong
            native=int(libc.pthread_self())
            if native<=0:
                raise RuntimeError("pthread_self returned invalid identity")
            with self._reg_lock:
                if any(info["host_pthread"]==native for info in self.status_source.values()):
                    raise RuntimeError("Concurrent native pthread identity unexpectedly reused")
                self.status_source[task]={
                    "host_pthread":native,"guest_alias":self.aliases[task],
                    "alias_basis":"unique bounded fixture token, NOT truncated host pthread_t"
                }
            barrier.wait(timeout=15)  # Every native identity exists simultaneously.
            current=overrides.get(task,self.aliases[task])
            with self._guest_engine_lock:
                cold=run_identity_probe(self.hmi,self.sysc,self.aliases,
                                        current_thread=current,cached=-2)
                # The original TLS cache update becomes the next fixture value.
                warm=run_identity_probe(self.hmi,self.sysc,self.aliases,
                                        current_thread=current,cached=cold["tls_after"])
            valid=(cold["returned_task_id"]==task and cold["tls_after"]==task and
                   warm["returned_task_id"]==task and warm["tls_after"]==task and
                   cold["trace"]["returned"] and warm["trace"]["returned"])
            result={
                "task":task,"original_arm_address":"0x20bf4",
                "native_pthread_seen":True,"guest_alias":self.aliases[task],
                "cold_task":cold["returned_task_id"],
                "warm_task":warm["returned_task_id"],
                "cold_tls_after":cold["tls_after"],"warm_tls_after":warm["tls_after"],
                "original_arm_identity_verified":bool(valid),
                "local_status_enqueued":False
            }
            if valid:
                try:
                    self.status_queue.put_nowait(Message(0,3,task,0).pack())
                    result["local_status_enqueued"]=True
                except queue.Full:
                    with self._reg_lock:
                        self.errors.append(f"Host-only queue1 fixture full for task {task}")
            with self._reg_lock:self.results[task]=result
        except Exception as exc:
            with self._reg_lock:self.errors.append(f"task {task}: {type(exc).__name__}: {exc}")
            try:barrier.abort()
            except Exception:pass

    def run(self,*,guest_identity_faults=None):
        """Start isolated native host threads, run original ARM lookup,
        then hand accepted 16-byte status envelopes to synthetic startup.

        guest_identity_faults is an explicitly synthetic negative-test injector:
        it can pass a wrong guest pthread token but cannot force success.
        """
        if self._has_run:raise RuntimeError("Run already executed; create a new fixture")
        faults=dict(guest_identity_faults or {})
        if not set(faults).issubset(self.task_ids):
            raise ValueError("Faults must reference configured tasks")
        self._has_run=True
        try:
            self.h.step(timeout_ms=0)
            raise AssertionError("Unexpected readiness before setup")
        except StartupBlocked:
            pass
        self.h.startup.create_resources()
        self.h.startup.apply_power_state(True)
        barrier=threading.Barrier(len(self.task_ids)+1)
        threads=[threading.Thread(name=f"CA01-fixture-{task}",
                     target=self._worker,args=(task,barrier,faults))
                 for task in self.task_ids]
        for thread in threads:thread.start()
        try:barrier.wait(timeout=15)
        except threading.BrokenBarrierError:
            self.errors.append("Host pthread rendezvous failed")
        for thread in threads:
            thread.join(timeout=60)
            if thread.is_alive():
                self.errors.append(f"Timed out awaiting host thread {thread.name}")
        if len(self.status_source)!=len(self.task_ids):
            self.errors.append("Not all requested pthread registrations completed")
        ids=[x["host_pthread"] for x in self.status_source.values()]
        if len(ids)!=len(set(ids)):
            self.errors.append("Host pthread IDs were not unique while registered")
        raw_envelopes=[]
        accepted=[]
        while True:
            try:raw=self.status_queue.get_nowait()
            except queue.Empty:break
            event=Message.unpack(raw)
            raw_envelopes.append([event.code,event.subcommand,event.event,event.payload])
            task=event.event
            result=self.results.get(task)
            if (event.code!=0 or event.subcommand!=3 or event.payload!=0 or
                    not result or not result["original_arm_identity_verified"] or
                    task in accepted or self.h.startup.states.get(task)!=2):
                self.errors.append(f"Untrusted or duplicate status event for task {task}")
                continue
            self.h.startup.task_initialized(task)
            accepted.append(task)
        # Crucially do NOT call release_startup_barrier or
        # complete_display_initialization. Their real dependencies are absent.
        try:
            self.h.step(timeout_ms=0)
            self.errors.append("Display queue unexpectedly passed readiness gate")
        except StartupBlocked:
            pass
        return {
            "scope":"native host pthreads + hashed original ARM GetTid + synthetic status queue1",
            "task_ids":list(self.task_ids),
            "native_threads_registered":len(self.status_source),
            "per_task":[self.results[k] for k in sorted(self.results)],
            "status_envelopes":raw_envelopes,
            "status_tasks_accepted":accepted,
            "task_states":{str(k):v for k,v in sorted(self.h.startup.states.items())},
            "errors":list(self.errors),
            "parent_sync_verified":False,
            "display_initialized":False,
            "draw_ready":self.h.display_ready,
            "original_pthread_create_executed":False,
            "original_queue1_implemented":False,
            "original_toyota_app_started":False,
            "native_hmi_queue_entries":len(self.h.queue),
            "synthetic_status_queue_only":True,
            "full_startup":False
        }


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--hmi",type=Path,required=True)
    cli.add_argument("--sysc",type=Path,required=True)
    cli.add_argument("--runtime-library",type=Path,required=True)
    cli.add_argument("--output",type=Path,required=True)
    args=cli.parse_args()
    if args.output.exists() or args.output.is_symlink():
        cli.error("Output must not already exist")
    bridge=ThreadedStartupBridge(args.hmi.read_bytes(),args.sysc.read_bytes(),
                                  runtime_library=args.runtime_library)
    result=bridge.run()
    with args.output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2)
        stream.write("\n")
    print("Original ARM task identity reports:",
          {v["task"]:v["cold_task"] for v in result["per_task"]})
    print("Parent barrier unresolved; original radio not started.")
    if result["errors"]:
        raise SystemExit(2)

if __name__=="__main__":
    main()
