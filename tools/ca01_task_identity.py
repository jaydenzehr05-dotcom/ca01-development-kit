#!/usr/bin/env python3
"""Execute original rq_tsk_GetTid with explicit guest thread/table/TLS fixtures.

No original pthread creation or system startup is claimed. The result is
calculated by original ARM instructions, not an invented GetTid return value.
"""
import argparse,json,struct
from pathlib import Path
from ca01_startup_trace import prepare,BIAS,REGISTRY
from ca01_hmi_startup import ElfImage


def run_identity_probe(hmi,sysc,task_threads,current_thread,cached=-2):
 trace,defined=prepare(hmi,sysc) # Verifies both complete canonical hashes.
 image=ElfImage(hmi)
 setup_pointer=struct.unpack('<I',image.read(REGISTRY,4))[0]
 task_count=struct.unpack('<I',image.read(setup_pointer+28,4))[0]
 if not 1<=task_count<=256:raise ValueError('Unexpected original task table bound')
 if not 0<current_thread<=0xffffffff or not -2<=cached<task_count:raise ValueError('Invalid bounded thread fixture')
 if any(not 0<=task<task_count or not 0<thread<=0xffffffff for task,thread in task_threads.items()):raise ValueError('Invalid task table fixture')
 uc=trace.uc;table=0x50000000;tls=0x5000f000
 uc.mem_map(table,0x10000)
 # Observed header count/pointer and80-byte record layout. This is isolated
 # fixture state, not proof the original configuration or task creation ran.
 uc.mem_write(defined['bf_sys_TskMng']+4,struct.pack('<II',task_count,table))
 for task,thread in task_threads.items():uc.mem_write(table+task*0x50+0x40,struct.pack('<I',thread))
 uc.mem_write(tls,struct.pack('<i',cached))
 trace.services['pthread_self']=lambda uc,args:current_thread
 def fixture_tls(uc,args):
  # Two original TLS descriptors are passed by address. We do not read or
  # resolve their module relocations, or remove the engine's TLS guards.
  if not BIAS<=args[0]<BIAS+0x200000:raise ValueError('Unexpected original TLS descriptor address')
  return tls
 trace.services['__tls_get_addr']=fixture_tls
 result=trace.run(defined['rq_tsk_GetTid'],0,instruction_limit=5000)
 if not result['returned']:raise RuntimeError('Original identity lookup blocked: '+json.dumps(result))
 from unicorn.arm_const import UC_ARM_REG_R0
 raw=uc.reg_read(UC_ARM_REG_R0);value=raw if raw<0x80000000 else raw-0x100000000
 return dict(scope='Original ARM task lookup with synthetic pthread identity, task records and TLS cell; not original pthread startup',
             original_function='rq_tsk_GetTid',canonical_address='0x20bf4',
             task_record_bytes=80,thread_field_offset=64,task_count=task_count,
             fixture_task_threads=task_threads,fixture_current_thread=current_thread,tls_before=cached,
             returned_task_id=value,tls_after=struct.unpack('<i',uc.mem_read(tls,4))[0],
             trace=result,full_startup=False,queue_send_performed=False,task10_initialized=False)


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--hmi',type=Path,required=True)
 p.add_argument('--sysc',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists() or a.output.is_symlink():p.error('Output must be new')
 hmi=a.hmi.read_bytes();sysc=a.sysc.read_bytes()
 cases={name:run_identity_probe(hmi,sysc,{3:0x1234,39:0x5678},thread,cached)
        for name,thread,cached in [('search',0x5678,-2),('stale-cache',0x5678,3),('unknown-thread',0x9999,-2),('cached-unmanaged',0x5678,-1)]}
 with a.output.open('x') as f:json.dump(cases,f,indent=2);f.write('\n')
 print('Original ARM identity results:',{k:v['returned_task_id'] for k,v in cases.items()})
if __name__=='__main__':main()
