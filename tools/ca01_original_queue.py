#!/usr/bin/env python3
"""Execute original CA01 queue functions with explicit emulated libc/pthreads.

Original ARM code owns queue allocation layout, FIFO indexes, copies and return
codes. Host services own only bounded guest memory and deterministic cooperative
mutex/condition semantics. Virtual CLOCK_REALTIME deadlines avoid real sleeps.
This is neither native Toyota pthread execution nor a substitute parent/display
service. Unknown imports and syscalls remain blocked. Payload pools require
explicit initialization through the original functions and embedded profile.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
import argparse,json,struct
from pathlib import Path
from ca01_startup_trace import prepare,REGISTRY,BIAS,HMI_SHA256,SYSC_SHA256
from ca01_hmi_startup import Message,StartupSequence,StartupBlocked,ElfImage,decode_queue_table
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
 UC_ARM_REG_SP,UC_ARM_REG_PC,UC_ARM_REG_C1_C0_2,UC_ARM_REG_FPEXC)

HEAP=0x50000000
HEAP_BYTES=4*1024*1024
STACK=0x70000000
STACK_BYTES=0x10000

class QueueBlocked(RuntimeError):pass

@dataclass(eq=False)
class QueueWait:
 actor:str
 function:str
 kind:str
 mutex:int
 condition:int|None
 generation:int
 deadline_ns:int|None
 context:object=None
 stack:bytes=b''
 consumed:bool=False


def signed(word):return word if word<0x80000000 else word-0x100000000


def trace_create_boundary(hmi,sysc):
 t,d=prepare(hmi,sysc)
 return t.run(d['rq_msg_Create'],0xffffffff)


class OriginalQueueRuntime:
 """One isolated guest, cooperative actors, original ARM ring implementation.

 Calls can suspend at actual pthread waits. A different actor may execute
 original ARM send/receive; resume reacquires the exact guest mutex and restores
 the suspended CPU and private stack. Guest queue memory remains shared.
 No concurrent host entry into a Unicorn instance is supported.
 """
 ALLOWED={'fs_sys_CnfEntry','fs_msg_Init','rq_msg_Create','rq_msg_Delete',
          'rq_msg_SendT','rq_msg_Send','rq_msg_ReceiveT','rq_msg_ReceiveP',
          'rq_msg_Receive','rq_msg_DelRsrv','fc_msg_Clear','rq_tsk_GetBlockObj','rq_tsk_GetTid',
          'fs_mem_Init','rq_mem_Create','rq_mem_Alloc','rq_mem_Free'}
 def __init__(self,hmi,sysc):
  self.trace,self.defined=prepare(hmi,sysc)
  self.uc=self.trace.uc
  self.uc.mem_map(HEAP,HEAP_BYTES)
  self.uc.reg_write(UC_ARM_REG_C1_C0_2,0xf00000)
  self.uc.reg_write(UC_ARM_REG_FPEXC,0x40000000)
  self.next_heap=HEAP;self.allocations={};self.freed=set()
  self.mutexes={};self.conditions={};self.waiters=[]
  self.now_ns=1000_000_000_000
  self.actor='';self.waiting=None;self.history=[]
  self.diagnostics=[]
  callbacks={'malloc':self._malloc,'calloc':self._calloc,'free':self._free,
   'memcpy':self._memcpy,'memset':self._memset,
   'pthread_mutex_init':self._mutex_init,'pthread_mutex_lock':self._lock,
   'pthread_mutex_unlock':self._unlock,'pthread_mutex_destroy':self._mutex_destroy,
   'pthread_cond_init':self._cond_init,'pthread_cond_signal':self._signal,
   'pthread_cond_wait':self._wait,'pthread_cond_timedwait':self._timedwait,
   'pthread_cond_destroy':self._cond_destroy,'clock_gettime':self._clock}
  self.trace.services.update(callbacks)
  # Only known queue watermark notifications have a scoped host log sink.
  # Other diagnostics, force-standby and pool-release code still execute/trap.
  self.trace.imports[self.defined['rq_drc_ErrorTraceP']]='model_queue_watermark_log'
  self.trace.services['model_queue_watermark_log']=self._watermark
  self.call('fs_sys_CnfEntry',REGISTRY)
  self.call('fs_msg_Init')
  self.queue_count=self.read_words(self.defined['bf_sys_MsgMng'],1)[0]
  if self.queue_count!=96:raise RuntimeError('Unexpected original queue count')
 def read_words(self,p,n):return struct.unpack('<'+'I'*n,self.uc.mem_read(p,4*n))
 def _allocate(self,size):
  if not 0<size<=1024*1024:raise ValueError('Guest allocation outside 1..1MiB bound')
  p=self.next_heap;end=p+((size+15)&~15)
  if end>HEAP+HEAP_BYTES:raise MemoryError('Bounded guest heap exhausted')
  self.next_heap=end;self.allocations[p]=size
  self.uc.mem_write(p,bytes(size));return p
 def buffer(self,data):
  p=self._allocate(len(data));self.uc.mem_write(p,data);return p
 def _malloc(self,u,a):return self._allocate(a[0])
 def _calloc(self,u,a):return self._allocate(a[0]*a[1])
 def _free(self,u,a):
  if a[0]==0:return 0
  if a[0] not in self.allocations:raise ValueError('Unowned/double guest free')
  del self.allocations[a[0]];self.freed.add(a[0]);return 0
 def _memcpy(self,u,a):
  if not 0<a[2]<=1024*1024:raise ValueError('Copy outside bounded range')
  u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));return a[0]
 def _memset(self,u,a):
  if a[2]>1024*1024:raise ValueError('Fill outside bounded range')
  u.mem_read(a[0],a[2]);u.mem_write(a[0],bytes([a[1]&255])*a[2]);return a[0]
 def _mutex_init(self,u,a):
  u.mem_read(a[0],24)
  if a[1] or a[0] in self.mutexes:raise ValueError('Unsupported attr or duplicate mutex init')
  self.mutexes[a[0]]=None;return 0
 def _lock(self,u,a):
  if a[0] not in self.mutexes:raise ValueError('Uninitialized guest mutex')
  owner=self.mutexes[a[0]]
  if owner is not None:
   if owner==self.actor:raise ValueError('Recursive acquisition of nonrecursive guest mutex')
   return self._suspend('mutex',a[0],None,None)
  self.mutexes[a[0]]=self.actor;return 0
 def _unlock(self,u,a):
  if a[0] not in self.mutexes or self.mutexes[a[0]]!=self.actor:
   raise ValueError('Guest mutex unlock by nonowner')
  self.mutexes[a[0]]=None;return 0
 def _mutex_destroy(self,u,a):
  if a[0] not in self.mutexes or self.mutexes[a[0]] is not None:
   raise ValueError('Destroy unknown/owned mutex')
  if any(w.mutex==a[0] and not w.consumed for w in self.waiters):
   raise ValueError('Destroy mutex with suspended waiter')
  del self.mutexes[a[0]];return 0
 def _cond_init(self,u,a):
  u.mem_read(a[0],48)
  if a[1] or a[0] in self.conditions:raise ValueError('Unsupported attr or duplicate condition init')
  self.conditions[a[0]]=0;return 0
 def _signal(self,u,a):
  if a[0] not in self.conditions:raise ValueError('Uninitialized condition')
  self.conditions[a[0]]+=1;return 0
 def _cond_destroy(self,u,a):
  if a[0] not in self.conditions:raise ValueError('Unknown condition')
  if any(w.condition==a[0] and not w.consumed for w in self.waiters):
   raise ValueError('Destroy condition with suspended waiter')
  del self.conditions[a[0]];return 0
 def _suspend(self,kind,mutex,condition,deadline):
  self.waiting=QueueWait(self.actor,self.function,kind,mutex,condition,
            self.conditions.get(condition,0),deadline)
  self.trace._halt('queue_service_wait',kind=kind,mutex=hex(mutex),
                   condition=hex(condition) if condition else None,deadline_ns=deadline)
  return 0 # A suspended context is never reported as a successful guest return.
 def _wait_common(self,a,deadline):
  if a[0] not in self.conditions:raise ValueError('Uninitialized guest condition')
  if self.mutexes.get(a[1])!=self.actor:raise ValueError('Condition wait without owned mutex')
  self.mutexes[a[1]]=None
  return self._suspend('condition',a[1],a[0],deadline)
 def _wait(self,u,a):return self._wait_common(a,None)
 def _timedwait(self,u,a):
  sec,nsec=struct.unpack('<ii',u.mem_read(a[2],8))
  if sec<0 or not 0<=nsec<1_000_000_000:raise ValueError('Invalid ARM32 timespec')
  return self._wait_common(a,sec*1_000_000_000+nsec)
 def _watermark(self,u,a):
  words=list(a)+list(self.read_words(u.reg_read(UC_ARM_REG_SP),3))
  code=a[2]
  if a[0] or a[1] or code not in (0x12000440,0x12000240,0x12000820,0x12000730,0x12000620):
   raise RuntimeError('Non-watermark diagnostic blocked: '+hex(code))
  state=self.state(a[3]);_,table=self.read_words(self.defined['bf_sys_MsgMng'],2)
  offset=0x24 if code in (0x12000440,0x12000240) else 0x28
  threshold=self.read_words(table+a[3]*136+offset,1)[0]
  if words[4]!=state['count'] or words[5]!=threshold:
   raise RuntimeError('Watermark diagnostic mismatches original queue record')
  self.diagnostics.append(dict(scope='modeled log sink only',words=words))
  return 0
 def _clock(self,u,a):
  if a[0]!=0:raise ValueError('Queue requests must use CLOCK_REALTIME')
  u.mem_write(a[1],struct.pack('<ii',*divmod(self.now_ns,1_000_000_000)));return 0
 def _record(self,function,result):
  value=signed(self.uc.reg_read(UC_ARM_REG_R0))
  self.history.append({'function':function,'actor':self.actor,'trace':result,'r0':value})
  if result['halt_reason']=='queue_service_wait':
   w=self.waiting;w.context=self.uc.context_save()
   w.stack=bytes(self.uc.mem_read(STACK,STACK_BYTES));self.waiters.append(w)
   self.waiting=None;return w
  if not result['returned']:raise RuntimeError('Original queue blocked: '+json.dumps(result))
  return value
 def call(self,function,*args,actor='main'):
  if function not in self.ALLOWED:raise ValueError('Not an approved original queue function')
  if not isinstance(actor,str) or not actor:raise ValueError('Actor identity required')
  if len(args)>4:raise ValueError('At most four ARM argument registers')
  self.actor=actor;self.function=function
  for reg,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),list(args)+[0]*(4-len(args))):
   self.uc.reg_write(reg,value&0xffffffff)
  result=self.trace.run(self.defined[function],args[0]&0xffffffff if args else 0,
                        instruction_limit=50000)
  return self._record(function,result)
 def resume(self,w):
  if w not in self.waiters or w.consumed:raise ValueError('Unknown/already consumed wait')
  if self.mutexes.get(w.mutex,'missing') is not None:raise QueueBlocked('Mutex not available')
  signaled=w.kind=='mutex' or self.conditions.get(w.condition,-1)>w.generation
  expired=w.deadline_ns is not None and self.now_ns>=w.deadline_ns
  if not signaled and not expired:raise QueueBlocked('No signal or elapsed deadline')
  # Reacquisition is real model state, never an unconditional pthread success.
  self.mutexes[w.mutex]=w.actor;w.consumed=True
  self.actor=w.actor;self.function=w.function
  self.uc.context_restore(w.context);self.uc.mem_write(STACK,w.stack)
  self.uc.reg_write(UC_ARM_REG_R0,0 if signaled else 110) # Linux ETIMEDOUT.
  t=self.trace;t.reason=None;t.boundary={};t.instructions=0;t.emulator_steps=0
  t.entries=[];t.service_calls=[];t.tail=deque(maxlen=128)
  self.uc.emu_start(self.uc.reg_read(UC_ARM_REG_PC),t.sentinel+4,count=50000,timeout=2000000)
  reason=t.reason or ('instruction_limit' if t.emulator_steps>=50000 else 'time_limit')
  return self._record(w.function,dict(returned=reason=='returned',halt_reason=reason,
   boundary=t.boundary,instructions=t.instructions,service_calls=t.service_calls,
   function_entries=t.entries,last_instruction_addresses=list(t.tail)))
 def advance_time(self,milliseconds):
  if type(milliseconds) is not int or milliseconds<0:raise ValueError('Nonnegative virtual milliseconds required')
  self.now_ns+=milliseconds*1_000_000
 def initialize_payload_pools(self):
  """Execute original pool initialization using the embedded HMI profile.

  This is an isolated resource subset, not a successful full SysResInit.
  The recovered rq_mem_Alloc uses libc allocations; no external service is
  claimed and no invented pool descriptor is inserted into guest memory.
  """
  if hasattr(self,'pool_profiles'):raise ValueError('Memory pools already configured')
  setup=self.read_words(self.defined['bf_sys_CnfSetup'],1)[0]
  count=self.read_words(setup+0x2c,1)[0]
  if count!=8:raise ValueError('Unexpected original pool count')
  table=self.read_words(self.defined['bf_sys_MemInf'],1)[0]
  profiles={}
  for index in range(count):
   row=self.read_words(table+index*16,4)
   if not any(row):continue
   if row[0]!=1 or row[1]!=index or index==0:raise ValueError('Unexpected original pool profile')
   profiles[index]=row
  self.call('fs_mem_Init')
  for index,row in profiles.items():
   if self.call('rq_mem_Create',index,row[2],row[3])!=index:
    raise RuntimeError('Original memory pool create failed')
  self.pool_profiles=profiles
 def allocate_payload(self,data):
  if not hasattr(self,'pool_profiles') or 1 not in self.pool_profiles:
   raise ValueError('Original pool1 must be initialized explicitly')
  shape=self.pool_profiles[1]
  if not isinstance(data,bytes) or not data or shape[3] and len(data)>shape[2]:
   raise ValueError('Payload does not fit original pool1 block')
  pointer=self.call('rq_mem_Alloc',1,len(data))
  if pointer not in self.allocations:raise RuntimeError('Original pool allocation did not yield owned guest memory')
  self.uc.mem_write(pointer,data);return pointer
 def configure_tasks(self,aliases):
  if hasattr(self,'task_table'):raise ValueError('Task fixtures already configured')
  if (not aliases or len(set(aliases.values()))!=len(aliases) or
      any(type(k) is not int or not 0<=k<96 or type(v) is not int or not 0<v<=0xffffffff for k,v in aliases.items())):
   raise ValueError('Invalid unique guest task aliases')
  self.task_aliases=dict(aliases);self.task_table=self._allocate(96*80)
  self.tls={task:self.buffer(struct.pack('<i',-2)) for task in aliases}
  self.uc.mem_write(self.defined['bf_sys_TskMng']+4,struct.pack('<II',96,self.task_table))
  for task,alias in aliases.items():self.uc.mem_write(self.task_table+task*80+64,struct.pack('<I',alias))
  def current():
   if not self.actor.startswith('task:'):raise ValueError('No task alias for this actor')
   task=int(self.actor.split(':')[1])
   if task not in aliases:raise ValueError('Unknown task fixture')
   return task
  def tls(u,a):
   if not BIAS<=a[0]<BIAS+0x200000:raise ValueError('Invalid guest TLS descriptor')
   return self.tls[current()]
  self.trace.services['pthread_self']=lambda u,a:self.task_aliases[current()]
  self.trace.services['__tls_get_addr']=tls
 def block_object(self,task):
  if not hasattr(self,'task_aliases') or task not in self.task_aliases:raise ValueError('Task not configured')
  actor='task:'+str(task)
  queue=self.call('rq_tsk_GetBlockObj',actor=actor)
  return dict(task=task,queue=queue,
              record_value=self.read_words(self.task_table+task*80+8,1)[0])
 def state(self,queue):
  if type(queue) is not int or not 1<=queue<self.queue_count:raise ValueError('Invalid queue')
  _,table=self.read_words(self.defined['bf_sys_MsgMng'],2)
  words=self.read_words(table+queue*136,8)
  return dict(zip(('enabled','unknown','slot_bytes','capacity','count','read_index','write_index','buffer'),words))
 def create(self,queue,capacity):
  if (type(queue) is not int or queue not in [-1,*range(1,self.queue_count)] or
      type(capacity) is not int or not 1<=capacity<=4096):raise ValueError('Invalid queue shape')
  if queue!=-1 and self.state(queue)['enabled']:raise ValueError('Queue already enabled')
  return self.call('rq_msg_Create',queue,capacity,16)
 def send(self,queue,message,timeout_ms=0):
  if not isinstance(message,Message):raise ValueError('Authoritative 16-byte message required')
  self.state(queue)
  if type(timeout_ms) is not int or not 0<=timeout_ms<=60000:raise ValueError('Invalid timeout')
  result=self.call('rq_msg_SendT',queue,self.buffer(message.pack()),16,timeout_ms)
  if isinstance(result,QueueWait):
   self.advance_time(timeout_ms);result=self.resume(result)
  return result
 def receive(self,queue,timeout_ms):
  self.state(queue)
  if type(timeout_ms) is not int or not 0<=timeout_ms<=60000:raise ValueError('Invalid timeout')
  out=self.buffer(bytes(16));result=self.call('rq_msg_ReceiveT',queue,out,timeout_ms)
  if isinstance(result,QueueWait):
   self.advance_time(timeout_ms);result=self.resume(result)
  return result,Message.unpack(bytes(self.uc.mem_read(out,16))) if result==0 else None
 def poll(self,queue):
  self.state(queue);out=self.buffer(bytes(16));result=self.call('rq_msg_ReceiveP',queue,out)
  return result,Message.unpack(bytes(self.uc.mem_read(out,16))) if result==-1 else None


class OriginalQueueTransport:
 """16-byte/64-slot transport adapter for the existing gated HMI harness."""
 message_bytes=16
 capacity=64
 def __init__(self,runtime,queue):
  self.runtime=runtime;self.queue=queue
  state=runtime.state(queue)
  if state['enabled']!=1 or state['slot_bytes']!=16 or state['capacity']!=64:
   raise ValueError('Draw transport requires the original 64x16 queue shape')
 def __len__(self):return self.runtime.state(self.queue)['count']
 def send(self,message,timeout_ms=5000):return self.runtime.send(self.queue,message,timeout_ms)
 def receive_t(self,timeout_ms):return self.runtime.receive(self.queue,timeout_ms)
 def receive_p(self):return self.runtime.poll(self.queue)



class OriginalStatusTransport:
 """queue.Queue-compatible adapter with serialized original ARM operations.

 Host thread entry is locked because a Unicorn guest is not reentrant.
 Thread identity verification and startup state updates remain in the existing
 bridge; neither task bodies nor pthread_create are silently replaced.
 """
 def __init__(self,runtime):
  import threading
  self.runtime=runtime;self.lock=threading.Lock()
 def put_nowait(self,raw):
  import queue,threading
  message=Message.unpack(raw)
  with self.lock:
   result=self.runtime.call('rq_msg_SendT',1,self.runtime.buffer(message.pack()),16,0,
        actor='status-producer:'+str(threading.get_ident()))
  if result==-1:raise queue.Full
  if result!=0:raise RuntimeError('Unexpected original status send result')
 def get_nowait(self):
  import queue
  with self.lock:status,message=self.runtime.poll(1)
  if status==-2:raise queue.Empty
  if status!=-1 or message is None:raise RuntimeError('Unexpected original status receive result')
  return message.pack()


from ca01_threaded_startup import ThreadedStartupBridge

class OriginalThreadedStartupBridge(ThreadedStartupBridge):
 """Existing native host identity bridge using original ARM queue1/queue40."""
 def __init__(self,hmi,sysc,*,runtime_library,task_ids=(3,10,39,40,41)):
  super().__init__(hmi,sysc,runtime_library=runtime_library,task_ids=task_ids)
  self.original=OriginalQueueRuntime(hmi,sysc)
  image=ElfImage(hmi)
  from ca01_hmi_startup import REGISTRY_NAMES
  config=dict(zip(REGISTRY_NAMES,struct.unpack('<18I',image.read(REGISTRY,72))))
  rows={x['queue_id']:x for x in decode_queue_table(image.read(config['bf_sys_MsgInf'],96*16),96)}
  for queue_id in (1,40):self.original.create(queue_id,rows[queue_id]['capacity'])
  self.status_queue=OriginalStatusTransport(self.original)
  self.h.queue=OriginalQueueTransport(self.original,40)
 def run(self,**kwargs):
  result=super().run(**kwargs)
  result.update(scope='Native host identity fixtures + original ARM queue1 and queue40; emulated libc/pthreads',
   original_queue1_functions_executed=True,original_queue1_capacity=self.original.state(1)['capacity'],
   synthetic_status_queue_only=False,guest_pthread_services_modeled=True,
   original_queue_calls=[dict(function=x['function'],r0=x['r0'],instructions=x['trace']['instructions']) for x in self.original.history])
  result['original_hmi_queue_entries']=result.pop('native_hmi_queue_entries')
  return result


def startup_queue_demo(hmi,sysc):
 """Original queue transport to existing explicit startup model; barriers stay shut."""
 q=OriginalQueueRuntime(hmi,sysc);image=ElfImage(hmi)
 pointers=struct.unpack('<18I',image.read(REGISTRY,72))
 # Decode named pointers from the original registry, never infer configuration.
 from ca01_hmi_startup import REGISTRY_NAMES
 config=dict(zip(REGISTRY_NAMES,pointers))
 profiles=decode_queue_table(image.read(config['bf_sys_MsgInf'],96*16),96)
 rows={x['queue_id']:x for x in profiles}
 for queue in (1,40):q.create(queue,rows[queue]['capacity'])
 sequence=StartupSequence();sequence.create_resources();sequence.apply_power_state(True)
 accepted=[]
 for task in (3,10,39,40,41):
  if q.send(1,Message(0,3,task,0))!=0:raise RuntimeError('Status send failed')
 for _ in range(5):
  status,event=q.receive(1,0)
  if status!=0 or event.code!=0 or event.subcommand!=3 or event.payload or event.event in accepted:
   raise RuntimeError('Unexpected original queue status envelope')
  sequence.task_initialized(event.event);accepted.append(event.event)
 blocked=[]
 for action in (lambda:sequence.release_startup_barrier(lambda:False),
                lambda:sequence.complete_display_initialization(lambda:True)):
  try:action()
  except StartupBlocked as e:blocked.append(str(e))
  else:raise AssertionError('Missing parent/display services bypassed')
 heartbeat=Message(0,0,10,0);q.send(40,heartbeat)
 from ca01_hmi_startup import HmiHarness
 harness=HmiHarness(queue_transport=OriginalQueueTransport(q,40),
   heartbeat=lambda m:None,command=lambda m:None,diagnostic=lambda m:None,
   release_payload=lambda pool,p:None)
 harness.startup=sequence
 try:harness.step(timeout_ms=0)
 except StartupBlocked:pass
 else:raise AssertionError('Original draw transport bypassed display gate')
 if harness.draw_pending or len(harness.queue)!=1:raise AssertionError('Unready queue consumed heartbeat')
 return dict(scope='Original ARM queue operations with modeled libc/pthreads and synthetic task-status events',
  accepted_tasks=accepted,queue1_capacity=rows[1]['capacity'],draw_queue_capacity=rows[40]['capacity'],
  heartbeat_words=[0,0,10,0],draw_queue_count=q.state(40)['count'],draw_before_ready=False,
  flag1=sequence.flag1,flag2=sequence.flag2,barriers=blocked,full_startup=False,
  original_queue_functions_executed=True,original_tasks_started=False,native_pthreads_executed=False,
  original_queue_calls=[dict(function=x['function'],r0=x['r0'],instructions=x['trace']['instructions']) for x in q.history])


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--hmi',type=Path,required=True);p.add_argument('--sysc',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True)
 p.add_argument('--runtime-library',type=Path,help='Optional existing native C harness runtime for threaded integration')
 a=p.parse_args()
 h=a.hmi.read_bytes();s=a.sysc.read_bytes()
 report=dict(input_hashes={'HMI':HMI_SHA256,'SYSC':SYSC_SHA256},first_boundary=trace_create_boundary(h,s),startup=startup_queue_demo(h,s))
 if a.runtime_library:
  report['threaded_startup']=OriginalThreadedStartupBridge(h,s,runtime_library=a.runtime_library).run()
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print('Original ARM queue transport verified; parent/display remain blocked.')
if __name__=='__main__':main()
