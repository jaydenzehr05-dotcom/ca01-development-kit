#!/usr/bin/env python3
"""Original ARM task-wait/release, parent eventfd handshake and display boundary.

Runs only hash-gated guest bytes. Task manager states and parent process records
are explicit fixtures; actual ipasz.conf values and original process startup
remain unavailable. Parent eventfds are real fresh Linux objects local to this
process, never inherited radio descriptors. No readiness flags are fabricated.
"""
from __future__ import annotations
from collections import deque
import argparse,json,os,struct
from pathlib import Path
from ca01_original_queue import OriginalQueueRuntime,QueueWait,QueueBlocked,STACK
from ca01_hmi_startup import Message,ElfImage
from ca01_startup_trace import STARTUP_MODE_ADDRESS
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_PC

class TaskBarrierHarness:
 def __init__(self,hmi,sysc):
  self.q=OriginalQueueRuntime(hmi,sysc)
  self.q.ALLOWED=set(self.q.ALLOWED)|{'rq_tsk_WaitInit','rq_tsk_BlockBegin','rq_tsk_BlockEnd',
    'fc_sys_RcvInitWait','fc_sys_RcvTskCond'}
  self.q.create(1,64)
  self.q.configure_tasks({task:0x5000+task*0x100 for task in (3,10,39,40,41)})
  # Deliberately configured fixture states, not original SysResInit or pthreads.
  for task in self.q.task_aliases:self.q.uc.mem_write(self.q.task_table+task*80,b'\x02')
  self.q.uc.mem_write(STARTUP_MODE_ADDRESS,struct.pack('<I',1))
 @property
 def wait_count(self):return self.q.read_words(self.q.defined['bf_sys_TskMng'],1)[0]
 def block_queue(self,task):return self.q.read_words(self.q.task_table+task*80+8,1)[0]
 def wait_target(self,task):return self.q.read_words(self.q.task_table+task*80+4,1)[0]
 def state(self,task):return self.q.uc.mem_read(self.q.task_table+task*80,1)[0]
 def begin_wait(self,waiter,target):
  if waiter not in self.q.task_aliases or target not in self.q.task_aliases or waiter==target:
   raise ValueError('Distinct configured task fixtures required')
  wait=self.q.call('rq_tsk_WaitInit',target,actor='task:'+str(waiter))
  if not isinstance(wait,QueueWait):raise RuntimeError('Original wait did not suspend')
  status,event=self.q.receive(1,0)
  if status!=0 or event!=Message(0,5,waiter,target):raise RuntimeError('Original wait registration mismatch')
  self.q.call('fc_sys_RcvInitWait',event.event,event.payload,actor='system')
  return wait,event
 def initialize_task(self,task):
  if task not in self.q.task_aliases:raise ValueError('Unconfigured task')
  return self.q.call('fc_sys_RcvTskCond',task,0,actor='system')


class ParentRuntime(OriginalQueueRuntime):
 """Queue runtime extended only for explicitly registered local eventfds."""
 def configure_eventfds(self,allowed):
  self.allowed_fds=set(allowed);self.read_targets={};self.read_values=[];self.io=[]
  self.trace.services['read']=self._event_read
  self.trace.services['write']=self._event_write
 def _check(self,a):
  if a[0] not in self.allowed_fds or a[2]!=8:raise ValueError('Only registered 8-byte local eventfd I/O permitted')
 def _event_read(self,u,a):
  self._check(a)
  try:data=os.read(a[0],8)
  except BlockingIOError:
   result=self._suspend('eventfd_read',0,a[0],None)
   self.read_targets[self.waiting]=a[1]
   return result
  self.read_values.append(struct.unpack('<Q',data)[0]);u.mem_write(a[1],data)
  self.io.append(dict(operation='read',value=self.read_values[-1]));return 8
 def _event_write(self,u,a):
  self._check(a);data=bytes(u.mem_read(a[1],8));count=os.write(a[0],data)
  self.io.append(dict(operation='write',value=struct.unpack('<Q',data)[0]));return count
 def resume(self,w):
  if w.kind!='eventfd_read':return super().resume(w)
  if w not in self.waiters or w.consumed or w not in self.read_targets:raise ValueError('Unknown parent wait')
  try:data=os.read(w.condition,8)
  except BlockingIOError as e:raise QueueBlocked('Parent eventfd has no token') from e
  # Restore first: the original read destination is on the suspended stack.
  w.consumed=True;self.actor=w.actor;self.function=w.function
  self.uc.context_restore(w.context);self.uc.mem_write(STACK,w.stack)
  self.uc.mem_write(self.read_targets.pop(w),data);self.uc.reg_write(UC_ARM_REG_R0,8)
  self.read_values.append(struct.unpack('<Q',data)[0]);self.io.append(dict(operation='read',value=self.read_values[-1]))
  t=self.trace;t.reason=None;t.boundary={};t.instructions=0;t.emulator_steps=0
  t.entries=[];t.service_calls=[];t.tail=deque(maxlen=128)
  self.uc.emu_start(self.uc.reg_read(UC_ARM_REG_PC),t.sentinel+4,count=50000,timeout=2000000)
  reason=t.reason or ('instruction_limit' if t.emulator_steps>=50000 else 'time_limit')
  return self._record(w.function,dict(returned=reason=='returned',halt_reason=reason,boundary=t.boundary,
    instructions=t.instructions,service_calls=t.service_calls,function_entries=t.entries,
    last_instruction_addresses=list(t.tail)))


class ParentHandshake:
 """Explicit process-table fixture around original SycSynWait and getters.

 This proves the handshake contract only. It never calls SycSynInit, supplies
 unknown post-init callbacks, or sets global startup/display readiness.
 """
 def __init__(self,hmi,sysc,*,process_id,expected_token):
  if type(process_id) is not int or not 1<=process_id<32:raise ValueError('Bounded positive process id required')
  if type(expected_token) is not int or not -0x80000000<=expected_token<0x80000000:raise ValueError('Signed32 token fixture required')
  self.q=ParentRuntime(hmi,sysc);self.process_id=process_id;self.expected_token=expected_token
  self.protocol_returned=False;self.started=False;self.closed=False
  self.parent_fd=os.eventfd(0,os.EFD_NONBLOCK|os.EFD_CLOEXEC)
  try:self.child_fd=os.eventfd(0,os.EFD_NONBLOCK|os.EFD_CLOEXEC)
  except BaseException:os.close(self.parent_fd);raise
  try:self._configure_records(process_id,expected_token)
  except BaseException:
   self.close();raise
 def _configure_records(self,process_id,expected_token):
  self.q.configure_eventfds((self.parent_fd,self.child_fd))
  self.q.ALLOWED=set(self.q.ALLOWED)|{'rq_prc_GetPrcid','fc_sys_SycSynWait'}
  # These are synthetic process/shared descriptor records, NOT recovered config.
  records=self.q.buffer(bytes(32*64));descriptors=self.q.buffer(bytes(0x300))
  self.q.uc.mem_write(records+0x44,struct.pack('<i',expected_token))
  self.q.uc.mem_write(self.q.defined['tb_sys_PrcInf'],struct.pack('<I',records))
  self.q.uc.mem_write(self.q.defined['bf_zsy_PrcPid'],struct.pack('<I',process_id))
  self.q.uc.mem_write(self.q.defined['bf_zsy_PrcMng'],struct.pack('<I',descriptors))
  self.q.uc.mem_write(descriptors+0x80+4*process_id,struct.pack('<I',self.parent_fd))
  self.q.uc.mem_write(descriptors+0x100+4*process_id,struct.pack('<I',self.child_fd))
  if self.q.call('rq_prc_GetPrcid')!=process_id:
   self.close();raise RuntimeError('Original process identity fixture not recognized')
 @property
 def read_values(self):return self.q.read_values
 def signal(self,value):
  if self.closed:raise ValueError('Closed fixture')
  os.eventfd_write(self.child_fd,value)
 def begin(self):
  if self.closed or self.started:raise ValueError('Handshake must run once on an open fixture')
  self.started=True;result=self.q.call('fc_sys_SycSynWait',actor='parent-child')
  self.protocol_returned=not isinstance(result,QueueWait);return result
 def resume(self,wait):
  if self.closed:raise ValueError('Closed fixture')
  result=self.q.resume(wait);self.protocol_returned=not isinstance(result,QueueWait);return result
 def parent_notification(self):return os.eventfd_read(self.parent_fd)
 def close(self):
  if not self.closed:
   os.close(self.parent_fd);os.close(self.child_fd);self.closed=True
 def __enter__(self):return self
 def __exit__(self,*args):self.close()


def display_init_boundary(hmi,sysc):
 """Run isolated original display initializer wrapper to its missing import.

 Not a complete execution of task39. Initialized zero descriptor fields do
 not imply usable display memory or an original display-manager provider.
 """
 q=OriginalQueueRuntime(hmi,sysc);image=ElfImage(hmi)
 q.trace.executable_ranges.extend((s['p_vaddr'],s['p_vaddr']+s['p_memsz']) for s in image.segments if s['p_flags']&1)
 imports={s['st_value']:s.name for s in image.elf.get_section_by_name('.dynsym').iter_symbols()
          if s['st_shndx']=='SHN_UNDEF' and s['st_value']}
 q.trace.imports.update(imports)
 result=q.trace.run(0x16094,0)
 return dict(result,display_ready=False,scope='Isolated original display wrapper, not full task39',
             original_wrapper='0x16094',provider_replaced=False)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--hmi',type=Path,required=True);p.add_argument('--sysc',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 hmi=a.hmi.read_bytes();sysc=a.sysc.read_bytes()
 h=TaskBarrierHarness(hmi,sysc);wait,event=h.begin_wait(40,39);private=h.block_queue(40)
 h.initialize_task(39);h.q.resume(wait)
 with ParentHandshake(hmi,sysc,process_id=3,expected_token=42) as parent:
  blocked=parent.begin();parent.signal(41);blocked=parent.resume(blocked)
  wrong_rejected=isinstance(blocked,QueueWait)
  parent.signal(42);parent.resume(blocked)
  handshake=dict(scope='Explicit synthetic configuration with real local eventfds',
    fixture_process_id=3,fixture_expected_token=42,wrong_token_rejected=wrong_rejected,
    parent_notification=parent.parent_notification(),read_values=parent.read_values,
    protocol_returned=parent.protocol_returned,authentic_config_recovered=False,
    global_readiness_modified=False,io=parent.q.io)
 report=dict(task_wait=dict(original_message=[event.code,event.subcommand,event.event,event.payload],
  private_queue=private,private_queue_deleted=h.q.state(private)['enabled']==0,
  wait_count=h.wait_count,waiting_task_state=h.state(40),target_state=h.state(39),
  original_calls=[dict(function=x['function'],instructions=x['trace']['instructions']) for x in h.q.history]),
  parent_handshake=handshake,display=display_init_boundary(hmi,sysc),full_startup=False)
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print('Original task wait/release and local eventfd contract verified; full startup remains blocked.')
if __name__=='__main__':main()
