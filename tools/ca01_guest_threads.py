#!/usr/bin/env python3
"""Bounded cooperative ARM pthread adapter for recovered CA01 task entrypoints.

Original task init/create/start, queues, flags and HMI entrypoints execute in
one hash-gated Unicorn guest. pthread configuration and scheduling are explicit
models, never host pthread calls. Each guest has an independent stack/TLS cell.
Missing imports/data/unsupported lifecycle operations stop without readiness.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
import argparse,json,struct,hashlib
from pathlib import Path
from ca01_original_queue import OriginalQueueRuntime,QueueWait,QueueBlocked,signed
from ca01_hmi_startup import ElfImage,REGISTRY_NAMES
from ca01_startup_trace import REGISTRY,HMI_SHA256,SYSC_SHA256,STARTUP_MODE_ADDRESS
from unicorn import UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UcError
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
 UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
 UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC)

GROUP_SHA256='c87538f1de097ef01c8f169971d922068a9f7c2c87faaa1fb9a036cd14dc87ef'
TASKS=(3,10,39,40,41)
STACK_SIZE=0x10000

@dataclass
class GuestThread:
 task:int
 alias:int
 entry:int
 policy:int
 priority:int
 stack_base:int
 tls:int
 context:object
 status:str='runnable'
 wait:QueueWait|None=None
 name:str=''
 cancel_type:int=0
 niceness:int=0
 total_instructions:int=0
 last:dict|None=None

class GuestPthreadBridge(OriginalQueueRuntime):
 def __init__(self,hmi,sysc,*,max_threads=5,group_data=None):
  if group_data is not None and hashlib.sha256(group_data).hexdigest()!=GROUP_SHA256:raise ValueError('Group canonical SHA-256 mismatch')
  if type(max_threads) is not int or not 1<=max_threads<=len(TASKS):raise ValueError('Thread limit must be1..5')
  self.external_ranges=[];self.threads={};self.attrs={};self._active=None
  self.max_threads=max_threads;self.epoch_ns=1000_000_000_000
  super().__init__(hmi,sysc)
  self.ALLOWED=set(self.ALLOWED)|{'fs_tsk_Init','rq_tsk_Create','rq_tsk_Start','fc_sys_AccOnStop',
   'fs_flg_Init','rq_flg_Create','rq_flg_Set','rq_tsk_GetTid','rq_tsk_WaitInit',
   'rq_tsk_BlockEnd','fc_sys_RcvInitWait','fc_sys_RcvTskCond'}
  self.image=ElfImage(hmi)
  self.registry=dict(zip(REGISTRY_NAMES,struct.unpack('<18I',self.image.read(REGISTRY,72))))
  self._bind_hmi()
  self.group_binding=self._bind_group(group_data) if group_data is not None else None
  self.trace.services.update({'pthread_attr_init':self._attr_init,
   'pthread_attr_setschedpolicy':self._attr_policy,'pthread_attr_setschedparam':self._attr_priority,
   'pthread_attr_setinheritsched':self._attr_inherit,'pthread_create':self._create,
   'pthread_self':self._self,'__tls_get_addr':self._tls,'pthread_setcanceltype':self._cancel_type,
   'syscall':self._syscall,'prctl':self._prctl,'pthread_exit':self._exit,
   'pthread_getschedparam':self._get_sched,'pthread_setschedparam':self._set_sched,
   'nice':self._nice,'pthread_cond_broadcast':self._signal})
  self.call('fs_tsk_Init')
  count,self.task_table=self.read_words(self.defined['bf_sys_TskMng']+4,2)
  if count!=96:raise RuntimeError('Original task count changed')
  self.configs={}
  for task in TASKS:
   address=self.registry['bf_sys_TskInf']+48*task
   row=self.read_words(address,12)
   if row[0]!=1 or row[7]!=task:raise RuntimeError('Unexpected original task profile')
   self.configs[task]=row
   if self.call('rq_tsk_Create',task,address)!=task:raise RuntimeError('Original task create failed')
  self.call('fs_flg_Init')
  for index in range(32):
   enabled,identity=self.read_words(self.registry['bf_sys_FlgInf']+8*index,2)
   if not enabled:continue
   if enabled!=1 or identity!=index or index==0:raise RuntimeError('Unexpected original flag profile')
   self.call('rq_flg_Create',index)
  self.create(1,64);self.create(40,64);self.create(41,16)
  # Explicit fixture for the known mode1 parent barrier; not parsed ipasz.conf.
  self.uc.mem_write(STARTUP_MODE_ADDRESS,struct.pack('<I',1))
 def _bind_hmi(self):
  from elftools.elf.relocation import RelocationSection
  self.trace.executable_ranges.extend((s['p_vaddr'],s['p_vaddr']+s['p_memsz']) for s in self.image.segments if s['p_flags']&1)
  addresses={name:address for address,name in self.trace.imports.items()}
  next_trap=0x62000000
  for section in self.image.elf.iter_sections():
   if not isinstance(section,RelocationSection):continue
   table=self.image.elf.get_section(section['sh_link'])
   for rel in section.iter_relocations():
    sym=table.get_symbol(rel['r_info_sym']);name=sym.name;dst=rel['r_offset'];kind=rel['r_info_type']
    if kind==20: # R_ARM_COPY cannot be replaced by zero-filled original BSS.
     self.external_ranges.append((dst,dst+sym['st_size'],name));continue
    if kind not in (21,22):raise ValueError('Unsupported original HMI relocation')
    if name in self.defined:value=self.defined[name]
    else:
     if name not in addresses:
      addresses[name]=next_trap;self.uc.mem_map(next_trap,4096)
      self.trace.imports[next_trap]=name;next_trap+=4096
     value=addresses[name]
    self.uc.mem_write(dst,struct.pack('<I',value))
  def guard(u,access,address,size,value,data):
   for start,end,name in self.external_ranges:
    if address<end and start<address+size:
     self.trace._halt('unimplemented_relocation',symbol=name,address=hex(address));return
  self.uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,guard)
 def _bind_group(self,data):
  """Load the recovered provider with real ELF relocations and COPY ownership."""
  from elftools.elf.relocation import RelocationSection
  image=ElfImage(data);bias=0x20000000
  regions=[]
  for segment in image.segments:
   start=(bias+segment['p_vaddr'])&~4095
   end=(bias+segment['p_vaddr']+segment['p_memsz']+4095)&~4095
   if regions and start<=regions[-1][1]:regions[-1]=(regions[-1][0],max(end,regions[-1][1]))
   else:regions.append((start,end))
  for start,end in regions:self.uc.mem_map(start,end-start)
  for segment in image.segments:
   start=bias+segment['p_vaddr'];self.uc.mem_write(start,segment.data())
   if segment['p_flags']&1:self.trace.executable_ranges.append((start,start+segment['p_memsz']))
  hmi={x.name:x['st_value'] for x in self.image.elf.get_section_by_name('.dynsym').iter_symbols() if x.name and x['st_shndx']!='SHN_UNDEF'}
  symbols={x.name:x for x in image.elf.get_section_by_name('.dynsym').iter_symbols() if x.name and x['st_shndx']!='SHN_UNDEF'}
  exports={name:bias+x['st_value'] for name,x in symbols.items()}
  for name,x in symbols.items():
   if x['st_info']['type']=='STT_FUNC':self.trace.symbols[exports[name]]=name
  copied=[];unresolved=[]
  for start,end,name in self.external_ranges:
   symbol=symbols.get(name)
   if symbol is None:unresolved.append((start,end,name));continue
   if symbol['st_size']!=end-start:raise ValueError('Original COPY symbol size mismatch')
   self.uc.mem_write(start,bytes(self.uc.mem_read(exports[name],end-start)));copied.append(name)
  self.external_ranges=unresolved
  addresses={name:address for address,name in self.trace.imports.items()};next_trap=0x64000000
  def resolve(name):
   nonlocal next_trap
   # Executable COPY definitions take precedence, as in normal ELF interposition.
   if name in hmi:return hmi[name]
   if name in self.defined:return self.defined[name]
   if name in exports:return exports[name]
   if name not in addresses:
    addresses[name]=next_trap;self.uc.mem_map(next_trap,4096)
    self.trace.imports[next_trap]=name;next_trap+=4096
   return addresses[name]
  for section in image.elf.iter_sections():
   if not isinstance(section,RelocationSection):continue
   table=image.elf.get_section(section['sh_link'])
   for rel in section.iter_relocations():
    destination=bias+rel['r_offset'];kind=rel['r_info_type'];sym=table.get_symbol(rel['r_info_sym'])
    addend=self.read_words(destination,1)[0]
    if kind==23:value=bias+addend
    elif kind in (2,21,22):
     value=resolve(sym.name)
     if kind==2:value+=addend
    else:raise ValueError('Unsupported original group relocation')
    self.uc.mem_write(destination,struct.pack('<I',value&0xffffffff))
  for section in self.image.elf.iter_sections():
   if not isinstance(section,RelocationSection):continue
   table=self.image.elf.get_section(section['sh_link'])
   for rel in section.iter_relocations():
    if rel['r_info_type'] in (21,22):
     sym=table.get_symbol(rel['r_info_sym'])
     if sym.name in exports:self.uc.mem_write(rel['r_offset'],struct.pack('<I',resolve(sym.name)))
  return dict(sha256=GROUP_SHA256,bias=hex(bias),copy_symbols=copied,
              rq_grp_Init=hex(exports['rq_grp_Init']),loader='GOT/REL/COPY relocation; no text patch')
 def _check_external(self,p,n):
  for start,end,name in self.external_ranges:
   if p<end and start<p+n:raise RuntimeError('Unprovided original COPY relocation: '+name)
 def _memcpy(self,u,a):
  self._check_external(a[0],a[2]);self._check_external(a[1],a[2])
  if a[1]==0 and a[2]:raise RuntimeError('Uninitialized NULL guest memcpy source')
  return super()._memcpy(u,a)
 def _memset(self,u,a):
  self._check_external(a[0],a[2]);return super()._memset(u,a)
 def _clock(self,u,a):
  if a[0] not in (0,1):raise ValueError('Only realtime/monotonic clock models available')
  value=self.now_ns if a[0]==0 else self.now_ns-self.epoch_ns
  u.mem_write(a[1],struct.pack('<ii',*divmod(value,1_000_000_000)));return 0
 def _current(self):
  if not self.actor.startswith('task:'):raise ValueError('No created guest thread for actor')
  task=int(self.actor.split(':')[1])
  if task not in self.threads:raise ValueError('Guest thread was not created')
  return self.threads[task]
 def _attr_init(self,u,a):
  u.mem_read(a[0],36)
  self.attrs[a[0]]=dict(owner=self.actor,policy=0,priority=0,inherit=0,valid=True);return 0
 def _attr(self,p):
  attr=self.attrs.get(p)
  if attr is None or attr['owner']!=self.actor:raise ValueError('Uninitialized or foreign pthread attributes')
  return attr
 def _attr_policy(self,u,a):
  attr=self._attr(a[0])
  if a[1] not in (0,1):attr['valid']=False;return 22
  attr['policy']=a[1];return 0
 def _valid_sched(self,policy,priority):return policy==0 and priority==0 or policy==1 and 1<=priority<=99
 def _attr_priority(self,u,a):
  attr=self._attr(a[0]);value=struct.unpack('<i',u.mem_read(a[1],4))[0]
  if not self._valid_sched(attr['policy'],value):attr['valid']=False;return 22
  attr['priority']=value;return 0
 def _attr_inherit(self,u,a):
  attr=self._attr(a[0])
  if a[1]!=1:attr['valid']=False;return 22
  attr['inherit']=a[1];return 0
 def _create(self,u,a):
  attr=self._attr(a[1]);delta=a[0]-(self.task_table+64)
  task=delta//80
  if (delta%80 or task not in self.configs or a[2]!=self.configs[task][2] or a[3]!=0 or
      not attr['valid'] or attr['inherit']!=1):return 22
  if task in self.threads or len(self.threads)>=self.max_threads:return 11 # EAGAIN, no phantom child.
  index=len(self.threads);alias=0x1001+index
  base=0x71000000+index*STACK_SIZE;u.mem_map(base,STACK_SIZE)
  tls=self.buffer(struct.pack('<i',-2)+bytes(252))
  parent=u.context_save()
  try:
   for reg in (UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,
    UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12):u.reg_write(reg,0)
   u.reg_write(UC_ARM_REG_SP,base+STACK_SIZE-0x1000);u.reg_write(UC_ARM_REG_LR,self.trace.sentinel)
   u.reg_write(UC_ARM_REG_PC,a[2]);u.reg_write(UC_ARM_REG_R0,a[3]);context=u.context_save()
  finally:u.context_restore(parent)
  self.threads[task]=GuestThread(task,alias,a[2],attr['policy'],attr['priority'],base,tls,context)
  u.mem_write(a[0],struct.pack('<I',alias))
  return 0 # A concrete runnable guest context exists before this return.
 def _self(self,u,a):return self._current().alias
 def _tls(self,u,a):
  caller=u.reg_read(UC_ARM_REG_LR);entry=self.defined['rq_tsk_GetTid']
  if not entry<=caller<entry+256:raise ValueError('Unverified original TLS caller')
  return self._current().tls
 def _cancel_type(self,u,a):
  thread=self._current()
  if a[0] not in (0,1):return 22
  if a[1]:u.mem_write(a[1],struct.pack('<I',thread.cancel_type))
  thread.cancel_type=a[0];return 0
 def _syscall(self,u,a):
  if a[0]!=224:raise ValueError('Only virtual ARM gettid is implemented')
  return self._current().alias
 def _prctl(self,u,a):
  if a[0]!=15:raise ValueError('Only virtual PR_SET_NAME is implemented')
  self._check_external(a[1],16)
  self._current().name=bytes(u.mem_read(a[1],16)).split(b'\0')[0][:15].decode('utf8','replace');return 0
 def _exit(self,u,a):
  self._current();self.trace._halt('guest_thread_exit',return_value=a[0]);return 0
 def _find_alias(self,alias):
  for thread in self.threads.values():
   if thread.alias==alias:return thread
  raise ValueError('Unknown guest pthread alias')
 def _get_sched(self,u,a):
  thread=self._find_alias(a[0]);u.mem_write(a[1],struct.pack('<i',thread.policy))
  u.mem_write(a[2],struct.pack('<i',thread.priority));return 0
 def _set_sched(self,u,a):
  thread=self._find_alias(a[0]);priority=struct.unpack('<i',u.mem_read(a[2],4))[0]
  if not self._valid_sched(a[1],priority):return 22
  thread.policy=a[1];thread.priority=priority;return 0
 def _nice(self,u,a):
  thread=self._current();thread.niceness=max(-20,min(19,thread.niceness+signed(a[0])));return thread.niceness
 def flag_value(self,flag):
  _,table=self.read_words(self.defined['bf_sys_FlgMng'],2)
  return self.read_words(table+flag*0x78+12,1)[0]
 def flag_condition(self,flag):
  _,table=self.read_words(self.defined['bf_sys_FlgMng'],2);return table+flag*0x78+0x30
 def start_task(self,task):
  if self._active is not None:raise RuntimeError('No reentrant scheduler entry')
  if type(task) is not int or task not in self.configs or task in self.threads:raise ValueError('Distinct configured task required')
  self.call('fc_sys_AccOnStop',task,actor='manager')
  if task not in self.threads:raise RuntimeError('Original start did not schedule a guest thread')
  return self.threads[task]
 def probe_identity(self,task):
  if task not in self.threads or self._active is not None:raise ValueError('Created idle guest context required')
  return self.call('rq_tsk_GetTid',actor='task:'+str(task))
 def runnable_order(self):
  ready=[t for t in self.threads.values() if t.status=='runnable']
  return [t.task for t in sorted(ready,key=lambda t:(-t.policy,-t.priority,t.alias))]
 def _execute(self,thread,instruction_limit):
  if type(instruction_limit) is not int or not 1<=instruction_limit<=50000:raise ValueError('Instruction bound must be1..50000')
  t=self.trace;t.reason=None;t.boundary={};t.instructions=0;t.emulator_steps=0
  t.entries=[];t.service_calls=[];t.tail=deque(maxlen=128)
  error=None
  try:self.uc.emu_start(self.uc.reg_read(UC_ARM_REG_PC),t.sentinel+4,count=instruction_limit,timeout=2000000)
  except UcError as e:error=str(e)
  reason=t.reason or ('unicorn_error' if error else 'instruction_limit' if t.emulator_steps>=instruction_limit else 'time_limit')
  thread.context=self.uc.context_save();thread.total_instructions+=t.instructions
  if reason=='queue_service_wait':
   w=self.waiting;w.context=thread.context;w.stack=bytes(self.uc.mem_read(thread.stack_base,STACK_SIZE))
   w.guest_task=thread.task;self.waiters.append(w);self.waiting=None;thread.wait=w;thread.status='waiting'
  elif reason in ('returned','guest_thread_exit'):thread.status='exited'
  elif reason=='instruction_limit':thread.status='runnable'
  else:thread.status='blocked'
  result=dict(task=thread.task,entry=hex(thread.entry),status=thread.status,halt_reason=reason,
    instructions=t.instructions,total_instructions=thread.total_instructions,boundary=t.boundary,
    service_calls=list(t.service_calls),function_entries=list(t.entries),error=error,display_ready=bool(self.flag_value(2)),
    stop_pc=hex(self.uc.reg_read(UC_ARM_REG_PC)))
  if reason=='service_error':
   result['boundary']=dict(t.boundary,arguments=[self.uc.reg_read(reg) for reg in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)],caller_return=hex(self.uc.reg_read(UC_ARM_REG_LR)))
  thread.last=result;return result
 def run_task(self,task,*,instruction_limit=50000):
  if self._active is not None:raise RuntimeError('No reentrant scheduler entry')
  thread=self.threads[task]
  if thread.status!='runnable':raise ValueError('Guest is not runnable')
  self._active=thread;self.actor='task:'+str(task);self.function='HMI_task'+str(task)
  try:self.uc.context_restore(thread.context);return self._execute(thread,instruction_limit)
  finally:self._active=None
 def resume_task(self,task,*,instruction_limit=50000):
  if type(instruction_limit) is not int or not 1<=instruction_limit<=50000:raise ValueError('Instruction bound must be1..50000')
  if self._active is not None:raise RuntimeError('No reentrant scheduler entry')
  thread=self.threads[task];w=thread.wait
  if thread.status!='waiting' or w is None or w.consumed:raise ValueError('Guest has no pending wait')
  if self.mutexes.get(w.mutex,'missing') is not None:raise QueueBlocked('Guest mutex not available')
  signaled=w.kind=='mutex' or self.conditions.get(w.condition,-1)>w.generation
  expired=w.deadline_ns is not None and self.now_ns>=w.deadline_ns
  if not signaled and not expired:raise QueueBlocked('No guest signal or elapsed deadline')
  self.mutexes[w.mutex]=w.actor;w.consumed=True;thread.wait=None
  self._active=thread;self.actor=w.actor;self.function=w.function
  try:
   self.uc.context_restore(w.context);self.uc.mem_write(thread.stack_base,w.stack)
   self.uc.reg_write(UC_ARM_REG_R0,0 if signaled else 110)
   return self._execute(thread,instruction_limit)
  finally:self._active=None
 def resume(self,wait):
  if hasattr(wait,'guest_task'):
   if wait is not self.threads[wait.guest_task].wait:raise ValueError('Stale guest wait')
   return self.resume_task(wait.guest_task)
  return super().resume(wait)
 def report(self):
  return dict(scope='Cooperative guest pthread model executing original ARM tasks; not native pthreads',
   native_pthreads=False,full_startup=False,display_ready=bool(self.flag_value(2)),
   fixture_startup_mode=1,startup_mode_address=hex(STARTUP_MODE_ADDRESS),authentic_parent_sync=False,group_binding=self.group_binding,
   threads=[dict(task=t.task,alias=hex(t.alias),entry=hex(t.entry),policy=t.policy,priority=t.priority,
    stack=hex(t.stack_base),tls=hex(t.tls),name=t.name,status=t.status,last=t.last) for t in self.threads.values()])


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--hmi',type=Path,required=True);p.add_argument('--sysc',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True)
 p.add_argument('--group',type=Path,help='Optional hash-verified recovered group library')
 a=p.parse_args()
 hmi=a.hmi.read_bytes();sysc=a.sysc.read_bytes();group=a.group.read_bytes() if a.group else None
 cases={};fixture_cases={}
 for task in (39,40,41):
  bridge=GuestPthreadBridge(hmi,sysc,group_data=group)
  bridge.start_task(task);baseline=bridge.run_task(task);cases[str(task)]=bridge.report()
  if baseline['status']=='waiting':
   bridge.call('rq_flg_Set',1,1) # Explicit exploration fixture; never authentic parent success.
   bridge.resume_task(task);fixture_cases[str(task)]=bridge.report()
 group_dependency=None
 if group is not None:
  bridge=GuestPthreadBridge(hmi,sysc,group_data=group)
  for task in (39,10):bridge.start_task(task);bridge.run_task(task)
  bridge.call('rq_flg_Set',1,1)
  bridge.resume_task(39);bridge.resume_task(10);messages=[]
  while True:
   status,event=bridge.poll(1)
   if status==-2:break
   messages.append([event.code,event.subcommand,event.event,event.payload])
   if event.subcommand==3:bridge.call('fc_sys_RcvTskCond',event.event,event.payload,actor='system')
   elif event.subcommand==5:bridge.call('fc_sys_RcvInitWait',event.event,event.payload,actor='system')
   else:raise RuntimeError('Unexpected original status message')
  bridge.resume_task(39)
  group_dependency=dict(scope='Explicit parent-ready fixture plus original group dependency messages',
                         messages=messages,result=bridge.report())
 report=dict(input_hashes={'HMI':HMI_SHA256,'SYSC':SYSC_SHA256,'GROUP':GROUP_SHA256 if group else None},
  parent_barrier_held_cases=cases,explicit_parent_ready_fixture_cases=fixture_cases,
  group_dependency_release=group_dependency,authentic_parent_sync=False,full_startup=False)
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print('Original task entrypoints executed with bounded guest pthread contexts; full startup remains blocked.')
if __name__=='__main__':main()
