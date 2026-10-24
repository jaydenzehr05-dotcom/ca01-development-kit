#!/usr/bin/env python3
"""Original producer config parser and isolated original parent semaphore loop.

Configuration bytes/names are explicit synthetic fixtures. Actual ipasz.conf,
parent boot, real semaphore namespace and valid flash-device state are absent.
This probe does not bypass those requirements or perform host IPC/device I/O.
"""
from __future__ import annotations
import argparse,hashlib,json,re,struct
from pathlib import Path
from ca01_common_memory import CommonMemoryProbe,FUNCTIONS
from ca01_hmi_startup import ElfImage
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_SP,UC_ARM_REG_PC
SYSTEM_SHA256='57d4971846c30f2cf1bd964d6c00c05b1bcc64121df48d1b5da9c427aec5ac26'
HEAP=0x50000000
PSM_START=0x2f410
PSM_END=0x2f4f4

def configuration_fixture(slots,*,numeric_id=51):
 slots=tuple(slots)
 if not slots or any(type(x)is not int or not 0<=x<64 for x in slots) or len(set(slots))!=len(slots):raise ValueError('Distinct slots in 0..63 required')
 if type(numeric_id)is not int or not 0<=numeric_id<=0x7fffffff:raise ValueError('Bounded nonnegative numeric field required')
 lines=['[PSM]',f'num={max(slots)+1}']
 for index in range(max(slots)+1):
  lines.append(f'use={"true" if index in slots else "false"} psmid={numeric_id} name=/ca01_fixture_{index:02d}')
 return ('\n'.join(lines)+'\n').encode('ascii')

class VirtualNamedSemaphores:
 def __init__(self,p):self.p=p;self.objects={};self.handles={};self.events=[]
 def unlink(self,name):
  if not name.startswith('/ca01_fixture_'):raise ValueError('Only explicit synthetic semaphore names supported')
  existed=name in self.objects
  if existed:del self.objects[name]
  else:self.p.uc.mem_write(self.p.errno,struct.pack('<I',2))
  self.events.append(dict(operation='unlink',name=name,result=0 if existed else -1));return 0 if existed else -1
 def open(self,name,flags,mode,initial):
  if not re.fullmatch(r'/ca01_fixture_[0-9]{2}',name) or flags!=0xc2 or mode!=0o666 or initial!=1:
   raise ValueError('Unsupported virtual semaphore creation contract')
  if name in self.objects:raise ValueError('Exclusive semaphore already exists')
  handle=self.p.allocate(32);state=dict(name=name,count=initial)
  self.objects[name]=state;self.handles[handle]=state
  self.events.append(dict(operation='open',name=name,flags=flags,mode=mode,initial=initial,handle=hex(handle)));return handle
 def wait(self,handle,deadline):
  if handle not in self.handles:raise ValueError('Unowned semaphore handle')
  state=self.handles[handle];sec,nsec=struct.unpack('<ii',self.p.uc.mem_read(deadline,8))
  if not 0<=nsec<1_000_000_000 or sec<1000:raise ValueError('Invalid original deadline')
  if state['count']:
   state['count']-=1;result=0
  else:
   # One isolated actor, no concurrent posts. Advance to original deadline.
   self.p.now_ns=max(self.p.now_ns,sec*1_000_000_000+nsec)
   self.p.uc.mem_write(self.p.errno,struct.pack('<I',110));result=-1
  self.events.append(dict(operation='take',name=state['name'],result=result,count=state['count'],deadline=[sec,nsec]));return result
 def post(self,handle):
  if handle not in self.handles:raise ValueError('Unowned semaphore handle')
  state=self.handles[handle]
  if state['count']==0x7fffffff:raise ValueError('Semaphore overflow')
  state['count']+=1;self.events.append(dict(operation='give',name=state['name'],count=state['count']));return 0
 def count(self,name):return self.objects[name]['count']

class PsmStartupProbe(CommonMemoryProbe):
 APPROVED=FUNCTIONS|{'fs_cnf_Load','fs_psm_Init','rq_psm_Create','rq_psm_Take','rq_psm_Give'}
 def __init__(self,sysp,*,flash_data=None):
  super().__init__(sysp,role='producer',flash_data=flash_data)
  self.uc.mem_map(HEAP,0x100000);self.next_heap=HEAP;self.errno=self.allocate(4)
  self.named=VirtualNamedSemaphores(self);self.configuration=None;self.configuration_label=None
  self.file=0;self.file_offset=0;self.file_closed=False;self.token_next=0;self.created_slots=[]
  self.now_ns=1000_000_000_000;self.parent_mapped=False;self.in_parent_slice=False
  self.trace.services.update({'malloc':lambda u,a:self.allocate(a[0]),'atoi':self._atoi,
   'strtok':self._strtok,'strcpy':self._strcpy,'fgets':self._fgets,'fclose':self._fclose,
   'sem_unlink':lambda u,a:self.named.unlink(self._string(a[0])),
   'sem_open':lambda u,a:self.named.open(self._string(a[0]),a[1],a[2],a[3]),
   'sem_timedwait':lambda u,a:self.named.wait(a[0],a[1]),'sem_post':lambda u,a:self.named.post(a[0]),
   '__errno_location':lambda u,a:self.errno,'clock_gettime':self._clock})
 def allocate(self,n):
  if type(n)is not int or not 0<n<=8192 or self.next_heap+((n+15)&~15)>HEAP+0x100000:raise ValueError('Bounded parser allocation exceeded')
  p=self.next_heap;self.next_heap+=(n+15)&~15;self.uc.mem_write(p,bytes(n));return p
 def set_configuration_fixture(self,data,label):
  if self.configuration is not None or not isinstance(label,str) or not label.strip():raise ValueError('New explicitly labeled fixture required')
  if not isinstance(data,bytes) or len(data)>8192:raise ValueError('Bounded bytes required')
  lines=data.decode('ascii').splitlines()
  if len(lines)<3 or lines[0]!='[PSM]' or not re.fullmatch(r'num=[0-9]{1,2}',lines[1]) or not 1<=len(lines)-2<=64:
   raise ValueError('Only bounded synthetic PSM configuration supported')
  if int(lines[1][4:])!=len(lines)-2:raise ValueError('Synthetic row count mismatch')
  for line in lines[2:]:
   if not re.fullmatch(r'use=(true|false) psmid=[0-9]{1,10} name=/ca01_fixture_[0-9]{2}',line) or len(line)>100:
    raise ValueError('Unsafe or unsupported fixture record')
  self.configuration=data;self.configuration_label=label;self.trace.services['fopen']=self._fopen
 def _fopen(self,u,a):
  if self._string(a[0])!='ipasz.conf' or self._string(a[1])!='r' or self.file:raise ValueError('Unsupported fixture fopen')
  self.file=self.allocate(32);return self.file
 def _fgets(self,u,a):
  if a[2]!=self.file or not self.file or self.file_closed or a[1]!=128:raise ValueError('Unsupported fixture fgets')
  if self.file_offset>=len(self.configuration):return 0
  end=min(self.file_offset+a[1]-1,len(self.configuration));nl=self.configuration.find(b'\n',self.file_offset,end)
  if nl!=-1:end=nl+1
  data=self.configuration[self.file_offset:end];u.mem_write(a[0],data+b'\0');self.file_offset=end;return a[0]
 def _fclose(self,u,a):
  if a[0]!=self.file or self.file_closed:raise ValueError('Unsupported fclose')
  self.file_closed=True;return 0
 def _atoi(self,u,a):
  match=re.match(r'\s*[+-]?[0-9]+',self._string(a[0]));value=int(match.group()) if match else 0
  if not -0x80000000<=value<=0x7fffffff:raise ValueError('Fixture integer overflow')
  return value
 def _strcpy(self,u,a):
  data=self._string(a[1]).encode('ascii')
  if len(data)>23:raise ValueError('Original PSM name field overflow prevented')
  u.mem_write(a[0],data+b'\0');return a[0]
 def _strtok(self,u,a):
  delimiters=self._string(a[1]).encode('ascii');p=a[0] or self.token_next
  if not p:return 0
  for _ in range(128):
   byte=u.mem_read(p,1)[0]
   if byte==0:self.token_next=0;return 0
   if byte not in delimiters:break
   p+=1
  else:raise ValueError('Bounded tokenizer exceeded')
  start=p
  for _ in range(128):
   byte=u.mem_read(p,1)[0]
   if byte==0:self.token_next=0;return start
   if byte in delimiters:u.mem_write(p,b'\0');self.token_next=p+1;return start
   p+=1
  raise ValueError('Bounded token exceeded')
 def _clock(self,u,a):
  if a[0]!=0:raise ValueError('Only original realtime semaphore clock supported')
  u.mem_write(a[1],struct.pack('<ii',*divmod(self.now_ns,1_000_000_000)));return 0
 def record(self,slot):
  if type(slot)is not int or not 0<=slot<64:raise ValueError('Invalid PSM slot')
  table=self.pointer('tb_sys_PsmInf');p=table+32*slot
  enabled,numeric=struct.unpack('<II',self.uc.mem_read(p,8))
  return dict(slot=slot,enabled=enabled,numeric_id=numeric,name=self._string(p+8))
 def run_parent_psm_slice(self,system):
  if hashlib.sha256(system).hexdigest()!=SYSTEM_SHA256:raise ValueError('Canonical parent SHA-256 mismatch')
  if self.parent_mapped or self.configuration is None or not self.file_closed:raise ValueError('Original parsed fixture required; one parent slice per guest')
  image=ElfImage(system);intervals=[]
  for seg in image.segments:
   start=seg['p_vaddr']&~4095;end=(seg['p_vaddr']+seg['p_memsz']+4095)&~4095
   if intervals and start<=intervals[-1][1]:intervals[-1]=(intervals[-1][0],max(end,intervals[-1][1]))
   else:intervals.append((start,end))
  for start,end in intervals:self.uc.mem_map(start,end-start)
  for seg in image.segments:self.uc.mem_write(seg['p_vaddr'],seg.data())
  # This isolated slice needs one executable COPY input and three PLT targets.
  # Copy the original parsed pointer, not a guessed production table or ID.
  definitions={s.name:s for s in image.elf.get_section_by_name('.dynsym').iter_symbols() if s.name}
  psm=definitions['tb_sys_PsmInf']
  if psm['st_size']!=4:raise ValueError('Original COPY pointer contract changed')
  self.uc.mem_write(psm['st_value'],struct.pack('<I',self.pointer('tb_sys_PsmInf')))
  from elftools.elf.relocation import RelocationSection
  bound={}
  for section in image.elf.iter_sections():
   if not isinstance(section,RelocationSection):continue
   table=image.elf.get_section(section['sh_link'])
   for rel in section.iter_relocations():
    symbol=table.get_symbol(rel['r_info_sym'])
    if rel['r_info_type']==22 and symbol.name in ('rq_psm_Create','rq_drc_ErrorTraceP','rq_sys_ForceStnby'):
     self.uc.mem_write(rel['r_offset'],struct.pack('<I',self.defined[symbol.name]));bound[symbol.name]=symbol['st_value']
  if set(bound)!={'rq_psm_Create','rq_drc_ErrorTraceP','rq_sys_ForceStnby'}:raise ValueError('Required original PLT bindings missing')
  self.trace.executable_ranges.append((PSM_START,PSM_END+4))
  self.trace.executable_ranges.extend((p,p+12) for p in bound.values())
  self.trace.symbols[PSM_START]='PROC_SYSTEM_PSM_creation_loop_slice'
  def checkpoint(u,address,size,_):
   if self.in_parent_slice and address==PSM_END:self.trace._halt('psm_loop_boundary',address=hex(address))
   if self.in_parent_slice and address==self.defined['rq_psm_Create']:
    slot=u.reg_read(UC_ARM_REG_R0);self.created_slots.append(self.record(slot))
  self.uc.hook_add(UC_HOOK_CODE,checkpoint);self.parent_mapped=True;self.in_parent_slice=True
  try:result=self.trace.run(PSM_START,0,instruction_limit=20000)
  finally:self.in_parent_slice=False
  self.history.append(dict(function='original_parent_psm_slice',trace=result));return result
 def last_ioctl(self,result):
  b=result['boundary']
  if b.get('symbol')!='ioctl':raise ValueError('No original ioctl boundary')
  fd,request,p=b['arguments'][:3]
  return dict(descriptor=fd,request=request,words=list(struct.unpack('<III',self.uc.mem_read(p,12))),initialized_device=False)
 def report(self):
  result=super().report();result.update(configuration_fixture=self.configuration_label,
   configuration_sha256=hashlib.sha256(self.configuration).hexdigest() if self.configuration is not None else None,
   authentic_configuration=False,parent_full_boot=False,parent_slice_sha256=SYSTEM_SHA256 if self.parent_mapped else None,
   created_slots=self.created_slots,named_semaphore_events=self.named.events)
  return result

def investigate(sysp,flash,system):
 report={}
 for slots in ((25,),(6,25)):
  p=PsmStartupProbe(sysp,flash_data=flash);p.set_configuration_fixture(configuration_fixture(slots),'synthetic parser and PSM-loop fixture; not radio config')
  p.run('fs_cnf_Load');p.run('fs_psm_Init');p.run_parent_psm_slice(system)
  p.run('fc_sys_InitComAdr');p.run('fs_sys_ExPreInit');r=p.run('rq_sys_LoadVclPara')
  case=p.report()
  if r['boundary'].get('symbol')=='ioctl':case['uninitialized_flash_ioctl_boundary']=p.last_ioctl(r)
  report['slots_'+ '_'.join(map(str,slots))]=case
 return report

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ('sysp','flash','system','output'):p.add_argument('--'+key,type=Path,required=True)
 a=p.parse_args();r=investigate(a.sysp.read_bytes(),a.flash.read_bytes(),a.system.read_bytes())
 with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 print('Original parser/parent PSM slice saved; fixture configuration; no flash data read.')
if __name__=='__main__':main()
