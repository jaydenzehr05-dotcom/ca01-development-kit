#!/usr/bin/env python3
"""Hash-gated original ARM common-memory producer/consumer investigation.

Only virtual /SHM_SYS_COM exists here. No host IPC, device access, flash reads,
process startup or missing-service success is supplied. Mapped zero pages are
not accepted as initialized vehicle data. Explicit synthetic test regions are
labeled and never reported as authentic radio contents.
"""
from __future__ import annotations
import argparse,hashlib,json,struct
from pathlib import Path
from ca01_startup_trace import BoundedArmTrace,SYSC_SHA256
from ca01_hmi_startup import ElfImage
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_PC
SYSP_SHA256='5fa0b9571f51693bb7b2f3fddfec1228d46ef66b359f126cba1719d08eba58e5'
FLASH_SHA256='e5ca3288453da45f666c8855ec5d2a29243f765789a36ad3a6943e674c4355b6'
SHARED_BYTES=0x208000
SHARED_BASE=0x40000000
BIAS=0x10000000
NAME='/SHM_SYS_COM'
FUNCTIONS={'fc_sys_InitComAdr','fs_sys_ExPreInit','rq_sys_GetVclPara',
 'rq_sys_LoadVclPara','fs_sys_InitCom','fs_sys_GetComAdr'}

def load_library(data,role,flash_data=None):
 """Isolated role, optional genuine flash provider; no executable/text patches."""
 if role not in ('producer','consumer'):raise ValueError('Unknown common-memory role')
 expected=SYSP_SHA256 if role=='producer' else SYSC_SHA256
 if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Canonical library SHA-256 mismatch')
 if flash_data is not None:
  if role!='producer' or hashlib.sha256(flash_data).hexdigest()!=FLASH_SHA256:raise ValueError('Canonical flash provider SHA-256 mismatch')
 from elftools.elf.relocation import RelocationSection
 uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);ranges=[];images=[];definitions={};functions={}
 for content,bias in [(data,BIAS)]+([(flash_data,0x20000000)] if flash_data is not None else []):
  image=ElfImage(content);images.append((image,bias));intervals=[]
  for seg in image.segments:
   start=(bias+seg['p_vaddr'])&~4095;end=(bias+seg['p_vaddr']+seg['p_memsz']+4095)&~4095
   if intervals and start<=intervals[-1][1]:intervals[-1]=(intervals[-1][0],max(end,intervals[-1][1]))
   else:intervals.append((start,end))
  for start,end in intervals:uc.mem_map(start,end-start)
  for seg in image.segments:
   uc.mem_write(bias+seg['p_vaddr'],seg.data())
   if seg['p_flags']&1:ranges.append((bias+seg['p_vaddr'],bias+seg['p_vaddr']+seg['p_memsz']))
  for symbol in image.elf.get_section_by_name('.dynsym').iter_symbols():
   if symbol.name and symbol['st_shndx']!='SHN_UNDEF':
    definitions.setdefault(symbol.name,bias+symbol['st_value'])
    if symbol['st_info']['type']=='STT_FUNC':functions[bias+symbol['st_value']]=symbol.name
 imports={};traps={};blocked={}
 for image,bias in images:
  for section in image.elf.iter_sections():
   if not isinstance(section,RelocationSection):continue
   symbols=image.elf.get_section(section['sh_link'])
   for rel in section.iter_relocations():
    target=bias+rel['r_offset'];kind=rel['r_info_type'];sym=symbols.get_symbol(rel['r_info_sym'])
    addend=struct.unpack('<I',uc.mem_read(target,4))[0]
    if kind==23:value=bias+addend
    elif kind in (17,18):blocked[target]=sym.name+' (unimplemented TLS)';continue
    elif kind in (2,21,22):
     if sym.name in definitions:value=definitions[sym.name]
     else:
      if sym.name not in traps:
       address=0x60000000+4096*len(traps);traps[sym.name]=address;imports[address]=sym.name
      value=traps[sym.name]
     if kind==2:value+=addend
    else:raise ValueError('Unsupported original ARM relocation '+str(kind))
    uc.mem_write(target,struct.pack('<I',value&0xffffffff))
 return BoundedArmTrace(uc,ranges,imports,symbols=functions,blocked_reads=blocked),definitions

class VirtualCommonMemory:
 """Bounded in-guest backing only; never opens the host shared-memory namespace."""
 def __init__(self,probe,snapshot):
  if snapshot is not None and (not isinstance(snapshot,bytes) or len(snapshot)!=SHARED_BYTES):
   raise ValueError('Snapshot must contain exactly 0x208000 bytes')
  self.probe=probe;self.exists=snapshot is not None;self.size=SHARED_BYTES if self.exists else 0
  self.data=snapshot;self.fd=71;self.opened=False;self.mapped=False;self.events=[]
 def unlink(self,name):
  if name!=NAME or self.mapped:raise ValueError('Unsupported unlink')
  # POSIX missing-name unlink returns -1; original producer ignores it.
  result=0 if self.exists else -1
  self.exists=False;self.opened=False;self.size=0;self.data=None
  self.events.append(dict(operation='unlink',name=name,result=result));return result
 def open(self,name,flags,mode):
  if name!=NAME or flags not in (2,0xc2) or mode!=0o666:raise ValueError('Unsupported common-memory open contract')
  if self.opened:raise ValueError('Repeated descriptor acquisition is outside this bounded probe')
  if flags==0xc2:
   if self.probe.role!='producer' or self.exists:raise ValueError('Producer requires exclusive fresh virtual object')
   self.exists=True
  if not self.exists:raise ValueError('Parent shared-memory object is missing')
  self.opened=True;self.events.append(dict(operation='open',name=name,flags=flags,mode=mode,fd=self.fd));return self.fd
 def truncate(self,fd,size):
  if fd!=self.fd or not self.opened or self.mapped or size!=SHARED_BYTES:raise ValueError('Unsupported common-memory truncate')
  self.size=size
  if self.data is None:self.data=bytes(size) # actual new POSIX object semantics, not verified vehicle contents
  self.events.append(dict(operation='truncate',size=size));return 0
 def map(self,u,args):
  fd,offset=struct.unpack('<II',u.mem_read(u.reg_read(UC_ARM_REG_SP),8))
  if list(args)!=[0,SHARED_BYTES,3,1] or fd!=self.fd or offset!=0 or self.size!=SHARED_BYTES or not self.opened or self.mapped:
   raise ValueError('Unsupported common-memory mmap contract')
  u.mem_map(SHARED_BASE,SHARED_BYTES);u.mem_write(SHARED_BASE,self.data);self.mapped=True
  self.events.append(dict(operation='map',base=hex(SHARED_BASE),size=SHARED_BYTES));return SHARED_BASE

class CommonMemoryProbe:
 APPROVED=FUNCTIONS
 def __init__(self,data,*,role,snapshot=None,flash_data=None):
  # Validate all inputs before guest preparation.
  if snapshot is not None and (not isinstance(snapshot,bytes) or len(snapshot)!=SHARED_BYTES):raise ValueError('Invalid snapshot length/type')
  self.trace,self.defined=load_library(data,role,flash_data);self.uc=self.trace.uc;self.role=role
  # Stop at original diagnostic entry; never execute an invented logging success.
  self.trace.imports[self.defined['rq_drc_ErrorTraceP']]='rq_drc_ErrorTraceP'
  self.flash_bound=flash_data is not None
  self.sha256=hashlib.sha256(data).hexdigest();self.scratch=0x70008000
  self.backend=VirtualCommonMemory(self,snapshot);self.history=[];self.pointer_writes=[];self.fixture_regions={}
  self.trace.services.update({'memset':self._memset,'memcpy':self._memcpy,
   'shm_unlink':lambda u,a:self.backend.unlink(self._string(a[0])),
   'shm_open':lambda u,a:self.backend.open(self._string(a[0]),a[1],a[2]),
   'ftruncate':lambda u,a:self.backend.truncate(a[0],a[1]),'mmap':self.backend.map})
  def write(u,access,address,size,value,_):
   p=self.defined['bf_sys_VclPara']
   if address<p+4 and p<address+size:self.pointer_writes.append(dict(pc=hex(u.reg_read(UC_ARM_REG_PC)),address=hex(address),value=hex(value),size=size))
  self.uc.hook_add(UC_HOOK_MEM_WRITE,write)
  self.uc.hook_add(UC_HOOK_MEM_READ,self._guard_read)
 def _string(self,address):
  value=self.trace._guest_string(address)
  if value is None:raise ValueError('Invalid bounded guest string')
  return value
 def _check_content(self,address,size):
  if not size or address+size<=SHARED_BASE or address>=SHARED_BASE+SHARED_BYTES:return
  for index in self.fixture_regions:
   r=self.region(index)
   if r['address']<=address and address+size<=r['address']+r['size']:return
  raise ValueError('Unverified shared-memory content read; no authentic vehicle snapshot supplied')
 def _guard_read(self,u,access,address,size,value,_):
  try:self._check_content(address,size)
  except ValueError as error:self.trace._halt('unverified_shared_memory',address=hex(address),size=size,error=str(error))
 def _memset(self,u,a):
  if not 0<a[2]<=SHARED_BYTES:raise ValueError('Unbounded memset')
  u.mem_read(a[0],a[2]);u.mem_write(a[0],bytes([a[1]&255])*a[2]);return a[0]
 def _memcpy(self,u,a):
  if not 0<a[2]<=SHARED_BYTES or a[0]==0 or a[1]==0:raise ValueError('Invalid bounded memcpy')
  self._check_content(a[1],a[2]);u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));return a[0]
 def pointer(self,name):return struct.unpack('<I',self.uc.mem_read(self.defined[name],4))[0]
 def region(self,index):
  if type(index) is not int or not 0<=index<60:raise ValueError('Invalid region index')
  address,size=struct.unpack('<II',self.uc.mem_read(self.defined['bf_sys_ComAdr']+index*8,8))
  return dict(index=index,address=address,offset=address-SHARED_BASE if address else None,size=size)
 def verify_fixture_region(self,index,label):
  if not isinstance(label,str) or not label.strip():raise ValueError('Explicit synthetic fixture label required')
  r=self.region(index)
  if not self.backend.mapped or not r['address'] or r['size']==0:raise ValueError('Original layout must be initialized first')
  self.fixture_regions[index]=label
 def run(self,name,*args):
  if name not in (self.APPROVED|({'fs_drv_FlmInit'} if self.flash_bound else set())) or len(args)>3:raise ValueError('Unapproved original common-memory probe')
  for r in (UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3):self.uc.reg_write(r,0)
  for r,value in zip((UC_ARM_REG_R1,UC_ARM_REG_R2),args[1:]):self.uc.reg_write(r,value)
  result=self.trace.run(self.defined[name],args[0] if args else 0,instruction_limit=20000)
  self.history.append(dict(function=name,trace=result));return result
 def report(self):
  return dict(role=self.role,sha256=self.sha256,flash_provider_sha256=FLASH_SHA256 if self.flash_bound else None,history=self.history,backend_events=self.backend.events,
   regions=[self.region(i) for i in range(60) if self.region(i)['address']],pointer_writes=self.pointer_writes,
   fixture_regions=self.fixture_regions,full_startup=False,authentic_vehicle_data=False,
   host_ipc=False,hardware_access=False)

def investigate(sysc,sysp,flash_data=None):
 consumer=CommonMemoryProbe(sysc,role='consumer');consumer.run('fs_sys_InitCom')
 consumer.run('fc_sys_InitComAdr');consumer.run('rq_sys_LoadVclPara')
 producer=CommonMemoryProbe(sysp,role='producer');producer.run('fc_sys_InitComAdr')
 producer.run('fs_sys_ExPreInit');producer.run('rq_sys_GetVclPara',producer.scratch)
 producer.run('rq_sys_LoadVclPara')
 report=dict(scope='Original ARM isolated common-memory slices; no complete startup',consumer=consumer.report(),producer=producer.report())
 if flash_data is not None:
  bound=CommonMemoryProbe(sysp,role='producer',flash_data=flash_data)
  bound.run('fc_sys_InitComAdr');bound.run('fs_sys_ExPreInit');bound.run('rq_sys_LoadVclPara')
  device=CommonMemoryProbe(sysp,role='producer',flash_data=flash_data);device.run('fs_drv_FlmInit')
  report.update(bound_flash_read=bound.report(),independent_device_initializer=device.report())
 return report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sysc',type=Path,required=True)
 p.add_argument('--sysp',type=Path,required=True);p.add_argument('--flash',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 for source in (a.sysc,a.sysp)+((a.flash,) if a.flash else ()):
  if source.stat().st_size>1024*1024:p.error('Input exceeds canonical library size bound')
 result=investigate(a.sysc.read_bytes(),a.sysp.read_bytes(),a.flash.read_bytes() if a.flash else None)
 with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print('Original ARM trace saved; full startup: False; hardware access: False')
if __name__=='__main__':main()
