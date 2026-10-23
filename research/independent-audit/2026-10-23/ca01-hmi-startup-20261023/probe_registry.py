from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_SP,UC_ARM_REG_LR
import struct,json,hashlib
base=Path('/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022')
assert hashlib.sha256((base/'06-PROC_HMI').read_bytes()).hexdigest()=='cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503'
assert hashlib.sha256((base/'06-libipas_sysc.so').read_bytes()).hexdigest()=='a1f2812d0b1776fa79dcb9ebddd5dca2d16443f77db19c35f4aac2cbabc302b4'
uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);bias=0x10000000;symbols={};writes=[]
for filename,load in [('06-PROC_HMI',0),('06-libipas_sysc.so',bias)]:
 with (base/filename).open('rb') as f:
  elf=ELFFile(f)
  for seg in elf.iter_segments():
   if seg['p_type']!='PT_LOAD':continue
   addr=load+seg['p_vaddr'];start=addr&~4095;end=(addr+seg['p_memsz']+4095)&~4095
   uc.mem_map(start,end-start);uc.mem_write(addr,seg.data())
  if load:
   sy=elf.get_section_by_name('.dynsym')
   for s in sy.iter_symbols():
    if s['st_shndx']!='SHN_UNDEF':symbols[load+s['st_value']]=s.name
   for sec in elf.iter_sections():
    if not isinstance(sec,RelocationSection):continue
    symtab=elf.get_section(sec['sh_link'])
    for rel in sec.iter_relocations():
     dst=load+rel['r_offset'];kind=rel['r_info_type'];s=symtab.get_symbol(rel['r_info_sym'])
     if kind==23: value=struct.unpack('<I',uc.mem_read(dst,4))[0]+load
     elif kind in (21,22):
      if s['st_shndx']=='SHN_UNDEF':continue
      value=load+s['st_value']
     elif kind==2:
      if s['st_shndx']=='SHN_UNDEF':continue
      value=struct.unpack('<I',uc.mem_read(dst,4))[0]+load+s['st_value']
     else:continue
     uc.mem_write(dst,struct.pack('<I',value))
   target=next(s for s in sy.iter_symbols() if s.name=='fs_sys_CnfEntry' and s['st_shndx']!='SHN_UNDEF');start=load+target['st_value'];size=target['st_size']
uc.mem_map(0x70000000,0x10000);uc.reg_write(UC_ARM_REG_SP,0x7000f000);uc.reg_write(UC_ARM_REG_LR,0x7000fff0);uc.reg_write(UC_ARM_REG_R0,0x59f948)
trace=[]
def code(uc,a,size,user):
 if not start<=a<start+404:raise RuntimeError('Outside configured function '+hex(a))
 trace.append(hex(a))
def write(uc,access,a,size,value,user):
 if a in symbols:writes.append(dict(symbol=symbols[a],address=hex(a-bias),value=hex(value)))
uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_WRITE,write)
uc.emu_start(start,0x7000fff0,count=1000,timeout=1000000)
from unicorn.arm_const import UC_ARM_REG_PC
assert uc.reg_read(UC_ARM_REG_PC)==0x7000fff0 and len(writes)==18
print(json.dumps(writes,indent=2));print('instructions',len(trace))
Path('/tmp/ca01-hmi-startup-20261023/registry-probe.json').write_text(json.dumps(dict(writes=writes,trace=trace),indent=2)+'\n')
