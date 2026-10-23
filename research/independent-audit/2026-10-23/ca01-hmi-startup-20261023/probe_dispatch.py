from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import *
import struct,json,hashlib
p=Path('/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_HMI');assert hashlib.sha256(p.read_bytes()).hexdigest()=='cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503'
reports=[]
for name,words in [('timeout-heartbeat',(0,0,10,0)),('command',(0x41002,7,0,0)),('owned-command',(0x41002,7,0,0x12345678)),('unknown-owned',(0x9999,0,0,0x76543210))]:
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
 with p.open('rb') as f:
  e=ELFFile(f)
  for seg in e.iter_segments():
   if seg['p_type']!='PT_LOAD':continue
   a=seg['p_vaddr'];low=a&~4095;high=(a+seg['p_memsz']+4095)&~4095;u.mem_map(low,high-low);u.mem_write(a,seg.data())
 u.mem_map(0x70000000,0x10000);u.mem_write(0x70000000,struct.pack('<4I',*words));u.reg_write(UC_ARM_REG_R0,0x70000000);u.reg_write(UC_ARM_REG_SP,0x7000f000);u.reg_write(UC_ARM_REG_LR,0x7000fff0)
 calls=[];trace=[]
 def hook(u,a,size,user):
  trace.append(hex(a))
  if a in [0x2b054,0xd5a4,0xd610]:
   calls.append(dict(address=hex(a),r0=hex(u.reg_read(UC_ARM_REG_R0)),r1=hex(u.reg_read(UC_ARM_REG_R1))))
   u.reg_write(UC_ARM_REG_R0,0);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR));return
  if not (0x2b170<=a<0x2b1f8 or 0x2a978<=a<0x2aa18):raise RuntimeError('Unapproved instruction '+hex(a))
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x2b170,0x7000fff0,count=500,timeout=1000000)
 assert u.reg_read(UC_ARM_REG_PC)==0x7000fff0
 r=dict(name=name,message=list(words),return_value=u.reg_read(UC_ARM_REG_R0),pending_draw_flag=u.mem_read(0x26c98a2,1)[0],calls=calls,trace=trace)
 if name=='timeout-heartbeat':assert r['pending_draw_flag']==1 and r['return_value']==1
 if 'owned' in name:assert any(c['address']=='0xd5a4' and c['r0']=='0x1' and int(c['r1'],16)==words[3] for c in calls)
 reports.append(r)
 print(name,'return',r['return_value'],'drawflag',r['pending_draw_flag'],'calls',calls)
Path('/tmp/ca01-hmi-startup-20261023/dispatcher-probes.json').write_text(json.dumps(dict(scope='Bounded actual ARM dispatcher only; command/error/free callees mocked; no application startup or rendering.',hmi_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),runs=reports),indent=2)+'\n')
