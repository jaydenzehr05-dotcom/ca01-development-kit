"""Analysis-only original ARM producer/parser probe, no device or full startup."""
import sys,hashlib,struct,json
from pathlib import Path
sys.path.insert(0,'/home/starlight/projects/rav4-radio/ca01-development-kit/tools')
from ca01_startup_trace import BoundedArmTrace
from ca01_hmi_startup import ElfImage
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP
from elftools.elf.relocation import RelocationSection
ROOT=Path('/home/starlight/projects/rav4-radio')
DISPLAY=ROOT/'system-audit/ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered/01116817-PROC_DISPLAY'
HMI=ROOT/'system-audit/ca01-updater-independent-20261022/06-PROC_HMI'
D_SHA='ed6c8180598afb2f3d0ddd74793add46bfa012bc387516229726ee5f776e303f'
H_SHA='cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503'

def load(path,digest,ranges):
 data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==digest
 im=ElfImage(data);u=Uc(UC_ARCH_ARM,UC_MODE_ARM);intervals=[]
 for s in im.segments:
  a=s['p_vaddr']&~4095;b=(s['p_vaddr']+s['p_memsz']+4095)&~4095
  if intervals and a<=intervals[-1][1]:intervals[-1]=(intervals[-1][0],max(b,intervals[-1][1]))
  else:intervals.append((a,b))
 for a,b in intervals:u.mem_map(a,b-a)
 for s in im.segments:u.mem_write(s['p_vaddr'],s.data())
 imports={};names={};copy=[]
 for section in im.elf.iter_sections():
  if not isinstance(section,RelocationSection):continue
  table=im.elf.get_section(section['sh_link'])
  for rel in section.iter_relocations():
   sym=table.get_symbol(rel['r_info_sym']);kind=rel['r_info_type'];dst=rel['r_offset']
   if kind==20:copy.append((dst,dst+sym['st_size'],sym.name));continue
   if kind not in (21,22):raise ValueError('Unsupported relocation')
   if kind==22 and sym['st_value']:ranges.append((sym['st_value'],sym['st_value']+12))
   if sym.name not in names:
    trap=0x60000000+len(names)*4096;names[sym.name]=trap;imports[trap]=sym.name
   u.mem_write(dst,struct.pack('<I',names[sym.name]))
 t=BoundedArmTrace(u,ranges,imports)
 u.mem_map(0x50000000,0x10000)
 def guard(u,access,p,n,value,_):
  for a,b,name in copy:
   if p<b and a<p+n:t._halt('unprovided_copy',symbol=name)
 u.hook_add(UC_HOOK_MEM_READ,guard)
 return t

def case(blob,payload,category=1,page=2,property=0x1234,used=0):
 entry=0x27ddb0 if blob else 0x27d3a4
 t=load(DISPLAY,D_SHA,[(entry,entry+240),(0x27d310,0x27d3a4)]);u=t.uc
 def memcpy(u,a):
  if not 0<=a[2]<=4096:raise ValueError('Bounded real memcpy only')
  u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));return a[0]
 t.services['memcpy']=memcpy
 u.mem_write(0x50000000,payload);u.mem_write(0x7000f000,struct.pack('<I',len(payload)))
 u.mem_write(0x13046ee,struct.pack('<H',used))
 for r,v in [(UC_ARM_REG_R1,page),(UC_ARM_REG_R2,property),(UC_ARM_REG_R3,0x50000000)]:u.reg_write(r,v)
 producer=t.run(entry,category)
 count=struct.unpack('<H',u.mem_read(0x13046f0,2))[0]
 result=dict(kind='blob' if blob else 'scalar',producer=producer,record_count=count,
  startup_completed=False,transport_implemented=False,scene_dispatched=False)
 if not producer['returned']:return result
 total=struct.unpack('<H',u.mem_read(0x12f66c0+used,2))[0]
 raw=bytes(u.mem_read(0x12f66c0+used,total));result['record_hex']=raw.hex()
 expected=struct.pack('<HBBHB',len(payload)+7,category,page,property,int(blob))+payload
 assert raw==expected and count==1
 # Independent original HMI parser; observe actual handler entry and stop.
 t=load(HMI,H_SHA,[(0xf3b0,0xf48c),(0xe6c4,0xe6c8),(0xe214,0xe218)]);u=t.uc
 u.mem_write(0x50000000,raw)
 decoded={}
 def dispatch(u,address,size,_):
  if address not in (0xe6c4,0xe214):return
  regs=[u.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
  decoded.update(handler=hex(address),category=regs[0],page=regs[1],property=regs[2])
  if address==0xe6c4:decoded['scalar']=regs[3]
  else:
   n=struct.unpack('<I',u.mem_read(u.reg_read(UC_ARM_REG_SP),4))[0]
   decoded.update(bytes=n,payload_hex=bytes(u.mem_read(regs[3],n)).hex())
  t._halt('original_property_handler_boundary',handler=hex(address))
 u.hook_add(UC_HOOK_CODE,dispatch)
 parser=t.run(0xf3b0,0x50000000)
 assert parser['halt_reason']=='original_property_handler_boundary',parser
 assert (decoded['category'],decoded['page'],decoded['property'])==(category,page,property)
 if blob:assert decoded['payload_hex']==payload.hex() and decoded['bytes']==len(payload)
 else:assert decoded['scalar']==struct.unpack('<I',payload)[0]
 result.update(parser=parser,decoded=decoded);return result

if __name__=='__main__':
 results=[case(False,bytes.fromhex('78563412')),case(True,b'CA01 record probe'),case(False,b'\x01\0\0\0',category=3,page=0),case(False,b'\x01\0\0\0',used=0xe02d-10)]
 for r in results[:2]:assert r['producer']['returned'] and r.get('parser',{}).get('halt_reason')=='original_property_handler_boundary',r
 for r in results[2:]:assert not r['producer']['returned'] and r['record_count']==0 and r['producer']['boundary']['symbol']=='rq_drc_ErrorTraceP',r
 report=dict(scope='Original scalar/blob serializer to original HMI parser only; handler boundary stops, no property store/scene/transport completion',hashes=dict(display=D_SHA,hmi=H_SHA),cases=results)
 with Path('/tmp/ca01-original-property-record-verified-proof.json').open('x') as f:json.dump(report,f,indent=2)
 print('2 original producer/parser positive cases and2 fail-closed negative cases verified.')
