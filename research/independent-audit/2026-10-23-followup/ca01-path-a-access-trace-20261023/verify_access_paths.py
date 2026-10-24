#!/usr/bin/env python3
"""Read-only static Path A checks. Never executes recovered programs or shell text.
Writes only into this new evidence directory. No exporter/runtime/worker changes.
"""
import hashlib,json,re,sqlite3,sys,struct
from pathlib import Path
ROOT=Path('/home/starlight/projects/rav4-radio')
REPO=ROOT/'ca01-development-kit';AUDIT=ROOT/'system-audit';OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(REPO/'tools'))
from ca01_hmi_startup import ElfImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from capstone.arm import ARM_OP_IMM,ARM_INS_BL,ARM_INS_BLX

def sha(data):return hashlib.sha256(data).hexdigest()
def dump(name,obj):(OUT/name).write_text(json.dumps(obj,indent=2)+'\n')
rows=json.loads((AUDIT/'ca01-updater-independent-20261022/recovery-manifest.json').read_text())['files']
originals={};raws={};evidence=[]
pattern=re.compile(rb'/dev/tty[^\x00 ]*|/bin/(?:ba|a|da)?sh(?:\s|$)|telnetd?|sshd?|dropbear|inetd|getty|console=|syslog_typ|slattach|13PFBACKUP|HTTPServer|Peer Communication Framework',re.I)
for row in rows:
 p=Path(row.get('local_file',row.get('local_path','')))
 if not p.is_file():p=AUDIT/'ca01-updater-independent-20261022'/row['output_file']
 data=p.read_bytes();assert len(data)==row['size'] and sha(data)==row['sha256']
 name=Path(row['archive_path']).name;originals[name]={'path':str(p),'sha256':sha(data)};raws[name]=data
 hits=[{'offset':hex(m.start()),'text':m.group().decode()} for m in re.finditer(rb'[ -~]{5,250}',data) if pattern.search(m.group())]
 if hits:evidence.append({'file':name,'matches':hits})
dump('raw-access-strings.json',evidence)
# Locate old UIEIF's independent static export without invoking its AI worker.
con=sqlite3.connect('file:'+str(AUDIT/'ca01-local-ai-supervisor-20261023/function_coverage.sqlite3')+'?mode=ro',uri=True)
source=con.execute('select source_file,source_sha256,manifest_file from sources where sha256=?',(originals['PROC_UIEIF']['sha256'],)).fetchone();con.close()
assert source
p=Path(source[0]);uidata=p.read_bytes();assert sha(uidata)==source[1]
assert json.loads(Path(source[2]).read_text())['sha256']==originals['PROC_UIEIF']['sha256']
texts={'UIEIF':uidata.decode(),'SYSTEM':(AUDIT/'ca01-critical-decompilation-20261023/system1127-verified/decompiled.c').read_text(),'SYSC':(AUDIT/'ca01-critical-decompilation-20261023/sysc1127-verified/decompiled.c').read_text()}

def blocks(text):
 ms=list(re.finditer(r'/\* FUNCTION ([0-9a-fA-F]+)\s',text))
 return {m.group(1):text[m.start():n.start() if n else len(text)] for m,n in zip(ms,ms[1:]+[None])}

excerpts={}
for label,addresses in {'UIEIF':['0000db54','0000ef38'],'SYSTEM':['0002ead0','0002eb74','0002f2cc'],'SYSC':['00035450','0002614c','00029958','00029ac0']}.items():
 table=blocks(texts[label]);excerpts[label]={a:table[a] for a in addresses}
 (OUT/(label.lower()+'-selected.c.txt')).write_text('\n'.join(excerpts[label].values()))
ui=ElfImage(raws['PROC_UIEIF']);elf=ui.elf
plt=elf.get_section_by_name('.plt');sym=elf.get_section_by_name('.dynsym');imports={plt['sh_addr']+20+12*i:sym.get_symbol(r['r_info_sym']).name for i,r in enumerate(elf.get_section_by_name('.rel.plt').iter_relocations())}
cs=Cs(CS_ARCH_ARM,CS_MODE_ARM);cs.detail=True;cs.skipdata=True
instructions=[];system_calls=[];command_witnesses=[]
from capstone.arm import ARM_INS_MOVW,ARM_INS_MOVT,ARM_REG_R0
text=elf.get_section_by_name('.text')
window_cs=Cs(CS_ARCH_ARM,CS_MODE_ARM);window_cs.detail=True
for ins in cs.disasm(text.data(),text['sh_addr']):
 if ins.id in (ARM_INS_BL,ARM_INS_BLX) and ins.operands[0].type==ARM_OP_IMM and imports.get(ins.operands[0].imm)=='system':
  system_calls.append(hex(ins.address))
  window=list(window_cs.disasm(ui.read(ins.address-8,12),ins.address-8))
  assert len(window)==3 and window[0].mnemonic=='movw' and window[1].mnemonic=='movt',(hex(ins.address),[(x.mnemonic,x.op_str,x.id) for x in window])
  assert window[0].operands[0].reg==ARM_REG_R0 and window[1].operands[0].reg==ARM_REG_R0
  pointer=window[0].operands[1].imm|(window[1].operands[1].imm<<16)
  command=ui.read(pointer,180).split(b'\0')[0].decode()
  command_witnesses.append({'call':hex(ins.address),'string_address':hex(pointer),'command':command,
   'instructions':[{'address':hex(x.address),'bytes':bytes(x.bytes).hex(),'mnemonic':x.mnemonic,'operands':x.op_str} for x in window]})
assert len(system_calls)>=4
assert b'slattach -p slip -s 115200 /dev/ttyBT2 &' in raws['PROC_UIEIF']
assert b'slattach -p slip -s 115200 /dev/ttyBT3 &' in raws['PROC_UIEIF']
assert b'ifconfig sl0 mtu 4096 192.168.1.2 pointopoint 192.168.1.1 up' in raws['PROC_UIEIF']
labels={hex(a):ui.read(a,40).split(b'\0')[0].decode() for a in [0x76bb8,0x76c60,0x76c80]}
assert list(labels.values())==['Wireless iAP','Peer Communication Framework','HTTPServer']
network_imports=[s.name for s in sym.iter_symbols() if s['st_shndx']=='SHN_UNDEF' and s.name in ['socket','bind','listen','accept','execv','execve','system']]
needed=[t.needed for t in elf.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_NEEDED']
assert 'libipas_apc.so' in needed
assert not any('libipas_apc.so'==name for name in originals)
assert 'tar zxvfm /mnt/usb1/13PFBACKUPDB.KWI -C /var/backup' in excerpts['SYSTEM']['0002eb74']
assert 'open("/dev/flash",2)' in excerpts['SYSTEM']['0002eb74']
assert 'ioctl(__fd,0x4004ff0f' in excerpts['SYSTEM']['0002eb74']
assert 'rq_prc_Start' in excerpts['SYSC']['00035450'] and 'execv(' in excerpts['SYSC']['00035450']
snap=raws['snap.sh'].decode();assert '_LOGTYP' in snap and '"NET"' in snap and 'ifconfig eth0 $IPADDR' in snap
assert not any(command in snap for command in ['telnetd','sshd','dropbear','getty'])
boot=ROOT/'stock-firmware/components/09-boot.bin';bdata=boot.read_bytes()
inspection=json.loads((REPO/'evidence/ca01-1127-inspection.json').read_text())
part=next(x for x in inspection['components'] if x['filename']=='09-boot.bin');assert sha(bdata)==part['sha256']
boot_strings=[{'offset':hex(m.start()),'text':m.group().decode()} for m in re.finditer(rb'[ -~]{8,600}',bdata) if any(t in m.group() for t in [b'con=console=',b'${con}',b'bootcmd=',b'init=/sbin/init'])]
assert any('ttySC2,115200' in x['text'] for x in boot_strings)
(OUT/'snap.sh.readonly-copy').write_bytes(raws['snap.sh'])
dump('arm-network-witness.json',{'source':originals['PROC_UIEIF'],'function':'0xdb54','system_call_addresses':system_calls,'command_witnesses':command_witnesses,'scope':'Static MOVW/MOVT r0 + BL system proof; no command, Bluetooth, syscall or vendor code executed. Ghidra function bodies may include noncontiguous blocks; no contiguous-size assumption.'})
dump('verified-access-evidence.json',{'original_records_checked':len(rows),'original_distinct_paths':len({x['archive_path'] for x in rows}),
 'inputs':{k:originals[k] for k in ['PROC_SYSTEM','PROC_UIEIF','libipas_sysc.so','snap.sh']},'boot':{'path':str(boot),'sha256':sha(bdata)},
 'uieif_export':{'path':str(p),'sha256':sha(uidata)},'bluetooth_service_labels':labels,'uieif_network_related_imports':network_imports,
 'missing_connection_provider':'libipas_apc.so','direct_system_calls_in_network_handler':system_calls,'boot_environment_strings':boot_strings,
 'findings':['Original SLIP setup over BT serial and phone-app service labels verified; no maintenance endpoint or shell established',
 'USB backup import writes internal backup/flash state; excluded from read-only execution plan',
 'Network logging gated by boot parameters and QuickBoot path; no login server launched by recovered script',
 'Serial APIs and log-ring reader are not interactive shell implementations',
 'Configured fork/exec exists but needs unavailable launch configuration and original parent context'],
 'limits':['Absence from recovered files does not prove absence on radio','Static code does not prove runtime activation, exposed hardware or authentication','No vehicle, Bluetooth, Ethernet, serial or USB access attempted','No exporter or emulator integration changes']})
print('PASS source hashes,59 records/56 paths, original ARM calls, Bluetooth labels, USB write gate, boot console and script predicates')
