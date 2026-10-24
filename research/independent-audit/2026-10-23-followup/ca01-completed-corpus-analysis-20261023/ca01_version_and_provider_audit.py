import sqlite3,hashlib,json,sys,io,collections,re
from pathlib import Path
sys.path.insert(0,'tools')
from elftools.elf.elffile import ELFFile
root=Path('/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023')
c=sqlite3.connect('file:'+str(root/'progress.sqlite3')+'?mode=ro&immutable=1',uri=True);c.row_factory=sqlite3.Row
items=[dict(x) for x in c.execute('select * from inputs where elf=1')];groups=collections.defaultdict(list);inputs=[];providers=collections.defaultdict(list)
for row in items:
 p=Path(row['path']);data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==row['sha256'];elf=ELFFile(io.BytesIO(data));sections={}
 for name in ['.text','.rodata','.data','.dynsym']:
  s=elf.get_section_by_name(name);sections[name]=s.data() if s else b''
 groups[row['archive_path']].append((row,sections))
 for sym in elf.get_section_by_name('.dynsym').iter_symbols():
  if sym['st_shndx']!='SHN_UNDEF' and sym.name and any(x in sym.name for x in ['sysDisMng','fs_flm','rq_grp_Init','sysSec','SecStart','fs_drv_MemInit','psm_Create','fs_cnf_Load']):providers[sym.name].append(dict(name=row['archive_path'],version=row['version'],address=hex(sym['st_value'])))
 inputs.append(dict(name=row['archive_path'],version=row['version'],sha256=row['sha256'],path=str(p),bytes=len(data)))
pairs=[]
for name,rows in groups.items():
 if len(rows)!=2:continue
 rows.sort(key=lambda x:x[0]['version']);a,b=rows
 pair=dict(name=name,section_equal={s:a[1][s]==b[1][s] for s in a[1]})
 pair['nontext_diffs']={}
 for sec in ['.rodata','.data']:
  x,y=a[1][sec],b[1][sec]
  if len(x)==len(y) and x!=y:
   changed=[i for i in range(len(x)) if x[i]!=y[i]];pair['nontext_diffs'][sec]=dict(bytes_changed=len(changed),first_offset=hex(changed[0]),last_offset=hex(changed[-1]))
 pairs.append(pair)
report=dict(inputs=inputs,pairs=pairs,selected_providers=dict(providers),verified_inputs=len(inputs))
Path('/tmp/ca01-version-provider-audit.json').write_text(json.dumps(report,indent=2))
print('HASH VERIFIED',len(inputs),'VERSION PAIRS',len(pairs))
for pair in pairs:print(pair)
for k,v in providers.items():
 if k in ['sysDisMngInit','fs_drv_MemInit','fs_flm_Read','fs_cnf_Load']:print('PROVIDER',k,v)
