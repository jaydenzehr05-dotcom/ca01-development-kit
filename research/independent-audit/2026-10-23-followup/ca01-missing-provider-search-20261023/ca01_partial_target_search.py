from pathlib import Path
import re,json,hashlib,io
from elftools.elf.elffile import ELFFile
base=Path('/home/starlight/projects/rav4-radio/system-audit')
pat=re.compile(rb'libipas_apc(?:\.so)?|ipasz\.conf|libsecurity\.so|rq_apc_Cnct|rq_apc_AppInfNsw|fd_uif_SetUieInf')
r={'partials':[],'elfs':[]}
for p in sorted(base.glob('ca01-1134-firmware-analysis-20261023/recovered-*/UNTRUSTED.partial.bin')):
 data=p.read_bytes();mask=(p.parent/'known-byte-mask.bin').read_bytes(); assert len(data)==len(mask)
 row={'path':str(p),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'known':sum(bool(b) for b in mask),'matches':[]}
 for m in pat.finditer(data):
  known=all(mask[m.start():m.end()]);row['matches'].append({'offset':m.start(),'text':m.group().decode(),'fully_known':known})
 r['partials'].append(row)
for p in sorted((base/'ca01-updater-independent-20261022').iterdir()):
 if not p.is_file():continue
 data=p.read_bytes()
 if not data.startswith(b'\x7fELF'):continue
 elf=ELFFile(io.BytesIO(data)); dyn=elf.get_section_by_name('.dynsym'); symbols=[]
 if dyn:
  for s in dyn.iter_symbols():
   if pat.fullmatch(s.name.encode()):symbols.append({'symbol':s.name,'defined':s['st_shndx']!='SHN_UNDEF'})
 needed=[]
 for sec in elf.iter_sections():
  if sec.name=='.dynamic':
   needed=[t.needed for t in sec.iter_tags() if t.entry.d_tag=='DT_NEEDED' and pat.search(t.needed.encode())]
 if symbols or needed or pat.search(data):r['elfs'].append({'path':str(p),'sha256':hashlib.sha256(data).hexdigest(),'symbols':symbols,'needed':needed,'strings':[{'offset':m.start(),'text':m.group().decode()} for m in pat.finditer(data)]})
for row in r['partials']:
 manifest=json.loads((Path(row['path']).parent/'recovered-manifest.json').read_text())
 for hit in row['matches']:
  hit['containing_complete_entries']=[x['archive_path'] for x in manifest if x['partial_data_offset']<=hit['offset']<x['partial_data_offset']+x['size']]
Path('/tmp/ca01-missing-partial-search.json').write_text(json.dumps(r,indent=2))
print(json.dumps({'partial_regions':len(r['partials']),'bytes':sum(x['bytes'] for x in r['partials']),'known':sum(x['known'] for x in r['partials']),'partial_matches':[x for x in r['partials'] if x['matches']],'elf_references':len(r['elfs']),'defined_providers':[x for x in r['elfs'] if any(s['defined'] for s in x['symbols'])]},indent=2))
