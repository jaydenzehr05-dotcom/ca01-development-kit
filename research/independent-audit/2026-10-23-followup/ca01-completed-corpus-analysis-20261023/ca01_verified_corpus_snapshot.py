"""Independent read-only structural audit of current selected CA01 exports."""
from pathlib import Path
import json,re,hashlib,collections,sqlite3
ROOT=Path('/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023')
report=json.loads((ROOT/'MANUAL_EXECUTABLE_COVERAGE.json').read_text());counts=collections.Counter();kinds=collections.Counter();warnings=collections.Counter();rows=[]
for item in report['items']:
 if item['status']!='done':continue
 folder=Path(item['path']);manifest=json.loads((folder/'manifest.json').read_text());text=(folder/'decompiled.c').read_text()
 assert manifest['sha256']==item['sha'];functions=manifest['functions'];assert len(functions)==manifest['functions_catalogued']
 matches=list(re.finditer(r'^/\* FUNCTION ([0-9a-fA-F]+) (.*?) bytes=(\d+) \*/',text,re.M));bodies={}
 for i,m in enumerate(matches):
  address=int(m.group(1),16);assert address not in bodies
  bodies[address]=text[m.start():matches[i+1].start() if i+1<len(matches) else len(text)]
 stats=collections.Counter(f['status'] for f in functions);assert len(bodies)==len(functions)==stats['decompiled']
 assert len({int(f['address'],16) for f in functions})==len(functions)
 for f in functions:
  body=bodies[int(f['address'],16)];assert '{' in body and '}' in body
  kind=f.get('classification') or ('import_thunk' if f.get('memory_block')=='.plt' else 'text_body' if f.get('memory_block')=='.text' else 'other_executable')
  kinds[kind]+=1
  if kind=='text_body':
   for marker in ['/* WARNING:','Could not recover','Treating indirect jump as call','extraout_','unaff_']:
    if marker in body:warnings[marker]+=1
 counts.update(stats)
 rows.append(dict(name=item['name'],version=item['version'],sha256=item['sha'],entries=len(functions),source_file=str(folder/'decompiled.c'),source_sha256=hashlib.sha256((folder/'decompiled.c').read_bytes()).hexdigest(),manifest_sha256=hashlib.sha256((folder/'manifest.json').read_bytes()).hexdigest()))
with sqlite3.connect('file:'+str(ROOT/'function_coverage.sqlite3')+'?mode=ro&immutable=1',uri=True) as c:
 indexed=dict(c.execute('SELECT status,count(*) FROM functions GROUP BY status').fetchall())
summary=dict(report_path=str(ROOT/'MANUAL_EXECUTABLE_COVERAGE.json'),selected_exports=len(rows),input_rows=len(report['items']),statuses=dict(counts),classes=dict(kinds),warning_body_counts=dict(warnings),index_statuses=indexed,selected_sources=rows,
 limits='Structural body/identity checks; not proof of full function discovery, source equivalence, correct C semantics or runnable firmware')
Path('/tmp/ca01-verified-corpus-snapshot.json').write_text(json.dumps(summary,indent=2))
print({k:v for k,v in summary.items() if k!='selected_sources'})
