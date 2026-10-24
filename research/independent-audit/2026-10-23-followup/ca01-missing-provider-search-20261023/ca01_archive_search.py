import tarfile,zipfile,io,re,json,hashlib,time
from pathlib import Path
root=Path('/home/starlight/projects/rav4-radio')
pat=re.compile(rb'libipas_apc(?:\.so)?|ipasz\.conf|libsecurity\.so|rq_apc_Cnct|rq_apc_AppInfNsw|fd_uif_SetUieInf',re.I)
report={'targets':pat.pattern.decode(),'archives':[],'matches':[],'errors':[],'skipped':[]}
def inspect(data,path,stats,depth=0):
 stats['files']+=1;stats['bytes']+=len(data)
 for m in pat.finditer(data):
  report['matches'].append({'path':path,'offset':m.start(),'match':m.group().decode(),'context':data[max(0,m.start()-100):m.end()+150].decode('utf8','backslashreplace')})
 if depth>=4:return
 if path.lower().endswith(('.tgz','.tar.gz','.tar.xz','.tar.bz2','.tar')):
  try:
   with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as t: scan_tar(t,path,stats,depth+1)
  except Exception as e:report['errors'].append({'path':path,'error':str(e)})
 elif data[:4]==b'PK\x03\x04':
  try:
   with zipfile.ZipFile(io.BytesIO(data)) as z:scan_zip(z,path,stats,depth+1)
  except Exception as e:report['errors'].append({'path':path,'error':str(e)})
def scan_tar(t,parent,stats,depth):
 for m in t:
  p=parent+'!'+m.name
  if pat.search(m.name.encode()):report['matches'].append({'path':p,'filename_match':True})
  if not m.isfile():continue
  if m.size>512*1024*1024:report['skipped'].append({'path':p,'size':m.size});continue
  f=t.extractfile(m)
  if f:inspect(f.read(),p,stats,depth)
def scan_zip(z,parent,stats,depth):
 for m in z.infolist():
  if m.is_dir():continue
  p=parent+'!'+m.filename
  if m.file_size>512*1024*1024:report['skipped'].append({'path':p,'size':m.file_size});continue
  inspect(z.read(m),p,stats,depth)
for p in [root/'vendor-source/20130619_LE2355.tgz',root/'vendor-source/OSS_SOFT_PACK.tgz',root/'related-firmware/DENSO_TEN_17_OSS_SOFT_PACK.zip']:
 s={'path':str(p),'sha256':hashlib.file_digest(p.open('rb'),'sha256').hexdigest(),'files':0,'bytes':0};report['archives'].append(s)
 print('SCANNING',p.name,flush=True)
 try:
  if p.suffix=='.zip':
   with zipfile.ZipFile(p) as z:scan_zip(z,str(p),s,0)
  else:
   with tarfile.open(p,'r|gz') as t:scan_tar(t,str(p),s,0)
 except Exception as e:report['errors'].append({'path':str(p),'error':str(e)})
 print(json.dumps(s),flush=True)
 Path('/tmp/ca01-missing-archive-search.json').write_text(json.dumps(report,indent=2))
print('MATCHES',len(report['matches']),'ERRORS',len(report['errors']),'SKIPPED',len(report['skipped']),flush=True)
