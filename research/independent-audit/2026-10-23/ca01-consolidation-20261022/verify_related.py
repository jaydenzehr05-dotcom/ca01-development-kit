from pathlib import Path
import json,hashlib,zipfile,tarfile,io,re
root=Path('/home/starlight/projects/rav4-radio/related-firmware');out=Path('/tmp/ca01-consolidation-20261022/related-verification')
manifest=json.loads((root/'DOWNLOAD_MANIFEST.json').read_text());checked=[]
for row in manifest['files']:
 p=root/row['filename'];h=hashlib.sha256(p.read_bytes()).hexdigest();assert p.stat().st_size==row['bytes'] and h==row['sha256']
 checked.append(dict(local_path=str(p),size=p.stat().st_size,sha256=h))
report=dict(downloaded_files=checked,selected_modules=[])
with zipfile.ZipFile(root/'DENSO_TEN_17_OSS_SOFT_PACK.zip') as z:
 report['zip_entries']=len(z.infolist());report['zip_crc_error']=z.testzip();assert report['zip_crc_error'] is None
 report['zip_members']=[dict(path=i.filename,size=i.file_size,compressed_size=i.compress_size) for i in z.infolist()]
 for module in ['Evoproxy_1.6.18','evo_bvd_rca13','evo_hli_rca13','evo_socket_adapter_rca13']:
  member=next(n for n in z.namelist() if n.endswith('/'+module+'.tar.xz'));data=z.read(member);records=[]
  with tarfile.open(fileobj=io.BytesIO(data),mode='r:xz') as tar:
   for m in tar:
    if not m.isfile():continue
    raw=tar.extractfile(m).read();local=root/'selected-source'/module/m.name
    assert local.is_file() and local.read_bytes()==raw,str(local)
    records.append(dict(archive_path=m.name,local_path=str(local),size=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
  report['selected_modules'].append(dict(module=module,zip_member=member,archive_sha256=hashlib.sha256(data).hexdigest(),files=records))
 member=next(n for n in z.namelist() if '/linux-kernel-' in n)
 with tarfile.open(fileobj=io.BytesIO(z.read(member)),mode='r:xz') as tar:
  candidates=[]
  for m in tar:
   if m.isfile() and Path(m.name).name=='Makefile':
    raw=tar.extractfile(m).read()
    if re.search(rb'^VERSION\s*=\s*3\s*$',raw,re.M) and re.search(rb'^PATCHLEVEL\s*=\s*10\s*$',raw,re.M):
     candidates.append(dict(path=m.name,sha256=hashlib.sha256(raw).hexdigest(),version_fields=re.findall(r'^(?:VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=.*$',raw.decode(errors='replace'),re.M),text=raw[:700].decode(errors='replace')))
 report['kernel_version_makefiles']=candidates
 assert candidates,'No actual root kernel version Makefile found'
(out/'verified-related.json').write_text(json.dumps(report,indent=2)+'\n')
print('Verified',len(checked),'downloads, all ZIP CRCs,',sum(len(m['files']) for m in report['selected_modules']),'selected source files.')
print(json.dumps(candidates,indent=2))
