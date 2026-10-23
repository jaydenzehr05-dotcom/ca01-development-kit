import tarfile,pathlib,re,json,io,hashlib
base=pathlib.Path('/home/starlight/projects/rav4-radio/vendor-source')
exact=re.compile(rb'libsecurity\.so|sysAes(?:Key|Init|Exec)|sysSecStartUp|sysUserRsaPrvKeyNonCrt|sysRsaPssVerify|sysSha256Init|rma1_hwreg|vigilancer',re.I)
records=[]; stats=[]
def scan(tf,prefix,st,depth=0):
 for m in tf:
  st['members']+=1
  if not m.isfile(): continue
  st['regular_members']+=1
  data=tf.extractfile(m).read(); st['bytes_scanned']+=len(data)
  path=prefix+m.name
  hits=list(exact.finditer(data))
  if hits:
   records.append({'path':path,'matches':[{'marker':h.group().decode('ascii'),'line':data[:h.start()].count(b'\n')+1,'byte_offset':h.start()} for h in hits]})
  if depth<2 and re.search(r'\.(?:tar\.(?:gz|bz2|xz)|tgz|tbz2?)$',m.name,re.I):
   try:
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as nested:
     st['nested_archives']+=1; scan(nested,path+'!',st,depth+1)
   except tarfile.TarError: pass
for name in ['OSS_SOFT_PACK.tgz','20130619_LE2355.tgz']:
 st={'archive':name,'members':0,'regular_members':0,'bytes_scanned':0,'nested_archives':0}
 with tarfile.open(base/name,'r:gz') as tf:scan(tf,name+'!',st)
 stats.append(st)
json.dump({'coverage':stats,'exact_marker_hits':records},open('/tmp/ca01-libsecurity-archives/exact-symbols.json','w'),indent=2)
print(json.dumps(stats));print('matching files',len(records))
