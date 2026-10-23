from pathlib import Path
import json,re,hashlib,collections,math,struct
roots=[('audio-leading',Path('/tmp/ca01-more-recovery/audio/UNTRUSTED.partial.bin'),Path('/tmp/ca01-more-recovery/audio/known-byte-mask.bin'),0,1092092),('middleware-known-suffix',Path('/tmp/ca01-middleware-research/known-suffix.bin'),None,0,None)]
patterns={'ELF':b'\x7fELF','gzip':b'\x1f\x8b\x08','xz':b'\xfd7zXZ\0','bzip2':b'BZh','zip':b'PK\x03\x04','squashfs-le':b'hsqs','squashfs-be':b'sqsh','cpio-newc':b'070701','cpio-crc':b'070702','romfs':b'-rom1fs-','cramfs-le':bytes.fromhex('453dcd28'),'jffs2-le':bytes.fromhex('8519'),'UBI':b'UBI#','uImage':bytes.fromhex('27051956'),'zImage':bytes.fromhex('18286f01'),'sqlite':b'SQLite format 3\0','shstrtab':b'\0.shstrtab\0','libsecurity':b'libsecurity','sysAes':b'sysAes','sysRsa':b'sysRsa','sysSha256':b'sysSha256','sysSec':b'sysSec','AES-Sbox-first16':bytes.fromhex('637c777bf26b6fc53001672bfed7ab76'),'SHA256-K-first4-le':struct.pack('<4I',0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5)}
results=[]
for name,p,mp,a,b in roots:
 o=p.read_bytes()[a:b];mask=mp.read_bytes()[a:b] if mp else bytes([1])*len(o);hits={}
 for tag,pat in patterns.items():
  found=[m.start() for m in re.finditer(re.escape(pat),o) if all(mask[m.start():m.start()+len(pat)])]
  if found:hits[tag]=found[:100]
 # Without relying on USTAR magic: check all offsets having ASCII octal checksum fields.
 headers=[]
 for m in re.finditer(rb'[0-7]{6}[\0 ][\0 ]',o):
  start=m.start()-148;h=o[start:start+512]
  if start<0 or len(h)!=512 or not all(mask[start:start+512]):continue
  try:checksum=int(h[148:156].strip(b'\0 '),8);size=int(h[124:136].strip(b'\0 '),8)
  except ValueError:continue
  if checksum!=sum(h[:148])+256+sum(h[156:]):continue
  headers.append({'offset':start,'name':h[:100].split(b'\0')[0].decode('ascii','replace'),'size':size,'type':h[156]})
 c=collections.Counter(o);results.append({'region':name,'source_artifact':str(p),'region_sha256':hashlib.sha256(o).hexdigest(),'size':len(o),'known_bytes':sum(mask),'entropy_including_zero_filled_unknowns':-sum(n/len(o)*math.log2(n/len(o)) for n in c.values()),'known_signature_hits':hits,'all_patterns_searched':list(patterns),'magic_independent_tar_headers':headers,'tar_checksum_filter':'six octal digits plus two space/NUL terminators; every matching offset tested, not restricted to grid'})
Path('/tmp/ca01-libsecurity-local/region-signatures.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
