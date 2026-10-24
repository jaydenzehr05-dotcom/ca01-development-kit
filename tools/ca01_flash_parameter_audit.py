#!/usr/bin/env python3
"""Read-only scoped audit for original NOR parameter/profile sources.

Manifest hashes establish identity, not load addresses. No raw file offset is
assumed to be a NOR address. A recognized image header is only a candidate:
CRC, model compatibility and authenticity remain unverified. No extraction,
mounting, vendor executable launch, device access or firmware writes occur.
"""
import argparse,hashlib,json,stat,struct
from pathlib import Path
MAGIC=b'13Cy-NOR-FLASH-IMAGE\0'
REQUIRED={'vehicle_parameters':(0xb0000,0x100),'profile_table_1':(0xc0000,0x25f4),'profile_table_2':(0xd0000,0xa261)}

def inspect_image(data):
 offsets=[];position=0
 while len(offsets)<16:
  position=data.find(MAGIC,position)
  if position<0:break
  offsets.append(position);position+=len(MAGIC)
 result=dict(bytes=len(data),signature_offsets=offsets,header_candidate=False,
  verified_parameter_source=False,crc_verified=False,authenticity_verified=False)
 if not data.startswith(MAGIC) or len(data)<128:return result
 start,end=struct.unpack_from('<II',data,0x20)
 result['candidate_header']=dict(start=hex(start),end_exclusive=hex(end),header_bytes=128)
 if start>=end or end>0x800000 or end-start!=len(data)-128 or (start|end)&3:
  result['rejection']='Header range, alignment or payload size inconsistent';return result
 result['header_candidate']=True
 result['candidate_coverage']={name:start<=begin and begin+size<=end for name,(begin,size) in REQUIRED.items()}
 return result

def audit_records(records):
 rows=[];errors=[];seen={}
 for record in records:
  p=Path(record['path'])
  key=str(p)
  identity=(record['size'],record['sha256'])
  if key in seen:
   if seen[key]!=identity:errors.append(dict(path=str(p),error='Conflicting duplicate manifest size/SHA-256 assertions'))
   continue
  seen[key]=identity
  try:
   info=p.stat()
   if not stat.S_ISREG(info.st_mode) or info.st_size>64*1024*1024:raise ValueError('Not a bounded regular file')
   data=p.read_bytes();digest=hashlib.sha256(data).hexdigest()
   if len(data)!=record['size'] or digest!=record['sha256']:raise ValueError('Recorded size/SHA-256 mismatch')
   row=dict(record);row.update(inspect_image(data));rows.append(row)
  except (OSError,ValueError) as error:errors.append(dict(path=str(p),error=str(error)))
 return dict(scope='Recorded recovered-file, package-component and carved-payload manifests only; not every local file or archive',
  required_flash_ranges={name:dict(address=hex(begin),bytes=size) for name,(begin,size) in REQUIRED.items()},
  files=rows,errors=errors,verified_files=len(rows),header_candidates=sum(r['header_candidate'] for r in rows),
  verified_parameter_sources=0,limits='Hashes prove identity, not raw NOR mapping, CRC, board compatibility or authenticity; no candidate automatically promoted')

def collect_records(root):
 records=[];manifests=[];resolutions=[]
 audit=root/'system-audit';old=audit/'ca01-updater-independent-20261022';new=audit/'ca01-1134-firmware-analysis-20261023'
 manifests=[old/'recovery-manifest.json']
 manifests+=sorted(new.glob('recovered-1134-*/recovered-manifest.json'))
 manifests+=sorted((audit/'ca01-additional-recovery-20261022').glob('*/recovered-manifest.json'))
 for manifest in manifests:
  parsed=json.loads(manifest.read_text());rows=parsed['files'] if isinstance(parsed,dict) else parsed
  for row in rows:
   p=Path(row.get('local_path',row.get('local_file','')))
   if not p.is_file():
    candidate=manifest.parent/'recovered'/p.name
    if candidate.is_file():resolutions.append(dict(recorded=str(p),current=str(candidate)));p=candidate
   records.append(dict(path=str(p),size=row['size'],sha256=row['sha256'],source_manifest=str(manifest),provenance=row['archive_path']))
 for directory in (root/'stock-firmware/components',new/'components-1134'):
  manifest=directory/'manifest.json';parsed=json.loads(manifest.read_text())
  for row in parsed['components']:
   records.append(dict(path=str(directory/row['filename']),size=row['size'],sha256=row['sha256'],source_manifest=str(manifest),provenance='KWI component; NOR load address not established'))
 for directory in (audit/'carved-payloads',new/'inner-1134'):
  manifest=directory/'manifest.json'
  for row in json.loads(manifest.read_text()):
   filename=row['component'].replace('.bin','.payload.bin')
   records.append(dict(path=str(directory/filename),size=row['inner_size'],sha256=row['inner_sha256'],source_manifest=str(manifest),provenance='Carved wrapper payload; '+row['note']))
 return records,resolutions

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--research-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 records,resolutions=collect_records(a.research_root);report=audit_records(records);report['manifest_path_resolutions']=resolutions
 with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print(f"Verified {report['verified_files']} recorded files; header candidates {report['header_candidates']}; verified parameter sources 0; errors {len(report['errors'])}")
 if report['errors']:raise SystemExit(2)
if __name__=='__main__':main()
