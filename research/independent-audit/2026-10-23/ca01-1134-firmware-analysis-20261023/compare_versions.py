#!/usr/bin/env python3
"""Lossless CA01 1127 vs 1134 KWI table comparison (read-only inputs)."""
import sys, json, collections, math
from pathlib import Path
ROOT=Path('/home/starlight/projects/rav4-radio')
sys.path.insert(0,str(ROOT/'ca01-development-kit/tools'))
from ca01_inspect import inspect_bytes
A=ROOT/'stock-firmware/15TBDANA-CA01_1127.kwi'
B=ROOT/'stock-firmware/15TBDANA-CA01_1134.kwi'
old=A.read_bytes(); new=B.read_bytes()
oa=inspect_bytes(old); nb=inspect_bytes(new)
base=Path(__file__).resolve().parent
(base/'1127-inspection.json').write_text(json.dumps(oa,indent=2)+'\n')
(base/'1134-inspection.json').write_text(json.dumps(nb,indent=2)+'\n')
print('HEADERS',oa['header_size'],nb['header_size'],'PAYLOAD_START',oa['payload_base'],nb['payload_base'])
print('TOTAL',oa['file_size'],nb['file_size'],'DIFF',nb['file_size']-oa['file_size'])
print('HASH 1127',oa['sha256'])
print('HASH 1134',nb['sha256'])
print('TAG',oa['package_tag'],nb['package_tag'],'FIELD',oa['version_field_hex'],nb['version_field_hex'])
rows=[]
for a,b in zip(oa['components'],nb['components']):
  assert a['index']==b['index'] and a['name']==b['name']
  rows.append(dict(index=a['index'],name=a['name'],old_version=a['version'],new_version=b['version'],
                   old_update_raw=a['update_value_raw'],new_update_raw=b['update_value_raw'],
                   old_size=a['size'],new_size=b['size'],size_delta=b['size']-a['size'],
                   byte_identical=a['sha256']==b['sha256'],old_sha256=a['sha256'],
                   new_sha256=b['sha256'],old_offset=a['offset'],new_offset=b['offset']))
  print(f"{a['index']:2d} {a['name']:<20s} sizes={a['size']:9d}->{b['size']:9d} delta={b['size']-a['size']:+9d} equal={rows[-1]['byte_identical']} version={a['version']} -> {b['version']}")
result=dict(old_file=str(A),new_file=str(B),old_sha256=oa['sha256'],new_sha256=nb['sha256'],
            metadata_equal_except_version=None,components=rows)
(base/'component-comparison.json').write_text(json.dumps(result,indent=2)+'\n')
print('CHANGED',sum(not r['byte_identical'] for r in rows),'UNCHANGED',sum(r['byte_identical'] for r in rows))
