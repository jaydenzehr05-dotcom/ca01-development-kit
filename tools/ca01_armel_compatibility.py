#!/usr/bin/env python3
"""Inspect availability of ARM ELF DT_NEEDED in recovered set and ARMel rootfs (read only)."""
import argparse,json,subprocess
from pathlib import Path
from ca01_gui_dependency_audit import audit
def main():
 p=argparse.ArgumentParser()
 p.add_argument('--recovered',type=Path,required=True)
 p.add_argument('--rootfs',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True)
 a=p.parse_args()
 inventory=audit(a.recovered)
 roots=[a.rootfs/'lib',a.rootfs/'usr/lib']
 roots=[r for r in roots if r.exists()]
 candidate={}
 for root in roots:
  for path in root.rglob('*.so*'):
   if not path.is_file():continue
   candidate.setdefault(path.name,str(path.relative_to(a.rootfs)))
 rows=[]
 for e in inventory['programs']:
  unresolved=[n for n in e['missing'] if n not in candidate]
  system=[n for n in e['missing'] if n in candidate]
  rows.append({'program':e['original_name'],'needed':len(e['required']),
               'in_recovered':e['available'],'in_armel_system':system,'unresolved':unresolved})
 report={'read_only':True,'disclaimer':'SONAME presence != ABI compatibility or working graphics/hardware',
         'rootfs':str(a.rootfs),'recovered':str(a.recovered),'programs':rows,
         'unique_unresolved':sorted({name for row in rows for name in row['unresolved']})}
 a.output.parent.mkdir(parents=True,exist_ok=True)
 a.output.write_text(json.dumps(report,indent=2)+'\n')
 for x in rows:
  if x['program'] in ('PROC_HMI','PROC_DISPLAY','PROC_REPRO'):
   print(x['program'],'dependencies',x['needed'],'recovered',len(x['in_recovered']),'system',len(x['in_armel_system']),'unresolved',len(x['unresolved']))
   print('Missing:',', '.join(x['unresolved']))
 print('Unique unresolved:',len(report['unique_unresolved']))
if __name__=='__main__':main()
