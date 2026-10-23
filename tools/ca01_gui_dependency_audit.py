#!/usr/bin/env python3
"""Read-only dependency inventory for recovered ARM ELFs."""
import argparse,json,subprocess,hashlib
from pathlib import Path
def audit(directory):
 files=sorted(p for p in Path(directory).iterdir() if p.is_file())
 index={p.name.split('-',1)[-1]:p for p in files}
 out=[]
 for p in files:
  r=subprocess.run(['readelf','-d',str(p)],capture_output=True,text=True)
  if r.returncode:continue
  needed=[]
  for line in r.stdout.splitlines():
   if '(NEEDED)' in line and '[' in line:
    needed.append(line.split('[',1)[1].split(']',1)[0])
  q=subprocess.run(['readelf','-l',str(p)],capture_output=True,text=True)
  interp=next((x.split('interpreter:',1)[1].strip(' ]') for x in q.stdout.splitlines() if 'Requesting program interpreter:' in x),None)
  out.append({'file':p.name,'original_name':p.name.split('-',1)[-1],'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
     'required':needed,'available':sorted(x for x in needed if x in index),
     'missing':sorted(x for x in needed if x not in index),'interpreter':interp})
 return {'scope':'recovered-folder-only; missing means not in this recovered folder, NOT absent from production radio or vendor archives',
         'files_examined':len(files),'elfs':len(out),
         'unique_required':sorted({v for x in out for v in x['required']}),
         'unique_missing':sorted({v for x in out for v in x['missing']}),'programs':out}
def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('folder',type=Path)
 parser.add_argument('--output',type=Path)
 a=parser.parse_args()
 data=audit(a.folder)
 s=json.dumps(data,indent=2)+'\n'
 if a.output:a.output.write_text(s)
 else:print(s)
if __name__=='__main__':main()
