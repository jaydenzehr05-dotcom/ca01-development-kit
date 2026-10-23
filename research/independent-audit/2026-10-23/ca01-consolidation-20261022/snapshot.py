import subprocess,json,hashlib,tarfile
from pathlib import Path
root=Path('/tmp/ca01-consolidation-20261022')
for label,folder in [('main','/home/starlight/projects/rav4-radio/ca01-development-kit'),('research','/tmp/ca01-firmware-updater-research')]:
 p=Path(folder)
 def git(*args):return subprocess.check_output(['git','-C',folder,*args])
 files=sorted(set(git('ls-files','-m','-o','--exclude-standard','-z').decode().strip('\0').split('\0'))-{''})
 records=[]
 with tarfile.open(root/(label+'-working-files.tar'),'x') as tar:
  for name in files:
   f=p/name;assert f.is_file() and not f.is_symlink()
   records.append(dict(path=name,size=f.stat().st_size,sha256=hashlib.sha256(f.read_bytes()).hexdigest()))
   tar.add(f,arcname=name,recursive=False)
 (root/(label+'-snapshot.json')).write_text(json.dumps(dict(path=folder,head=git('rev-parse','HEAD').decode().strip(),status=git('status','--porcelain=v1').decode(),files=records),indent=2)+'\n')
 (root/(label+'-unstaged.patch')).write_bytes(git('diff','--binary'))
 (root/(label+'-staged.patch')).write_bytes(git('diff','--cached','--binary'))
 print(label,'snapshot',len(files),'files',sum(r['size'] for r in records),'bytes')
