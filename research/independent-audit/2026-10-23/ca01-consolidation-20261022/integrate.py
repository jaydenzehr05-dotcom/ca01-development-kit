from pathlib import Path
import subprocess,json,hashlib,shutil
base=Path('/tmp/ca01-consolidation-20261022'); main=Path('/home/starlight/projects/rav4-radio/ca01-development-kit'); research=Path('/tmp/ca01-firmware-updater-research')
for name in ['main','research']:
 s=json.loads((base/(name+'-snapshot.json')).read_text()); repo=Path(s['path'])
 assert subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()==s['head']
 assert subprocess.check_output(['git','-C',str(repo),'status','--porcelain=v1'],text=True)==s['status']
 for f in s['files']:assert hashlib.sha256((repo/f['path']).read_bytes()).hexdigest()==f['sha256']
subprocess.run(['git','merge','--squash','a562b3b3ca8ba91f697b2b8624cb0aeea9f8e479'],cwd=main,check=True)
subprocess.run(['git','apply',str(base/'research-unstaged.patch')],cwd=main,check=True)
untracked=subprocess.check_output(['git','ls-files','-o','--exclude-standard','-z'],cwd=research).decode().strip('\0').split('\0')
for name in untracked:
 if not name:continue
 src=research/name;dst=main/name
 if dst.exists():assert src.read_bytes()==dst.read_bytes(),name
 else:
  dst.parent.mkdir(parents=True,exist_ok=True)
  with dst.open('xb') as f:f.write(src.read_bytes())
  dst.chmod(src.stat().st_mode & 0o777)
print('Squashed published research + all uncommitted research; main emulator files retained. No commit yet.')
