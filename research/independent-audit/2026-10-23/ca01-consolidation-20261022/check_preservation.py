from pathlib import Path
import hashlib,json,subprocess
out=Path('/tmp/ca01-consolidation-20261022'); root=Path('/home/starlight/projects/rav4-radio')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=root/'system-audit/ca01-updater-independent-20261022/recovery-manifest.json';rows=json.loads(manifest.read_text())['files']
for r in rows:
 p=Path(r['local_path']);assert p.stat().st_size==r['size'] and sha(p)==r['sha256']
partial=root/'system-audit/ca01-additional-recovery-20261022';parts=json.loads((partial/'SHA256-MANIFEST.json').read_text())
for r in parts:
 p=partial/r['relative_path'];assert p.stat().st_size==r['size'] and sha(p)==r['sha256']
search=root/'system-audit/ca01-libsecurity-search-20261022';search_rows=json.loads((search/'SHA256-MANIFEST.json').read_text())['files']
for r in search_rows:
 p=search/r['path'];assert p.stat().st_size==r['size'] and sha(p)==r['sha256']
originals={'stock-firmware/15TBDANA-CA01_1127.kwi':'39431b79ed849be627c13be586019ceaab34470a534b76c385f73f1748d367ca','vendor-source/OSS_SOFT_PACK.tgz':'32d36d304284f03bab05f3c1457124e4c162c0163ac683ac5e6091403f6e3bf9','vendor-source/20130619_LE2355.tgz':'534800cc7991dfd29d72ce68ab750833cad3eea5d4f8fac0bffa6fc1e6dfb29e'}
for p,h in originals.items():assert sha(root/p)==h
snap=json.loads((out/'research-snapshot.json').read_text());research=Path(snap['path'])
assert subprocess.check_output(['git','-C',str(research),'rev-parse','HEAD'],text=True).strip()==snap['head']
assert subprocess.check_output(['git','-C',str(research),'status','--porcelain=v1'],text=True)==snap['status']
for r in snap['files']:assert sha(research/r['path'])==r['sha256']
report=dict(complete_recovered_files=len(rows),arm_elf_files=sum(r.get('ELF',False) for r in rows),partial_artifacts_verified=len(parts),search_artifacts_verified=len(search_rows),research_worktree_unchanged=True,originals=originals)
(out/'preservation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
