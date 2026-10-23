#!/usr/bin/env python3
"""Find exact instruction-byte windows irrespective of shifts in ELF layout.

This detects preserved binary regions even when an inserted/reordered function
makes a naïve positional byte comparison misleading. It does not establish
semantic function equivalence.
"""
import json,collections,hashlib,zlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
ROOT=Path("/home/starlight/projects/rav4-radio")
BASE=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023"
old=json.loads((ROOT/"system-audit/ca01-updater-independent-20261022/recovery-manifest.json").read_text())["files"]
new=json.loads((BASE/"recovered-1134-06-audio/recovered-manifest.json").read_text())
p1={x["archive_path"]:Path(x["local_path"]) for x in old}
p2={x["archive_path"]:Path(x["local_file"]) for x in new}
names=["PROC_DISPLAY","PROC_VRS","PROC_HMI"]
def load_text(f):
  with f.open("rb") as fp:
    e=ELFFile(fp)
    t=e.get_section_by_name(".text")
    return t.data(),t["sh_addr"],t["sh_offset"],(e.get_section_by_name(".symtab") is not None)
results=[]
for name in names:
  path="./opt/ftl/apl/"+name
  a,old_vaddr,old_fileoff,has_symtab1=load_text(p1[path])
  b,new_vaddr,new_fileoff,has_symtab2=load_text(p2[path])
  window=64;step=128
  index={}
  # Every ARM instruction aligned 4B, including Thumb data? sampling only.
  for n in range(0,len(b)-window+1,4):
    chunk=b[n:n+window]
    h=zlib.crc32(chunk)
    index[h]=n
  matched=0
  inplace=0
  deltas=collections.Counter()
  samples=0
  first=[]
  for i in range(0,len(a)-window+1,step):
    samples+=1
    chunk=a[i:i+window]
    if i+window<=len(b) and b[i:i+window]==chunk:inplace+=1
    j=index.get(zlib.crc32(chunk))
    if j is not None and b[j:j+window]==chunk:
      matched+=1
      deltas[j-i]+=1
    elif len(first)<30:
      first.append({"old_text_offset":i,"old_vaddr":hex(old_vaddr+i),
                    "old_first_16_hex":chunk[:16].hex()})
  result=dict(name=name,
      code_sha_1127=hashlib.sha256(a).hexdigest(),
      code_sha_1134=hashlib.sha256(b).hexdigest(),
      text_length_1127=len(a),text_length_1134=len(b),
      vaddr_1127=hex(old_vaddr),vaddr_1134=hex(new_vaddr),
      has_symtab_1127=has_symtab1,has_symtab_1134=has_symtab2,
      checked_64byte_samples=samples,
      matched_at_exact_same_offset=inplace,
      matched_anywhere_at_4byte_alignment=matched,
      relocated_window_percentage=round(100*matched/max(samples,1),2),
      same_offset_window_percentage=round(100*inplace/max(samples,1),2),
      most_common_relative_shifts=deltas.most_common(18),
      unmatched_sample_examples=first,
      caveat="Exact 64-byte chunks found elsewhere in new code; a match does not prove all code behavior is preserved")
  results.append(result)
  print(name,"64-byte windows",samples,"same offset",inplace,
        "matched elsewhere",matched,
        "match%",result["relocated_window_percentage"],
        "common relocation",result["most_common_relative_shifts"][:7],flush=True)
(BASE/"display-code-anchors.json").write_text(json.dumps(results,indent=2)+"\n")
