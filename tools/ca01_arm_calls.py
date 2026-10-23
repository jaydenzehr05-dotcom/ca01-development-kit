#!/usr/bin/env python3
"""Hash-gated static ARM32 call candidates; never execute original code.

Visits every aligned .text word even across undecodable data. Decoded words
are candidates, not proof of reachable code. ARM/Thumb state and embedded
literal data require function-level analysis before semantic conclusions.
"""
from pathlib import Path
import argparse,hashlib,io,json,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from capstone.arm import ARM_OP_IMM,ARM_INS_BL,ARM_INS_BLX
from elftools.elf.elffile import ELFFile


def decode_prel31(word,place):
 value=word&0x7fffffff
 return (place+(value if value<0x40000000 else value-0x80000000))&0xffffffff


def scan_arm32_calls(code,address,imports):
 if address%4 or len(code)%4:raise ValueError('ARM32 scan requires aligned complete words')
 decoder=Cs(CS_ARCH_ARM,CS_MODE_ARM);decoder.detail=True;decoder.skipdata=True
 calls={};visited=0;bad=0;direct=0
 for ins in decoder.disasm(code,address):
  if ins.address!=address+visited:raise ValueError('Decoder skipped an unaccounted range')
  visited+=ins.size
  if not ins.id:bad+=ins.size;continue
  if ins.id not in (ARM_INS_BL,ARM_INS_BLX):continue
  if not ins.operands or ins.operands[0].type!=ARM_OP_IMM:continue
  direct+=1
  name=imports.get(ins.operands[0].imm)
  if name:calls.setdefault(name,[]).append(hex(ins.address))
 if visited!=len(code):raise ValueError('Decoder did not account for complete input')
 return dict(visited_bytes=visited,undecodable_bytes=bad,decoded_candidate_bytes=visited-bad,
             direct_branch_calls=direct,calls=dict(sorted(calls.items())))


def audit_elf(path,expected_sha256):
 data=Path(path).read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=expected_sha256:raise ValueError('Original ELF SHA-256 mismatch')
 elf=ELFFile(io.BytesIO(data))
 if elf.elfclass!=32 or not elf.little_endian or elf.header.e_machine!='EM_ARM':raise ValueError('Requires little-endian ARM32 ELF')
 text=elf.get_section_by_name('.text');plt=elf.get_section_by_name('.plt')
 reloc=elf.get_section_by_name('.rel.plt');symbols=elf.get_section_by_name('.dynsym')
 unwind=elf.get_section_by_name('.ARM.exidx')
 if any(x is None for x in (text,plt,reloc,symbols,unwind)):raise ValueError('Required ARM ELF sections absent')
 rows=list(reloc.iter_relocations())
 if plt['sh_size']!=20+12*len(rows):raise ValueError('Unverified ARM PLT layout')
 imports={plt['sh_addr']+20+12*i:symbols.get_symbol(row['r_info_sym']).name for i,row in enumerate(rows)}
 starts=[]
 raw=unwind.data()
 if len(raw)%8:raise ValueError('Malformed exception index')
 for offset in range(0,len(raw),8):starts.append(decode_prel31(struct.unpack_from('<I',raw,offset)[0],unwind['sh_addr']+offset))
 thumb=sum(x&1 for x in starts)
 if thumb:raise ValueError('Thumb unwind entries require a separate state-aware scan')
 if any(a>b for a,b in zip(starts,starts[1:])):raise ValueError('Unsorted exception index')
 if any(not text['sh_addr']<=x<=text['sh_addr']+text['sh_size'] for x in starts):raise ValueError('Unwind range outside text')
 scan=scan_arm32_calls(text.data(),text['sh_addr'],imports)
 return dict(path=str(Path(path).resolve()),sha256=sha,text_address=hex(text['sh_addr']),text_bytes=text['sh_size'],
             plt_imports=len(imports),unwind_entries=len(starts),unwind_thumb_entries=thumb,
             unwind_starts=[hex(x) for x in starts],scan=scan,
             limits=['Static aligned ARM instruction candidates, not reachability or function equivalence',
                     'Data words can decode as instructions; indirect/GOT/callback calls are not counted',
                     'No Thumb unwind entries detected, but unwinding alone is not proof every word is ARM code'])


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('elf',type=Path);p.add_argument('--sha256',required=True)
 p.add_argument('--output',required=True,type=Path);a=p.parse_args()
 if a.output.exists() or a.output.is_symlink():p.error('Output must be new')
 result=audit_elf(a.elf,a.sha256)
 with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print('Accounted for',result['scan']['visited_bytes'],'text bytes;',sum(map(len,result['scan']['calls'].values())),'direct import-call candidates')
if __name__=='__main__':main()
