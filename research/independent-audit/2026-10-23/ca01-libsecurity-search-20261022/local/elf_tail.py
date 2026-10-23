from pathlib import Path
import struct,json
b=Path('/tmp/ca01-more-recovery/audio/UNTRUSTED.partial.bin').read_bytes();mask=Path('/tmp/ca01-more-recovery/audio/known-byte-mask.bin').read_bytes();s=b.find(b'\0.shstrtab\0');strtab=b[s:s+219];table=s+219;sections=[]
for i in range(26):
 row=struct.unpack_from('<10I',b,table+i*40);name=strtab[row[0]:].split(b'\0')[0].decode();sections.append(dict(zip(['index','name','type','flags','address','file_offset','size','link','info','alignment','entry_size'],[i,name,*row[1:]])))
base=s-next(x['file_offset'] for x in sections if x['name']=='.shstrtab')
for x in sections:
 a=base+x['file_offset'];z=a+x['size'];x['partial_output_offset']=a;x['fully_available']=a>=0 and z<=len(b) and all(mask[a:z])
dyn=next(x for x in sections if x['name']=='.dynamic');a=dyn['partial_output_offset'];entries=[struct.unpack_from('<II',b,i) for i in range(a,a+dyn['size'],8)];r={'partial_file_start_relative_output':base,'section_table_output_offset':table,'section_table_fully_known':all(mask[table:table+26*40]),'section_count_inferred':26,'section_names_output_offset':s,'sections':sections,'dynamic_entries':entries,'identity':'Unidentified incomplete ELF tail; no ELF header, archive header, dynstr or dynsym is present.','limitation':'Start coordinate is inferred by internally consistent shstrtab offset, not validated by a recovered file header.'};Path('/tmp/ca01-libsecurity-local/audio-leading-elf-sections.json').write_text(json.dumps(r,indent=2));print(json.dumps(r,indent=2))
