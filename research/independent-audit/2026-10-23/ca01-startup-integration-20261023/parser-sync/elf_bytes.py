import pathlib,struct
P=pathlib.Path('/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so');B=P.read_bytes();H=struct.unpack_from('<16sHHIIIIIHHHHHH',B);SEG=[struct.unpack_from('<IIIIIIII',B,H[5]+i*H[9]) for i in range(H[10])]
def off(a):
 a-=0x10000
 for p in SEG:
  if p[0]==1 and p[2]<=a<p[2]+p[4]:return p[1]+a-p[2]
 raise ValueError(hex(a))
def word(a):return struct.unpack_from('<I',B,off(a))[0]
def string(a):o=off(a);return B[o:B.index(0,o)].decode('ascii','backslashreplace')
def resolve(basepc,baselit,stringlit):
 base=(basepc+word(baselit))&0xffffffff;addr=(base+word(stringlit))&0xffffffff
 return {'ghidra_address':hex(addr),'elf_address':hex(addr-0x10000),'file_offset':off(addr),'value':string(addr)}
if __name__=='__main__':
 for x in [(0x1c400,0x1c5b4,0x1c5bc),(0x1c8b8,0x1c934,0x1c944),(0x1c8b8,0x1c934,0x1c948)]:print(resolve(*x))
