"""Bind the hash-verified recovered group module into a bounded ARM trace.

Only application exports are resolved here. Thread/task services remain
explicit boundaries until their actual startup context exists.
"""
import hashlib,struct
from pathlib import Path
from ca01_hmi_startup import ElfImage

GROUP_SHA256='c87538f1de097ef01c8f169971d922068a9f7c2c87faaa1fb9a036cd14dc87ef'
GROUP_BIAS=0x20000000


def bind_group(trace,hmi_image,path):
    data=Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest()!=GROUP_SHA256:raise ValueError('Group library SHA-256 mismatch')
    group=ElfImage(data);uc=trace.uc
    for seg in group.segments:
        start=GROUP_BIAS+seg['p_vaddr'];end=start+seg['p_memsz']
        uc.mem_map(start&~4095,((end+4095)&~4095)-(start&~4095))
        uc.mem_write(start,seg.data())
        if seg['p_flags']&1:trace.executable_ranges.append((start,end))
    hmi_symbols={s.name:s['st_value'] for s in hmi_image.elf.get_section_by_name('.dynsym').iter_symbols()
                 if s['st_shndx']!='SHN_UNDEF' and s.name}
    group_symbols={s.name:GROUP_BIAS+s['st_value'] for s in group.elf.get_section_by_name('.dynsym').iter_symbols()
                   if s['st_shndx']!='SHN_UNDEF' and s.name}
    for image,bias in ((hmi_image,0),(group,GROUP_BIAS)):
        trace.symbols.update({bias+s['st_value']:s.name for s in image.elf.get_section_by_name('.dynsym').iter_symbols()
          if s['st_shndx']!='SHN_UNDEF' and s['st_info']['type']=='STT_FUNC'})
    # A separate page per unknown import preserves the engine's external-data
    # guards. The complete region is mapped once; no unknown code executes.
    uc.mem_map(0x62000000,0x400000);traps={}
    def external(symbol):
        if symbol.name in hmi_symbols:return hmi_symbols[symbol.name]
        if symbol.name not in traps:
            if len(traps)>=1024:raise ValueError('Too many group imports')
            address=0x62000000+len(traps)*4096;traps[symbol.name]=address
            trace.imports[address]=symbol.name
        return traps[symbol.name]
    from elftools.elf.relocation import RelocationSection
    for section in group.elf.iter_sections():
        if not isinstance(section,RelocationSection):continue
        table=group.elf.get_section(section['sh_link'])
        for rel in section.iter_relocations():
            destination=GROUP_BIAS+rel['r_offset'];kind=rel['r_info_type']
            symbol=table.get_symbol(rel['r_info_sym'])
            addend=struct.unpack('<I',uc.mem_read(destination,4))[0]
            if kind==23:value=GROUP_BIAS+addend
            elif kind in (2,21,22):
                value=external(symbol) if symbol['st_shndx']=='SHN_UNDEF' else GROUP_BIAS+symbol['st_value']
                if kind==2:value+=addend
                if symbol['st_shndx']=='SHN_UNDEF' and symbol['st_info']['type']=='STT_OBJECT' and symbol.name not in hmi_symbols:
                    trace.blocked_reads[destination]=symbol.name
            else:raise ValueError('Unsupported group relocation '+str(kind))
            uc.mem_write(destination,struct.pack('<I',value&0xffffffff))
    # Real rq_grp_Init calls the original HMI pt_grp_Init, then the real task
    # readiness interface. Never replace that wait by an automatic success.
    plt=next(s['st_value'] for s in hmi_image.elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='rq_grp_Init')
    trace.imports.pop(plt)
    uc.mem_write(plt,struct.pack('<3I',0xe59fc000,0xe12fff1c,group_symbols['rq_grp_Init']))
    return dict(sha256=GROUP_SHA256,bias=hex(GROUP_BIAS),entry=hex(group_symbols['rq_grp_Init']),
                application_callback=hex(hmi_symbols['pt_grp_Init']),
                deferred_service='rq_tsk_WaitInit: available system code requires actual task/queue startup context')
