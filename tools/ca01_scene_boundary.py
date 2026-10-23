#!/usr/bin/env python3
"""Original scene/startup boundary trace and hash-gated MC requirements.

No graphics service is substituted here. Initial BSS is uninitialized-scene
state, so these traces identify prerequisites, not a fully booted next frame.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct
from ca01_hmi_startup import ElfImage,HMI_SHA256
from ca01_startup_trace import BoundedArmTrace


class ConfiguredSemaphores:
    """Stateful scoped model of configured sem_init(value=1) objects.

    Original rq_sem_Take ignores the extra r1 value and uses a 30-second
    sem_timedwait. This bounded probe stops explicitly if a lock would block;
    it never synthesizes a timeout return or claims a successful busy take.
    """
    def __init__(self,ids):
        import threading
        self.semaphores={index:threading.Semaphore(1) for index in ids}
    def take(self,uc,args):
        if args[0] not in self.semaphores:raise ValueError('Semaphore was not configured')
        if not self.semaphores[args[0]].acquire(blocking=False):raise RuntimeError('Semaphore would block: original timeout is30s')
        return 0
    def give(self,uc,args):
        if args[0] not in self.semaphores:raise ValueError('Semaphore was not configured')
        self.semaphores[args[0]].release();return 0


def inspect_scene_boundary(path,*,provide_clock=False,provide_semaphores=False,system_library=None,group_library=None,instruction_limit=20000):
    if provide_semaphores and not provide_clock:raise ValueError("Core clock/memory services required before semaphore model")
    data=Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest()!=HMI_SHA256:raise ValueError('Canonical HMI SHA-256 mismatch')
    image=ElfImage(data)
    from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM
    def engine():
        if provide_clock:
            from ca01_startup_trace import prepare,BIAS
            if system_library is None:raise ValueError('Verified system library required for clock integration')
            trace,defined=prepare(data,Path(system_library).read_bytes())
            uc=trace.uc;ranges=list(trace.executable_ranges)
        else:uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);ranges=[]
        for seg in image.segments:
            address=seg['p_vaddr'];end=address+seg['p_memsz']
            if not provide_clock:
                uc.mem_map(address&~4095,((end+4095)&~4095)-(address&~4095))
                uc.mem_write(address,seg.data())
            if seg['p_flags']&1:ranges.append((address,end))
        # PLT entries are already mapped, so add their fail-closed traps after
        # the engine has mapped its own separate stack/sentinel region.
        if not provide_clock:trace=BoundedArmTrace(uc,ranges,{})
        else:trace.executable_ranges=ranges
        hmi_imports={s['st_value']:s.name for s in image.elf.get_section_by_name('.dynsym').iter_symbols()
                       if s['st_shndx']=='SHN_UNDEF' and s['st_value']}
        trace.imports.update(hmi_imports)
        if provide_clock:
            import time
            def host_clock(uc,args):
                if args[0]!=1 or not 0x70000000<=args[1]<=0x7000fff8:
                    raise ValueError('Unexpected CLOCK_MONOTONIC ABI')
                ns=time.monotonic_ns();seconds,nanos=divmod(ns,1000000000)
                uc.mem_write(args[1],struct.pack('<ii',seconds,nanos))
                return 0
            trace.services['clock_gettime']=host_clock
            def guest_memset(uc,args):
                if args[2]>1024*1024:raise ValueError('Guest memset exceeds bounded service limit')
                # Verify the range is mapped before writing; never dereference a
                # guest pointer in the host address space.
                uc.mem_read(args[0],args[2])
                uc.mem_write(args[0],bytes([args[1]&255])*args[2])
                return args[0]
            trace.services['memset']=guest_memset
            if provide_semaphores:
                rows=[struct.unpack('<4I',image.read(0x59dfbc+index*16,16)) for index in range(64)]
                ids=[]
                for index,row in enumerate(rows):
                    if row[0]:
                        if row[0]!=1 or row[1]!=index:raise ValueError('Unexpected semaphore profile')
                        ids.append(index)
                semaphores=ConfiguredSemaphores(ids)
                trace.services['rq_sem_Take']=semaphores.take
                trace.services['rq_sem_Give']=semaphores.give
            # Bind the original HMI import to the original recovered sysc
            # export. All arithmetic in rq_sys_GetTick1ms remains original.
            address=next(a for a,n in hmi_imports.items() if n=='rq_sys_GetTick1ms')
            trace.imports.pop(address)
            uc.mem_write(address,struct.pack('<3I',0xe59fc000,0xe12fff1c,defined['rq_sys_GetTick1ms']))
        if group_library is not None:
            from ca01_group_binding import bind_group
            trace.group_binding=bind_group(trace,image,group_library)
        return trace
    e=engine();e.uc.mem_write(0x70001000,struct.pack('<4I',0,0,10,0))
    heartbeat=e.run(0x2b170,0x70001000)
    pending=e.uc.mem_read(0x26c98a2,1)[0]
    update=e.run(0x2b1f8,0,instruction_limit=instruction_limit)
    task_engine=engine()
    task39=task_engine.run(0x2a7ac,0)
    scene_initialization=engine().run(0x4058c,0,instruction_limit=instruction_limit)
    def string(address):return image.read(address,128).split(b'\0')[0].decode('ascii')
    rows=[]
    for index in range(10):
        words=struct.unpack('<4I',image.read(0x3f23fc+index*16,16))
        rows.append(dict(index=index,first=string(words[0]) if words[0] else None,
                         first_flag=words[1],second=string(words[2]) if words[2] else None,second_flag=words[3]))
    prefixes=[string(v) for v in struct.unpack('<16I',image.read(0x5dd934,64))]
    names=sorted({row[key] for row in rows for key in ('first','second') if row[key]})
    mui_names=sorted({m.group()[:-1].decode() for m in re.finditer(rb'[A-Za-z0-9_.-]{1,80}\.mui\x00',data)})
    return dict(hmi_sha256=HMI_SHA256,scope='Bounded original ARM instructions with zeroed initial BSS and fail-closed imports; no full scene initialization.',
      heartbeat=heartbeat,pending_after_heartbeat=pending,scene_update=update,task39_initialization=task39,scene_initialization=scene_initialization,
      full_scene_rendered=False,group_binding=getattr(task_engine,'group_binding',None),clock_service_provided=provide_clock,semaphore_model_provided=provide_semaphores,missing_resources=dict(
        mra_table_address='0x3f23fc',mra_records=rows,mra_names=names,
        mc_directory='/opt/ftl/gui/MC/',profile_prefix_table='0x5dd934',profile_prefixes=prefixes,
        mra_path_builder='0x3e9e8',mra_loading_loop='0x3eaf0',
        mui_directory='/opt/ftl/gui/MC/mui/',mui_path_builder='0x3e9a0',mui_names=mui_names,
        file_adapter='0x639cc -> rq_fls_Open',font_directory='/opt/ftl/gui/font/',
        caveat='Static requirements and candidate names, not recovered assets. Actual region/generation selection unknown. MRA container format not yet established.'))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--hmi',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--system-library',type=Path)
    p.add_argument('--group-library',type=Path,help='Canonical recovered libipas_grp.so; execute original group startup to its real wait boundary')
    p.add_argument('--provide-clock',action='store_true',help='Original sysc tick code with real CLOCK_MONOTONIC and bounded guest memset')
    p.add_argument('--configured-semaphores',action='store_true',help='Stateful scoped semaphore model from the verified HMI profile')
    p.add_argument('--instruction-limit',type=int,default=20000)
    a=p.parse_args()
    if a.output.exists() or a.output.is_symlink():p.error('Output must not exist')
    report=inspect_scene_boundary(a.hmi,provide_clock=a.provide_clock,provide_semaphores=a.configured_semaphores,system_library=a.system_library,group_library=a.group_library,instruction_limit=a.instruction_limit)
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print('Recorded blocked original scene and concrete asset requirements:',a.output)

if __name__=='__main__':main()
