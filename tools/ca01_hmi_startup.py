#!/usr/bin/env python3
"""Deterministic host-side model of observed CA01 HMI startup/queue boundaries.

The inspector reads ELF bytes; the model executes no Toyota code. It does not
export a replacement SysPowerOn, create
POSIX queues, or render pixels. Local queues use the shared C pthread runtime;
startup transitions remain an explicitly synthetic event model. Callbacks are mandatory so
missing services cannot silently become successful no-ops.
"""
from dataclasses import dataclass
import struct

class StartupBlocked(RuntimeError):
    """A required boundary has not been satisfied in the synthetic harness."""

@dataclass(frozen=True)
class Message:
    code: int
    subcommand: int
    event: int
    payload: int

    def __post_init__(self):
        if any(type(v) is not int or not 0 <= v <= 0xffffffff
               for v in (self.code,self.subcommand,self.event,self.payload)):
            raise ValueError('Message fields must be unsigned32-bit integers')

    def pack(self):
        return struct.pack('<4I',self.code,self.subcommand,self.event,self.payload)

    @classmethod
    def unpack(cls,data):
        if len(data)!=16:raise ValueError('Expected exactly16 message bytes')
        return cls(*struct.unpack('<4I',data))

class LocalQueue:
    """ctypes binding to the ONE C ring, with native pthread timed waits.

    Compile src/ca01_hmi_ipc.c explicitly; importing this module runs no build.
    The envelope has no host pointers. Lifetime must outlast concurrent users.
    """
    def __init__(self,capacity,*,runtime_library):
        import ctypes as c
        import weakref
        import sys
        if sys.byteorder!='little':raise RuntimeError('Little-endian runtime required')
        if type(capacity) is not int or not 1<=capacity<=64:
            raise ValueError('Capacity must be1..64')
        self.runtime=c.CDLL(str(runtime_library))
        signatures={
            'ca01_message_bytes':([],c.c_size_t),
            'ca01_queue_capacity':([],c.c_uint32),
            'ca01_queue_new':([c.c_uint32],c.c_void_p),
            'ca01_queue_delete':([c.c_void_p],None),
            'ca01_queue_count':([c.c_void_p],c.c_uint32),
            'ca01_queue_send_t':([c.c_void_p,c.c_void_p,c.c_uint32],c.c_int),
            'ca01_queue_receive_t':([c.c_void_p,c.c_void_p,c.c_uint32],c.c_int),
            'ca01_queue_receive_p':([c.c_void_p,c.c_void_p],c.c_int)}
        for name,(args,result) in signatures.items():
            fn=getattr(self.runtime,name);fn.argtypes=args;fn.restype=result
        if self.runtime.ca01_message_bytes()!=16 or self.runtime.ca01_queue_capacity()!=64:
            raise RuntimeError('Native IPC contract mismatch')
        self.pointer=self.runtime.ca01_queue_new(capacity)
        if not self.pointer:raise RuntimeError('Native queue initialization failed')
        self._cleanup=weakref.finalize(self,self.runtime.ca01_queue_delete,self.pointer)

    def __len__(self):return self.runtime.ca01_queue_count(self.pointer)

    def send(self,message,timeout_ms=0):
        import ctypes as c
        if not isinstance(message,Message):raise TypeError('Expected Message')
        self._timeout(timeout_ms)
        envelope=c.create_string_buffer(message.pack(),16)
        return self.runtime.ca01_queue_send_t(self.pointer,envelope,timeout_ms)

    @staticmethod
    def _timeout(ms):
        if type(ms) is not int or not 0<=ms<=0xffffffff:
            raise ValueError('Timeout must be unsigned32-bit milliseconds')

    def receive_p(self):
        import ctypes as c
        envelope=c.create_string_buffer(16)
        status=self.runtime.ca01_queue_receive_p(self.pointer,envelope)
        return status,Message.unpack(envelope.raw) if status==-1 else None

    def receive_t(self,timeout_ms=0):
        import ctypes as c
        self._timeout(timeout_ms)
        envelope=c.create_string_buffer(16)
        status=self.runtime.ca01_queue_receive_t(self.pointer,envelope,timeout_ms)
        return status,Message.unpack(envelope.raw) if status==0 else None

class StartupSequence:
    """Explicit SELF-AUTHORED event model of recovered startup conditions.

    This does not execute SysPowerOn or claim real external resources exist.
    Its event inputs represent proven service boundaries. Actual startup must
    first pass configuration, shared-memory and parent-IPC prerequisites.
    """
    def __init__(self):
        self.states={3:1,10:1,39:1,40:1,41:1}
        self.created=False
        self.active=False
        self.flag1=False
        self.flag2=False
        self.trace=[]

    def create_resources(self):
        if self.created:raise StartupBlocked('Resources already created')
        self.created=True
        self.states[3]=2  # SysInit starts enabled type8, not types3/5.
        self.trace.append(dict(event='model_resources_created',initial_started=[3]))

    def apply_power_state(self,active):
        if not self.created:raise StartupBlocked('SysResInit resources not created')
        if type(active) is not bool:raise TypeError('Explicit effective power state required')
        if active==self.active:return
        # Only the initial ON edge is verified here; do not invent stop/restart.
        if self.active and not active:raise StartupBlocked('Power-off sequence not modeled')
        self.active=active
        if active:
            for task in (10,39,40,41):
                if self.states[task]==1:
                    self.states[task]=2
                    self.trace.append(dict(event='AccOnStop_start',task=task,mask=1))

    def task_initialized(self,task):
        if self.states.get(task)!=2:raise StartupBlocked('Task is not at started status2')
        self.states[task]=3
        self.trace.append(dict(event='queue1_task_status',words=[0,3,task,0]))

    def release_startup_barrier(self,parent_sync):
        if not all(state==3 for state in self.states.values()):
            raise StartupBlocked('Startup barrier waits for every enabled task2+ status3')
        # The callback must implement applicable process-sync mode and post-init
        # requirements. We do not infer the absent ipasz.conf mode or token.
        if parent_sync() is not True:raise StartupBlocked('Parent sync/post-init service unresolved')
        self.flag1=True
        self.trace.append(dict(event='SycSynInit_flag',flag=1,value=1))

    def complete_display_initialization(self,initialize):
        if self.states[39]!=3 or not self.flag1:
            raise StartupBlocked('Task0x27 remains at startup flag1 barrier')
        if initialize() is not True:raise StartupBlocked('Display initialization service unresolved')
        self.flag2=True
        self.trace.append(dict(event='task39_ready',flag=2,value=1))

class HmiHarness:
    """Queue0x28 replay after the externally supplied display-ready gate.

    The four callbacks are host test/integration boundaries. None is vendor
    startup, a real message function, or proof of a displayed Toyota screen.
    Payload values are opaque32-bit tokens; they are never dereferenced.
    """
    def __init__(self,*,runtime_library=None,heartbeat,command,diagnostic,release_payload,
                 queue_transport=None):
        if not all(callable(x) for x in (heartbeat,command,diagnostic,release_payload)):
            raise TypeError('All service callbacks are required')
        self.heartbeat=heartbeat
        self.command=command
        self.diagnostic=diagnostic
        self.release_payload=release_payload
        if queue_transport is None:
            if runtime_library is None:raise ValueError('Native runtime or explicit queue transport required')
            self.queue=LocalQueue(64,runtime_library=runtime_library)
        else:
            if (getattr(queue_transport,'message_bytes',None)!=16 or
                    getattr(queue_transport,'capacity',None)!=64 or
                    not all(callable(getattr(queue_transport,name,None)) for name in
                            ('send','receive_t','receive_p','__len__'))):
                raise ValueError('Injected draw transport must satisfy the 64x16 contract')
            self.queue=queue_transport
        self.startup=StartupSequence()
        self.draw_pending=False

    def startup_requirements(self):
        return dict(required_external_files=['ipasz.conf'],
            unmodeled_services=['configuration_parser','common_memory','process_IPC',
                'parent_sync','system_task_state_machine','display_initialization'],
            sys_power_on_implemented=False)

    @property
    def display_ready(self):return self.startup.flag2 and self.startup.states[40]>=2

    def draw_frame(self,draw):
        if not self.display_ready:raise StartupBlocked('Drawing waits for task0x27 readiness')
        if not self.draw_pending:return False
        # Original update routine clears the byte before its drawing callees.
        self.draw_pending=False
        draw()
        return True

    def _dispatch(self,message):
        try:
            if message.code==0:
                if message.subcommand==0 and message.event==10:self.draw_pending=True
                self.heartbeat(message)
            elif message.code==0x41002:self.command(message)
            else:self.diagnostic(message)
        finally:
            # Harness exception cleanup policy also preserves payload ownership.
            if message.payload:self.release_payload(1,message.payload)

    def step(self,timeout_ms=500):
        if not self.display_ready:
            raise StartupBlocked('Drawing task0x28 waits for display-ready flag2/1')
        status,message=self.queue.receive_t(timeout_ms)
        timeout=status==-1
        if timeout:message=Message(0,0,10,0)
        self._dispatch(message)
        dispatched=1
        for _ in range(15):
            status,message=self.queue.receive_p()
            if status!=-1:break
            self._dispatch(message)
            dispatched+=1
        return dict(dispatched=dispatched,timeout_heartbeat=timeout,
            remaining=len(self.queue),draw_pending=self.draw_pending,synthetic_harness=True,
            toyota_application_started=False,pixels_rendered=False)


def decode_queue_table(data,count):
    """Decode the verified16-byte enabled/id/capacity/slot-size profile."""
    if type(count) is not int or not 0<=count<=4096 or len(data)!=count*16:
        raise ValueError('Invalid queue table bounds')
    rows=[]
    for index in range(count):
        enabled,queue,capacity,size=struct.unpack_from('<4I',data,index*16)
        if enabled==0:continue
        if enabled!=1 or queue!=index or size!=16 or not 1<=capacity<=4096:
            raise ValueError('Unsupported queue configuration')
        rows.append(dict(index=index,queue_id=queue,capacity=capacity,slot_bytes=size))
    return rows

# These addresses/strides are intentionally limited to the verified1127 binaries.
HMI_SHA256='cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503'
SYSC_SHA256='a1f2812d0b1776fa79dcb9ebddd5dca2d16443f77db19c35f4aac2cbabc302b4'
REGISTRY_NAMES=('bf_sys_CnfSetup','bf_sys_PowInf','bf_sys_PreInf','bf_sys_AplInf',
 'bf_sys_ResInf','bf_sys_StbInf','bf_sys_TskInf','bf_sys_RodInf','bf_sys_MsgInf',
 'bf_sys_FlgInf','bf_sys_SemInf','bf_sys_MemInf','bf_sys_TimInf','bf_sys_AbkInf',
 'bf_sys_BkmInf','bf_sys_DrcInf','bf_sys_LogInf','bf_sys_MmdInf')

class ElfImage:
    """Read file-backed virtual ranges; never invent bytes for BSS or holes."""
    def __init__(self,data):
        import io
        from elftools.elf.elffile import ELFFile
        self.data=data
        self.elf=ELFFile(io.BytesIO(data))
        if self.elf.elfclass!=32 or not self.elf.little_endian or self.elf['e_machine']!='EM_ARM':
            raise ValueError('Expected ELF32 little-endian ARM')
        self.segments=[s for s in self.elf.iter_segments() if s['p_type']=='PT_LOAD']

    def read(self,address,size):
        if type(size) is not int or size<0:raise ValueError('Invalid read size')
        for seg in self.segments:
            delta=address-seg['p_vaddr']
            if 0<=delta<=seg['p_filesz'] and size<=seg['p_filesz']-delta:
                offset=seg['p_offset']+delta
                data=self.data[offset:offset+size]
                if len(data)==size:return data
        raise ValueError('Range not wholly file-backed')


def inspect_configuration(hmi_path,system_library_path):
    """Static configuration decode after checking both proven binary versions."""
    from pathlib import Path
    import hashlib
    data=Path(hmi_path).read_bytes()
    if hashlib.sha256(data).hexdigest()!=HMI_SHA256:raise ValueError('HMI SHA-256 differs from verified baseline')
    system=Path(system_library_path).read_bytes()
    if hashlib.sha256(system).hexdigest()!=SYSC_SHA256:raise ValueError('System library SHA-256 differs from verified baseline')
    image=ElfImage(data)
    pointers=struct.unpack('<18I',image.read(0x59f948,72))
    registry=dict(zip(REGISTRY_NAMES,pointers))
    setup=struct.unpack('<17I',image.read(registry['bf_sys_CnfSetup'],68))
    tasks,queues=setup[7],setup[8]
    if tasks!=96 or queues!=96:raise ValueError('Unexpected baseline configuration counts')
    dyn=image.elf.get_section_by_name('.dynsym')
    names={s['st_value']:s.name for s in dyn.iter_symbols() if s.name and s['st_value']}
    task_rows=[]
    for index in range(tasks):
        words=struct.unpack('<12I',image.read(registry['bf_sys_TskInf']+index*48,48))
        if any(words):
            task_rows.append(dict(index=index,enabled=words[0]==1,raw_words=list(words),
                entry=hex(words[2]),entry_label=names.get(words[2],'FUN_'+format(words[2],'08x')),
                labels_are='ELF dynamic symbol or generated address; remaining field meanings partly unverified'))
    return dict(scope='Read-only verified1127 configuration; no startup execution',
        hmi_sha256=HMI_SHA256,system_library_sha256=SYSC_SHA256,
        registry_address='0x59f948',registry={k:hex(v) for k,v in registry.items()},
        task_record_bytes=48,task_count=tasks,tasks=task_rows,
        queue_record_bytes=16,queue_count=queues,
        queues=decode_queue_table(image.read(registry['bf_sys_MsgInf'],queues*16),queues),
        startup_requirements=dict(relative_configuration_file='ipasz.conf',
            parent_synchronization_contract="Inherited P/C/R eventfds; barrier depends on parsed process sync flag and startup mode",display_ready_gate=dict(task=39,flag_id=2,argument=1),
            draw_loop=dict(task=40,entry='0x2b22c',queue=40,initial_timeout_ms=500,max_batch=16)))


def main():
    import argparse,json
    from pathlib import Path
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hmi',type=Path,required=True)
    p.add_argument('--system-library',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True,help='New JSON output file')
    p.add_argument('--runtime-library',type=Path,help='Explicitly built native ca01_hmi_ipc shared library')
    p.add_argument('--synthetic-replay',action='store_true',help='Explicit host-only display-ready/heartbeat simulation')
    args=p.parse_args()
    if args.output.exists() or args.output.is_symlink():p.error('Output must not exist')
    report=inspect_configuration(args.hmi,args.system_library)
    if args.synthetic_replay:
        if not args.runtime_library:p.error('--synthetic-replay requires --runtime-library')
        events=[]
        h=HmiHarness(runtime_library=args.runtime_library,heartbeat=lambda m:events.append(dict(callback='heartbeat',words=list(struct.unpack('<4I',m.pack())))),
            command=lambda m:events.append(dict(callback='command',subcommand=m.subcommand)),
            diagnostic=lambda m:events.append(dict(callback='diagnostic',code=m.code)),
            release_payload=lambda pool,pointer:events.append(dict(callback='release',pool=pool,pointer=pointer)))
        try:h.step()
        except StartupBlocked as error:blocked=str(error)
        h.startup.create_resources()
        h.startup.apply_power_state(True)
        for task in (3,10,39,40,41):h.startup.task_initialized(task)
        h.startup.release_startup_barrier(lambda:True)
        h.startup.complete_display_initialization(lambda:True)
        report['synthetic_replay']=dict(before_ready=blocked,after_ready=h.step(),events=events,startup_events=h.startup.trace,
            caveat='Ready flag supplied by self-authored harness, not original startup. No graphics callback or Toyota screen executed.')
    with args.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print('Configured active tasks:',[t['index'] for t in report['tasks'] if t['enabled']])
    print('Configured queues:',[(q['queue_id'],q['capacity'],q['slot_bytes']) for q in report['queues']])
    print('No Toyota application was started. Report:',args.output)

if __name__=='__main__':main()
