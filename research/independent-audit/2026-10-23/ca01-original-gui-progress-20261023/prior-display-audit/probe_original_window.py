#!/usr/bin/env python3
"""Execute only bounded *original ARM HMI* window-building and plane calls.

The original ELF is hash-checked and mapped into Unicorn. Only external
malloc/sysDisMngMemAlloc and vehicle profile lookup are substituted.
No Toyota process, OS services, EGL, or panel hardware is started.
Synthetic descriptor contents are hypotheses, not recovered vendor ABI.
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP,
                               UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3)

BASE=Path("/home/starlight/projects/rav4-radio")
HMI=BASE/"system-audit/ca01-updater-independent-20261022/06-PROC_HMI"
EXPECTED="cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503"
OUTPUT=Path(__file__).with_name("unicorn-original-window.json")
DATA=HMI.read_bytes()
assert hashlib.sha256(DATA).hexdigest()==EXPECTED, "Wrong HMI baseline"
R = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
END=0x7000FFF0
HEAP=0x70001000
CONFIG_PROFILES=((0x295FE8,800,480),(0x296108,480,480))
DESC=(0x01a24bb8,0x01a24bc8,0x01a24bd8)
WINDOW_HANDLES=0x026c98b4
WIN_GLOBAL=0x00925f38
ALLOC_IMPORT=0xd0b8
MALLOC_IMPORT=0xd5f8
PLANE_SW_IMPORT=0xd664
PLANE_ALPHA_IMPORT=0xd580
PLANE_TRANS_TRAMPOLINE=0x71001000
PLANE_PTR=0x005dd7cc

def get4(u,a):
    return struct.unpack("<I",u.mem_read(a,4))[0]

def put4(u,a,x):
    u.mem_write(a,struct.pack("<I",x))

def new_unicorn():
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    with HMI.open("rb") as f:
        elf=ELFFile(f)
        assert elf.elfclass==32 and elf.little_endian and elf["e_machine"]=="EM_ARM"
        for segment in elf.iter_segments():
            if segment["p_type"]!="PT_LOAD": continue
            a=segment["p_vaddr"]
            lo=a & ~4095
            hi=(a+segment["p_memsz"]+4095)&~4095
            u.mem_map(lo,hi-lo)
            u.mem_write(a,segment.data())
    u.mem_map(0x70000000,0x20000)
    u.mem_map(0x71000000,0x20000)
    u.reg_write(UC_ARM_REG_SP,0x7001E000)
    u.reg_write(UC_ARM_REG_LR,END)
    return u

def emulate_window(profile, malloc_fails=False, alloc_fail_idx=None):
    profile_addr,width,height=profile
    u=new_unicorn()
    calls=[]
    trace=[]
    def hook(uc,a,size,data):
        if len(trace)<1000:trace.append(hex(a))
        if a==0x2a548: # actual profile-selection function is external to this slice
            uc.reg_write(UC_ARM_REG_R0,profile_addr)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a==ALLOC_IMPORT:
            amt=uc.reg_read(UC_ARM_REG_R0)
            dst=uc.reg_read(UC_ARM_REG_R1)
            idx=len([x for x in calls if x["service"]=="sysDisMngMemAlloc"])
            # Define *synthetic* descriptor for proof of HMI's offset +12 load.
            handle=0x31000000 + idx*0x00100000
            failed=alloc_fail_idx==idx
            if not failed:
                uc.mem_write(dst,struct.pack("<4I",amt,idx,0,handle))
            calls.append(dict(service="sysDisMngMemAlloc",size=amt,
                              descriptor=hex(dst),
                              synthetic_handle=None if failed else hex(handle),
                              service_return=-1 if failed else 0))
            uc.reg_write(UC_ARM_REG_R0,0xffffffff if failed else 0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a==MALLOC_IMPORT:
            requested=uc.reg_read(UC_ARM_REG_R0)
            calls.append(dict(service="malloc",requested=requested,synthetic=True))
            if not malloc_fails:
                # Model malloc memory as nonzero junk to prove which words the
                # *original* constructor actually initializes.
                uc.mem_write(HEAP,bytes([0xa5])*32)
            uc.reg_write(UC_ARM_REG_R0,0 if malloc_fails else HEAP)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a>=0x70000000 and a!=END:
            raise RuntimeError(f"unexpected executable trampoline at {a:#x}")
        elif not (0x15000<=a<0x17000 or 0x2a000<=a<0x2c000):
            raise RuntimeError(f"unexpected instruction at {a:#x}")
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(0x2b66c,END,count=3000,timeout=4000000)
    assert u.reg_read(UC_ARM_REG_PC)==END, f"did not return {u.reg_read(UC_ARM_REG_PC):#x}"
    ptr=u.reg_read(UC_ARM_REG_R0)
    assert len([x for x in calls if x["service"]=="sysDisMngMemAlloc"])==3
    for i,addr in enumerate(DESC):
        if alloc_fail_idx==i:
            assert get4(u,addr)==0 and get4(u,addr+12)==0
        else:
            assert get4(u,addr)==width*height*4
            assert get4(u,addr+12)==0x31000000+i*0x00100000
    if malloc_fails:
        assert ptr==0, f"malloc failed but window is not NULL ({ptr:#x})"
        assert get4(u,WIN_GLOBAL)==0
        return dict(profile=hex(profile_addr),width=width,height=height,
                    failed_malloc=True,window_address=None,
                    calls=calls,run_instruction_count=len(trace),
                    no_window=True)
    assert ptr==HEAP, f"unexpected malloc pointer: {ptr:#x}"
    words=struct.unpack("<8I",u.mem_read(ptr,32))
    handles=struct.unpack("<3I",u.mem_read(WINDOW_HANDLES,12))
    assert words[:6]==(width,height,width,2,3,WINDOW_HANDLES),words
    expected_handles=tuple(0 if i==alloc_fail_idx else 0x31000000+i*0x100000
                           for i in range(3))
    assert handles==expected_handles,handles
    assert get4(u,WIN_GLOBAL)==ptr
    assert words[6:]==(0xa5a5a5a5,0xa5a5a5a5), (
        "The original constructor unexpectedly initialized tail words",words)
    return dict(profile=hex(profile_addr),width=width,height=height,
                failed_malloc=False,window_address=hex(ptr),
                window_first_six=[hex(x) for x in words[:6]],
                handles=[hex(h) for h in handles],
                descriptor_stride=16,handle_word_offset=12,
                display_allocation_failure_ignored_by_original=alloc_fail_idx is not None,
                callback_word_7_from_uninitialized_malloc=hex(words[7]),
                tail_words_preserved=[hex(x) for x in words[6:]],
                calls=calls,run_instruction_count=len(trace))

def emulate_plane():
    u=new_unicorn()
    calls=[]
    # Real HMI uses a tail branch to the sysDisMngPlnTrans PLT stub (0xd4fc).
    # Capture the ARM call registers there; do not mutate the vendor GOT.
    def hook(uc,a,size,data):
        names={PLANE_SW_IMPORT:"sysDisMngPlnDispSw",
               PLANE_ALPHA_IMPORT:"sysDisMngPlnAlpha",
               0xd4fc:"sysDisMngPlnTrans"}
        if a in names:
            regs=[uc.reg_read(x) for x in R]
            calls.append(dict(service=names[a],r0=hex(regs[0]),r1=hex(regs[1]),
                              r2=hex(regs[2]),r3=hex(regs[3])))
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a>=0x70000000 and a!=END:
            raise RuntimeError(f"unapproved trampoline {a:#x}")
        elif not (0x15000<=a<0x17000):
            raise RuntimeError(f"unapproved plane instruction {a:#x}")
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(0x15f84,END,count=1500,timeout=3000000)
    assert u.reg_read(UC_ARM_REG_PC)==END
    assert [c["service"] for c in calls]==[
        "sysDisMngPlnDispSw","sysDisMngPlnAlpha","sysDisMngPlnTrans"],calls
    assert calls[0]["r0"]=="0x0"
    assert [calls[1]["r0"],calls[1]["r1"],calls[1]["r2"]]==["0x0","0xff","0x1"]
    return dict(original_function="0x15f84",calls=calls,
                imported_call="0xd4fc",
                noted="Transparency field semantics still unverified")

def main():
    result=dict(scope="Bounded ORIGINAL ARM HMI instructions under Unicorn; import boundaries synthetic. No real display library or Toyota application startup.",
                source_sha256=EXPECTED, profiles=[], caveats=[
                    "Original FUN_0002a548 vehicle selection was replaced by a verified profile pointer",
                    "Original imported sysDisMngMemAlloc was replaced with a synthetic descriptor writer, not authentic vendor implementation",
                    "Original constructor leaves window words 6/7 untouched; calloc-like test memory would have masked this. Real malloc contents are undefined until another component sets them.",
                    "No original GL calls, fonts, textures, GUI state machine, or screen pixels executed"
                ])
    for profile in CONFIG_PROFILES:
        item=emulate_window(profile)
        result["profiles"].append(item)
        print("ORIGINAL_WINDOW_OK",item["width"],item["height"],
              item["window_address"],item["handles"])
    oom=emulate_window(CONFIG_PROFILES[0],True)
    result["malloc_failure"]=oom
    print("ORIGINAL_WINDOW_MALLOC_FAILURE_OK",oom["failed_malloc"])
    alloc_failed=emulate_window(CONFIG_PROFILES[0],alloc_fail_idx=1)
    assert alloc_failed["display_allocation_failure_ignored_by_original"]
    assert alloc_failed["handles"][1]=="0x0"
    result["display_allocation_failure"]=alloc_failed
    print("ORIGINAL_DISPLAY_ALLOCATION_FAILURE_OBSERVED window built despite null handle")
    result["plane"]=emulate_plane()
    print("ORIGINAL_PLANE_CALLS_OK",[c["service"] for c in result["plane"]["calls"]])
    OUTPUT.write_text(json.dumps(result,indent=2)+"\n",encoding="utf8")
    print("PASS original-bounded-arm-display-boundaries",OUTPUT)

if __name__=="__main__":
    main()
