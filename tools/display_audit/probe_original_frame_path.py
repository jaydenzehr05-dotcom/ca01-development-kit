#!/usr/bin/env python3
"""Bounded ORIGINAL HMI frame swap path with ALL external boundary calls recorded.

EGL/swap success, native window callback, config selection and sysDisMng
methods are synthetic intercepts. Real HMI ARM instructions execute between
those boundaries, including the original handle-to-memory-token mapping,
VRAM rectangle packing, display-plane setup and branch decisions.
NO real Toyota process or rendering occurs.
"""
from __future__ import annotations
import json
import struct
from pathlib import Path
from unicorn import UC_ARCH_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP,
    UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
from probe_original_window import new_unicorn, END, R, DESC, WIN_GLOBAL, put4, get4, EXPECTED

OUT=Path(__file__).with_name("unicorn-original-frame.json")
EGL_SWAP=0x0000d724
EGL_ERROR_CHECK=0x0002b624
CALLBACK=0x71001000
VRAM_UPDATE=0x0000d4b4
VRAM_WAIT=0x0000cf68
PLANE_SW=0x0000d664
PLANE_ALPHA=0x0000d580
PLANE_TRANS=0x0000d4fc
GET_PROFILE=0x0002a548
WINDOW_ADDR=0x70001000
REG_NAMES=("r0","r1","r2","r3")
WIDTH,HEIGHT=800,480

def run(egl_check_succeeds: bool, callback_return: int):
    u=new_unicorn()
    calls=[]
    seen=[]
    descriptors=[]
    for idx,addr in enumerate(DESC):
        handle=0x31000000+idx*0x00100000
        token=0x60001000+idx*0x10000
        u.mem_write(addr,struct.pack("<4I",WIDTH*HEIGHT*4,token,0,handle))
        descriptors.append(dict(address=hex(addr),handle=hex(handle),
                                synthetic_memory_token=hex(token)))
    window=(WIDTH,HEIGHT,WIDTH,2,3,0x026c98b4,0,CALLBACK)
    u.mem_write(WINDOW_ADDR,struct.pack("<8I",*window))
    put4(u,WIN_GLOBAL,WINDOW_ADDR)
    put4(u,0x026c98c4,0x1000)
    put4(u,0x026c98c0,0x2000)
    def args(uc):
        return [uc.reg_read(k) for k in R]
    def rect16(uc,address):
        return list(struct.unpack("<2H",uc.mem_read(address,4)))
    def hook(uc,a,size,data):
        if len(seen)<1500:seen.append(hex(a))
        reg=args(uc)
        if a==EGL_SWAP:
            calls.append(dict(name="eglSwapBuffers",args=[hex(reg[0]),hex(reg[1])]))
            uc.reg_write(UC_ARM_REG_R0,1)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a==EGL_ERROR_CHECK:
            calls.append(dict(name="HMI egl error checker",result=bool(egl_check_succeeds)))
            uc.reg_write(UC_ARM_REG_R0,int(egl_check_succeeds))
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a==CALLBACK:
            calls.append(dict(name="window +0x1c callback",window_arg=hex(reg[0]),
                              returned_synthetic_handle=hex(callback_return)))
            assert reg[0]==WINDOW_ADDR
            uc.reg_write(UC_ARM_REG_R0,callback_return)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a==GET_PROFILE:
            uc.reg_write(UC_ARM_REG_R0,0x295fe8)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a==VRAM_UPDATE:
            sp=uc.reg_read(UC_ARM_REG_SP)
            ptr4,ptr5,token=struct.unpack("<3I",uc.mem_read(sp,12))
            calls.append(dict(name="sysDisMngPlnUpdateVram",r0=hex(reg[0]),
              r1=hex(reg[1]),r2_rect=rect16(uc,reg[2]),r3_rect=rect16(uc,reg[3]),
              stack4_rect=rect16(uc,ptr4),stack5_rect=rect16(uc,ptr5),
              stack6_token=hex(token),addresses=[hex(x) for x in [reg[2],reg[3],ptr4,ptr5]]))
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a==VRAM_WAIT:
            calls.append(dict(name="sysDisMngPlnWaitDispVram",r0=hex(reg[0]),r1=hex(reg[1])))
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a in (PLANE_SW,PLANE_ALPHA,PLANE_TRANS):
            name={PLANE_SW:"sysDisMngPlnDispSw",PLANE_ALPHA:"sysDisMngPlnAlpha",
                  PLANE_TRANS:"sysDisMngPlnTrans"}[a]
            calls.append(dict(name=name,args=[hex(x) for x in reg[:3]]))
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif a>=0x70000000:
            raise RuntimeError(f"Unapproved executed trampoline {a:#x}")
        elif not (0x15000<=a<0x17000 or 0x2a000<=a<0x2bc00):
            raise RuntimeError(f"Unapproved original HMI instruction {a:#x}")
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(0x2b9fc,END,count=3000,timeout=4000000)
    assert u.reg_read(UC_ARM_REG_PC)==END
    status=u.reg_read(UC_ARM_REG_R0)
    names=[x["name"] for x in calls]
    if not egl_check_succeeds:
        assert status==0 and names[:2]==["eglSwapBuffers","HMI egl error checker"]
        assert "window +0x1c callback" not in names
    elif callback_return not in (0x31000000,0x31100000,0x31200000):
        assert status==1 and "window +0x1c callback" in names
        assert "sysDisMngPlnUpdateVram" not in names
    else:
        expected=["eglSwapBuffers","HMI egl error checker","window +0x1c callback",
            "sysDisMngPlnUpdateVram","sysDisMngPlnWaitDispVram",
            "sysDisMngPlnDispSw","sysDisMngPlnAlpha","sysDisMngPlnTrans"]
        # First descriptor has token !=0; all are routed through update.
        assert names==expected, (names,expected)
        update=calls[3]
        idx=[0x31000000,0x31100000,0x31200000].index(callback_return)
        expected_token=0x60001000+idx*0x10000
        assert update["stack6_token"]==hex(expected_token),update
        assert update["r2_rect"]==[WIDTH,HEIGHT],update
        assert update["r3_rect"]==[0,0],update
        assert update["stack4_rect"]==[0,0],update
        assert update["stack5_rect"]==[WIDTH,HEIGHT],update
        assert calls[4]["r1"]==hex(expected_token)
    return dict(original_function="0x2b9fc",status=status,
      egl_check_success=egl_check_succeeds,callback_return=hex(callback_return),
      calls=calls,synthetic_descriptors=descriptors,
      original_instruction_hook_count=len(seen),pixels_rendered=False)

def main():
    cases=[
        run(True,0x31000000),
        run(True,0x31100000),
        run(True,0x31200000),
        run(True,0x39000000),
        run(False,0x31100000)
    ]
    OUT.write_text(json.dumps(dict(scope="Bounded original HMI frame-submission slice; EGL and sysDisMng imported services plus +0x1c callback intercepted. No original GL or Toyota pixels.",source_sha256=EXPECTED,
      cases=cases),indent=2)+"\n")
    for x in cases:
        print("FRAME_PATH_OK",x["callback_return"],"eglcheck",x["egl_check_success"],
              "return",x["status"],[c["name"] for c in x["calls"]])
    print("PASS original-bounded-arm-frame-submission",OUT)

if __name__=="__main__":
    main()
