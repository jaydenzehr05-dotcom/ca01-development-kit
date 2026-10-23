#!/usr/bin/env python3
"""Execute CA01 hardware probe in Unicorn with a strict fake syscall layer.

Enforces read-only opens, stdout-only writes, read-only framebuffer ioctl and
bounded passive Linux input polling. No physical device is accessed.
"""
import io, struct, unittest
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R7, UC_ARM_REG_SP
)
ROOT=Path(__file__).resolve().parents[1]
PROC_FILES={
    "/proc/version","/proc/cmdline","/proc/partitions",
    "/proc/bus/input/devices","/proc/asound/cards","/proc/fb",
}
FRAMEBUFFERS={"/dev/fb0","/dev/graphics/fb0"}
EVENTS={f"/dev/input/event{i}" for i in range(8)}
ALLOWED=PROC_FILES|FRAMEBUFFERS|EVENTS
def emulate(event=True,audio_available=True,interrupt_io=False):
    raw=(ROOT/"build/ca01-hw-probe-arm").read_bytes()
    elf=ELFFile(io.BytesIO(raw))
    assert elf.header["e_machine"]=="EM_ARM"
    assert not any(p["p_type"] in ("PT_INTERP","PT_DYNAMIC") for p in elf.iter_segments())
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    segments=[p for p in elf.iter_segments() if p["p_type"]=="PT_LOAD"]
    lo=min(p["p_vaddr"] for p in segments)&~4095
    hi=(max(p["p_vaddr"]+p["p_memsz"] for p in segments)+4095)&~4095
    uc.mem_map(lo,hi-lo)
    for p in segments:uc.mem_write(p["p_vaddr"],p.data())
    uc.mem_map(0x70000000,0x100000)
    uc.reg_write(UC_ARM_REG_SP,0x700ff000)
    files={};open_paths=[];syscalls=[];output=bytearray();exits=[];interrupted=False
    def string(ptr):
        data=bytearray()
        for j in range(180):
            ch=bytes(uc.mem_read(ptr+j,1))
            if ch==b"\x00":return data.decode("ascii")
            data+=ch
        raise AssertionError("unbounded path")
    def handler(machine,intno,_):
        nonlocal interrupted
        assert intno==2
        num=machine.reg_read(UC_ARM_REG_R7)
        a,b,c=[machine.reg_read(t) for t in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
        syscalls.append(num);result=0
        if num==1:
            exits.append(a);machine.emu_stop()
        elif num==5:
            path=string(a)
            assert path in ALLOWED,path
            assert b in (0,2048),"open must be read-only"
            assert b==2048 if path in EVENTS else b==0
            open_paths.append(path)
            if (path in EVENTS and (not event or path!="/dev/input/event0")) or (path=="/proc/asound/cards" and not audio_available) or path=="/dev/graphics/fb0":
                result=-2
            else:
                result=len(files)+3
                if path=="/dev/input/event0":
                    data=struct.pack("<iiHHi",12,35,1,115,1)
                else:data=("MOCK "+path+"\n").encode()
                files[result]={"path":path,"data":data,"pos":0,"closed":False}
        elif num==3:
            assert a in files and not files[a]["closed"]
            item=files[a]
            if interrupt_io and not interrupted:
                result=-4;interrupted=True
            elif item["path"] in EVENTS and item["pos"]>=len(item["data"]):
                result=-11
            else:
                take=item["data"][item["pos"]:item["pos"]+c]
                if take:machine.mem_write(b,take)
                item["pos"]+=len(take)
                result=len(take)
        elif num==4:
            assert a==1,"only stdout writes allowed"
            assert c<=4096
            output.extend(machine.mem_read(b,c))
            result=c
        elif num==6:
            assert a in files and not files[a]["closed"]
            files[a]["closed"]=True
        elif num==54:
            assert a in files and files[a]["path"]=="/dev/fb0"
            assert b==0x4600,"only FBIOGET_VSCREENINFO"
            machine.mem_write(c,struct.pack("<40I",800,480,800,480,0,0,16,*([0]*33)))
        elif num==168:
            assert c==2000 and b==8
            descriptors=bytearray(machine.mem_read(a,64))
            for i in range(8):
                fd,events,revents=struct.unpack_from("<iHH",descriptors,i*8)
                assert events==1
                if fd>=0 and event:
                    assert fd in files
                    if files[fd]["path"]=="/dev/input/event0":
                        struct.pack_into("<H",descriptors,i*8+6,1)
            machine.mem_write(a,bytes(descriptors))
            result=1 if event else 0
        else:raise AssertionError(f"Forbidden syscall {num}")
        machine.reg_write(UC_ARM_REG_R0,result&0xffffffff)
    uc.hook_add(UC_HOOK_INTR,handler)
    uc.emu_start(elf.header["e_entry"],hi,count=7000000)
    assert exits==[0],"probe did not exit cleanly"
    assert all(rec["closed"] for rec in files.values())
    assert set(open_paths)==ALLOWED
    return output.decode("ascii"),syscalls,open_paths

class CA01HardwareProbeTests(unittest.TestCase):
    def test_key_event_and_hardware_diagnostics(self):
        text,nums,paths=emulate()
        self.assertIn("width=800 height=480 bpp=16",text)
        self.assertIn("event0 key=115 VOLUMEUP value=1",text)
        self.assertIn("volatile register reads DISABLED",text)
        self.assertNotIn("/proc/asic/",text)
        self.assertEqual(set(nums),{1,3,4,5,6,54,168})
        self.assertEqual(len(paths),16)
    def test_no_input_nodes(self):
        text,_,_=emulate(event=False)
        self.assertIn("event devices opened=0",text)
        self.assertIn("events captured=0",text)
    def test_missing_audio_diagnostics_and_no_asic_register_reads(self):
        text,_,_=emulate(audio_available=False,interrupt_io=True)
        self.assertIn("unavailable (errno 2)",text)
        self.assertIn("VOLUMEUP",text)
        self.assertNotIn("/proc/asic/",text)

if __name__=="__main__":
    unittest.main()
