#!/usr/bin/env python3
"""Execute ARM instructions with a mock Linux syscall boundary.

This checks program behavior, NOT compatibility with a physical head unit.
Dependencies: unicorn==2.1.4, pyelftools==0.32.
"""
import io
from pathlib import Path
import struct
import unittest
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R7, UC_ARM_REG_SP

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"/proc/version", "/proc/cpuinfo", "/proc/meminfo", "/proc/fb",
           "/proc/bus/input/devices", "/proc/mounts", "/dev/fb0", "/dev/graphics/fb0"}


def emulate(missing=False, short_io=False, ioctl_error=False):
    elf = ELFFile(io.BytesIO((ROOT / "build/radio-probe-arm").read_bytes()))
    assert elf.header["e_machine"] == "EM_ARM"
    assert not any(s["p_type"] in ("PT_INTERP", "PT_DYNAMIC") for s in elf.iter_segments())
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    lo = min(s["p_vaddr"] for s in segments) & ~4095
    hi = (max(s["p_vaddr"] + s["p_memsz"] for s in segments) + 4095) & ~4095
    uc.mem_map(lo, hi - lo)
    for segment in segments:
        uc.mem_write(segment["p_vaddr"], segment.data())
    uc.mem_map(0x70000000, 0x100000)
    uc.reg_write(UC_ARM_REG_SP, 0x700ff000)
    output = bytearray()
    files = {}
    opened = []
    syscalls = set()
    exits = []
    reads = 0
    writes = 0

    def cstring(address):
        result = bytearray()
        for i in range(256):
            ch = bytes(uc.mem_read(address + i, 1))
            if ch == b"\0":
                return result.decode("ascii")
            result.extend(ch)
        raise AssertionError("Unterminated path")

    def interrupt(machine, intno, _):
        nonlocal reads, writes
        assert intno == 2, ("Unexpected ARM interrupt", intno)
        num = machine.reg_read(UC_ARM_REG_R7)
        a, b, c = [machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        syscalls.add(num)
        result = 0
        if num == 1:
            exits.append(a)
            machine.emu_stop()
        elif num == 5:
            path = cstring(a)
            assert path in ALLOWED, path
            assert b == 0 and c == 0, "Any write/create open is forbidden"
            opened.append(path)
            if missing or path == "/dev/graphics/fb0":
                result = -2
            else:
                result = len(files) + 3
                # Large input tests the 16 KiB cap; short reads test EOF handling.
                content = b"x" * 17000 if path == "/proc/mounts" else ("MOCK " + path + "\n").encode()
                files[result] = [path, content, 0, False]
        elif num == 3:
            assert a in files and not files[a][3]
            reads += 1
            if short_io and reads == 1:
                result = -4
            else:
                item = files[a]
                count = min(c, 7) if short_io else c
                chunk = item[1][item[2]:item[2] + count]
                if chunk:
                    machine.mem_write(b, chunk)
                item[2] += len(chunk)
                result = len(chunk)
        elif num == 4:
            assert a == 1, "Only stdout writes are allowed"
            writes += 1
            if short_io and writes == 1:
                result = -4
            else:
                result = min(c, 3) if short_io else c
                output.extend(machine.mem_read(b, result))
        elif num == 6:
            assert a in files and not files[a][3]
            files[a][3] = True
        elif num == 54:
            assert a in files and files[a][0] == "/dev/fb0"
            assert b == 0x4600, "Only FBIOGET_VSCREENINFO is allowed"
            if ioctl_error:
                result = -25
            else:
                machine.mem_write(c, struct.pack("<40I", 800, 480, 800, 960, 0, 0, 16, *([0] * 33)))
        else:
            raise AssertionError("Unexpected syscall " + str(num))
        machine.reg_write(UC_ARM_REG_R0, result & 0xffffffff)

    uc.hook_add(UC_HOOK_INTR, interrupt)
    uc.emu_start(elf.header["e_entry"], hi, count=8_000_000)
    assert exits == [0], "Program did not exit cleanly"
    assert all(item[3] for item in files.values()), "Unclosed descriptors"
    assert set(opened) == ALLOWED
    return output.decode("ascii"), syscalls, files


class ProbeTest(unittest.TestCase):
    def test_dimensions_and_read_only_syscalls(self):
        output, syscalls, files = emulate()
        self.assertIn("visible=800x480 virtual=800x960 bits_per_pixel=16", output)
        self.assertEqual(syscalls, {1, 3, 4, 5, 6, 54})
        mounts = next(item for item in files.values() if item[0] == "/proc/mounts")
        self.assertEqual(mounts[2], 16384)

    def test_missing_files(self):
        output, _, _ = emulate(missing=True)
        self.assertEqual(output.count("unavailable, errno=2"), 8)
        self.assertIn("Probe complete.", output)

    def test_short_reads_writes_and_interrupted_calls(self):
        normal, _, _ = emulate()
        short, _, _ = emulate(short_io=True)
        self.assertEqual(short, normal)

    def test_unavailable_framebuffer_ioctl(self):
        output, _, _ = emulate(ioctl_error=True)
        self.assertIn("query failed, errno=25", output)
        self.assertIn("Probe complete.", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
