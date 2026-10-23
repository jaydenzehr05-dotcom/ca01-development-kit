#!/usr/bin/env python3
"""Bounded Unicorn slices of canonical CA01 startup; halt at unknown services.

Guest instructions execute only in Unicorn memory. No imported service, guest
syscall, host configuration, pthread, device, or network operation is performed.
This is not an application launcher or proof that Toyota startup completes.
"""
import argparse
from collections import deque
import hashlib
import io
import json
from pathlib import Path
import struct

HMI_SHA256 = 'cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503'
SYSC_SHA256 = 'a1f2812d0b1776fa79dcb9ebddd5dca2d16443f77db19c35f4aac2cbabc302b4'
BIAS = 0x10000000
REGISTRY = 0x59f948


def verify_inputs(hmi_data, sysc_data):
    """No emulation/ELF parsing before both immutable fixture hashes match."""
    for label, data, expected in [('HMI', hmi_data, HMI_SHA256), ('SYSC', sysc_data, SYSC_SHA256)]:
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(label + ' canonical SHA-256 mismatch')


class BoundedArmTrace:
    """Fail-closed instruction engine, also testable with synthetic ARM bytes."""
    def __init__(self, uc, executable_ranges, imports, *, symbols=None, blocked_reads=None):
        from unicorn import UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ
        self.uc = uc
        self.executable_ranges = executable_ranges
        self.imports = imports
        self.symbols = symbols or {}
        self.blocked_reads = blocked_reads or {}
        self.sentinel = 0x7000fff0
        uc.mem_map(0x70000000, 0x10000)
        mapped = set()
        for address in imports:
            page = address & ~4095
            if page not in mapped:
                uc.mem_map(page, 4096)
                mapped.add(page)
        uc.hook_add(UC_HOOK_CODE, self._code)
        uc.hook_add(UC_HOOK_INTR, self._interrupt)
        uc.hook_add(UC_HOOK_MEM_INVALID, self._invalid)
        uc.hook_add(UC_HOOK_MEM_READ, self._read)

    def _halt(self, reason, **details):
        if self.reason is None:
            self.reason = reason
            self.boundary = details
        self.uc.emu_stop()

    def _guest_string(self, address):
        data = bytearray()
        try:
            for i in range(256):
                b = self.uc.mem_read(address + i, 1)[0]
                if not b:
                    return data.decode('utf-8', errors='replace')
                data.append(b)
        except Exception:
            return None
        return None

    def _code(self, uc, address, size, _):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_CPSR, UC_ARM_REG_LR
        if address == self.sentinel:
            self._halt('returned')
            return
        if address in self.imports:
            args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            details = dict(symbol=self.imports[address], address=hex(address), arguments=args,
                           caller_return=hex(uc.reg_read(UC_ARM_REG_LR)))
            if self.imports[address] == 'fopen':
                details['guest_strings'] = [self._guest_string(args[0]), self._guest_string(args[1])]
            self._halt('unimplemented_import', **details)
            return
        if not any(start <= address and address + size <= end for start, end in self.executable_ranges):
            self._halt('unapproved_code_address', address=hex(address))
            return
        if uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
            self._halt('unimplemented_thumb_mode', address=hex(address))
            return
        instruction = struct.unpack('<I', uc.mem_read(address, 4))[0]
        if instruction & 0x0f000000 == 0x0f000000:
            self._halt('unimplemented_syscall', address=hex(address), instruction=hex(instruction))
            return
        self.instructions += 1
        self.tail.append(hex(address))
        if address in self.symbols and len(self.entries) < 256:
            self.entries.append(dict(symbol=self.symbols[address], address=hex(address)))

    def _interrupt(self, uc, number, _):
        self._halt('unimplemented_interrupt', number=number)

    def _invalid(self, uc, access, address, size, value, _):
        self._halt('guest_memory_fault', address=hex(address), access=access, size=size)
        return False

    def _read(self, uc, access, address, size, value, _):
        for slot, name in self.blocked_reads.items():
            if address < slot + 4 and slot < address + size:
                self._halt('unimplemented_relocation', address=hex(slot), symbol=name)
                return
        if address & ~4095 in self.imports:
            self._halt('unimplemented_external_data', address=hex(address), symbol=self.imports[address & ~4095])

    def run(self, entry, argument, *, instruction_limit=20000, timeout_us=2000000):
        from unicorn import UcError
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
        if type(instruction_limit) is not int or not 1 <= instruction_limit <= 1000000:
            raise ValueError('Instruction bound must be 1..1000000')
        if type(timeout_us) is not int or not 1 <= timeout_us <= 10000000:
            raise ValueError('Time bound must be 1..10000000 microseconds')
        self.reason = None
        self.boundary = {}
        self.instructions = 0
        self.entries = []
        self.tail = deque(maxlen=128)
        self.uc.reg_write(UC_ARM_REG_SP, 0x7000f000)
        self.uc.reg_write(UC_ARM_REG_LR, self.sentinel)
        self.uc.reg_write(UC_ARM_REG_R0, argument)
        error = None
        try:
            self.uc.emu_start(entry, self.sentinel + 4, count=instruction_limit, timeout=timeout_us)
        except UcError as exc:
            error = str(exc)
            if self.reason is None:
                self.reason = 'unicorn_error'
        if self.reason is None:
            self.reason = 'instruction_limit' if self.instructions >= instruction_limit else 'time_limit'
        return dict(entry=hex(entry), argument=argument, halt_reason=self.reason,
                    returned=self.reason == 'returned', instructions=self.instructions,
                    instruction_limit=instruction_limit, timeout_us=timeout_us,
                    stop_pc=hex(self.uc.reg_read(UC_ARM_REG_PC)), boundary=self.boundary,
                    function_entries=self.entries, last_instruction_addresses=list(self.tail), error=error)


def prepare(hmi_data, sysc_data):
    """Map hashed copies and supported relocations; TLS remains an explicit trap."""
    verify_inputs(hmi_data, sysc_data)
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    executable, segments = [], []
    images = []
    for data, bias in [(hmi_data, 0), (sysc_data, BIAS)]:
        elf = ELFFile(io.BytesIO(data))
        images.append(elf)
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            address = bias + seg['p_vaddr']
            end = address + seg['p_memsz']
            segments.append((address, end, seg.data()))
            if bias and seg['p_flags'] & 1:
                executable.append((address, end))
    intervals = []
    for start, end, _ in sorted(segments):
        start, end = start & ~4095, (end + 4095) & ~4095
        if intervals and start <= intervals[-1][1]:
            intervals[-1] = (intervals[-1][0], max(end, intervals[-1][1]))
        else:
            intervals.append((start, end))
    for start, end in intervals:
        uc.mem_map(start, end - start)
    for start, _, data in segments:
        uc.mem_write(start, data)
    elf = images[1]
    syms = elf.get_section_by_name('.dynsym')
    defined = {s.name: BIAS + s['st_value'] for s in syms.iter_symbols() if s['st_shndx'] != 'SHN_UNDEF'}
    functions = {BIAS + s['st_value']: s.name for s in syms.iter_symbols()
                 if s['st_shndx'] != 'SHN_UNDEF' and s['st_info']['type'] == 'STT_FUNC'}
    imports, import_addresses, blocked = {}, {}, {}
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        table = elf.get_section(section['sh_link'])
        for rel in section.iter_relocations():
            dst = BIAS + rel['r_offset']
            kind = rel['r_info_type']
            sym = table.get_symbol(rel['r_info_sym'])
            addend = struct.unpack('<I', uc.mem_read(dst, 4))[0]
            if kind == 23:  # R_ARM_RELATIVE
                value = BIAS + addend
            elif kind in (17, 18):  # TLS is intentionally not synthesized.
                blocked[dst] = sym.name + ' (TLS relocation ' + str(kind) + ')'
                continue
            elif kind in (2, 21, 22):  # ABS32, GLOB_DAT, JUMP_SLOT
                if sym['st_shndx'] == 'SHN_UNDEF':
                    if sym.name not in import_addresses:
                        trap = 0x60000000 + 4096 * len(import_addresses)
                        import_addresses[sym.name] = trap
                        imports[trap] = sym.name
                    value = import_addresses[sym.name]
                else:
                    value = BIAS + sym['st_value']
                if kind == 2:
                    value += addend
            else:
                raise ValueError('Unsupported ARM relocation ' + str(kind))
            uc.mem_write(dst, struct.pack('<I', value & 0xffffffff))
    engine = BoundedArmTrace(uc, executable, imports, symbols=functions, blocked_reads=blocked)
    return engine, defined


def trace_startup(hmi_data, sysc_data, *, instruction_limit=20000):
    engine, defined = prepare(hmi_data, sysc_data)
    registration = engine.run(defined['fs_sys_CnfEntry'], REGISTRY, instruction_limit=instruction_limit)
    writes = {}
    for name in ('bf_sys_CnfSetup', 'bf_sys_PowInf', 'bf_sys_PreInf', 'bf_sys_AplInf',
                 'bf_sys_ResInf', 'bf_sys_StbInf', 'bf_sys_TskInf', 'bf_sys_RodInf',
                 'bf_sys_MsgInf', 'bf_sys_FlgInf', 'bf_sys_SemInf', 'bf_sys_MemInf',
                 'bf_sys_TimInf', 'bf_sys_AbkInf', 'bf_sys_BkmInf', 'bf_sys_DrcInf',
                 'bf_sys_LogInf', 'bf_sys_MmdInf'):
        writes[name] = hex(struct.unpack('<I', engine.uc.mem_read(defined[name], 4))[0])
    startup = None
    if registration['returned']:
        startup = engine.run(defined['SysPowerOn'], 9, instruction_limit=instruction_limit)
    return dict(scope='Bounded canonical ARM instruction slices in Unicorn; imported services halt.',
                hashes=dict(hmi=HMI_SHA256, sysc=SYSC_SHA256), library_bias=hex(BIAS),
                registration=registration, registered_pointers=writes, startup=startup,
                application_startup_completed=False, toyota_rendering_observed=False,
                host_services_called=False, guest_syscalls_executed=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hmi', type=Path, required=True)
    p.add_argument('--sysc', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--instruction-limit', type=int, default=20000)
    a = p.parse_args()
    if a.output.exists() or a.output.is_symlink():
        p.error('Output must be a new file')
    for source in (a.hmi, a.sysc):
        if source.stat().st_size > 64 * 1024 * 1024:
            p.error('Input exceeds fixture size bound')
    report = trace_startup(a.hmi.read_bytes(), a.sysc.read_bytes(), instruction_limit=a.instruction_limit)
    with a.output.open('x') as f:
        json.dump(report, f, indent=2)
        f.write('\n')
    halt = report['startup']['halt_reason'] if report['startup'] else report['registration']['halt_reason']
    print('Startup boundary:', halt, '; application startup completed: False')
    raise SystemExit(2)  # An observed boundary is deliberately not successful startup.


if __name__ == '__main__':
    main()
