# CA01 bootloader emulation harness — initial experiment

This harness is intentionally **not** a complete head-unit emulator. It allows
bounded execution of caller-selected ARM instructions inside a raw component
loaded at a hypothetical RAM base. It is suitable for controlled hypotheses
about function entry points, but **not** proof of legitimate boot execution.

## Inputs and assumptions

- Source: `09-boot.bin` from the 1127 KWI, stored **outside Git**.
- CPU: ARM 32-bit, little endian, ARM mode (not Thumb).
- Candidate code offsets derived from an earlier heuristic Ghidra raw import:
  `0x11060`, `0x11130`, `0x0fc4`.
- Assumed component mapping: `0x20000000`. This is **not** a confirmed
  production memory address. No image relocation has been reconstructed.
- Stack: isolated mapped test memory at `0x30000000`.
- MMIO devices, interrupt controllers, boot storage and CPU initialization
  are **not implemented**. Unmapped memory accesses stop execution.
- Writes outside the simulated stack stop the run.
- Instruction budget defaults to 5,000; 100,000 maximum.
- No emulation changes the input firmware or operates on a physical radio.

## Initial results

| Candidate offset | Trace length | Observed stop |
|---|---:|---|
| `0x11060` | 2 instructions | Unmapped 32-bit read at address 0 |
| `0x11130` | 25 instructions | Unmapped byte read at `0x4801ff0e` |
| `0x0fc4` | 1 instruction | Unmapped 32-bit read at address 0 |

The second result identifies **a concrete memory-address dependency**
(`0x4801ff0e`) under this assumed mapping and CPU mode. We **cannot yet**
identify this address as a real device register, because the entry points,
relocations and ABI state remain unvalidated. These short runs have not
reached firmware decompression or filesystem extraction.

Detailed JSON traces are retained in the local `../system-audit/emulation-*.json`
files. The other two offsets may simply be invalid entries.

## Reproduce

```sh
.venv/bin/python tools/ca01_boot_emulate.py \
  --input /path/to/09-boot.bin \
  --offset 0x11130 --base 0x20000000 --budget 150 \
  --output /tmp/ca01-boot-trace.json

.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
```

## Next milestones (needed for a credible bootloader emulator)

1. Identify the real boot image header, executable offset, relocation
   base and actual entry point. The first bytes of the extracted component
   contain metadata, not a reliable ARM vector table.
2. Compare built U-Boot functions against manufacturer-provided source and
   align Ghidra disassembly to a known function or string reference.
3. Implement **explicit**, independently supported MMIO semantics for
   encountered hardware addresses (never blindly return zero for all MMIO).
4. Emulate read-only SD/eMMC contents with identified partition boundaries.
5. Trace the updater's real transform/verification path and only then carve
   any materialized output into separate files for REA/Ghidra/Binwalk.

Tests validate harness constraints on **synthetic ARM instructions**.
They do not establish firmware compatibility or boot integrity.


## Follow-up: register-argument hypothesis

A read of the Unicorn/Capstone traces shows that candidate `0x11060`
begins with `push {r3, r4, r5, r6, r7, sl, fp, lr}` and
`ldrd r4, r5, [r0]`. The original harness initialized `r0=0`,
so its immediate address-zero fault is consistent with a **missing caller
argument**, not necessarily a hardware-register access.

The harness now offers `--argument-mode stack-buffer`, which sets `r0`
to mapped writable stack-backed memory for controlled experiments. This is a
synthetic argument, not a recovered production caller.

Under that artificial argument, execution at `0x11060` proceeded for
26 logged instructions, then stopped with `UC_ERR_INSN_INVALID` at
`0x2000be14`. It made no blocked writes or unmapped accesses, but
did not return normally or identify an unpacker. The result is a useful
distinction between setup-dependent failures and genuinely unsupported
instructions or invalid function boundaries.

The `0x11130` trace starts with a conventional ARM function prologue and
calls a helper at component offset `0x131b4`; that helper attempts to read
from `0x4801ff0e`. The address might be calculated from a relocated
constant or uninitialized input. It has **not** been confirmed as MMIO.

Source inputs and detailed results remain read-only and local in
`../system-audit/emulation-11060-arg.json` and earlier trace files.

**Next prerequisite:** identify the real calling conventions, image
relocations and correct load base before creating any peripheral model.
Mapping arbitrary addresses to invented devices would produce misleading
traces rather than valid firmware behavior.
