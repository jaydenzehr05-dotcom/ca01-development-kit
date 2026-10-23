# CA01 Phase 1: isolated ARM Linux / QEMU environment

> Historical milestone. The current integrated results are in
> [local consolidation](CA01_LOCAL_CONSOLIDATION.md) and
> [loader/graphics verification](CA01_ARM_LOADER_AND_GRAPHICS.md).

## Installed (on TrystansTower WSL Ubuntu 24.04)
- QEMU 8.2.2 ARM user mode: `/usr/bin/qemu-arm`, `qemu-arm-static`.
- QEMU 8.2.2 ARM system emulator: `/usr/bin/qemu-system-arm`.
- Debian Bookworm minimal ARMhf root filesystem: `../system-audit/gui-emulation/armhf-rootfs`.
- Debian Bookworm minimal **ARMel** root filesystem: `../system-audit/gui-emulation/armel-rootfs`.

The original recovered Toyota programs use the **ARMel soft-float** linker `/lib/ld-linux.so.3`, *not* the ARMhf `/lib/ld-linux-armhf.so.3`. Therefore ARMel is the relevant userspace baseline, even though it is newer than Toyota's original Linux 2.6-era runtime and does not establish compatibility.

## How to verify basic ARM execution

```sh
python3 tools/ca01_verify_armhf.py ../system-audit/gui-emulation/armel-rootfs
python3 tools/ca01_verify_armhf.py ../system-audit/gui-emulation/armhf-rootfs
file ../system-audit/gui-emulation/armel-rootfs/bin/dash
```

The verifier uses `qemu-arm-static -L ROOT ROOT/bin/sh -c ...`, so it executes a *real ARM-compiled shell* with its target dynamic loader, but uses the host Linux kernel's syscall implementation. The `uname` output can identify the host and must not be treated as proof of ARM system-mode or radio hardware simulation.

The filesystem bootstraps were performed with `debootstrap --foreign` followed by an emulated `--second-stage`. Do not modify or write firmware; recovered vendor executables were not started.

**Out of scope for Phase 1:** actual Toyota GUI, device drivers, GPU/GLES/OpenVG, CAN, audio, flash storage, original kernel, proprietary services and a real boot process. The 89 unresolved SONAMEs in the previous recovery-only scan are not all irrecoverable; some are standard libraries, but proprietary GPU libraries and device shims will require further work. A future compatibility test should isolate recovered application execution under `chroot`/container restrictions and mock all hardware access.

No Git push or radio modifications.
