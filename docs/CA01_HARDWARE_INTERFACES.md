# CA01 hardware interfaces: evidence-first map
Status: read-only research, 2026-10-22. No physical radio has been queried.

All source locations are relative to the official Denso Ten `OSS_SOFT_PACK.tgz`.
The release contains **candidate board support**; file presence does not prove
a given driver is compiled into a production `15TBDANA-CA01` image.
Machine-readable line-level observations: `evidence/vendor-driver-contracts.json`.

## What the source establishes

| Subsystem | Original source | Interface seen | Missing verification |
|---|---|---|---|
| Remote/buttons | `kernel/src/drivers/input/misc/ftenbb_asic_remocon.c` | Kernel Linux input subsystem, `input_report_key()`, `input_register_device()`, `EV_KEY` | Whether this exact remote is installed and which input event device maps to steering wheel |
| ASIC diagnostics | `kernel/src/drivers/mfd/ftenbb_asic-proc.c` | `/proc/asic/{gpio,adc,intc_m,intc_l,psel}`, optional `/proc/asic/scifa/scifaN` | Presence in production, register-read side effects, privileges |
| ASIC controller | `kernel/src/drivers/mfd/ftenbb_asic-core.c` | Linux multi-function device/core support | MCU protocol and each driver register contract |
| Serial | `kernel/src/drivers/serial/ftenbb_asic_scifa.c` | Linux `uart_driver` / TTY API | Actual UART wiring, message framing and vehicle-side microcontroller protocol |
| Audio | `kernel/src/sound/soc/ftenbb/ftenbb_asic_fsi.c`, `fsi-ak7756_lvds.c` | ALSA SoC PCM/FSI path | Tuner control, DSP initialization, mixer routing, amp handoff |
| Display | `kernel/src/arch/arm/mach-shmobile/board-ftenbb.c` | `sh_mobile_lcdc_fb` framebuffer platform device | Exact CA01 display geometry/pixel depth/production config |
| Camera | `kernel/src/drivers/media/video/ftenbb_ceu.c` | V4L2 subdevice and camera input integration | Physical reverse-camera routing and reverse-gear trigger; do not interfere with original safety-critical path |
| Storage | `kernel/src/drivers/mmc/host/ftenbb_asic_sdhi.c` and board source | SD/MMC controller, bootloader's ext3 eMMC references | Production partition map, backup and recovery procedure |

### Input: two distinct compile-time code maps

The remote driver uses an `#ifdef ASIC_REMOCON_EPS` branch, with a separate
mapping in its `#else` branch. Both map raw hardware data to **standard
Linux key codes**. For example, `KEY_VOLUMEUP`/`KEY_VOLUMEDOWN`,
`KEY_CHANNELUP`/`KEY_CHANNELDOWN`, and `KEY_POWER` are present.
The `ASIC_REMOCON_EPS` branch additionally includes hook/on-hook phone codes,
while the alternate map includes playback/menu keys. We must determine
which branch applies to the installed unit before interpreting raw ASIC bytes.

Proof locations: `ftenbb_asic_remocon.c:36-110` for maps,
`:175-177` for `input_report_key()`, `:269-305` for input registration.

### ASIC status interfaces

`ftenbb_asic-proc.c:340-365` defines `/proc/asic` and several diagnostic
read entries, with optional serial register entries named
`/proc/asic/scifa/scifa0`, `scifa1`, etc. The corresponding drivers might
be disabled by kernel configuration. **Read-only system calls do not guarantee
that reading hardware registers is side-effect free**, so do not execute
the diagnostic probe on the physical vehicle without reviewing each handler.

### Kernel board registration

`board-ftenbb.c:923-981` declares an array of platform devices, with some
conditional on `CONFIG_*` macros. Listed device families include LCDC,
FSI audio, camera/CEU, SD/MMC, and the Fujitsu Ten ASIC. A board file is
evidence of possible hardware support, not proof of the active production
kernel configuration.

## Runnable research artifact

`build/ca01-hw-probe-arm` is a **standalone, static, 32-bit ARM Linux EABI ELF**
built by `build_hw_probe.sh`. It reads selected `/proc` files, queries
`FBIOGET_VSCREENINFO`, and passively opens `/dev/input/event0..7` for a
bounded key-event sample. It uses read-only opens and stdout-only writes;
it does NOT flash, initialize vehicle services or control the car.
**Vendor ASIC register diagnostics are disabled in the default build**
(`CA01_ENABLE_ASIC_READS=0`) because read-only MMIO access can still have
side effects. The alternate compile-time mode is for reviewed bench use only.

Unit tests in `tests/test_hw_probe_emulation.py` enforce syscall restrictions
under Unicorn with **mocked** devices. They are not validation on the real radio.

## Missing system services: what we would implement

1. Linux event reader to normalize steering-wheel and head-unit buttons.
2. Hardware-discovery service reporting available input/audio/video devices,
   using vendor-specific register diagnostics only after review.
3. Audio source/tuner/volume/DSP control adapter (vendor protocol not recovered).
4. Bluetooth calling/media manager (vendor firmware/middleware compatibility not known).
5. Reverse-camera display adapter (must preserve safety behavior, no real test).
6. Vehicle signal bridge (CAN/serial frame layout and attached microcontroller unknown).
7. Init/service supervision for the chosen root filesystem (production init not recovered).

## Next validation gates

- Confirm the **exact** shipping board/kernel configuration.
- Recover the original userspace binaries, or document their IPC and device APIs.
- Verify inactive/active TTY, ALSA, V4L2, framebuffer and evdev nodes on a
  bench unit through read-only observation, not by probing unknown vehicle buses.
- Develop replacement service shims in a PC emulator with mocked hardware.
- Never install a custom image until recovery, signing/acceptance, and original
  backups are independently demonstrated.
