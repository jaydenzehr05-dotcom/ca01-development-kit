# CA01 system-layer inventory and missing dependencies

This project targets the Fujitsu Ten `15TBDANA-CA01` platform. The source
archives are **board-support references**, not a proven build of the production
RAV4 firmware. Do not equate archive file presence with installed driver support.

## Current recovered/runtime inventory

The integrated collection has 59 complete recovered files (21 ARM executables,
20 ARM shared libraries and 18 other files). See the hash-verified
[dependency inventory](docs/CA01_DEPENDENCY_INVENTORY.md) and
[local consolidation](docs/CA01_LOCAL_CONSOLIDATION.md). The recovery-only set
is missing 89 requested library names; the installed ARMEL environment supplies
some system dependencies. Fresh isolated traces leave HMI 17, Display 47 and
Repro 18 unresolved names. No complete radio or stock GUI boot is established.

## What is available

- Fujitsu Ten / Renesas ARM Linux kernel and bootloader sources in the Denso Ten
  source releases (external archives; not redistributed in this repository).
- CA01 `1127` update package, its ten separately identifiable sections and a
  working read-only container inspector.
- Static ARM/Linux diagnostic executable and mocked-syscall tests.
- Read-only inventory command (`tools/ca01_system_inventory.py`) to fingerprint
  supplied component files and identify platform source candidates.

## Source leads

| Subsystem | Relevant source paths | Status |
| --- | --- | --- |
| Board | `kernel/src/arch/arm/mach-shmobile/board-ftenbb.c` | Candidate board definition |
| Display | `sh_mobile_lcdc_fb` device referenced in board file | API and production configuration unverified |
| Audio | `kernel/src/sound/soc/ftenbb/`, `fsi-ak7756_lvds.c` | Device and DSP protocol unverified |
| Remote input | `kernel/src/drivers/input/misc/ftenbb_asic_remocon.c` | Input events and production wiring unverified |
| Hardware ASIC | `kernel/src/drivers/mfd/ftenbb_asic-core.c` | Userspace API unverified |
| Camera | `kernel/src/drivers/media/video/ftenbb_ceu.c` | Reverse-camera path unverified |
| Storage | `kernel/src/drivers/mmc/host/ftenbb_asic_sdhi.c` | Installed partition table unverified |
| Serial | `kernel/src/drivers/serial/ftenbb_asic_scifa.c` | Attached MCU and message protocol unverified |
| Boot | `boot/src/board/fujitsuten/rma1_13PF/` | Acceptance/signing/recovery unverified |

## Generate an inventory

Use the **extracted** component directory, not the .kwi as a direct input:

```sh
python3 tools/ca01_system_inventory.py \
  --components /path/to/components \
  --archive /path/to/OSS_SOFT_PACK.tgz \
  --archive /path/to/20130619_LE2355.tgz \
  --output /path/to/ca01-system-inventory.json
```

Only file names, hashes and entropy measurements are generated. No provided
firmware or archives are modified. An entropy score near 8 **does not prove**
encryption; a filename match **does not prove** production-device compatibility.

## Actual blockers

1. Recover exact production kernel config, board variant and rootfs layout.
2. Determine how original middleware talks to the radio ASIC, audio, vehicle
   controls, Bluetooth and camera.
3. Recover or substitute required proprietary userspace system services.
4. Establish safe, verifiable boot/authentication and recovery before any
   hardware installation.

A decompiler cannot recover source from encrypted/unknown update payloads
without first identifying their internal representation. The existing source
is useful for building a **development Linux image**, but a working physical
radio has *not* been demonstrated. Do not flash unverified images.

## Related-source integration

The verified DENSO TEN17 archive and63 selected source files are inventoried outside Git with hashes and original URLs. Linux3.10.101-ltsi and Evo Bluetooth interfaces are useful comparison sources, not a replacement CA01 rootfs or established ABI match. See [source recovery and related-firmware inventory](docs/CA01_RELATED_FIRMWARE_AND_SOURCES.md).
