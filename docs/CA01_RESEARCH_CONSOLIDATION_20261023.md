# Toyota CA01 — complete local research consolidation (2026-10-23)

This is a **local Git integration of the latest Codex working-tree research and the separate independent reverse-engineering findings** for the 2017 Toyota RAV4 factory Fujitsu Ten / DENSO TEN head unit. Device identification: Toyota radio part **86140-0R170** (matching label required before selecting any hardware action), firmware family **15TBDANA-CA01**, original updates **UU.11.27** and **UU.11.34**.

The older consolidated commits already include the original source-archive research, GUI emulation, boot/init trace, and firmware extraction work. This commit adds the currently uncommitted Codex decompilation toolchain, tests, evidence, and a curated full offline snapshot of the independent research. **Local Git only. No radio connected, no modified KWI accepted, no firmware flashed, and no remote push.**

## Start here

- [Independent audit archive](../research/independent-audit/2026-10-23/README.md) — dated copy of research source scripts, reports, small evidence, FCC exhibits and hypothesis reviews.
- [Independent audit provenance and SHA-256 manifest](../evidence/ca01-independent-audit-snapshot.json) — copied file SHA-256, exact prior on-PC paths, excluded large archive locations.
- [Codex critical binary decompilation](CA01_CRITICAL_BINARY_DECOMPILATION.md) — `PROC_DISPLAY`, `PROC_SYSTEM`, `libipas_sysc`, corrected callsite discovery, original task identity and tests.
- [GUI startup and IPC](CA01_HMI_STARTUP_IPC.md) and [display ABI](CA01_DISPLAY_ABI_AND_ASSET_FINDINGS.md) — prior committed original ARM probes.
- [Read-only service access and PCB/FCC assessment](../research/independent-audit/2026-10-23/ca01-service-access-assessment-20261023/ACCESS_AND_HARDWARE_FEASIBILITY.md).
- [Independent storage/partition evidence](../research/independent-audit/2026-10-23/ca01-1134-filesystem-tools-20261023/FILESYSTEM_AND_TOOLING_FINDINGS.md).
- [Verified UU.11.34 vs UU.11.27 comparison](../research/independent-audit/2026-10-23/ca01-1134-firmware-analysis-20261023/CA01_UU1134_FINDINGS.md).
- [Latest supervised offline research snapshot](../research/independent-audit/2026-10-23/ca01-local-ai-supervisor-20261023/CURRENT_STATUS.md), **frozen at archival time**; read the active external supervisor's `CURRENT_STATUS.md` for newer results.

## 1. Recovered content and what is still missing

The vendor KWI files are proprietary update containers, **not complete verified factory eMMC images**. Initial verified extraction produced 59 complete output-entry records representing **56 distinct installed paths**: 47 Audio, three GUI language XML and six Voice DB/version paths. Among them are 21 ARM executables and 20 ARM shared libraries. Most menu resources are not among those complete paths.

Core missing factory assets:

- **GUI scenes and bundles:** `/opt/ftl/gui/MC/`, `/opt/ftl/gui/MC/mui/` and `/opt/ftl/gui/font/`; relevant missing `CmA.mra`, `CmAl.mra`, `CmB.mra`, `CmBa.mra`, `CmC.mra`, `CmD.mra`, `CmE.mra`, `CmF.mra`, `CmG.mra`, `CmX.mra`, `CmY.mra`, `OnsTrans.mra`, `XMStationLogo.mra` and >500 MUI filename references, including `Opening.mui`.
- **Proprietary runtime providers:** `libipas_fls.so` (e.g. `rq_fls_Open`), `libdisplay_if.so`, `libdismng_if.so` (`sysDisMngInit`) and the authentic provider for `fs_mpl_Create`; other missing `libipas_*` and `libOpenVG.so` files.
- **Complete userspace and startup:** actual `ipasz.conf`, factory root filesystem, boot/kernel/userspace configuration, thread/IPC services, valid graphics driver/native window implementation.
- **Updater cryptography:** missing `libsecurity.so` and authentic key/mode initialization context.

The newer **UU.11.34** update did not add new validated installed paths or recover these files. Relative to UU.11.27, original `PROC_HMI` .text is byte-identical (build timestamp only), as are those of `PROC_SYSTEM` and `PROC_REPRO`; `PROC_DISPLAY` and `PROC_VRS` contain material machine-code differences. All 20 recovered libraries are unchanged between those two packages. These are verified local comparisons of **complete recovered entries**; incomplete update prefixes remain unknown.

## 2. Original execution and GUI research

The prior integrated harness executes bounded **original ARM instructions** for HMI window setup, drawing and frame submission with explicitly synthetic drivers/IPC; tested at **800×480 and 480×480** with three frame descriptors. Verified HMI startup barriers include task 0x27 initializing graphics and notifying task 0x28; the latter has a 64-message, 16-byte message queue. Original file/resource loaders refer to `Opening.mui`/`Opening.mra` and missing MC resources.

Codex's pending decompilation work newly reconstructs and crosschecks selected `PROC_SYSTEM` master-init logic, `PROC_DISPLAY` tasks, and `rq_tsk_GetTid` pthread/TLS caching and thread-table behavior. It corrects an earlier Capstone linear-scan limitation. See the dedicated report. **These are Ghidra-like C reconstructions and targeted original ARM probes, NOT recovered original source code or fully executing stock application.**

## 3. Independent Ghidra / local-AI progress

An independent long-running supervisor runs locally in WSL, reading SHA-256 verified recovered binaries and writing separate research outputs. The snapshot includes the worker's Python code, Ghidra script, scoped review scripts, and dated machine-generated hypothesis reviews. The worker can continue after this commit; the Git copy does not update itself.

The earlier HMI 1134 initial Ghidra pass discovered **8,355 entries**, decompiled 6,290, and left 2,065 time-budget omissions. A targeted address-only retry successfully reconstructed **2,064 more**, giving **8,354 decompiled / 8,355 discovered** and **one genuine failed attempt** (as reconciled in its manifest). This measures discovered entry representations, **not a proportion of semantically reverse-engineered original firmware**. `PROC_DISPLAY` has 6,698 of 6,706 discovered entries decompiled in an existing broad pass, with eight failed; separately scoped/seeded reconstructions overlap and are not added naively.

The new `function_coverage.sqlite3` indexes candidate function addresses and bounded C excerpts; `progress.sqlite3` tracks queued jobs. **Both live SQLite files and all large generated decompiled.c exports remain outside Git**, referenced by absolute paths in the manifest. Model analyses are *unverified hypotheses*. A completed AI review may cover only selected functions rather than every function of its binary.

## 4. Update authentication: main obstacle to a diagnostic KWI

Original recovered `PROC_REPRO` explicitly imports `sysSha256Init`, `sysSha256Update`, `sysSha256Final`, `sysRsaPssVerify`, key initialization and AES-related paths. Decompiled function `0x0001e9c0` calls SHA-256 finalization then RSA-PSS verification. Callers `0x0000a9bc` and `0x0000dec0` use those checks following decrypt/hash processing and emit `Sign Check error`/ `Sign Check Final error`.

This is concrete evidence of cryptographic authenticity checks on some update content. **The exact signed extent and boot trust policy are not fully established.** The mere presence of `BootSig` or `crc32` fields does not make an unsigned/custom update acceptable. No signing key, bypass, alternate entrypoint or safely installable modified update has been recovered. **Do not flash a fake or custom KWI to the car.**

## 5. USB, Bluetooth and service-access feasibility

Original `PROC_SYSTEM` code mounts VFAT at `/mnt/usb1` and invokes libusb, confirming stock **USB host-side** use. It also includes a backup *import* from `/mnt/usb1/13PFBACKUPDB.KWI` into `/var/backup`, **not proof of a factory rootfs-export function**. There is no verified USB gadget/peripheral protocol or user-available SSH, TCP/IP-over-Bluetooth, RFCOMM diagnostic serial or SPP connection.

An isolated standalone **ARM EABI5 read-only file-export prototype** exists in the independent service-access snapshot (`ca01_readonly_exporter.c` with `test_offline_exporter.py`). It passed host and QEMU ARM tests on a fully synthetic six-file test tree, including no-writes dry run, content matching, symlink-skipping and overwrite refusal. Its static glibc build declares Linux **3.2** minimum; a recovered original script references **2.6.35.7** modules. The actual radio kernel is not independently measured. **The binary is not proven bootable on the real radio and no verified means of launching it has been found.**

The safest next software path is to identify a legitimate maintenance/serial shell, confirm ABI/kernel compatibility, and only then consider copying **selected files to a pre-mounted USB storage destination**. Wireless SSH requires additional authenticated Bluetooth profile and network-stack research, and is less plausible than ordinary host-mode USB.

## 6. Physical memory map and service documentation

Original `PROC_REPRO` code references:

| Device | Established original call-path reference | Unknown |
| --- | --- | --- |
| `/dev/mmcblk0p1` / `p2` | EXT3 updater/rollback selection and `/var/verup` | Physical partition role, size, factory rootfs |
| `/dev/mmcblk0p3` | EXT3 mounted at `/opt/ftl/cddb` | Partition metadata |
| `/dev/mmcblk0p5` | `snap.sh` `tfat` mount to `/var/backup` | Present on specific car, private contents |
| `/dev/mmcblk0p6` | `snap.sh` `tfat` mount to `/var/log` | Present on specific car, private contents |
| `/dev/mmcblk0p8` | `snap.sh` backup-cache device | Layout |
| `/dev/mtdblock0` | `snap.sh` `mkfs.ext2` and mount to `/var/db` | Whether NOR/RAM-backed persistence applies |

A recovered `snap.sh` references a `2.6.35.7` driver tree, optional `eth0`/`smc91x` boot diagnostic mode, and `/dev/pvrsrvkm`. This establishes **original software references**, not a confirmed exposed Ethernet connector or a production kernel measurement.

Exact radio `86140-0R170` appears related to Fujitsu Ten FCC IDs `FT0049A` and `FT0049B`, **subject to direct label verification**. Public FCC exhibits include internal PCB, separate CPU/audio/switch and ALPS UGXZE-102A Bluetooth assembly pictures. The independent archive preserves three SHA-256-verified public FCC PDFs; links are in its hardware assessment. No validated detailed CPU-board schematic, internal UART pinout, chip marking for eMMC, or user-removable SD card was found.

If software execution remains blocked, the best acquisition path is an exact-matching donor head unit and a **read-only complete eMMC acquisition**, not only p1-3. Include partition table and accessible boot partitions where appropriate; preserve privacy and hashes. Board access requires validated power/ground/voltage test points, not guessed pin connections.

## 7. Verification, provenance and scope

The preexisting Codex working-tree additions are committed *as authored*: bounded Ghidra batch, selected function seeding, source/entry checks, repaired ARM call scanning, original task-identity probes and associated ten regression tests. Prior GUI, recovery and ARM tests remain in the existing checkout.

The independent archive is a **source and evidence snapshot**, not a replacement for the 1.6 GiB working directory. The manifest hashes each copied file and identifies large omitted raw/decompiled artifacts. It also preserves the eight text files that still differ in the separate older dirty research worktree rather than overwriting newer `main` versions.

**Do not equate:** structural KWI parsing with successful signature verification; entry decompilation with semantics; supported hardware drivers with exposed physical ports; host QEMU success with real head-unit compatibility; or copied scene filename references with recovered `.mui`/`.mra` content.

Next actions, in priority order: (1) inspect exact installed unit labeling, (2) determine any authorized shell/debug console or vendor read-only diagnostic mode, (3) prove actual kernel/ABI and USB mount behavior before deployment, (4) acquire complete eMMC from a donor if needed, (5) resume original GUI resource and proprietary library linkage research. **No live writes or unsigned firmware experimentation.**
