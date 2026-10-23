# Toyota CA01 — filesystem evidence and GitHub tooling audit

Date: 2026-10-23 EDT. Verified directly against the authorized WSL workstation.
All inspection is read-only against the archived `15TBDANA-CA01_1134.kwi` and the previously SHA-256-verified recovered `PROC_REPRO` executable. **No live-radio access, filesystem modifications, commits, or pushes.**

## What is actually known about physical storage

The **original** `PROC_REPRO` ARM ELF contains directly referenced path strings
`/dev/mmcblk0p1`, `/dev/mmcblk0p2`, `/dev/mmcblk0p3`,
`/opt/ftl/cddb`, and `mkfs.ext3`. Ghidra 12.1.4 completed targeted static
decompilation of all five related callers. See
`ghidra-repro/partition-survey.txt` and
`ghidra-repro/partition-callers.c.txt`.

- Function `0x0001B048`: selects between **p1 and p2** according to a saved
  `stInfo.ulPartFlag` value. After binding the existing root at
  `/mnt/rpr_rb_root` (`0x1000` = Linux `MS_BIND`), explicitly mounts
  the selected block device at `/var/verup/` with filesystem argument
  **`ext3`** and then proceeds into the update flow.
- Function `0x0001B2B8`: selects p1/p2 from the same flag, unmounts
  that selected device, and builds a command beginning with **`mkfs.ext3`**.
  The whole command is passed into an existing firmware-updater dispatch routine.
- Functions `0x00015C44` and `0x000159F8`: explicitly
  `mount("/dev/mmcblk0p3/", "/opt/ftl/cddb/", "ext3", ...)` using
  different mount flags. Function `0x00015B04` contains the
  `fsck -a /dev/mmcblk0p3;mount /dev/mmcblk0p3 /opt/ftl/cddb` string.

**Strong evidence:** there is an eMMC block-device partition scheme and
multiple EXT3 mounts in the original Toyota updater. **Not proven:**
(a) partition layout on the exact individual vehicle, (b) that p1/p2
contain an entire factory Linux rootfs vs. an update/rollback subtree,
(c) where `/opt/ftl/gui/MC/` and the proprietary system libraries
physically reside, or (d) that the KWI contains the factory partition images.

## Existing tools actually installed

- Binwalk 2.3.3: `/usr/bin/binwalk`.
- Unblob in `ca01-development-kit/.venv/bin/unblob`, not on the global PATH.
- Ghidra 12.1.4, read-only ELF import/decompilation.
- `debugfs`, `unsquashfs`, `7z`, `mmls`, `fdisk`, `file`, `strings`.
- Custom proven CA01 header/component extractor and history-aware
  DEFLATE partial recovery tools; REA with unblob support.

Unblob dependency check found 7z/debugfs but **did not** find jefferson,
UBI Reader, sasquatch, EROFS tools, and several decompression utilities.
Do not install all of them without proof of applicable filesystem type.

## New scan of UU.11.34

All four input SHA256 values are recorded in the audit directory:
- full `15TBDANA-CA01_1134.kwi`;
- inner `07-gui.payload.bin`;
- inner `03-kernel.payload.bin`;
- inner `06-audio.payload.bin`.

`run_identification.sh` uses read-only **Binwalk filesystem-focused scans**
and **Unblob --skip-extraction** into isolated audit directories.

- Binwalk filesystem-focused scans produced **no validated signature** on
  these four sources.
- All four Unblob JSON reports contain zero subtasks, and no recognized
  embedded container; all inputs are effectively uninterpreted data.
- An unrestricted Binwalk v2 scan yields many misleading candidates
  including purported EXT images with impossible multi-terabyte sizes
  and a YAFFS signature with an invalid first object. These are
  **not evidence of actual filesystem headers**.
- The specialized CA01 recovery is still needed: the KWI has a proprietary
  header/wrappers and opaque leading portions before independently
  verified DEFLATE/TAR continuations. Tools using ordinary magic signatures
  alone may not see the actual contents.
- This is not a claim that the factory storage does not use EXT3, only that
  **a complete EXT image has not been identified within these update
  containers**.

## GitHub repositories actually reviewed

- https://github.com/ReFirmLabs/binwalk — Binwalk v3 (Rust);
  worthwhile future isolated upgrade to the installed 2.3.3,
  but it cannot recover bytes missing from the update.
- https://github.com/onekey-sec/unblob — already installed in project venv;
  supports custom handlers, which might codify the CA01 KWI wrapper.
- https://github.com/clearbluejar/ghidriff — use with installed Ghidra
  for old/new `PROC_DISPLAY` function comparisons, if Ghidra's large
  auto-analysis can be scoped or allowed sufficient resources.
- https://github.com/google/bindiff — another quality ARM-aware
  function-matching/binary-diff implementation.
- https://github.com/onekey-sec/jefferson — JFFS2 only, lower
  priority than EXT3 without a real JFFS2 signature.
- https://github.com/onekey-sec/ubi_reader — UBI/UBIFS only,
  likewise conditional on detecting an actual UBI image.
- https://github.com/onekey-sec/sasquatch — vendor-modified
  SquashFS support, conditional on detected SquashFS.
- https://github.com/KarpelesLab/kwi — **Toyota-related but different**
  Panasonic/Aisin `LOADING.KWI` parser, with `PCRD`/ext2 rootfs.
  It documents a DIFFERENT head-unit architecture from Fujitsu Ten CA01;
  **not** a validated decoder for `15TBDANA-CA01_1134.kwi`.

## Follow-on path (most efficient)

1. Continue using the proven CA01 component parser for KWI files. No generic
   extractor currently demonstrated better extraction of this package.
2. Prioritize a legitimately acquired **read-only eMMC storage image** from
   an exact matching unit, preferably with partition table metadata.
   No hardware disassembly, modifications, or flashing should be attempted
   just to satisfy this analysis without a separately reviewed safe procedure.
3. For a storage **image file**, not a live device, run
   `fdisk -l image.img` or `mmls image.img`. Validate partitions,
   extract a byte-exact *copy* of each partition using image-file offsets,
   run `e2fsck -n partition.img`, then explore using:
   `debugfs -R 'ls -p /opt/ftl/gui/MC' partition.img`.
   If this path does not exist, enumerate filesystem directories and try the
   other EXT3 partitions, fonts and library SONAMEs. Do not mount writable.
4. With no full image available yet, stay focused on Ghidra analysis of
   updater-storage callsites and a narrowly scoped `PROC_DISPLAY` diff;
   do not waste efforts on repeatedly scanning the same high-entropy wrapper.

### Original-code decompilation evidence

`CA01ReproPartitionSurvey.java` and `run_ghidra_repro.sh` reproduce
the exact five Ghidra function decompilations in a fresh temporary project.
The historical `UU.11.27` and newer `UU.11.34` `PROC_REPRO` machine
code is byte-identical (excluding build-date metadata).

All outputs live only under:
`/home/starlight/projects/rav4-radio/system-audit/ca01-1134-filesystem-tools-20261023/`

**Status: strong original-code evidence for EXT3/eMMC; no complete menu
resource filesystem recovered.**
