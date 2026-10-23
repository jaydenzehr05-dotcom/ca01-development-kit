# CA01 updater source archaeology and bounded call graphs

**The original updater `PROC_REPRO` was recovered from the KWI Audio component
and analyzed as a real ARM ELF.** It identifies the 64,000-byte AES prefix,
SHA256/RSA-PSS verification calls, key-selector fields, pathname-removal list,
and temporary tar installation path. The final sections record that binary
analysis with exact virtual addresses and explicit verification limits.

The two supplied source archives separately contain Fujitsu Ten boot,
filesystem-loading, boot-integrity and rollback code. No matching KWI parser,
middleware decoder, or proprietary installer C implementation was identified
in those archives. The source graphs below describe available family code;
they do not substitute generic boot helpers for the actual updater.
All archive paths and line numbers refer to original member bytes. Source
references and hashes are in `evidence/ca01-updater-source-paths.json`; binary
addresses and evidence are in `evidence/ca01-updater-binary-paths.json`.

## Scope and coverage

| Original archive | Top-level tar members | Recursive regular members scanned | Nested tar archives opened |
|---|---:|---:|---:|
| `OSS_SOFT_PACK.tgz` | 44,362 | 88,049 | 95 |
| `20130619_LE2355.tgz` | 35,853 | 33,803 | 0 |

All 80,215 top-level members were enumerated. Expanded trees were searched
with `rg`; a separate Python `tarfile` traversal searched member bytes in both
archives and recursively opened nested `.tgz`, `.tar.gz`, `.tar.bz2`, and
`.tar.xz` packages, to depth two. Total byte volume inspected was 1,630,558,215,
including compressed nested members and their unpacked contents, so this is
not a unique source-byte count. Standalone compressed non-tar files were not
recursively decoded. No files from the source archives were executed.

Exact searches covered `rma1_hwreg`, `vigilancer`, `bios.bin`, `s-bios.bin`,
`uImage_T_DAB_US_1M`, and bounded-word `kwi`. There were no occurrences of either
missing executable name in member bytes or the archive pathname inventories.
Relevant pathname hits appeared in three source files: the board implementation,
board configuration header, and f-bios Makefile. Bounded `kwi` elsewhere matched
Unicode/language data and coincidental binary/compressed bytes, not an updater.
There were 54 matching member records before those false positives were removed;
the evidence retains them so the negative conclusion can be audited.

Targeted vendor-source searches also covered firmware/software update, verup,
vup, rollback, verification, signature, compression, decompression, CRC16,
`KWIUpdate`, `decrypt`, `scrambl`, `64000`, and `0xfa00`. No applicable
64,000-byte prefix transformation was found. This does not exclude a
proprietary implementation, aliases, stripped code, or transformations without
those constants. Source absence does not establish that a runtime operation
never occurs.

## Confirmed source: boot mode selection and rollback

All paths in this section are members of `OSS_SOFT_PACK.tgz`.
Use `B = boot/src/board/fujitsuten/rma1_13PF/rma1_13PF.c` and
`S = boot/src/arch/arm/cpu/armv7/sh7740/system_subfunc.c`.

```text
B:1223 board_late_init()
  B:1233 check_wakeup_mode() [definition B:938]
    validate_system_errcnt()
    optional checkSDversionup() [B:769-935]
      fatload .ROOTFS/Side and .ROOTFS/<A|B>/flashverup/NFIMG.VER
      compare stored side/version; return SD version-up mode when applicable
    ACC-on path: crc32(BOOT_SIGADDR, BOOT_SIGSIZE) vs BOOT_SIGCODE
      failed boot CRC -> increment/check persistent system error count
      get_rollback_stat() [S:181] -> switch-flag bit 7
      get_system_side() [S:208] -> switch-flag low nibble, side 1 or 2
      conditional rollback branch [B:985-1078]
        ext2load mmc 1:<opposite side> BIOS_TEMP_ADDR /opt/ftl/boot/bios.bin
        write_to_flash(...) [S:265]
        ext2load mmc 1:<opposite side> BIOS_TEMP_ADDR /opt/ftl/boot/s-bios.bin
        write_to_flash(...)
        write MODULE_SWFLAG_BASE | MODULE_SWFLAG_RBACK | (next - 1)
        clear error counter and backup RAM
      repeated failures -> BOOT_MODE_RESCUE
  B:1235-1301 choose rescue_boot / tp_boot / first_load / vup_boot / default
  B:1313-1335 get_system_side() -> root_dev and uimg_dev environment
```

The alternative `check_BIOS_rollback()` at `B:1120-1221` is enclosed by
`BOOT_MODE_FIRST`. It loads `.ROOTFS/<A|B>/f-bios.bin` and
`.ROOTFS/<A|B>/s-bios.bin` using FAT, then writes BIOS and switch-flag data.
It is a conditional family variant, not proof that this exact layout applies
to shipping CA01. The source has vendor comment/conditional artifacts in some
branches; no compilation or production macro resolution was performed.

`write_to_flash()` at `S:265-327` formats `protect off`, `erase`, `cp.b`, and
`protect on` U-Boot commands. This is NOR programming beneath recovery logic.
It does not parse KWI component headers, decode middleware, validate a KWI
signature, or replace `/opt/ftl/bin` executables. Its existence does not prove
those operations share a call chain.

Partition mapping is explicit **in these family branches**: non-AFMA side 1
selects `/dev/mmcblk0p1` and `mmc 1:1`, side 2 selects `/dev/mmcblk0p2` and
`mmc 1:2`. AFMA instead keeps partition 1 and selects `bootside=A/B`
(`B:1313-1335`). No current radio partition map or exact shipping build was
verified.

## Confirmed source: installed kernel loading, verification and decompression

`boot/src/include/configs/rma1_13PF.h:355-363` selects
`/boot/uImage_T_DAB_US_1M` for `_BOARD_1M`, `_TYPE_DABASE`, non-China builds.
The pathname is an installed kernel load target, not a recovered KWI decoder.
The environment chain at that header's lines 416-479 is:

```text
sd_boot
  boot_sh; qbios_init; esd_bsw; qboot; mmu_off; clr_backmem; clr_kernmem
  run sd_lboot
    run sl_set -> root=${root_dev}, rootfstype=ext3, ro, rootwait
    mmcinfo 1
    READ_SD_CMD -> ext2load ${uimg_dev} <kernel address> /boot/uImage_...
      common/cmd_ext2.c:201 do_ext2load()
        mount selected partition [318]
        ext2fs_open(filename) [327]
        ext2fs_read(destination, filelen) [338]
    bootm
      common/cmd_bootm.c:210 bootm_start()
        boot_get_kernel() [call 221; implementation begins 862]
          legacy: image_get_kernel() [764-800]
            magic, image_check_hcrc(), optional image_check_dcrc(), architecture
          conditional FIT: fit_check_kernel() [817-847]
            fit_image_check_hashes() when verify enabled
      bootm_load_os() [328-443]
        uncompressed copy, or conditional gzip/bzip2/LZMA/LZO branch
  run rescue_boot -> initrd_boot (if normal sequence returns)
```

`common/image.c:164-185` calculates legacy header CRC32 with the header CRC
field zeroed and data CRC32 over the declared image data. Those are standard
legacy uImage integrity operations. FIT hash checking is likewise generic.
Neither establishes the meaning of the unknown 16-bit field in the KWI inner
wrapper, or any KWI cryptographic signature.

## Confirmed source: SH boot integrity and secure-build caveat

`boot/src/arch/arm/cpu/armv7/sh7740/boot_sh.c:275-505` defines `boot_sh()` or
`do_boot_sh()` depending on macros. It selects an SH image side, copies image
sections, checks cached contents through `comp_crcinfo()`, reloads from NOR
when needed, and can fail or try another side in conditional branches.
`comp_crcinfo()` at lines 184-242 uses CRC32 or a four-lane CRC32 ticket when
`CONFIG_SECUREBOOT` and `CONFIG_CRC32X4` are both defined.
`crc32_word4.c:150-208` contains `calc_crc32x4()`.

The word "secure" in macro names is not evidence that these CRCs are a
cryptographic signature scheme. `boot/src/13PF_config.rule:341-383` enables
those macros for certain target-name patterns. A matching shipping CA01
configuration has not been established. The two-line `ftensign.c` merely emits
a 16-byte `0x55` placeholder in `.ften_sign`; it supplies no KWI verifier or
production authentication policy.

## Confirmed source and binary: snapshot compression is a separate subsystem

`boot/f-bios/src/include/compress.h:12-22` defines the `codec` callback table.
Available implementations include raw LZ4, LZMA, zlib, LZF, pack, and none.
`compress/lzma/lzma_if.c:57-85` passes five initial property bytes and the
remaining compressed data to `LzmaUncompress()`. This is not an LZMA-alone
header with an eight-byte uncompressed-size field.
`compress/lz4/lz4_if.c:81-105` calls
`LZ4_uncompress_unknownOutputSize(src, dst, in_len, out_len)`.
Map-specific configs select LZ4 in many variants and zlib in `arm-ften-amap`;
no shipped CA01 codec selection was proved.

The snapshot core is **binary only**: `boot/f-bios/src/bios.o`, 40,012 bytes,
SHA-256 `9dc02d03d38be4e524bd4c7ec7ad447a068df20968c54ae6b17a82190df0977a`.
`file` and `readelf -Ws` identify an ARM EABI5 ELF32 little-endian relocatable
object, not stripped. Its symbols include `sbios_init`, `get_storage_bank`,
`codec`, and platform quick-boot callbacks, along with obfuscated names.
`boot/f-bios/src/Makefile:91-113` links the supplied `bios.o` with source-built
supporting objects. The core implementation source was not found. This object
is an existing vendor artifact; it is neither a newly recovered CA01 executable
nor evidence of the KWI updater. Snapshot platform comments and callbacks
identify the subsystem; a direct source call from its binary core into each
codec callback cannot be reconstructed from the C sources alone.

## Generic update and storage helpers deliberately excluded

| Source | Actual operation | Why it is not the identified CA01 KWI updater |
|---|---|---|
| `boot/src/common/update.c:241-315`, `update_tftp()` | TFTP download, FIT format/hash checks, FIT load parameters, flash writes | Generic FIT/TFTP facility; no KWI linkage or CA01 enablement shown |
| `boot/src/tools/updater/update.c:49-63`, `do_updater()` | Erase/write fixed address `0xFFF00000` from embedded image | Generic standalone updater mentioning a diskette; no KWI metadata or CA01 linkage |
| `boot/src/drivers/mmc/mmc.c:137-170`, `mmc_bwrite()` | Block write helper | Storage primitive, not update policy/parser |
| Other vendors' `board/*/auto_update.c` | Board-specific updater examples | Different vendors/platforms |
| Linux firmware loader, crypto, decompression libraries | Driver firmware request and general algorithms | Library presence supplies no KWI call chain |

The eMMC upload environment at `rma1_13PF.h:442-444` references an explicit
`u-boot-emmc.bin` raw block-writing command. It is not evidence that the KWI
updater uses that facility. No write, flash, boot, network download, or hardware
operation was performed in this investigation.

## Source-only remaining gaps (superseded in part below)

The execution path from KWI input to pathname table parsing, inner-wrapper
verification, any 64,000-byte transformation, executable reconstruction,
filesystem replacement, and final commit/rollback policy remains unknown.
Neither missing executable was recovered from these source archives. A useful
next binary target is the actual runtime updater ELF or its process/library
image; source-level generic compression and recovery helpers cannot substitute
for that evidence.

## Update: actual original updater recovered and analyzed

The earlier source-only gaps above are now partly resolved by **original binary
analysis**. A dictionary-independent DEFLATE suffix from the Audio component
contains the complete tar member `./opt/ftl/apl/PROC_REPRO`. Its tar header
checksum, bounds, and every content byte were validated by the extraction
research, including three independent zlib-dictionary crosschecks. This proves
the recovered member bytes; the complete gzip CRC and KWI signatures remain
unverified.

`PROC_REPRO`: 168,592 bytes, SHA-256
`47a48311b513bffaa3c8f41e9c3ebcc05ae3525e8efe069c714f5e8341fbb771`.
It is an ELF32 little-endian ARM EABI5 executable, stripped, entry `0xa6c0`,
interpreter `/lib/ld-linux.so.3`. Ghidra 12.1.4 loaded its ELF segments and
successfully analyzed it. This uses real ELF virtual addresses, unlike the
older speculative raw boot-component import. No recovered executable was run.
Machine-readable addresses, instruction excerpts and limitations are in
`evidence/ca01-updater-binary-paths.json`.

All `FUN_...` names below are **Ghidra-generated address labels**, not invented
vendor source symbols. Names such as `sysAesExec` are actual dynamic imports.
The proprietary updater implementation was found in a binary; matching
updater C source has not been found in the released archives.

### KWI first-block signature and key-selector provenance

```text
0x18fc8  KWI media processing state machine, including "Decoding start"
  0x19f58  first-block checker
    0x19dc8  decode first four bytes as big-endian length L
    read [0, L-256) as data, then 256 signature bytes
    read 244 additional metadata bytes starting at L
      metadata byte 2 -> RSA selector
      metadata byte 3 -> AES selector
    0x1ea68 -> sysSha256Init
    0x1e94c -> sysRsaPbcKeyInit -> sysRsaDecPbcKeyInit
    0x1ea28 -> sysSha256Update on first L-256 bytes
    0x1e9c0 -> sysSha256Final -> sysRsaPssVerify
  0x20c18  persist update state in /var/backup/13CyRprVupModNew
```

The original CA01 1127 file gives `L=848`, so this path reads 592 hashed data
bytes, a 256-byte signature, and then 244 additional bytes. The two selectors
are at absolute offsets 850 and 851 and have values **RSA=0, AES=4**. They
identify keys/API slots; they are not recovered key bytes. The 244 additional
bytes are outside that particular first-block SHA256 operation. That says
nothing about authentication performed elsewhere.

Later, the update-message handler at `0xb8a8` obtains the RSA selector from
payload byte `0x54` and AES selector from payload byte `0x55`, saving them in
globals `0x7ccc5` and `0x7cd2c`. Its streaming branch stores the same bytes in
`0x7cda4`. The first-block selectors are persisted through `0x20c18`; the
complete saved-state-to-update-message sequence has not yet been independently
traced. Do not equate a state-file write with a direct message send.

### Exact 64,000-byte AES prefix transformation

```text
0xa9bc  memory-buffer decode/check helper
  cap input prefix to min(length, 64000)
  0x1e94c  initialize RSA verification context
  0x1e870  sysAesKey -> sysAesInit
  0x1e7c0  sysAesExec -> sysAesFinish
  splice returned plaintext prefix with untouched remainder
  adjust stored sizes for AES-returned padding and 256-byte signature
  0x1ea68 / 0x1ea28 / 0x1e9c0  SHA256 and RSA-PSS check

0xe7ec  streaming input/output driver
  0xdec0  first-prefix decode/hash / continuation passthrough / final signature mode
    same 64000-byte prefix cap and imported AES operations
  write decoded data to /var/backup/13CyRprUpdFile.tgz
```

The cap is corroborated by raw ARM instructions: `0xa9f8: cmp r5,#0xfa00`
and `0xaa10: movhi r8,#0xfa00`. The first encrypted portion is therefore
64,000 decimal bytes; this is now confirmed by original updater instructions.
The memory helper uses AES's returned byte count when moving the clear suffix,
computes a padding adjustment `(prefix_length - returned_length) & 0xff`,
and removes 256 signature bytes from declared sizes. The streaming helper at
`0xdec0` has separate first, continuation and final-signature modes; `0xe7ec`
excludes signature/padding bytes when writing the temporary archive.

The signature finalizer at `0x1e9c0` calls `sysSha256Final` and
`sysRsaPssVerify`. Fresh follow-up establishes that mode 1 at `0xdec0` returns without a SHA
update; the large-component path hashes its initial decrypted prefix. See
[security interfaces](CA01_SECURITY_INTERFACES.md) for instruction evidence and
remaining boundary/nested-validation limits. The existence of these checks
**does not mean this investigation verified a signature**.

`0x1e870` passes opaque mode value `0x7c12776f` to `sysAesInit`. The actual
mode, IV, key provisioning and padding API semantics remain unknown because
`libsecurity.so` has not been recovered/analyzed. Its imported names prove the
operations called, not their complete implementation. The code does not supply
usable software key material. A complete offline decoder cannot currently be
claimed, and no signing check was bypassed.

### Pathname list, removal and tar installation

The table helper at `0xf2a0` reads an initial 16-bit count and computes
`12 + count * 256` bytes for the pathname-list area. It detects whether more
component data follows this list. This ties the observed two 256-byte middleware
pathname slots to a real updater table format; their presence alone does not
mean those two executable bodies follow immediately.

The installation state machine constructs commands using these literal
strings, verified directly at ELF virtual addresses:

| Address | Original literal | Observed use |
|---|---|---|
| `0x24060` | `rm -fR ` | Prefix destination plus successive 256-byte pathname entries |
| `0x24038` | `tar zxf ` | Temporary archive extraction command |
| `0x24044` | ` -C ` | Destination argument after temporary archive pathname |

The list-removal branch copies each 256-byte entry, appends its pathname to
the destination prefix, and prepares `rm -fR <destination/path>`. After the
list finishes, the response handler at `0xb7b0` advances to archive processing
when component data remains. The archive branch prepares
`tar zxf /var/backup/13CyRprUpdFile.tgz -C <destination> > /dev/null 2>&1`.
Commands are sent through message wrapper `0x1de48` to `/rpr_syslib`; this
wrapper packages the requested operation and calls `mq_send`. Servicing task
execution and physical installation were not observed.

Ghidra incorporates shared dispatch tails into different generated function
extents between analysis runs. Accordingly, command construction is supported
by literal addresses and concrete decompiled branches, while the original
source function boundaries remain uncertain. The label `0xbb28` itself is
an update-event handler calling `0xb8a8`; it should not be presented as a
recovered vendor name for every shared installation branch.

The binary has actual ext3 mount branches targeting `/dev/mmcblk0p1` or
`/dev/mmcblk0p2` at `/var/verup/`, destination-specific branches including
`/var/backup/` and `/opt/ftl/cddb/`, and a CDDB branch involving partition 3.
These show installer behavior compiled into this recovered updater. A full
mapping from every component/module ID to live active/standby storage, commit
conditions, and rollback has not yet been reconstructed.

### Revised remaining gaps

An actual original KWI updater has been identified and its 64,000-byte AES
prefix processing, signature APIs, selector fields, temporary archive and
pathname-list removal path have been located. Matching proprietary source,
`libsecurity.so` behavior/key access, complete authenticated offline decoding,
and all installation/rollback transitions remain unresolved. Neither
`rma1_hwreg` nor `vigilancer` has been recovered. No full gzip CRC, KWI
signature, hardware installation, or boot was verified.
