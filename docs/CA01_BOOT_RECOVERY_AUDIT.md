# CA01 1127 bootloader: read-only boot and recovery audit

**Scope:** Original `09-boot.bin` extracted byte-for-byte from official
`15TBDANA-CA01_1127.kwi`. No vehicle access, flashing, signing,
bootloader configuration writes, or secure-boot circumvention.

## Observed binary evidence

- Component size: 381,272 bytes. SHA-256:
  `3a1b20952818fb09fd6727eec15086a1c8c38b169586c64ced77a9da1c5af8ae`.
- The original component includes metadata at its beginning; it is **not an ELF**.
- Original strings include `U-Boot 2010.09.113PF-SB`,
  `bootcmd=run sd_boot`, `root_emmc=root=${root_dev} rootfstype=ext3 ro rootwait`,
  and `/boot/uImage_T_DAB_US_1M`.
- An SD loader string references `mmcinfo 1`, `ext2load`, and `bootm`.
- Boot strings mention errors, rollback status and rescue modes.
  These are presence claims, **not proof that a recovery method is enabled**.

Evidence: `evidence/ghidra-boot-survey.txt` (headless Ghidra output) and the
original byte-exact component in the local, untracked `stock-firmware` folder.

## Independent open-source source evidence

Manufacturer archive: `OSS_SOFT_PACK.tgz`:
- `boot/src/board/fujitsuten/rma1_13PF/rma1_13PF.c:1227-1298`
  selects `rescue_boot`, `first_load`, `vup_boot` and normal startup
  depending on state and conditional compilation.
- `boot/src/include/configs/rma1_13PF.h:90-108` defines different
  board-type boot-command defaults; `:416-475` defines SD/eMMC root,
  Linux image load, rescue and fallback environment strings.
- `boot/src/board/fujitsuten/rma1_13PF/rma1_13PF.c:323-345`
  has `CONFIG_SECUREBOOT` conditional hardware/debug paths.
- `boot/src/board/fujitsuten/rma1_13PF/ftensign.c` defines a small
  `.ften_sign` section with a placeholder pattern. This **does not**
  prove signatures can be forged, bypassed, or omitted on production CA01.

These are family source files. The shipping CA01 build configuration,
root partition identification and accepted image format remain unknown.

## Ghidra analysis limitations

A read-only headless raw import used `ARM:LE:32:v7` with base 0 (both
assumed). Its automatic analyzer classified 263 candidate functions and
13,331 decoded instructions, including "Reset" at byte offset zero.
Because the first bytes encode **component metadata**, such auto-generated
entry points are **not reliable evidence of executable code**. The survey
safely locates human-readable strings but does not establish correct
load address, true code entry or valid full decompilation.

REA+Ghidra **successfully decompiled a separate, valid ARM ELF test probe**.
REA did not automatically accept the headerless `09-boot.bin` as an ordinary
executable; direct Ghidra raw analysis was used with the assumptions above.

Run survey (no writes to input):
```sh
tools/ghidra/run_boot_ghidra.sh
```
Output: `../system-audit/ghidra-boot-survey.txt`.

## Gates required before a physical replacement boot

1. Identify the **exact** model / production board configuration and read-only
   storage partition map.
2. Verify U-Boot image load address, verified boot/signature acceptance,
   fallback / rollback behavior and active boot-mode selection.
3. Obtain reliable restorable backups for the *specific* radio and prove a
   recovery method with a compatible spare unit.
4. Cross-compile kernel + minimal userspace using matching memory maps and
   driver config; run in emulation and static checks.
5. Bench-test on a spare, never assume a rescue string guarantees recovery.

**Status:** There is evidence of vendor recovery logic in source and boot
strings. There is **no verified safe custom-boot path** for the actual car.
