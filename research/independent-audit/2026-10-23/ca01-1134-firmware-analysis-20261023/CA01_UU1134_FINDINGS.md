# Toyota CA01 UU.11.34 — Verified Offline Firmware Research

**Date:** 2026-10-23 (America/Toronto)  
**Scope:** 2017 RAV4/Fujitsu Ten `15TBDANA-CA01`, compared against local UU.11.27. Purely offline inspection of original bytes on the authorized PC. **No vehicle connection, firmware execution, modified KWI or remote Git push.**

## Executive findings

The newer package is **structurally valid for the CA01 component inspector** and contains ten update components. Nine contain byte differences. The package is only **517 bytes larger** overall. The unchanged section is `SH Base`.

**Critical result:** The newer `PROC_HMI` is byte-identical in every executable instruction; its only ten changed bytes encode a compiler **build timestamp**. The import set and library dependencies are unchanged. The existing November 2017 HMI reverse-engineering remains directly applicable to April 2018 HMI code.

The genuine **`PROC_DISPLAY`** and **`PROC_VRS`** executables do have substantial ARM machine-code differences. All **20 complete recovered shared libraries** are byte-for-byte identical. No previously missing proprietary file-service/display-management library or complete graphical menu resource was found in validated files.

**The original Toyota factory menus still do not run locally.** Do not confuse recovered process binaries with a factory root filesystem or working HMI runtime.

## Source and manifest verification

| Field | UU.11.27 baseline | UU.11.34 new |
| --- | --- | --- |
| Model | 15TBDANA-CA01 | 15TBDANA-CA01 |
| Metadata header size | 848 bytes | 848 bytes |
| Payload base offset | 1,092 | 1,092 |
| Package size | 15,164,495 bytes | 15,165,012 bytes |
| SHA-256 | `39431b79ed849be627c13be586019ceaab34470a534b76c385f73f1748d367ca` | `71c62cdcc357b5f249b216d68c06bd31168ab16939aab010a68777ffead04dbc` |

The new input is also stored under `ca01-development-kit/firmware/15TBDANA-CA01_1134.kwi` in the user's already-created **local commit `db49463`**. This independent investigation has not made another Git commit or changed that tracked source.

| Component | Old size | New size | Delta | Component bytes equal |
| --- | ---: | ---: | ---: | --- |
| SH Base | 892,788 | 892,788 | 0 | **Yes** |
| Middleware | 719,416 | 719,415 | -1 | No |
| Kernel | 1,808,838 | 1,808,792 | -46 | No |
| Device Driver | 236,704 | 236,712 | +8 | No |
| Bluetooth | 633,261 | 633,681 | +420 | No |
| Audio | 9,382,987 | 9,383,112 | +125 | No |
| GUI | 529,975 | 529,973 | -2 | No |
| Voice Recognition | 577,806 | 577,819 | +13 | No |
| Boot | 381,272 | 381,272 | 0 | No |
| BootSig | 356 | 356 | 0 | No |

These are **compressed and/or encoded component sizes**, not a count of actual updated instructions.

## Genuine file recovery from incomplete DEFLATE suffixes

The same observed leading opaque region and later raw DEFLATE continuation are present. The component checksum-shaped footers and unsigned gzip-like sizes were recorded, but **full gzip CRC and vendor signature verification were NOT possible** without the prefix. Using the already validated CA01 symbolic decoder and three independent zlib dictionary substitution checks, only individual checksum-valid TAR entries whose complete bytes are independent of missing history were exported.

| Component | Recovered continuation (bytes) | Independently known bytes | Complete files |
| --- | ---: | ---: | ---: |
| Middleware | 1,647,494 | 1,623,501 | 0 |
| Device Driver | 339,905 | 279,868 | 0 |
| Bluetooth | 1,656,001 | 1,487,773 | 0 |
| Audio | 23,439,895 | 23,423,809 | **47** |
| GUI | 2,644,922 | 2,588,152 | **3** |
| Voice Recognition | 2,451,174 | 2,295,553 | **6** |

This gives **56 distinct validated complete file paths** (47 Audio + 3 GUI + 6 Voice). The older recovery manifest counted 59 complete output entries because the three GUI language XMLs were represented twice; after name deduplication, the **path set is identical**. No new original filepath was validated.

Across the 47 Audio files, **24 changed** and **23 were identical**. GUI: **3 identical**. Voice: **6 identical**. All 20 recovered shared libraries are unchanged.

**No complete `/opt/ftl/gui/MC/`, font, MRA, MUI, `ScreenTrans.mui`, `libipas_fls.so`, `libdismng_if.so`, `libdisplay_if.so`, `libsecurity.so` or `fs_mpl_Create` implementation was recovered.** This is only a statement about fully validated recovered files; partially inaccessible leading regions and the factory eMMC root filesystem remain unknown.

REA with the configured `unblob` provider ran on the new GUI and Audio extracted payloads. Both completed with **zero recognized nested extraction subtasks**. No false claim of nested format recovery.

For the new Kernel, an independent stored-block LEN/NLEN scan located a valid **1,649,062-byte raw-DEFLATE suffix** beginning near payload byte 166,988. It is **not** a complete bootable kernel or a root filesystem, and no full CRC/signature can be validated.

## Exactly which executable code changed?

A byte-exact, individual SHA-256, ELF-section and dynamic import comparison shows:

| Recovered executable | Different raw bytes | `.text` section | Notes |
| --- | ---: | --- | --- |
| `PROC_HMI` | **10** | **identical** | Only timestamp: `Nov 10 2017 17:05:22` -> `Apr 23 2018 18:25:48` |
| `PROC_SYSTEM` | 11 | identical | `.rodata` bytes only |
| `PROC_REPRO` | 10 | identical | `.rodata` bytes only |
| **`PROC_DISPLAY`** | **2,480,180** | **different** | About 2,252,058 old-position `.text` bytes differ; old 3,996,420 bytes, new 3,996,140 bytes |
| **`PROC_VRS`** | **582,282** (including length delta) | **different** | About 482,236 old-position `.text` bytes differ; old 619,976 bytes, new 620,124 bytes |

The other changed `PROC_*` executables, the two FlashImage tools, and two BIOS files differ only in small regions, largely build-date/version data. Byte differences in aligned code sections **must not be mistaken for a count of new functionality**.

For `PROC_DISPLAY`, a shift-insensitive 64-byte instruction-window sampling comparison found **63.87%** exact matches somewhere in the new `.text` section, most commonly at the same offset or shifted by -280/-284 bytes. This proves substantial shared code and relocation, but **does not establish behavioral equivalence for remaining portions**. `PROC_VRS` had 24.53% matching windows under the same sampling method.

**No `DT_NEEDED` dependency or undefined ELF import-symbol names were added or removed** for the checked `PROC_HMI`, `PROC_DISPLAY`, `PROC_SYSTEM`, `PROC_REPRO` and `PROC_VRS`. `PROC_DISPLAY` still depends on the missing `libdismng_if.so` and `libipas_fls.so`, among many other libraries.

### Ghidra limits

A dedicated headless Ghidra import/analysis was attempted on the **new `PROC_DISPLAY`**. It loaded the authentic ARM ELF and identified relevant external symbols, but its auto-analysis hit the 160-second per-file limit. The post-script consequently reported **zero reliable direct external call references/decompiled callers**. The older-version Ghidra repetition was terminated to avoid unnecessary processing. **No complete Ghidra function-level diff or precise changed behavior is claimed.** This is recorded in `ghidra-1134-console.log`.

## Recommendations to Codex

1. **Do not restart HMI startup/GLES Ghidra research from the new `PROC_HMI`** — the machine-code `.text` and import contract are identical to the existing verified baseline. Update provenance/build metadata, not the existing reverse-engineering conclusions.
2. **Focus any version-specific reverse-engineering on `PROC_DISPLAY`.** Its code changed materially, although library and symbol names did not. Analyze in bounded batches with smaller Ghidra targets or direct ARM callsite analysis instead of another unrestricted 160-second headless attempt.
3. **Continue recovering the actual factory rootfs and proprietary GUI asset directories.** A newer KWI does not solve the absence of the `MC/` scene assets, fonts, and display/file-service libraries in the validated update contents.
4. Preserve existing original HMI rendering and IPC test suite; do not flash the car or claim authentic complete GUI menu rendering.
5. Keep the full binary recovery artifacts out of Git unless specifically requested. The original `1134.kwi` package itself is already committed locally.

## Reproducible offline evidence files

All findings are under:

`/home/starlight/projects/rav4-radio/system-audit/ca01-1134-firmware-analysis-20261023/`

- `compare_versions.py` / `component-comparison.json` — identical CA01 package layout and exact changed component sizes/SHA256
- `inspect_wrappers.py` / `wrapper-comparison.json` — inferred headers, unknown field values, CRC/ISIZE footer candidates
- `components-1134/` — SHA256-verified lossless extracted component bytes
- `inner-1134/` and `rea-07-gui.json`, `rea-06-audio.json` — REA/Unblob second pass
- `scan_deflate_1134.py` / component `*-scan.json` — independently located bit-aligned DEFLATE candidate boundaries
- `recover_suffix.py` / `recovered-1134-*/recovered-manifest.json` — valid complete recovered file bodies and history-independent masks
- `elf_binary_comparison.py` / `elf-byte-diff.json` — per-file difference counts and ELF section hashes
- `inspect_changed_elfs.py` / `key-elf-differences.json` — HMI timestamp, dependency and symbols comparisons
- `compare_display_code_blocks.py` / `display-code-anchors.json` — instruction-window correspondence independent of shifts
- `kernel_stored_scan.py` / `kernel-stored-scan.json` — bounded Kernel raw-deflate continuation
- `verify_findings.py` / `verified-1134-summary.json` — repeatable assertions over source hashes, exported complete-file content, named resources and Elf metadata

Run **`python3 verify_findings.py`** with the existing `ca01-development-kit/.venv` Python interpreter to recheck the saved evidence. For fresh exports, create new destinations; experimental recovery tools explicitly refuse overwrites.

**Status:** 1134 original input committed in local Git by earlier request; this audit is separate, local and uncommitted. No radio was accessed, updated or modified.
