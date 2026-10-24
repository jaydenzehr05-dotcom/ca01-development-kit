# Toyota CA01 - manually verified executable-code coverage

Generated: 2026-10-23T23:45:10.941094+00:00

Local AI enabled: False

Supervisor stopped: True

**Scope:** extracted ELF inputs and Ghidra-discovered executable functions only.
These are machine-code-derived C-like outputs, not factory source code.

## Totals

- Catalogue entries: **66,205**
- Decompiled: **66,205**
- Failed: **0**
- Not attempted: **0**

## Versioned ELF inputs

| Version | ELF path | Decompiled | Failed | Not attempted | Status |
|---|---|---:|---:|---:|---|
| 1127 | `./opt/ftl/apl/PROC_AUDIO` | 3385 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_AUDIO` | 3383 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_CDDB` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_CDDB` | 2802 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_CDP` | 269 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_CDP` | 269 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_DISPLAY` | 5575 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_DISPLAY` | 6706 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_DSV` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_DSV` | 423 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_DTV` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_DTV` | 4477 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_DVDDECK` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_DVDDECK` | 1816 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_DVDP` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_DVDP` | 418 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_EXT` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_EXT` | 245 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_HMI` | 8355 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_HMI` | 8355 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_MMP` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_MMP` | 2385 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_NAVIIF` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_NAVIIF` | 465 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_REPRO` | 410 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_REPRO` | 410 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_SPC` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_SPC` | 203 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_SYSTEM` | 1605 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_SYSTEM` | 1607 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_TMD` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_TMD` | 539 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_UIEIF` | 1123 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_UIEIF` | 1123 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_VI` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/apl/PROC_VI` | 413 | 0 | 0 | complete |
| 1127 | `./opt/ftl/apl/PROC_VRS` | 1621 | 0 | 0 | complete |
| 1134 | `./opt/ftl/apl/PROC_VRS` | 1621 | 0 | 0 | complete |
| 1127 | `./opt/ftl/bin/FlashImageCreater` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/bin/FlashImageCreater` | 50 | 0 | 0 | complete |
| 1127 | `./opt/ftl/bin/FlashImageWriter` | - | - | - | skipped_identical_text |
| 1134 | `./opt/ftl/bin/FlashImageWriter` | 52 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libAdlCd.so` | 105 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libAdlRd.so` | 159 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libAdlUb.so` | 142 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libComFlmLb.so` | 46 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libDIS_IF.so` | 204 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libDisdb_if.so` | 155 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libIFLB_CDDB.so` | 91 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libVOIAudioStream.so` | 232 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libVOIdata_cp.so` | 61 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libcoll.so` | 359 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libedbsong.so` | 826 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libi2c_cm.so` | 20 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libipas_grp.so` | 1116 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libipas_ls1.so` | 145 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libipas_skt.so` | 80 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libipas_sysc.so` | 962 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libipas_sysp.so` | 925 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libnavi_if.so` | 399 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libsct_ct.so` | 41 | 0 | 0 | complete |
| 1134 | `./opt/ftl/lib/libuie_api.so` | 32 | 0 | 0 | complete |

## Failed function addresses

