# Verified recovered-file and dependency inventory

All 59 preserved complete files were freshly checked against their recorded byte sizes and SHA-256 values. They include **41 ELF32 little-endian ARM files: 21 executables and 20 shared libraries**. This is a partial update-package recovery, not a full installed root filesystem. No target code was executed.

`evidence/ca01-dependency-inventory.json` contains every file, hash, provenance path, role basis, ELF interpreter, direct dependency, dynamic import/export and observed `/dev` string. The new tool reproduces the structural inventory directly from the preserved files and refuses hash/size mismatches or output overwrite. Role annotations are added after analysis, not guessed by the parser.

## Updater readiness

`PROC_REPRO` directly names 30 libraries: **6 recovered, 24 missing**. Across all 41 ELFs, **109 distinct needed names** are observed, **89 absent** from the recovered set. The required interpreter `/lib/ld-linux.so.3` is also absent. These findings do not establish absence from a physical radio.

Present direct dependencies: `libipas_ls1.so`, `libipas_sysc.so`, `libi2c_cm.so`, `libComFlmLb.so`, `libIFLB_CDDB.so`, `libipas_skt.so`.

Missing direct dependencies: `libm.so.6`, `libz.so.1`, `librt.so.1`, `libipas_std.so`, `libipas_fls.so`, `libipas_tab.so`, `libipas_can.so`, `libdismng_if.so`, `libipas_trc.so`, `libipas_mda.so`, `libgpo_ct.so`, `libmem_ct.so`, `libadi_ct.so`, `libIFLB_NAVIIF.so`, `libLMMDBSYS_IF.so`, `libnavi_ex.so`, `libsecurity.so`, `libexpat.so.1`, `libscac_lib_srb.so.1`, `libscac_implement.so.1`, `libscac_provide.so.1`, `libswi_ct.so`, `libgcc_s.so.1`, `libc.so.6`.

`libsecurity.so` is missing. No recovered dynamic export provides the updater’s AES/SHA/RSA/security APIs, or navigation’s `sysUserRsaPrvKeyNonCrt`. Also missing are the standard C runtime, zlib, Expat and several vendor IPC/device libraries. A successful standalone updater run cannot be claimed from this collection.

**Provider matches are evidence for analysis, not loader resolution.** The tool matches names and ELF architecture across the whole recovered collection, including peer executables. For example `inflate` is exported by `PROC_HMI`; that does not supply a loadable `libz.so.1` to `PROC_REPRO`. Versions/search order/transitive loading/interposition and runtime devices remain unverified. Weak imports are separated from required ones.

## Recovered executable/library roles

Roles below are supported by exported names/imports unless fresh decompilation is explicitly mentioned. A detailed role left unestablished is deliberate; a process name is not proof of behavior.

| File | Observed role / evidence |
|---|---|
| `libipas_grp.so` | Graphics/font/bitmap interface. Exports Bmp_ReadMotFile, FontUseCount and many gdr drawing functions. |
| `libVOIdata_cp.so` | Voice-data copy, checks and cleanup. Exports VOIdata_cp, VOIdata_grammar_check, VOIdata_recovery_fs. |
| `libipas_sysc.so` | System/task/IPC runtime interface. Exports rq_psm_Take/Give and hundreds of task, memory and system routines. |
| `libi2c_cm.so` | I2C device access. Fresh Ghidra: opens /dev/i2c-0 through -4, ioctl 0x703/0x707. |
| `libipas_sysp.so` | Alternative system/task runtime interface. Many exports overlap libipas_sysc; substitutability not verified. |
| `libComFlmLb.so` | Flash device access. Fresh Ghidra: /dev/flash, flash ioctl interface, sector operations. |
| `libcoll.so` | Text collation interface. Exports df_edb_Coll_* and df_edb_CollEx_*. |
| `libipas_skt.so` | Socket/network interface. Exports rq_skt_Connect, Accept, Bind, DNS and interface operations. |
| `libAdlRd.so` | Radio/preset database interface. Exports fd_adl_DabPch*, radio and satellite database functions. |
| `libnavi_if.so` | Navigation graphics and RSA interface. Exports AWN_Gfx_* and AWN_Navisec_RSA_Decription; latter independently decompiled. |
| `libAdlCd.so` | CD database/browsing interface. Exports fd_adl_CdBrw*, CD management objects. |
| `libDisdb_if.so` | Bluetooth/display database interface. Exports disBt*, disBtRgtShrInit and db_btd_*. |
| `libAdlUb.so` | USB/iPod database/browsing interface. Exports fd_adl_IpdBrw*, db_adl_usb_mng. |
| `libsct_ct.so` | Touchscreen controller interface. Exports fs_drv_SwiScTsw* reset, CRC and device operations. |
| `libuie_api.so` | UI process/image metadata interface. Exports uieChkUpdImgLib, uieGetAplInfLib, uieGetDcdInfLib. |
| `libDIS_IF.so` | Display/Bluetooth notification interface. Exports disBlA2dpVoiReq, disBlHfrOpeReq, disBEcNc*. |
| `libipas_ls1.so` | Intercomponent connection/configuration interface. Exports db_ls1_Cnct*, db_ls1_CnfInf, db_ls1_AvMode; physical transport not established. |
| `libedbsong.so` | Song/media browsing database interface. Exports df_edb_CdrSelLst_* and other selection/list APIs. |
| `libVOIAudioStream.so` | Voice/audio streaming interface. Exports CreateVBTAudioStream, Bargein*, audio-buffer interfaces. |
| `libIFLB_CDDB.so` | CDDB metadata/update interface. Exports cdbCtlVupStaReq, cdbCtlVupEndReq and cdbArt* metadata functions. |
| `FlashImageCreater` | Flash-image creation utility. Recovered executable imports open/read/ioctl and references /dev/flash; earlier interface research. |
| `FlashImageWriter` | Flash-image writing utility. Recovered executable imports open/write/ioctl and references /dev/flash; never executed. |
| `PROC_DSV` | Process DSV; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_MMP` | Process MMP; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_EXT` | Process EXT; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_REPRO` | Firmware update process. Decompiled KWI metadata, AES/RSA/SHA wrappers, archive installation and update coordination. |
| `PROC_CDDB` | Process CDDB; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_VRS` | Process VRS; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_SYSTEM` | System/security lifecycle process. Imports sysSecStartUp/Finish, serial and security-version queries. |
| `PROC_DTV` | Process DTV; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_HMI` | Process HMI; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_AUDIO` | Process AUDIO; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_VI` | Process VI; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_DVDDECK` | Process DVDDECK; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_NAVIIF` | Process NAVIIF; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_DISPLAY` | Process DISPLAY; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_CDP` | Process CDP; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_UIEIF` | Process UIEIF; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_SPC` | Process SPC; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_TMD` | Process TMD; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |
| `PROC_DVDP` | Process DVDP; detailed role not yet independently established. Filename and imports only; no semantic claim from filename alone. |

## Reproduce

```sh
/home/starlight/projects/rav4-radio/ca01-development-kit/.venv/bin/python \
  tools/ca01_dependency_inventory.py \
  /home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/recovery-manifest.json \
  --output /path/to/new-inventory.json
```

Uses the already-installed `pyelftools`. Controlled tests compile a small host ELF fixture and inspect it without executing it; no vendor binaries are included in tests. Recovery/crypto analysis and hardware interfaces are documented separately.
