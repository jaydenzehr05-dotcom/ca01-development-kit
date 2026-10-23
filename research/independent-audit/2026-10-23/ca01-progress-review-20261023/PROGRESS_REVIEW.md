# CA01 current progress and missing-system audit — 2026-10-23

This review reads current Git and the newer independent audit directories, rather than relying on the older handoff. No original firmware was modified, no vehicle accessed, and no commit or push performed by this review.

## Git and preservation

- Branch main, HEAD db49463f0bcaae024b297e146f949e4b4078ef8e: Integrate CA01 original GUI progress and UU.11.34 firmware.
- Working tree clean when inspected. This commit contains the earlier original-render integration plus the original 1134 KWI (24 changed files).
- Live read-only `git ls-remote origin refs/heads/main` returned 2f1c1fbeeade99bc84b231df84b3f6884d8f0322. The local commit is NOT on remote main at inspection time.
- New task10/file probes, 1134 comparison and EXT3/storage reports remain outside the Git checkout. They are not saved by the above commit.
- `docs/CA01_GUI_STATUS.md` still describes the earlier development cycle as uncommitted. Several inventories still describe HMI as semantically unexamined. These are stale, historical statements.

## What is new since the previous GUI milestone

1. Original missing-type reader executes its actual `(none)` fallback. Scene construction advances to fs_mpl_Create (pool id1, first raw descriptor fields13 and0x80000). No authentic implementation of that allocator was found. The subsequent sysDisMngInit boundary is reached ONLY in an explicitly synthetic pool-creation experiment, not a successful real allocator run.
2. Authentic rq_tsk_WaitInit now executes through original group and system code, reaching pthread_self. Original thread identity/task-table context is missing; task10 is not ready. A separate fixture captures the real 16-byte queue1 message `(0,5,39,10)` at rq_tsk_BlockBegin. No message is sent and no readiness is faked.
3. UU.11.34 was recovered and compared. HMI, SYSTEM and REPRO .text are identical to1127; HMI's ten changed bytes are timestamp data. All20 recovered shared libraries are identical. PROC_DISPLAY and PROC_VRS have genuine code differences, with unchanged required-library/import-name sets for the five compared programs.
4. EXT3/eMMC is now supported by five targeted original PROC_REPRO function decompilations, not just guessed from boot strings.
5. Recovery-count correction:59 old complete-entry records correspond to56 unique installed paths. New1134 recovery validates56 paths:47 Audio,3 GUI-language XML,6 Voice database/version files. It adds no new filepath or missing graphical resource.

Original HMI GL primitive rendering remains verified at800x480 and480x480, with three buffers. It uses fixture state/geometry and modeled display services. It is NOT a factory menu and not full application startup.

## Filesystems / namespace: what is and is not mapped

| Storage/path | Evidence | Missing mapping / contents |
| --- | --- | --- |
| /dev/mmcblk0p1 and p2 | Original PROC_REPRO0x1b048 selects one using stInfo.ulPartFlag and mounts EXT3 at /var/verup;0x1b2b8 builds mkfs.ext3 command | No partition table, byte offsets, sizes, UUIDs, images or directory trees. Active/standby role on actual unit unverified. Not established that each holds an entire Linux root. |
| /dev/mmcblk0p3 | Original0x15c44/0x159f8 mount EXT3 at /opt/ftl/cddb;0x15b04 has fsck/mount command | No complete CDDB partition image or metadata; relation to other persistent data unverified. |
| /mnt/rpr_rb_root | Original updater bind-mounts existing / there with MS_BIND before update | Alias/bind of current root, not evidence of another partition; actual root contents unknown. |
| /boot/uImage_T_DAB_US_1M | Boot source/strings name it | Complete production kernel/config/initramfs not recovered; only partial kernel suffix. |
| /opt/ftl/gui/MC/ | Original HMI container path builder0x3e9e8 and table/loading loop | No complete MRA containers; physical partition and resource-directory tree unknown. |
| /opt/ftl/gui/MC/mui/ | Original HMI0x3e9a0 constructs path | 534 filename references, no complete MUI payloads; file format only partly inferred from consumers. |
| /opt/ftl/gui/font/ | Original HMI paths/font imports | Original font/FDL data and service implementation missing. |
| /opt/ftl/gui/allwords/ | Three complete language XMLs recovered | This is a directory subset, not a filesystem image or sufficient menu assets. |
| /opt/ftl/lib/ and /opt/ftl/apl/ |20 libraries,21 executables recovered | Partial application tree, not full installed userspace. Original libc/loader/init/launch environment not fully recovered. |
| /opt/ftl/var/backup/vrs/VOI/ | Six complete voice DB/version files recovered | Not complete persistent storage or language/speech engine assets. |
| ipasz.conf (relative path) | Original system parser and first fopen traced | Actual config, enabled records, launch working directory, IPC object names and inherited eventfds missing. |
| /dev/flash; /dev/i2c-0..4; /proc/asic; input/audio/camera | Selected binary ioctl/source-family contracts | No actual device model, register map, wiring or matching complete driver set. No real devices mapped into emulation. |

The Debian ARMEL rootfs is host-supplied emulation infrastructure, not a recovered Toyota filesystem. Selected original ELF segments can be mapped into Unicorn/QEMU; that does not map factory partitions. Current Bubblewrap /proc and /dev are isolated/synthetic. No verified complete EXT3, SquashFS, JFFS2 or UBI image has been located in the KWI; p1/p2/p3 EXT3 evidence describes updater operations, not package partition images. Do not infer absent assets from failed generic signature scans.

## Missing code and data

The recovered-only inventory lacks89 DT_NEEDED names across41 ELFs. This count includes ordinary Linux libraries supplied separately by Debian; it is NOT89 unresolved libraries in the current emulation environment. The historical HMI loader report has17 unresolved names, reduced to16 in the separate tested GLES alias experiment. These are loader observations, not proof of all symbol/runtime compatibility.

Priority original gaps: libipas_fls.so/rq_fls_Open; fs_mpl_Create's authentic pool provider (no definition in59 complete records; library identity not proven); libdisplay_if.so; libdismng_if.so; libipas_std.so; libipas_pcd.so; libipas_trc.so; missing libOpenVG.so. libsecurity.so remains missing for full updater crypto, not a demonstrated immediate blocker for the isolated rectangle slice.

Required MRA names from original table:

`CmA.mra CmAl.mra CmB.mra CmBa.mra CmC.mra CmD.mra CmE.mra CmF.mra CmG.mra CmX.mra CmY.mra OnsTrans.mra XMStationLogo.mra`

Additional missing data:534 MUI referenced names, genuine fonts, full scene/resource tables, actual launch/config/pthread-task context, production rootfs/init and complete kernel/drivers. Missing type.txt is nonfatal for the verified reader only. rma1_hwreg and vigilancer occur in removal records and must not be counted as recovered binaries or guaranteed requirements.

## Component-level recovery gaps (1134)

Opaque leading bytes/history remain unresolved. The following known/unknown counts describe the recovered continuation only; they exclude an earlier undecoded prefix and cannot be turned into a full-package completion percentage.

| Component | Continuation bytes | Known bytes | Unknown bytes in continuation | Complete exported files |
| --- | ---: | ---: | ---: | ---: |
| 02-middle-ware | 1,647,494 | 1,623,501 | 23,993 | 0 |
| 04-device-driver | 339,905 | 279,868 | 60,037 | 0 |
| 05-bluetooth | 1,656,001 | 1,487,773 | 168,228 | 0 |
| 06-audio | 23,439,895 | 23,423,809 | 16,086 | 47 |
| 07-gui | 2,644,922 | 2,588,152 | 56,770 | 3 |
| 08-voice-recognition | 2,451,174 | 2,295,553 | 155,621 | 6 |

Kernel:1,649,062-byte verified suffix, not complete kernel/rootfs. SH-base has a readable suffix but no complete system/format reconstruction. Boot/BootSig: BIOS files and selected boot strings/code/source examined, but image base/full boot flow/signature acceptance unverified. The partial cachedmem.ko and dmamem.ko recoveries remain incomplete, never usable kernel modules. No new fully recovered driver/library names were supplied by1134.

## Per-ELF analysis coverage

No evidence supports claiming any of these files is fully reverse engineered. ELF inventory, an imported Ghidra project, automatic function count and selected decompilations are different coverage levels. There is no reliable whole-project percentage of understood code.

| Complete file | Verified analysis level / remaining scope |
| --- | --- |
| libipas_grp.so | Graphics/font/bitmap exports, original group initialization/HMI callback traced. Resource/font renderer not fully reverse engineered. |
| libVOIdata_cp.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Voice-data copy, checks and cleanup |
| libipas_sysc.so | Selected configuration parser, process barriers, queues/tasks/flags and original WaitInit traced. Complete runtime not reconstructed. |
| libi2c_cm.so | Selected original open/ioctl/read/write/retry interfaces decompiled; physical devices unknown. |
| libipas_sysp.so | Symbols and alternate runtime/provider comparisons; selected duplicate task exports verified. Interchangeability unproven. |
| libComFlmLb.so | Selected original flash init/read/copy/erase ioctl contracts decompiled; actual driver/hardware unresolved. |
| libcoll.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Text collation interface |
| libipas_skt.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Socket/network interface |
| libAdlRd.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Radio/preset database interface |
| libnavi_if.so | Exports inventoried; selected navigation RSA wrapper decompiled. Rest of navigation graphics/IPC not reconstructed. |
| libAdlCd.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: CD database/browsing interface |
| libDisdb_if.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Bluetooth/display database interface |
| libAdlUb.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: USB/iPod database/browsing interface |
| libsct_ct.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Touchscreen controller interface |
| libuie_api.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: UI process/image metadata interface |
| libDIS_IF.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Display/Bluetooth notification interface |
| libipas_ls1.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Intercomponent connection/configuration interface |
| libedbsong.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Song/media browsing database interface |
| libVOIAudioStream.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: Voice/audio streaming interface |
| libIFLB_CDDB.so | ELF/export role inventory; no completed semantic implementation or full ABI verification. Observed role: CDDB metadata/update interface |
| FlashImageCreater | Static flash-device/interface observations only; no complete algorithm or safe execution demonstrated. |
| FlashImageWriter | Static flash-device/interface observations only; never run against hardware. |
| PROC_DSV | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_MMP | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_EXT | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_REPRO | Substantial selected updater paths: KWI wrappers, crypto interfaces, install loop; now five storage/mount functions. Crypto provider and full transaction unresolved. |
| PROC_CDDB | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_VRS | ELF/import/version comparison; real code differences found. Function-level behavior and runtime protocol not recovered. |
| PROC_SYSTEM | Lifecycle/security imports inspected; full supervisor/process launch and boot sequencing not recovered. |
| PROC_DTV | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_HMI | Substantial selected-path analysis: configuration, drawing/task entry, heartbeat, original EGL/rectangle/frame slice. Menu/scene loaders only partial; not full startup. |
| PROC_AUDIO | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_VI | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_DVDDECK | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_NAVIIF | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_DISPLAY | ELF/import/version comparison, instruction-window anchors and limited callsite survey only. Ghidra recorded 6,887 functions but caller survey is empty; semantic version diff incomplete. |
| PROC_CDP | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_UIEIF | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_SPC | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_TMD | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |
| PROC_DVDP | ELF dependencies/imports/strings inventoried; no evidence of a completed semantic process analysis or runnable service. |

## Tooling audit and a new coverage defect

Existing Ghidra12.1.4, Capstone5, Unicorn2, QEMU ARMEL, Mesa, REA, Unblob26.6.4, Binwalk2.3.3, infgen, readelf/objdump, debugfs, Sleuth Kit and custom CA01 suffix tools are enough for the immediate next steps. Jefferson0.4.8 and UBI Reader0.8.16 ARE installed inside `.venv/bin`; an earlier PATH-only dependency finding was incomplete. This does not prove a relevant JFFS2/UBI filesystem exists or that every external helper is available.

NEW VERIFIED PROBLEM: `compare_display_import_calls.py` uses one linear Capstone.disasm over .text, without accounting for early decode termination. Fresh identical read-only decoding gives:

- 1127: 6,192/3,996,420 bytes (0.1549%), stops at0x151e8.
- 1134: 6,192/3,996,140 bytes (0.1549%), stops at0x151e8.

Thus its direct-call counts cover only a small prefix and cannot be used as whole-binary counts or a semantic comparison. Proper recovery should use executable ARM/Thumb mapping/function boundaries, account for literal data/undecodable gaps and report actual coverage. Word-by-word decode alone risks promoting embedded data to code.

The Ghidra display survey queries references to EXTERNAL-space function entries; all its relevant references are zero, despite654 PLT imports. It needs PLT/GOT/thunk callers resolved, plus persisted analysis and scoped decompilation. The prior160-second analysis timeout is not enough to explain or trust zero external callers. Finish/correct this before interpreting a function diff. Ghidra recorded6,887 functions in1134, but no successful caller sample.

Useful online additions, checked against upstream documentation:

- [ghidriff](https://github.com/clearbluejar/ghidriff): function matching plus changed decompiled code/JSON reports; best first additional tool for1127/1134 PROC_DISPLAY. Upstream currently targets Ghidra12.0.4/pyghidra3; installed12.1.4 compatibility needs a separate trial. It does not eliminate prerequisite analysis.
- [Google BinDiff](https://github.com/google/bindiff): alternative ARM-capable function matcher, using a compatible disassembler exporter. Optional second opinion rather than installing both immediately.
- [Binwalk v3](https://github.com/ReFirmLabs/binwalk): optional isolated upgrade for faster identification/validation; signature recognition cannot reconstruct missing encrypted prefixes or factory-only files.
- [Unblob custom handlers](https://unblob.org/development/): existing installed extractor can recognize the proven CA01 wrapper using a custom validated handler. Useful consolidation, lower priority than recovering missing data and fixing display analysis.

No new tool was installed during this audit. Existing debugfs/mmls are appropriate when a legitimate complete storage IMAGE exists; they cannot reconstruct one from filename strings. Jefferson/UBI/SquashFS additions have lower priority without their actual format headers. Public related KWI parsers for Panasonic/Aisin are not established CA01 decoders.

## Recommended next work, in order

1. Consolidate the six independent task/file probes,1134 validation and EXT3 evidence into tested repo tools and current inventories. Preserve raw firmware/recovery artifacts externally; update stale commit/test/role statements. No remote push implied.
2. Correct the truncated Capstone scan and Ghidra EXTERNAL/thunk reference lookup; report coverage, reuse persisted analysis and target small call trees. Then match/diff PROC_DISPLAY functions; prioritize display/file/memory/IPC initialization. Reuse unchanged HMI/REPRO/SYSTEM findings rather than reanalyzing timestamps. PROC_VRS follows after display.
3. Advance real original thread/task creation and pthread_self-to-task mapping, queue1 initialization and task10 readiness; preserve original waits and `(0,5,39,10)` envelope. Keep fixture assertions separate from successful authentic service execution.
4. Continue MC/MUI/font loader-format analysis in HMI/libipas_grp while pursuing legitimate matching complete factory filesystem data or service libraries. Know which unresolved operation requests which exact file. No promise that software tools alone can recover factory-only assets absent from the update.
5. With an authentic storage image: establish partition offsets/sizes using mmls/fdisk, validate EXT metadata read-only, enumerate p1/p2/p3 via debugfs, compare file hashes/ELF ABI/provenance and map actual GUI/config/library paths. No vehicle action authorized or performed by this review.

## Fresh validation for this review

- Current repository full suite:125 tests, OK (13.646s), `/tmp/ca01-current-audit-tests.log`.
- Copied six independent task/file probe scripts to `/tmp/ca01-audit-task10-20261023/` and reran their full check script: all expected stop boundaries/service-provider checks pass. Original audit outputs were preserved.
- Original59 recovered records and1134's56 paths freshly hash/size checked. Actual ELF .text comparison rechecked for HMI/SYSTEM/REPRO (same) and DISPLAY/VRS (different).
- Read-only live remote SHA checked; no fetch/push necessary. Git status clean and diff whitespace check clean.
- No source changes, firmware modifications, commits, pushes or tool installations.

## Complete recovered-only missing-library list

These89 names are absent from the recovered collection, not necessarily from Debian emulation and not evidence of absence from the real radio:

```text
ld-linux.so.3
libAdlBt.so
libEGL.so
libGLES_CM.so
libIFLB_NAVIIF.so
libIFLB_REPRO.so
libLMMDBSYS_IF.so
libLMMDB_IF.so
libNTWSET_IF.so
libOpenVG.so
libVBTEngineClient.so
libVBTLoader.so
libVECITransport.so
libVOITTS.so
libVOIapi.so
libVOIutil_cfg.so
libVOIutil_lp.so
libVOIutil_th.so
libVRS_IF.so
libadi_ct.so
libasound.so.2
libasoundex.so
libaud_dsp.so
libaud_dts.so
libaud_xmd.so
libbep_ct.so
libc.so.6
libcva_db.so
libdismng_if.so
libdisplay_if.so
libdsv_api.so
libdsv_db.so
libdtv.so
libecli.so
libexpat.so.1
libext_api.so
libgcc_s.so.1
libgpo_ct.so
libgps_ct.so
libgsp.so
libhmi_if.so
libiflb_btm.so
libinit.so
libipas_acd.so
libipas_apc.so
libipas_can.so
libipas_fls.so
libipas_lcn.so
libipas_mda.so
libipas_pcd.so
libipas_pcmc.so
libipas_pcmp.so
libipas_std.so
libipas_tab.so
libipas_trc.so
libipas_util.so
libipd_ct.so
libir_ct.so
libjpeg.so
libm.so.6
libmem_ct.so
libmir_if.so
libmmp_prc.so
libmod.so
libnavi_ex.so
libomx_service.so
libopt.so
libpng12.so.0
libpthread.so.0
librom_dc.so
librt.so.1
librtapi.so
libscac_implement.so.1
libscac_lib_srb.so.1
libscac_provide.so.1
libscp_ct.so
libsecurity.so
libspc_if.so
libsqlite3.so.0
libsse.so
libswi_ct.so
libsysras_if.so
libsyssrcc_if.so
libsyssrcp_if.so
libuie_db.so
libuieplayer.so
libusb-0.1.so.4
libvcl_in.so
libz.so.1
```

## Primary local evidence

- [TASK10_FILE_BOUNDARIES.md](/home/starlight/projects/rav4-radio/system-audit/ca01-task10-file-services-20261023/TASK10_FILE_BOUNDARIES.md)
- [CA01_UU1134_FINDINGS.md](/home/starlight/projects/rav4-radio/system-audit/ca01-1134-firmware-analysis-20261023/CA01_UU1134_FINDINGS.md)
- [FILESYSTEM_AND_TOOLING_FINDINGS.md](/home/starlight/projects/rav4-radio/system-audit/ca01-1134-filesystem-tools-20261023/FILESYSTEM_AND_TOOLING_FINDINGS.md)
- [CA01_GUI_STATUS.md](/home/starlight/projects/rav4-radio/ca01-development-kit/docs/CA01_GUI_STATUS.md)
- [ca01-dependency-inventory.json](/home/starlight/projects/rav4-radio/ca01-development-kit/evidence/ca01-dependency-inventory.json)
