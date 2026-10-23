# CA01 Phase 2: ARMEL runtime and GUI dependency audit

> Historical milestone. The current integrated results are in
> [local consolidation](CA01_LOCAL_CONSOLIDATION.md) and
> [loader/graphics verification](CA01_ARM_LOADER_AND_GRAPHICS.md).

## Completed

- Debian Bookworm ARMEL second-stage bootstrap successfully completed.
- Installed via ARM emulated apt: `libexpat1`, `libgcc-s1`, `libasound2`, `libsqlite3-0`, `zlib1g`, `libegl1`, `libgles1`, `libxml2` and package dependencies.
- Original ARMEL dynamic linker exists at `/lib/ld-linux.so.3`.
- No Toyota executable was launched into application logic or given device access.
- New read-only tool `tools/ca01_armel_compatibility.py` compares ELF DT_NEEDED against both recovered filenames and ARMEL system shared objects.
- Full evidence at `../system-audit/gui-emulation/compatibility.json`; rebuilt from live filesystem and recovered files.

## Results

| Program | DT_NEEDED libraries | From recovered files | From Debian ARMEL rootfs | Unresolved filenames |
|---|---:|---:|---:|---:|
| PROC_HMI | 31 | 7 | 6 | **18** |
| PROC_DISPLAY | 69 | 14 | 8 | **47** |
| PROC_REPRO | 30 | 6 | 6 | **18** |

Across 41 recovered ELF programs, the unresolved unique library names dropped from 89 (recovery-only) to **79** (recovery + ARMEL environment).

Important: this is a *direct SONAME filename inventory*, not a successful dynamic linking test, proof of ABI compatibility, or evidence every one of the 79 libraries is permanently missing from the radio. System libraries and symlink ABI conventions differ from the older Toyota distribution.

## Specific GUI obstacles

- `libEGL.so` (unversioned vendor SONAME) remains unresolved even though Debian provides `libEGL.so.1`; creating a symlink is not proof of ABI compatibility.
- `libGLES_CM.so` and `libOpenVG.so` are not supplied by the installed ARMEL Mesa/EGL packages; these are likely vendor-specific legacy graphics interfaces.
- Remaining Fujitsu Ten dependencies include `libdisplay_if.so`, `libdismng_if.so`, `libipas_std.so`, `libipas_fls.so`, `libipas_pcd.so`, `libipas_trc.so`, `libuie_db.so`, and more.
- GUI initialization may need physical display hardware, graphics drivers, IPC, services, sound and vehicle data.
- A loader-only `LD_TRACE_LOADED_OBJECTS=1` invocation under qemu-arm returned exit code zero but did not produce dependency output; therefore it is **not** evidence that the GUI runs or links successfully.

## Reproduce

```sh
python3 tools/ca01_armel_compatibility.py \
  --recovered ../system-audit/ca01-updater-independent-20261022 \
  --rootfs ../system-audit/gui-emulation/armel-rootfs \
  --output ../system-audit/gui-emulation/NEW-compatibility.json
python3 tools/ca01_verify_armhf.py ../system-audit/gui-emulation/armel-rootfs
```

## Next tasks

1. Recover any still-opaque proprietary libraries from the remaining update sections via the ongoing Codex KWI decoder work.
2. Build a *separate* throwaway ARMEL test root using the recovered libraries (originals unchanged), and use the ARMEL linker diagnostic mode to enumerate missing SONAMEs and symbol versions.
3. Select one non-hardware-dependent ARM executable for carefully sandboxed execution before attempting `PROC_HMI`.
4. For actual GUI rendering, acquire or emulate OpenVG/GLES1 backend and Fujitsu Ten IPC/display services. Do not claim a working GUI until pixels are rendered and verified.

Nothing committed/pushed and no physical radio accessed.
