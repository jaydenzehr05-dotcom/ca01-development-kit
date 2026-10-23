# CA01 local loader and graphics verification

This pass establishes a working, offline ARM library-inspection environment and an independently tested 800 x 480 software graphics path. It does **not** start the stock Toyota UI or emulate the entire radio.

## Verified outcomes

- All 59 preserved recovered files were rechecked against their recorded sizes and SHA-256 hashes. No source file or original firmware was modified.
- 41 complete ARM ELF files were copied into a disposable layout using their original `/opt/ftl/...` paths. Only the copies of executables received execute permissions.
- The ARM dynamic loader now produces real dependency reports for `PROC_HMI`, `PROC_DISPLAY` and `PROC_REPRO`.
- A self-authored ARM constructor/main guard verified that `LD_TRACE_LOADED_OBJECTS=1` skips both constructors and main; the same guard runs both in normal execution.
- A GCC-built ARM program initialized Mesa EGL 1.4 and OpenGL ES-CM 1.1, using the `softpipe` software renderer. It produced an actual 800 x 480 image. All 384,000 pixels matched the expected four-quadrant pattern.
- The initial main-checkout suite passed 38 tests. After integration with the research suite and four interpreter-validation regressions, the combined suite passes **71 tests** (18 sandbox tests).

## Actual loader observations

| Target | Distinct library names resolved | Distinct library names not found |
| --- | ---: | ---: |
| `PROC_HMI` | 15 | 17 |
| `PROC_DISPLAY` | 22 | 47 |
| `PROC_REPRO` | 13 | 18 |

These counts include dependencies observed through currently loadable libraries. They are not counts of original source files or an exhaustive installed-radio inventory. Resolving a filename does not prove all symbol versions, graphics interfaces, runtime services, or hardware interactions are compatible. A zero return code in linker trace mode does not mean the application can run.

The HMI missing-name list is:

```text
libGLES_CM.so
libLMMDB_IF.so
libOpenVG.so
libVRS_IF.so
libadi_ct.so
libcva_db.so
libdismng_if.so
libdisplay_if.so
libgpo_ct.so
libipas_fls.so
libipas_pcd.so
libipas_std.so
libipas_trc.so
libmem_ct.so
libmir_if.so
libspc_if.so
libuie_db.so
```

Debian's real `libEGL.so` now resolves. The tested GLES implementation is named `libGLESv1_CM.so.1`; it has **not** been silently renamed or substituted for Toyota's `libGLES_CM.so`. No empty placeholder libraries, invented success-returning functions, or security-library substitutes were created.

## Why the earlier loader attempt was silent

The recovered executable files intentionally lacked execute bits. QEMU rejected them with actual exit code 1 before producing a loader report. Earlier nested-shell exit reporting had obscured that failure. The corrected runner captures process results directly and rejects an empty diagnostic even when exit code is zero.

A separate mapping failure occurred at guest address `0x8000`: the host rejected the low mapping. The working command uses QEMU's `-B 0x100000000` host-address translation without lowering the host's `mmap_min_addr`. It lets QEMU load the target interpreter normally, rather than manually running ld.so at a conflicting placement.

## Isolation

`tools/ca01_loader_sandbox.py` uses Bubblewrap with all namespaces unshared, a read-only ARMEL root, a read-only vendor copy, a minimal device directory, an empty environment, no capabilities, temporary `/tmp`, bounded CPU/output/wall time, and core dumps disabled. It exposes no host home directory, vehicle devices, host GPU, display socket, or host network. It only supports loader-trace mode for the three named targets. Every executable and approved target must declare exactly `/lib/ld-linux.so.3` in a bounded, validated PT_INTERP record; static/custom-loader targets are rejected before any staging or execution.

No actual Toyota application main routine, updater, flash-writing tool, or recovered hardware-control service was run.

## Tools and packages used

Existing tools: QEMU 8.2.2, Bubblewrap 0.9.0, readelf, strace, patchelf and elfutils.

Added in the isolated Debian ARMEL root: `libegl-dev`, `libgles-dev`, `mesa-utils-bin`, and their package dependencies. Added to WSL: `gcc-arm-linux-gnueabi` and `libc6-dev-armel-cross` for a verified graphics diagnostic build.

The first Zig-built graphics diagnostic crashed during startup. A distribution-built EGL diagnostic initialized the off-screen renderer, and the same test C source compiled with GCC rendered successfully. The exact Zig startup failure was not resolved; it is not used for the successful graphics result. EGLInfo also reported expected unavailable X11/Wayland/GBM platforms; only the surfaceless software path was validated.

## Local files

New project files:

- `tools/ca01_loader_sandbox.py`
- `tests/test_loader_sandbox.py`
- `tools/ca01_arm_graphics_smoke.c`
- `evidence/ca01-local-loader-and-graphics.json`
- `docs/CA01_ARM_LOADER_AND_GRAPHICS.md`

Detailed logs and disposable copies are outside Git under:

```text
../system-audit/gui-emulation/verified-loader-20261022/
../system-audit/gui-emulation/loader-check-20261022T232304/
```

The successful graphics build, runtime command, raw image, and pixel checks are in the latter directory's `graphics-smoke-gcc/` subdirectory. The displayable PNG is:

```text
C:\Users\fathe\Documents\RAV4-Radio-UI-Test\ARM-graphics-test-800x480.png
```

It is a diagnostic pattern, not a screenshot of Toyota software.

## Reproduce dependency inspection

From the development-kit checkout, choose a new output directory:

```sh
python3 tools/ca01_loader_sandbox.py \
  --manifest ../system-audit/ca01-updater-independent-20261022/recovery-manifest.json \
  --rootfs ../system-audit/gui-emulation/armel-rootfs \
  --output ../system-audit/gui-emulation/NEW-loader-run
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

The next blockers are the missing vendor services/libraries and legacy OpenVG/GLES interfaces. The working software renderer provides a test baseline, not proof that it can directly replace the radio's graphics stack. Both efforts are integrated into local main; see [consolidation verification](CA01_LOCAL_CONSOLIDATION.md). No Git push or physical-radio access occurred.
