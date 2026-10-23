# CA01 ARM HMI compatibility prototype (23 October 2026)

This is a **working diagnostic prototype**, not a replacement head unit and not the
original Toyota GUI. It implements a CPU-side model of specific display and message
interfaces observed in the recovered `PROC_HMI` binary. It runs an ARM32 EABI soft-float
test program under QEMU, inside offline Bubblewrap, using Mesa software EGL/GLES1.

## Recovered-code evidence used

See [Ghidra source-backed findings](CA01_HMI_GHIDRA_FINDINGS.md).

| Recovered code location | Observation | Model behavior |
|---|---|---|
| `PROC_HMI FUN_00016054` | Three `sysDisMngMemAlloc(width * height * 4, ...)` calls | Three independent RGBA8 CPU buffers |
| `FUN_00015f7c` | Returns 3 | Exactly three buffer slots |
| `FUN_0002b66c` | 32-byte native-window object; 8 ARM32 words; width, height, stride, field 2, count 3, buffer-array pointer | 8-word serialized descriptor; 0x31000000 is a synthetic guest address, **not** a host pointer |
| `FUN_0002bb08` | `eglGetDisplay`, `eglInitialize`, `eglChooseConfig`, `eglCreateContext`, **`eglCreateWindowSurface`**, `eglMakeCurrent` | Checks descriptor, then creates a Mesa **pbuffer**, not a native window |
| `FUN_0002b9fc` | `eglSwapBuffers` then display plane-management calls | Copy `glReadPixels` into an RGBA buffer and rotate the model's front buffer |
| `FUN_0002b944` | Calls `eglCreatePbufferSurface` | Evidence the recovered binary already has an off-screen rendering path |
| `FUN_0002b22c` | Receives queue `0x28` messages | Shared pthread HMI queue: 64 slots, four-word/16-byte envelopes |
| `FUN_0002b170` | Dispatches message codes 0 and `0x41002` | Counts those codes; unknown codes remain unknown |

Crucial limitations: the original `rq_msg_*` parameter/payload ABI, message
semantics, native EGL window callbacks, proprietary display drivers and plane/alpha
semantics are not fully recovered. The model never masquerades as the
`sysDisMng*` or `rq_msg_*` vendor libraries. Allocator handles `0xca010001`
through `0xca010003` and guest address `0x31000000` are **synthetic**, not
physical RAM addresses or proprietary ABI values.

## Implementation

- `src/ca01_gui_compat.h`, `.c`: bounded triple-buffer RGBA8 model; stable
  synthetic handles; window descriptor; plane enable and alpha state;
  bottom-up GL frame conversion to top-down RGBA; front/back presentation;
  queue 0x28 and observed message-type counters. No host hardware I/O.
- `src/ca01_gui_egl_bridge.h`, `.c`: validates the recovered 32-byte
  window *shape*, creates a Mesa surfaceless EGL **pbuffer**, draws and reads
  back RGBA pixels. Uses `EGL_PBUFFER_BIT`, **not** `EGL_WINDOW_BIT`.
- `tools/ca01_gui_adapter_demo.c`: our own ARM program, renders a four-quadrant
  diagnostic then two solid-color frames, verifies frame rotation and queue
  events. It is **not** the recovered `PROC_HMI`.
- `tools/build_ca01_gui_adapter.sh`: cross-compiles for ARMEL;
  `tools/run_ca01_gui_adapter.sh`: Bubblewrap/QEMU offline executable with
  a read-only ARMEL rootfs, no network, no capabilities, minimal synthetic
  devices, bounded runtime and a dedicated writable diagnostic output folder.
- `tools/ca01_gui_pixel_validation.py`: validates PPM dimensions and
  expected pixel samples; optional PNG export using Pillow.
- `tests/ca01_gui_compat_native_test.c` and
  `tests/test_ca01_gui_compat.py`: host C model regression test, including
  bounds checking, descriptor validation, top-down/bottom-up conversion,
  three buffer rotations, disabled display plane behavior, bounded queue
  wrap-around/overflow, and observed message types.
- `tools/ca01_hmi_loader_alias_test.py`: stages byte-exact, hash-checked
  recovered ARM binaries into a disposable offline loader-trace sandbox;
  tests a symlink **to real Mesa GLES1**, not a fake or patched Toyota library.
  It never starts `PROC_HMI`.

## Verified ARM test

Commands from the repository root:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
tools/build_ca01_gui_adapter.sh
tools/run_ca01_gui_adapter.sh
```

For the image, use the `DIAGNOSTIC_OUTPUT=...` path printed above:

```sh
python3 tools/ca01_gui_pixel_validation.py \
  /path/to/output-YYYYMMDDTHHMMSSZ/adapter-frame0.ppm \
  --report /path/to/output-YYYYMMDDTHHMMSSZ/pixel-validation.json \
  --png /path/to/output-YYYYMMDDTHHMMSSZ/adapter-frame0.png
```

Actual verified results (2026-10-23 UTC 04:21):

```text
EGL_VENDOR=Mesa Project
GL_RENDERER=softpipe
CA01_SYNTHETIC_ADAPTER_OK frames=3 buffer_count=3 queue=0x28 zero=1 alt=1 other=1
```

The PPM is 800 × 480 pixels, 1,152,015 bytes. The validator
independently checked four sample colors:
upper-left blue, upper-right white, lower-left red, lower-right green.
SHA-256: `31d1e86be3ee064feda143cdaebf0755d4bacb0971f345d607d942698fdc3312`.
All three rendered frames and the queue events are exercised by the ARM
diagnostic; the single PPM records the first diagnostic frame.

Latest successful evidence:
`/home/starlight/projects/rav4-radio/system-audit/ca01-hmi-adapter/output-20261023T042152Z/`

A Windows-accessible preview was saved at:
`C:\Users\fathe\Documents\RAV4-Radio-UI-Test\CA01-synthetic-adapter-800x480.png`.

## Genuine GLES dependency loader-only test

Baseline `PROC_HMI` loader trace still shows 17 missing direct SONAMEs. In a
disposable, read-only vendor copy, the alias

```text
/opt/ftl/lib/libGLES_CM.so -> /usr/lib/arm-linux-gnueabi/libGLESv1_CM.so.1
```

is resolved by the guest ARM loader and reduces the missing count to **16**.
No new missing libraries appeared. The recovered executable was only inspected
through `LD_TRACE_LOADED_OBJECTS=1` and was **not started**. The Mesa library
exports all 55 GLES functions directly imported by the original HMI ELF,
but symbol-name coverage and loader resolution do not prove ABI compatibility,
working constructors, EGL context creation, or a working Toyota interface.
The trace report is outside Git:

`/home/starlight/projects/rav4-radio/system-audit/ca01-hmi-adapter/loader-soname-probe-20261023-0018/comparison.json`

The remaining 16 names are in that JSON, including `libOpenVG.so`,
`libdisplay_if.so`, `libdismng_if.so`, `libipas_std.so`,
`libipas_fls.so`, `libipas_pcd.so`, `libipas_trc.so`, and others.

## Next engineering steps (not accomplished)

1. **Recover or accurately model the proprietary display-management ABI.**
   Its signatures, error codes, allocator descriptors, virtual/physical
   memory mapping and display-plane callbacks must be determined from
   authentic binaries or verified implementation behavior. Do not export
   vendor-sounding no-op functions solely to silence the loader.
2. **Establish an actual native-window bridge** or a carefully scoped
   compatibility intercept using verified ABI and graphics behavior;
   the pbuffer bridge demonstrates rendering but does not let the unchanged
   original HMI automatically create a surface.
3. **Investigate and supply the remaining 16 SONAMEs and system services,**
   including `libOpenVG.so`, IPC/shm/task configuration, font/resources and
   startup tables. The shared `libipas_sysc.so` is recovered; `SysPowerOn(9)`
   depends on numerous system services and is **not** a simple no-op.
4. Only then attempt launching an unmodified original `PROC_HMI` within
   strict sandbox isolation and capture **pixels produced by that program**.
   A synthetic test image is not evidence the factory GUI works.

Nothing in this prototype changes the radio, flashes firmware, bypasses
signatures or pushes Git. Generated ARM binaries, screenshots, recovered
vendor binaries and Linux root filesystems remain outside the repository.

## Startup/IPC contract update

The adapter now links `src/ca01_hmi_ipc.c` and includes its authoritative `Ca01Message` declaration through the compatibility header. Its fourth word is an opaque ARM32 payload token. The Python startup harness uses this same queue through ctypes. See [CA01_HMI_STARTUP_IPC.md](CA01_HMI_STARTUP_IPC.md) for readiness barriers, timeout statuses, ownership and the first unresolved real startup service. Earlier runtime hashes above describe the earlier diagnostic output, not the newly rebuilt adapter.
