# CA01 EGL window-to-pbuffer bridge — ARMEL proof of concept

Date: 2026-10-23 (EDT). This independent test stays in `system-audit/`, **outside** the tracked `ca01-development-kit` repository. No Toyota executable is run; no real head unit, API, firmware updater, radio hardware or original binary bytes are modified.

## What actually works

- The original `PROC_HMI` (SHA-256 `cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503`) was read only to extract its display profiles. In the Ghidra-recovered `FUN_0002a548` branch table, the screen configuration contains **six 800x480 records and two 480x480 records**. `FUN_0002b66c` reads the selected record's uint16 fields at offsets `+10` and `+12` for native-window width/height. Actual selection depends on `rq_sys_GetVclPara`; it is not established for the particular radio.
- A real ARM EABI5 **soft-float** executable, running under `qemu-arm` against the installed ARMEL Mesa libraries, initialized EGL 1.4, GLES-CM 1.1, the `softpipe` software renderer, and an off-screen pbuffer. `eglGetProcAddress("glBlendFuncSeparateOES")` returned a function.
- Synthetic GLES1 fixed-function vertex-array geometry renders correctly at **both** derived screen dimensions. `glReadPixels` succeeds and outputs three distinct image frames per run.
- An opt-in ARM ELF `LD_PRELOAD` experiment intercepts calls to `eglChooseConfig` and `eglCreateWindowSurface`. It maps EGL_WINDOW_BIT -> EGL_PBUFFER_BIT, validates the reconstructed 32-byte `{width,height,width,2,3,buffer-array-pointer,...}` descriptor, and calls Mesa's real `eglCreatePbufferSurface`.
- Without the bridge, the same synthetic EGL_WINDOW_BIT request fails to find a configuration (expected exit code 13). With the bridge, the *unchanged synthetic caller* renders three frames **pixel-identical** to the direct pbuffer caller. A malformed window descriptor is rejected (expected exit code 15).
- All automated checks passed for **800x480 and 480x480**, including frame SHA-256 parity, distinct frames, correct output dimensions and non-flat triangle imagery.

## Results

| Configuration | Mesa without interception | Window->pbuffer interception |
| --- | --- | --- |
| Direct pbuffer, 800x480 | 3 frames PASS | Not necessary |
| Synthetic native-window request, 800x480 | Expected no config | 3 frames PASS, pixel-exact |
| Direct pbuffer, 480x480 | 3 frames PASS | Not necessary |
| Synthetic native-window request, 480x480 | Not needed | 3 frames PASS, pixel-exact |
| Malformed window buffer count | Not applicable | Rejected as intended |

Renderer: `Mesa Project`, `softpipe`, `OpenGL ES-CM 1.1 Mesa 22.3.6`. Selected Mesa EGLConfig reported surface mask `0x1` (pbuffer-capable) and GLES renderable mask `0x4d`.

Files:
- `armel_egl_pbuffer_probe.c`: actual ARMEL EGL/GLES1 caller and pixel readback, independent of the Toyota executable
- `egl_window_to_pbuffer_bridge.c`: ARMEL opt-in EGL call interceptor (not a vendor ABI implementation)
- `extract_hmi_display_profiles.py` / `display-profiles.json`: source hash-validated profile extraction
- `run_checks.sh` / `verify_outputs.py`: reproducible build, positive and negative checks, and output validation
- `results/verification.json`: file hashes, dimensions, comparisons
- `results/800x480/synthetic-frame00.png` and `results/480x480/synthetic-frame00.png`: **synthetic diagnostic** previews, not Toyota screen captures
- `results/*/*.log`: actual EGL run/error traces, including expected failures

To rerun from WSL:
```sh
bash /home/starlight/projects/rav4-radio/system-audit/ca01-hmi-egl-bridge-20261023/run_checks.sh
```
Prerequisites already present locally: ARMEL sysroot, ARMEL GCC, `qemu-arm`, Mesa EGL/GLES1, Python 3 + Pillow. No network access or package install is required.

## How this differs from Codex's concurrent GUI adapter

The concurrently developed `ca01-development-kit/src/ca01_gui_egl_bridge.c` is an **explicit pbuffer application layer**: the caller uses its new `ca01_egl_bridge_init` API, then renders and transfers pixels into a separate CPU triple-buffer model.

This experiment is a different **ELF dynamic-linker boundary**: a caller still invokes ordinary `eglChooseConfig(EGL_WINDOW_BIT)` and `eglCreateWindowSurface`, and the ARM ELF interposer substitutes a pbuffer. Those call sites exist directly in the recovered HMI. Neither approach is yet a running original Toyota HMI. No concurrent Codex-owned source files were edited.

## Remaining blockers — do not misinterpret this test

1. **The original HMI has not started.** Codex's separate loader trace still lists **16 unresolved direct SONAMEs** after its authentic Mesa `libGLES_CM.so` alias. They include `libdismng_if.so`, `libdisplay_if.so`, `libipas_std.so`, and `libOpenVG.so`.
2. The EGL interceptor only validates/reads the synthetic 32-byte window shape. It **does not allocate proprietary display-memory descriptors, map the native array of handles, implement `sysDisMng*` functions, or perform real plane flips**. It is not safe to use with arbitrary untrusted window pointers, and handles are not vendor-ABI substitutes.
3. The `fs_sys_CnfEntry` / `SysPowerOn(9)` startup graph loads process, task, IPC, shared memory and other services. Queue `0x28` and message `0x41002` are static evidence, not a fully recovered `rq_msg_*` ABI.
4. Factory `/opt/ftl/gui/MC/`, fonts and `ScreenTrans.mui` resources have not yet been recovered from this firmware; only EN-US, FR-CA and ES-MX language XMLs were validated.
5. Interposing a genuine original HMI would also require verifying its dynamic symbol binding, pointer validity, configuration flags, EGL extension calls, library constructors and multi-context use. Do **not** execute the recovered HMI until these prerequisites have been addressed inside an offline disposable sandbox.

## Recommended next implementation

Use the original ELF and available Ghidra project to recover the argument and data layouts for **`sysDisMngInit`, `sysDisMngMemAlloc`, `sysDisMngPlnDispSw`, `sysDisMngPlnAlpha`, `sysDisMngPlnTrans`**. The HMI allocates three `width*height*4` buffers in 16-byte descriptor slots, passing the values at descriptor offset `+12` to its native-window array. Determine authentic descriptor semantics and callback requirements before integrating the EGL interceptor with a full display-service layer. Continue authentic resource/library recovery in parallel.

**Status:** two factory-sized ARMEL EGL test modes PASS. The original Toyota GUI has not rendered. No Git commit or push was made by this independent investigation.
