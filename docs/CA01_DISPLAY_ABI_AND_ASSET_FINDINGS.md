> Consolidation note: this report records the independent 2026-10-23 investigation below. Its source scripts are now tracked under `tools/display_audit/`, with source hashes and integration edits in `evidence/ca01-display-audit-provenance.json`. Historical statements about the separate directory and no Git operations describe that investigation. To reproduce the consolidated version without overwriting its original evidence, run `bash tools/run_ca01_display_audit.sh` from the repository. This builds its earlier bridge as a negative control, compares fresh direct-pbuffer frames, and runs ARM fixtures in offline Bubblewrap. The existing startup work remains fail-closed at the missing configuration boundary; the next runtime integration milestone is still pending.

Historical audit. Later original primitive rendering and startup progress are recorded in [current GUI status](CA01_GUI_STATUS.md). The full factory interface remains unresolved.

# Toyota CA01 original-HMI display ABI investigation — 2026-10-23

**Status:** New original-ARM slices executed under Unicorn, synthetic ARMEL EGL bridge extended with a window callback, and authentic recovered resource inventory audited. **The complete original Toyota application has not launched, and no factory screen has rendered.**

**Provenance:** Original CA01 HMI `06-PROC_HMI`, SHA-256 `cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503`. `system-audit/ca01-updater-independent-20261022/06-PROC_HMI`. Original data mapped read-only into emulation; no ELF modifications, firmware flashes, car connection, Git commit, or push. All tests/models live in this **separate `system-audit` directory**, not in Codex's active checkout.

## 1. Bounded runs of ORIGINAL HMI ARM functions

`probe_original_window.py` uses hash-checked ELF PT_LOAD segments and Unicorn ARM32; only imported `sysDisMngMemAlloc` / `malloc` and the `rq_sys_GetVclPara` profile selector are simulated. Original code executes with bounded instruction and wall-time limits.

- `FUN_0002b66c`: the actual original HMI builds a **32-byte native window**, requests three allocations from `FUN_00016054`, and loads the handles from each **16-byte descriptor at offset +12** through `FUN_00015f18`.
- The original constructor's first six 32-bit words equal `[width, height, width, 2, 3, &handle_array]`. Width/height come from original valid table records. Six profiles are 800x480 and two are 480x480; which is selected in the actual vehicle remains unknown.
- At **800x480**, original ARM requests **1,536,000 bytes per buffer**. At **480x480**, original ARM requests **921,600 bytes per buffer**. The three destination descriptor addresses are `0x01A24BB8`, `0x01A24BC8`, `0x01A24BD8`.
- Original code allocates a 32-byte window with `malloc`, then **does not initialize words six and seven**. This was proven with a nonzero `0xA5` sentinel in synthetic malloc memory. Offset **`+0x1C` (word seven)** must be initialized by a separate native-window implementation before original `FUN_0002b9fc` can call it safely.
- Injecting a failed `malloc` causes the original window constructor to return NULL, as expected.
- **New negative finding:** injecting a failed *display-memory allocation* (one `sysDisMngMemAlloc` returns `-1` and no handle) **does not make the original constructor abort**; it still returns a window object containing a zero handle. That is original branch behavior under this injection, **not a claim about the proprietary allocator's ordinary error status**. Our adapter must reject invalid handles.

`FUN_00015f84` was separately run as real ARM instructions with intercepted external calls; their actual register arguments were:

| Original imported API | Observed arguments |
|---|---|
| `sysDisMngPlnDispSw` | `(0)` |
| `sysDisMngPlnAlpha` | `(0, 255, 1)` |
| `sysDisMngPlnTrans` | `(0, 0, 0x00ff00ff)` |

Numeric arguments are verified; hardware mode/colour semantics are not inferred.

## 2. Bounded original frame-submission run — callback contract recovered

`probe_original_frame_path.py` executes original HMI `FUN_0002b9fc`, `FUN_00015f34`, `FUN_00015fb8`, and `FUN_00015f84` with explicit synthetic boundaries for EGL, display APIs, native callback, and profile lookup.

Confirmed sequence:

1. Original HMI calls `eglSwapBuffers`, then its EGL error checker.
2. If the checker succeeds and the window exists, it calls `(*(window+0x1c))(window)`.
3. **The callback's returned 32-bit value is matched to one of the three descriptor fields at offset +12** by original `FUN_00015f34`. On a match, the routine reads the **descriptor word at offset +4**; it returns 0 on unknown handles.
4. If that descriptor word is nonzero, original `FUN_00015fb8` calls `sysDisMngPlnUpdateVram` with ARM register arguments `(0, 0, &(width,height), &(0,0))` and stack arguments `(&(0,0), &(width,height), descriptor_word_plus4)`. The original then calls `sysDisMngPlnWaitDispVram(0, descriptor_word_plus4)`.
5. It then makes the three plane-control calls shown above.

Unicorn verified **three valid synthetic handles**, an **unknown handle** (no VRAM update), and a failed EGL-check branch (returns zero). Under an unknown callback handle the original routine returns success without VRAM update, so the compatibility layer must catch and log this condition rather than assuming a frame reached the display.

This is new evidence for the correct **callback → handle lookup → VRAM mapping** interface. It does NOT recover how the genuine EGL/vendor library creates the callback, allocates or maps physical buffers, transfers ownership, or performs panel flips.

See `unicorn-original-window.json` and `unicorn-original-frame.json` for exact measured registers, stack rectangle fields, native addresses, branch cases and limitations.

## 3. Tested ARMEL window callback bridge v2

`egl_window_to_pbuffer_bridge_v2.c` is an explicitly opted-in `LD_PRELOAD` test interposer that:
- Rewrites EGL config `EGL_WINDOW_BIT` to Mesa pbuffer compatibility.
- Validates the synthetic original-shaped native window and **three distinct nonzero handles**.
- Creates a real ARMEL Mesa EGL pbuffer, stores synthetic window state, and writes an ARM function pointer to `window[7]` (offset `+0x1C`).
- Returns sequential synthetic handles through the HMI-shaped callback, wraps after three, and deregisters on `eglDestroySurface`. This is a **new test-only callback**, not the genuine Fujitsu Ten function or a production thread-safe driver.

`armel_callback_probe.c` compiles for ARM EABI5 soft-float, runs via QEMU against ARMEL Mesa GLES1 and checks both recovered screen sizes. Both **800x480** and **480x480** pass on the `softpipe` software renderer, with pixel-exact parity against independently validated v1 pbuffer frames.

Negative regression checks also pass:
- v1 successfully creates a pbuffer but has **no callback at +0x1C**, so the new caller explicitly fails (exit 23).
- v2 **rejects malformed window buffer counts** (exit 15).

Run `bash run_callback_checks.sh` from this directory to regenerate the validated output under `results/`.

## 4. Graphical resources — complete-file inventory

`audit_gui_assets.py` independently checked SHA-256 for **all 59 recovered complete CA01 files**: no mismatches.

Exactly **three distinct GUI resource paths** exist among the six complete recovered GUI entries, all under `./opt/ftl/gui/allwords/`:
- `13UP_EN-US-NA_DA-Base_FormatA.xml`
- `13UP_FR-CA_DA-Base_FormatA.xml`
- `13UP_ES-MX_DA-Base_FormatA.xml`

The recovered HMI refers to `/opt/ftl/gui/MC/`, `/opt/ftl/gui/font/`, `ScreenTrans.mui`, and `allwords_na.xml` but no matching actual complete resource files have been recovered. Some strings may represent filenames expected on a factory root filesystem rather than update package contents. **The incomplete recovery cannot establish that these files are absent from the real radio.**

Additional source *archive filenames* inspected (not treated as compatible binaries):
- DENSO TEN 2017 OSS ZIP: 95 entries
- older OSS source TGZ: 44,362 entries
- LE2355 TGZ: 35,853 entries

No archive path matched the specific target proprietary GUI resources or two missing display libraries. This does **not** rule out files hidden in nested payloads or future firmware images.

`validate_embedded_asset_signatures.py` rejected seven PNG/GIF/JPEG/OpenType-like magic sequences in the HMI because the required format headers are invalid. They are constants/version data, **not verified extractable icons or fonts**. See `embedded-magic-validation.json`.

## 5. Remaining blockers and next integration

- **Missing authentic `libdismng_if.so`, `libdisplay_if.so` and several other original HMI shared libraries**, including `libOpenVG.so` in the ELF dependency list. No claim that missing libraries can be replaced solely by matching symbol names.
- **Missing factory GUI MC, font, and transition assets** in the complete recovered entries.
- **Incomplete startup** (`ipasz.conf`, process supervision, parent handshake, task 0x27 -> 0x28 ready flag, message/IPC requirements) is being worked separately by Codex. This graphics investigation intentionally did not modify Codex's working tree.
- The real native-window callback might do more than return a handle; only the original caller's observed contract has been verified. The v2 callback is synthetic.
- **No original Toyota pixels**: the ARMEL probe renders self-authored geometry. Unicorn executes original non-GL window/swap/plane functions with external EGL and display services intercepted; the actual Toyota GUI scene graph, texture/font loading and GLES drawing code are not yet running in an original HMI process.

For the next realistic original-menu milestone, use authentic vendor firmware images or a legally obtained matching factory-system image to recover the missing display drivers and `MC/` resources. Then verify their exported ARMEL ABI and native EGL/window callbacks in an isolated offline sandbox. Only after configuration, IPC, window callbacks and assets are resolved should any unmodified full `PROC_HMI` runtime be attempted. Do not create hollow placeholder `SysPowerOn`/display libraries merely to satisfy a loader trace.

## Files and reproducibility

Run all local checks without modifying originals or Git:
```bash
bash /home/starlight/projects/rav4-radio/system-audit/ca01-hmi-display-abi-20261023/run_all_audit.sh
```

Source:
- `probe_original_window.py`: bound original HMI window + plane routines; startup/config/imports synthetic
- `probe_original_frame_path.py`: original HMI frame submission call sequence through VRAM and plane paths
- `egl_window_to_pbuffer_bridge_v2.c` / `armel_callback_probe.c` / `run_callback_checks.sh`
- `audit_gui_assets.py` / `validate_embedded_asset_signatures.py`

Evidence:
- `unicorn-original-window.json`, `unicorn-original-frame.json`
- `asset-inventory.json`, `embedded-magic-validation.json`
- `results/original-arm-*.log`, `results/callback-checks.log`, `results/*/v2.log`, `results/bridge-v2-sha256.txt`

**All new work is local and uncommitted. No Git push, Toyota head-unit connection, or firmware flash.**
