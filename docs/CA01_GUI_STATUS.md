# CA01 GUI recovery status — 2026-10-23

Original HMI ARM graphics instructions now produce validated off-screen pixels
under QEMU and ARMEL Mesa. **The factory home/radio/settings menus have not run.**
This is a bounded original rendering slice with fixture inputs, not full
`PROC_HMI` startup. No radio access, firmware modification, commit or push was
performed for this development cycle.

## What now executes

`tools/ca01_original_render.py` builds an ARMEL fixture linked above the original
ELF address range. It verifies the complete canonical HMI SHA-256 before staging
it read-only, maps its original segments privately, and binds explicit imports
to real Mesa or the functional display model. Unknown imports terminate.
Execution runs offline inside Bubblewrap with read-only firmware/rootfs,
minimal devices, and bounded time. No original executable entry point or runtime
constructor list is invoked. Private import/profile bindings are substitutions;
the recovered source file remains unchanged.

| Original HMI address | Executed behavior |
| --- | --- |
| `0x16094` | Reset display descriptors |
| `0x2b66c` | Construct native window from three display descriptors |
| `0x2bb08` | Initialize actual EGL/GLES context and surface; returns success |
| `0x2b170` | Dispatch heartbeat `(0,0,10,0)` from shared 16-byte-message queue |
| `0x1e092c` | Convert packed clear color and issue original GL clear |
| `0x1c4654` | Calculate rectangle vertices |
| `0x1e0640` | Set vertex pointer and execute original GL draw call |
| `0x2b9fc` | Swap, check callback handle, update/wait VRAM, invoke plane controls |
| `0x1602c` | Free the three display descriptors |

The original soft-float helpers used by the clear routine also execute. The
GL draw routine tail-branches into GL; its inherited return address alone is
not evidence of its caller. Evidence includes the canonical ELF hash, explicit
entry invocation, trace, geometry and independently checked framebuffer.
Additional private-memory integrity checks cover **32 bytes at seven selected
entries**, not entire function bodies or every invoked address.

The actual renderer is Mesa `softpipe`, EGL 1.4/OpenGL ES 1.1. Both recovered
profiles, **800×480 and 480×480**, produce three frames through distinct display
buffers. Each complete raster is independently checked for dimensions, RGB
histogram, rectangle bounds and row placement. Frame dimensions change across
iterations, producing different hashes.

The current image is a white rectangle on RGB `(17,34,68)`. Rectangle size,
projection, current color, initial graphics state and profile selection are
fixture inputs. Toyota's original geometry/clear/draw/submission instructions
execute, but **this is not a recovered Toyota menu or factory scene**.

## Integrated compatibility model

The existing C display model now exports the observed 16-byte descriptors,
with distinct handle and memory-token fields at offsets 12 and 4. VRAM begin
and wait operations enforce ownership and pending-buffer state. Original
frame submission copies actual GL readback into the selected modeled buffer.
Plane arguments are checked/logged without inventing hardware semantics.

The callback interposer and simpler bridge share window-shape validation.
The interposer remains a bounded ARM32 test adapter with a synthetic callback,
not a complete Fujitsu Ten driver. The authoritative queue remains the common
C implementation: **64 entries, four 32-bit words, 16 bytes per message**.
The per-iteration dispatcher limit of 16 is separate from capacity.

Readiness is recorded only after original graphics initialization succeeds and
three valid handles/callback exist. Failed second allocation and invalid
callback-handle tests produce no captured frames. Tests also cover malformed
windows, allocation cleanup, token/handle distinction and buffer rotation.
Full system/task readiness barriers remain outside this isolated slice.

## Startup and scene progress

- Default canonical startup still registers 18 configuration pointers in 82
  original instructions, then stops after 40 at `fopen("ipasz.conf","r")`.
  No host services run in this default trace. Configuration and the original
  parent-process/task handshake remain unresolved; no successful boot is claimed.
- The authentic recovered **`libipas_grp.so`** is usable in a bounded trace.
  Its `rq_grp_Init` calls original HMI `pt_grp_Init`, then reaches
  **`rq_tsk_WaitInit(10)`**. The callback's empty body is original code.
  The wait has not been replaced by success. Its system implementation exists,
  but needs actual task/queue startup context.
- The scene probe can execute original `rq_sys_GetTick1ms` using real host
  CLOCK_MONOTONIC data and original ARM millisecond arithmetic. A bounded guest
  memory service implements actual memset. Optional configured semaphores have
  real lock state; a busy lock stops explicitly instead of pretending success.
  This does not implement the full original 30-second timeout/fatal behavior.
- Original scene constructor **`0x4058c`** now reaches
  **`rq_fls_Open("type.txt","r")`** at HMI `0xd4a8`, return address `0x3ecc4`.
  The original reader has an open-failure fallback `"(none)"`; missing `type.txt`
  alone is **not proven fatal**. The authentic file-service implementation is
  still unavailable.
- Running scene update with zero initial scene BSS plus clock/memory/semaphores
  reaches its instruction budget in list/object processing. This artificial
  uninitialized context does not establish a production deadlock. No list
  sentinels or initialization successes were fabricated to bypass it.

The trace engine now distinguishes emulator steps from original instructions
when host services intervene, so exhausting the instruction budget reports the
correct boundary. Host services are explicit opt-ins and record arguments/results.

## Resource recovery and remaining blockers

Original path builders establish `/opt/ftl/gui/MC/mui/<name>` at `0x3e9a0`
and MC container path selection at `0x3e9e8`. The original loading loop
`0x3eaf0` reads ten records at `0x3f23fc`, referencing 13 unique containers:

```text
CmA.mra CmAl.mra CmB.mra CmBa.mra CmC.mra CmD.mra CmE.mra
CmF.mra CmG.mra CmX.mra CmY.mra OnsTrans.mra XMStationLogo.mra
```

There are 534 distinct MUI filename references. The profile-prefix table includes
`1/`, `2/`, `3/`, `4/` and corresponding `_61` variants; the actual vehicle's
region/generation selection remains unknown. MRA container layout has not been
established from real file bytes. Font resources under `/opt/ftl/gui/font/`
and the actual menu/transition assets remain unrecovered.

A fresh filename search of the three existing manufacturer archives scanned
**80,310 entries**, with no matching MRA/MUI/FDL/config/driver filenames. This
search did not inspect nested archive bodies and does not establish absence
from the physical head unit. No new authentic assets were recovered this cycle.

Missing original file/display services include `libipas_fls.so`,
`libdisplay_if.so` and `libdismng_if.so`; `libOpenVG.so` and other direct loader
dependencies also remain. The primitive slice does not solve full dynamic
linking, constructors, process/task startup or factory asset loading.

The next concrete integration target is the genuine display-task-10 readiness
path and file-service startup after a legitimate `ipasz.conf`/parent-process
context is available. Recovering MC/font resources from a legitimate complete
filesystem or compatible firmware remains essential for original menu scenes.
Current archive contents cannot supply those missing files by renaming libraries.

## Reproduce locally

From the development repository (existing ARMEL rootfs and test dependencies):

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
.venv/bin/python tools/ca01_original_render.py --width 800 --output /absolute/new/external/render-800
.venv/bin/python tools/ca01_original_render.py --width 480 --output /absolute/new/external/render-480
bash tools/run_ca01_display_audit.sh /absolute/new/external/display-audit
.venv/bin/python tools/ca01_scene_boundary.py \
  --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \
  --system-library ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
  --group-library ../system-audit/ca01-updater-independent-20261022/06-libipas_grp.so \
  --provide-clock --configured-semaphores --output /absolute/new/scene-boundary.json
```

Native rendering requires user namespaces/Bubblewrap permissions. Negative
modes `--mode alloc-fail` and `--mode invalid-callback` intentionally exit 2.
The scene command records a blocked slice, not completed application startup.

Verified this cycle: **125 tests passed**, both native rendering profiles passed,
and the prior independent display audit passed (59 recovered file hashes,
seven false embedded-asset candidates, callback/negative tests at both sizes).
An independent code review found no actionable blocker; its child sandbox could
not rerun native rendering because NETLINK_ROUTE setup was denied. The parent
sandbox's complete 125-test run included successful native rendering tests.
Existing installed tools were sufficient; no installation was necessary.

## Evidence and Git state

- Tracked summaries: `evidence/ca01-original-rendering.json`,
  `evidence/ca01-scene-resource-boundaries.json`.
- Local raw evidence, traces, builds and framebuffers:
  `/home/starlight/projects/rav4-radio/system-audit/ca01-original-gui-progress-20261023/`.
- Frame previews: `render-800/original-hmi-primitive-fixture.png` and
  `render-480/original-hmi-primitive-fixture.png`, explicitly fixture-driven.
- Original HMI SHA-256:
  `cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503`.
- Branch `main`, starting HEAD `2f1c1fbeeade99bc84b231df84b3f6884d8f0322`.
  Changes remain local and uncommitted for review. No remote push authorized
  for this cycle. Original firmware/archives and runtime artifacts remain outside Git.

Earlier reports are dated observations; this document supersedes their claims
that no original GL drawing instructions/pixels have executed. Their conclusion
that the full factory interface has not run remains accurate.
