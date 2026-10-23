# CA01 HMI integration handoff — 2026-10-23

## Scope
This is a coordination note for two independent lines of research. It lives **outside** `ca01-development-kit`; no tracked repository files were changed by this note. No original Toyota binary has been launched or produced pixels. No firmware has been flashed or Git pushed by the graphics investigation.

## Current verified baselines
- Startup: `ca01-development-kit/docs/CA01_HMI_STARTUP_IPC.md`, `tools/ca01_hmi_startup.py`, `evidence/ca01-hmi-startup-contracts.json`. The startup team's reported suite was **93 passing tests** (18 startup-focused); this handoff does not rerun that suite.
- Graphics: `system-audit/ca01-hmi-egl-bridge-20261023/BRIDGE_FINDINGS.md`, ARMEL `libca01_egl_bridge.so`, and two synthetic modes (800x480, 480x480) verified pixel-for-pixel. This is **not** original Toyota rendering.
- Original HMI: `system-audit/ca01-updater-independent-20261022/06-PROC_HMI`, SHA-256 `cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503`. Only use verified read-only copies in separate sandboxes.

## Important model incompatibility found by direct inspection
- `ca01-development-kit/src/ca01_gui_compat.h` currently has `CA01_QUEUE_CAPACITY = 16` for queue id `0x28`. The recovered config establishes **64 slots** (each 16 bytes). The `16` in `HmiHarness.step` is **maximum dispatches per batch**, not queue capacity.
- The same C header defines `Ca01Message` as **three** `uint32_t` fields (12 bytes). Actual queued messages are **four** 32-bit words: code, subcommand, event/value, optional payload pointer (16 bytes). See `tools/ca01_hmi_startup.py:Message`.
- The current C `ca01_queue_receive` returns generic `CA01_OK=0` upon dequeue; actual `rq_msg_ReceiveP` returns **-1** on success, **-2** when empty, while `rq_msg_ReceiveT` returns **0** on success, **-1** on normal timeout. Host-model APIs need not mimic these statuses, but ARM boundary adapters MUST translate faithfully.
- The C graphics queue lacks the actual payload-ownership/free semantics. Do not drop the payload field or free on successful dequeue; release after dispatch via `rq_mem_Free(1,payload)`, per verified ARM call boundary. Failed SendT timeout leaves ownership with sender.

## Codex-owned startup/IPC next milestone
- Preserve the verified task topology: startup -> task 0x27 graphics initialization -> `rq_flg_Set(2,1)` -> task 0x28 waits on flag2/1, then uses queue0x28 (64 x 16) and 500ms timed receive with max16 dispatches per drawing iteration.
- Trace `ipasz.conf` parser preconditions (do not fabricate a config), parent 8-byte synchronization handshake, `tsk_sys_System` activation, and `rq_ipc_*` external POSIX queue provenance. Distinguish `rq_msg_*` local ring from POSIX IPC.
- Make **one canonical queue/message contract**, deprecating or adapting the incompatible C model in a reviewed change. Tests should assert message size16, queue capacity64, ready flag gating, timeout heartbeat `(0,0,10,0)`, draw flag update, max16 batch, and correct ownership on success/failure.
- Do **not** implement a no-op `SysPowerOn` or signal ready before real graphics readiness. Deliver: exact startup service dependency matrix; a bounded ARM service test/trace or precise blocker evidence, not a claimed Toyota splash screen.

## Independent ChatGPT graphics/recovery next milestone
- Recover calling contracts and descriptor layout for `sysDisMngInit`, `sysDisMngMemAlloc`, `sysDisMngMemFree`, `sysDisMngPlnDispSw`, `sysDisMngPlnAlpha`, `sysDisMngPlnTrans` using original HMI assembly and authentic available libraries only. Source Ghidra evidence includes `FUN_00016054`, `FUN_00015f18`, `FUN_00015f84`, `FUN_0002b66c`, `FUN_0002b9fc`. Three allocation descriptors occupy 16-byte slots and each allocation requests width*height*4; the original passes word at descriptor offset+12 as a handle. Actual semantics remain unknown.
- Explore genuine assets under `/opt/ftl/gui/MC/`, `/opt/ftl/gui/font/`, and `ScreenTrans.mui` from recovered firmware/related images. Record verified provenance; do not treat language XMLs or OSS alternatives as original graphical assets.
- Extend the proven ARMEL EGL interception prototype only with tests for buffer/plane mapping and error propagation; do not export vendor-looking placeholder functions without a verified ABI. Maintain independent experiments under `system-audit`.

## Integration gate
Only join branches/components after both teams can demonstrate: (a) graphics service success explicitly raises readiness, (b) draw task receives one legitimate 16-byte timeout/command event, (c) EGL surface initialization and subsequent swap/capture have byte-exact or independently validated pixel evidence, and (d) all unresolved services are logged instead of faked. Only Codex performs any intended Git commit/push after reviewing concurrent changes. No head-unit update or firmware flash.

## Main priority
A **real HMI-owned rendered frame**, not a redesigned mockup or more self-authored triangles. If full startup remains blocked, a strictly sandboxed, clearly labeled slice of original HMI draw code is a useful independent research milestone, provided its required assets/services are validated and all provenance is retained.
