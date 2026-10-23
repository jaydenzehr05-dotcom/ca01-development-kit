# CA01 controlled startup and IPC integration

## Outcome and scope

The C GUI adapter and Python startup harness now share one native queue implementation, `src/ca01_hmi_ipc.c`, and one authoritative envelope declaration, `src/ca01_hmi_ipc.h`. The previous C adapter had a 12-byte envelope and 16 slots; both were incompatible with the recovered HMI profile. The shared implementation has four unsigned 32-bit words and 64 slots. Python binds that C queue through ctypes; it no longer maintains a second ring.

This is a self-authored ARM-compatible research service subset, **not a drop-in vendor library or a successful original HMI startup**. No dummy libraries or vendor symbol stubs are supplied. The original firmware remains unchanged. Startup transitions in `StartupSequence` are explicitly synthetic event inputs, separate from execution of original ARM instructions in the bounded trace tool.

## Real startup boundary

Hash-verified HMI main calls `fs_sys_CnfEntry(0x59f948)` followed by `SysPowerOn(9)`. The bounded tracer maps the original HMI and system-library ELF segments into Unicorn, applies supported ARM relocations, executes registration, and then executes `SysPowerOn`. It stops at the first unresolved imported operation rather than returning invented success. It never forwards guest OS calls to the host. Unexpected syscalls, unmapped operations, unsupported relocation forms and instruction exhaustion stop the run.

The first filesystem requirement is `fopen("ipasz.conf", "r")`, from system-library `fc_cnf_Init`, ELF 0xc89c. The path is relative to the original launch directory, which has not been recovered. The file is absent from the 59 complete recovered entries and the previously inspected top-level source filename manifests; that does not establish absence from every unrecovered region. Static failure handling is `fs_cnf_Load` -> `fc_cnf_ErrEnd` -> diagnostic and `exit(1)`. The controlled execution stops before providing a FILE pointer; it does not claim to have exercised successful configuration loading.

Subsequent genuine prerequisites include common shared-memory management, process registration, inherited synchronization eventfds, configured POSIX IPC/PSM/shared-memory objects, system-task startup, post-init callbacks and display initialization. Their presence and success are not fabricated to get past this boundary.

## Recovered ipasz.conf parser requirements

See `evidence/ca01-ipasz-parser-sync.json` for individual field offsets and canonical ELF addresses; full decompilation and instructions are preserved outside Git.

- `fgets(buffer,128,file)` reads at most 127 bytes per call. Only lines whose first byte is `#`, NUL or LF are skipped; leading whitespace is not trimmed before section/count detection.
- Section recognition tests prefixes, not full names: `[PR` -> process mode0; `[I` -> IPC mode1; `[PS` -> PSM mode2; `[S` -> shared-memory mode3. Full section spelling/closing brackets are not validated.
- After a section transition the parser seeks a line beginning `n`, using `atoi(line+4)&255`. Value255 continues the search. The count gates allocation but does not determine table size or validate row count.
- Token delimiters are exactly space, comma, LF and CR. Tab and `=` are not delimiters. Field recognition uses first characters and fixed offsets rather than full keyword comparisons.
- Tables allocate PRC32 x64 bytes, IPC32 x40 bytes, PSM64 x32 bytes and SHM64 x12 bytes. Records are appended sequentially, not indexed by the parsed ID.
- The original loaders lack robust row/name bounds and use unbounded string copies. The recovered schema is an analysis description, not a recommendation to execute malformed configuration.

Actual names, enabled rows, numeric values, process IDs and synchronization token remain missing. We have not generated an invented `ipasz.conf` or claimed newer vendor-source configuration is compatible.

## Parent synchronization: three eventfds, two different checks

`rq_prc_Create` at ELF0x25770 creates inherited eventfds in shared descriptor block0:

| Channel | Shared offset for process id | Constructor | Role |
|---|---|---|---|
|P|0x80 +4*id|`eventfd(0,0)`|Child notifies parent|
|C|0x100 +4*id|`eventfd(0,0)`|Blocking child startup barrier|
|R|0x180 +4*id|`eventfd(0,0x800)`|Nonblocking restart check|

`fc_sys_AccStart` (ELF0xad50) reads eight bytes once from R. A token match selects startup mode2; mismatch or an absent nonblocking token selects mode1. It then creates/starts system task1 and joins it. This read is not a blocking pipe handshake.

`SysSynWait` (ELF0xbb44) and `SycSynWait` (0x216b4) write their own process ID as a sign-extended 64-bit value to P, then read C until the expected token appears. Eventfds return accumulated counters, not independent pipe packets. The barrier applies when the current parsed process record's +8 flag is1 and startup mode is not2.

**The expected token is the signed 32-bit value at `*tb_sys_PrcInf +0x44`, sign-extended to 64 bits: PRC record1 field+4. It is not `bf_sys_CnfSetup +0x44`.** The GOT relocation at ELF0x318bc resolves this distinction. Its actual value depends on the missing configuration.

`rq_prc_Start` forks/execs the configured process; these eventfds have no CLOEXEC flag. Copying shared FD integers alone cannot reconstruct the underlying inherited kernel objects. Separately `rq_ipc_Create` calls `mq_open(name,O_RDWR)`, without O_CREAT. The actual queue creator is not established by the inspected system library.

## Exact activation and readiness conditions

The canonical HMI has enabled tasks1,3,10,39,40,41. Task records are48 bytes; the second word is a task type, not a proven priority. Task39 is type3, task40 type5. The following sequence is recovered static control flow, not evidence that these runtime events completed:

1. Task1 runs `SysPreInit` (ELF0xbc78), `SysSynInit` (0xbbdc), then `SysInit` (0xb994). `SysResInit` (0x24020) creates enabled tasks, assigns tasks39/40 an effective power mask1, and leaves them at state1. Creation does not start them.
2. `SysInit` starts enabled types4/7/8. It starts task3/type8; neither task39/type3 nor task40/type5 starts here.
3. `SysChk` (0xb7b4) derives effective mask bit1 from `GetAcc()==1`. If the mask changes, `SysOnCtl` (0x23bcc) requires both a changed bit in the task mask and a currently active effective mask.
4. State1 then enters `AccOnStop` (0x22bdc), which starts types1..6/8 and writes state2. This is the shared activation path for tasks39 and40. `AccOnInitAct` handles type7 and does not start either one.
5. An observed source of software ACC control is queue1 type10: `RcvPrcCtl` (0xb960) sets ACC1 for value0 and ACC0 otherwise. Restart mode2 can also set ACC1. The actual external producer and ordering remain unknown; we do not infer a physical ignition state.
6. `rq_sys_NtyTskSts(0)` (0x1e02c) sends `[0,3,self,0]` to queue1. In startup modes1/2, non-task3 callers wait for flag1/value1. `RcvTskCond` -> `TskCondActInit` marks state3 and releases registered task initialization waiters.
7. For modes1/2, all enabled tasks2 onward must reach state3 before `SycSynInit` (0x2174c). Applicable parent synchronization and configured post-init callbacks precede **flag1/value1**.
8. HMI task39 at0x2b5b8 proceeds through its initialization and only then sets **flag2/value1**. Task40 at0x2b22c waits for flag2 before its draw/message loop. Flag1 and flag2 are different barriers.

The host `StartupSequence` models only the initial effective-power ON path. Repeated ON inputs do not start duplicates; unsupported power-off/restart transitions fail explicitly. Required synchronization/post-init and display callbacks must return literal True; missing or failed service implementations cannot become readiness. These explicit fixture callbacks are not original services.

## Message ABI, scheduling and payload ownership

| Word | Offset | Meaning |
|---|---|---|
|0|0|code/class|
|1|4|family-specific subcommand|
|2|8|event/value|
|3|12|opaque owned guest payload address/token|

Compile-time layout checks and host/ARM tests enforce size16 and offsets. The envelope contains an ARM32 payload token even in a 64-bit host process; it is never cast to a host pointer. Queue0x28 has64 entries. Other recovered local queue capacities are1:64,10:16,41:16. The new C subset implements only the HMI queue; it does not implement the separate POSIX IPC namespace or duplicate the proprietary 0x88-byte queue-descriptor layout.

| Operation | Success | Empty / normal timeout |
|---|---:|---:|
|ReceiveP|−1|−2|
|ReceiveT|0|−1|

The C runtime uses pthread mutexes/conditions and bounded timed waits. Normal failed receive leaves all output bytes unchanged. Failed send retains caller ownership; dequeue does not free payload. Invalid vendor queue/deletion/fatal cleanup paths remain unsupported, not silently declared compatible. The GUI fixture's normalized result wrappers delegate to this same ring.

The HMI dispatcher frees nonzero payloads **after** handling via `rq_mem_Free(1,payload)`. The host harness requires a release callback and preserves ordering. Cleanup during Python callback exceptions is explicit harness policy, not a claimed original C exception behavior.

Task40's initial wait is500ms; after a timeout it dispatches `(0,0,10,0)`, then drains up to15 ReceiveP envelopes. The batch bound is16. The existing original-ARM dispatcher probe verified that this heartbeat sets byte0x26c98a2 through0x2a9c0. Frame-update0x2b1f8 checks that byte, clears it before drawing callees, and otherwise returns. The model now connects the same heartbeat to `draw_pending` and refuses queue consumption or drawing before task39's readiness. A callback is a downstream draw boundary, not proof of a Toyota screen.

## Reproduce verification

Build the native queue explicitly (outside the tracked source tree), then inspect/replay into a new report path:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -pthread -Isrc \
 src/ca01_hmi_ipc.c -o /tmp/libca01_hmi_ipc.so
.venv/bin/python tools/ca01_hmi_startup.py \
 --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \
 --system-library ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
 --runtime-library /tmp/libca01_hmi_ipc.so --synthetic-replay \
 --output /tmp/NEW-controlled-startup.json
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Run the separate original-code boundary tracer into another new report path:

```sh
.venv/bin/python tools/ca01_startup_trace.py \
 --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \
 --sysc ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
 --output /tmp/NEW-original-startup-boundary.json
```

Exit status2 is deliberate: a blocked startup is not a successful application launch. The verified run returned from registration after82 original ARM instructions, registered18 pointers, then executed40 startup instructions before trapping the unresolved `fopen("ipasz.conf","r")` import. Its return address is biased0x1000c8f8, canonical system-library0xc8f8.

The complete integrated suite passed **110 tests, zero failures and zero skips**, including25 startup/queue tests and10 bounded-trace tests. A separately cross-compiled ARMEL fixture passed under offline Bubblewrap/QEMU, including16-byte layout,64-slot FIFO, opaque payload preservation and receive timeout status. The rebuilt existing EGL bridge fixture also passed three synthetic Mesa/softpipe frames. Independent review found no remaining actionable issue. These checks establish the research subset and the first blocker; they do not establish successful original-service startup.

The replay intentionally supplies successful **synthetic** service events and reports no original application or pixels. The separate bounded trace is the evidence for the first real startup operation that remains unresolved. Do not confuse those outputs.

Artifacts, raw parser/activation evidence, native binaries, queue/replay reports and test logs are stored in `../system-audit/ca01-startup-integration-20261023/`. Prior real dispatcher probes remain in `../system-audit/ca01-hmi-startup-20261023/`. Addresses in this document are canonical ELF virtual addresses; shared-library Ghidra listings use image base0x10000 and require subtracting that base.

Remaining blockers: original ipasz.conf values and launch context, actual inherited parent services, configured queue/object creators, system/display initialization callbacks, and the still-missing proprietary dependencies in the broader loader inventory. No first Toyota screen or complete graphics-ready original startup is claimed. The source and small evidence reports are consolidated into the existing repository; firmware and generated runtime artifacts remain outside Git.
