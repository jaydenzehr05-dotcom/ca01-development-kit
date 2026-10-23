from pathlib import Path
import json,hashlib
repo=Path('/home/starlight/projects/rav4-radio/ca01-development-kit');scratch=Path('/tmp/ca01-hmi-startup-20261023')
profile=json.loads((scratch/'configuration-and-replay.json').read_text());ipc=json.loads(Path('/tmp/ca01-hmi-ipc-20261023/contracts.json').read_text())
functions={k:dict(elf_address=v['elf_address'],ghidra_address=v['ghidra_address']) for k,v in ipc['functions'].items()}
r=dict(scope='Startup/IPC contract research, read-only ELF inspection, bounded Unicorn function slices, and synthetic host harness. No original application startup, native preload shim or Toyota rendering.',
 configuration=profile,ipc={k:v for k,v in ipc.items() if k!='functions'},function_addresses=functions,
 configuration_registration_probe=json.loads((scratch/'registry-probe.json').read_text()),
 dispatcher_probes=json.loads((scratch/'dispatcher-probes.json').read_text()),
 startup_sequence=[dict(address='libipas_sysc.so ELF0xaeac',finding='SysPowerOn loads config, initializes process/common/tasks/IPC/shared memory/PSM, creates configured objects, then enters fc_sys_AccStart.'),
 dict(address='ELF0xc89c',finding='fc_cnf_Init opens relative ipasz.conf in mode r; absent from59 complete recovered files and both top-level source filename manifests.'),
 dict(address='ELF0x24d78',finding='fs_prc_Init uses incoming9 as process-table index and stores host getpid value in that slot.'),
 dict(address='ELF0xad50',finding='fc_sys_AccStart reads8-byte parent synchronization, sets state, creates/starts system task1 and joins its thread.'),
 dict(address='ELF0xbda8',finding='tsk_sys_System initializes resources and processes local system queue1 with cyclic/control/status state transitions; not a direct call to drawing task.'),
 dict(address='HMI0x2b5b8',finding='Configured task39 calls initialization then rq_flg_Set(2,1) and exits. Task40 waits rq_flg_Wait(2,1,...).'),
 dict(address='HMI0x2b22c',finding='Configured task40 reads queue40, initial timed wait500ms, up to15 additional P receives, then frame update.'),
 dict(address='HMI0x2a9c0',finding='Class0/subcommand0/event10 reaches this target and sets byte0x26c98a2 to1; executed under bounded Unicorn.'),
 dict(address='HMI0x2b1f8',finding='Frame update returns early unless byte0x26c98a2==1; resets flag before downstream drawing calls.')],
 tests=dict(focused=18,combined=93,failed=0,command=".venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v"),
 artifacts='/home/starlight/projects/rav4-radio/system-audit/ca01-hmi-startup-20261023',
 limitations=['Full ipasz.conf schema and actual values not recovered','Full system task/ACC/init state machine not implemented','External shared-memory/process synchronization and POSIX queue creator unknown','Host model is not a drop-in ARM library; no real-time pthread scheduling','Command/error/free callees mocked in dispatcher probes; drawing not executed','Other-chat EGL/display bridge files remain separate work'])
# Address taken from fresh symbol listing: fs_prc_Init ELF0x24d78.
(repo/'evidence/ca01-hmi-startup-contracts.json').write_text(json.dumps(r,indent=2)+'\n')
(repo/'docs/CA01_HMI_STARTUP_IPC.md').write_text('''# HMI startup and message boundary

This work covers startup/configuration and messaging, alongside the separate EGL/display bridge. It adds `tools/ca01_hmi_startup.py`,18 focused tests, a reproducible static Ghidra survey and `evidence/ca01-hmi-startup-contracts.json`. It does not implement a replacement `SysPowerOn`, load a preload shim, launch the original HMI or render a Toyota screen.

## New verified startup facts

The hash-verified HMI's main calls `fs_sys_CnfEntry(0x59f948)` then `SysPowerOn(9)`. A bounded Unicorn run of the original404-byte `fs_sys_CnfEntry` returned after82 instructions, recording18 configuration-pointer registrations. No imports or OS services were executed during that slice. The process index9 is used by `fs_prc_Init`; it is not a discovered graphics-mode selector.

The HMI configuration contains96 task records of48 bytes and96 message-queue records of16 bytes. Enabled tasks are1,3,10,39,40,41; task95 has nonzero configuration but is disabled. Unknown task fields remain raw words, rather than invented priority/stack semantics.

| Task | Configured entry | Observed role |
|---|---|---|
|1|`tsk_sys_System` imported PLT0xd5e0|System startup/state machine, local queue1|
|3|`tsk_ipc_MsqRcv` PLT0xcfa4|Interprocess receive bridge|
|10|`tsk_grp_DspCtl` PLT0xcd88|Named display-control task; detailed dependencies remain unresolved|
|39 (`0x27`)|HMI0x2b5b8|Initialization, then `rq_flg_Set(2,1)`, then exit|
|40 (`0x28`)|HMI0x2b22c|Waits for flag2/1, then drawing/message loop on local queue40|
|41 (`0x29`)|HMI0xf694|Separate message/control loop on queue41|

Configured queues are1(capacity64),10(capacity16),40(capacity64),41(capacity16); every slot is16 bytes. Configuration presence does not establish a task has actually started: the original system state machine controls activation.

`SysPowerOn` first loads a **relative `ipasz.conf`**. That file is absent from the59 complete recovered entries and both supplied top-level source filename manifests; this is not proof of absence inside every compressed/missing region. The parser recognizes PR/PS/I/S section prefixes, but full schema/values are not reconstructed. Process/common-memory setup, configured IPC/PSM/shared-memory objects and other libraries follow. `fc_sys_AccStart` obtains a parent synchronization FD, reads8 bytes and starts/joins system task1. `tsk_sys_System` initializes resources and handles state transitions on queue1. A no-op `SysPowerOn` would skip these actual prerequisites.

## Local queues are not POSIX queues

`rq_msg_*` uses process-local malloc-backed ring buffers, pthread mutexes and condition variables. Queue descriptors are0x88 bytes. Queue0x28 is not POSIX mq descriptor40. `rq_ipc_*` is a separate POSIX message-queue namespace; its create wrapper calls `mq_open` with `O_RDWR`, not `O_CREAT`, so a producer/creator service is another dependency.

| Local operation | Success | Empty / normal expired wait |
|---|---:|---:|
|`rq_msg_ReceiveP`|−1|−2|
|`rq_msg_ReceiveT`|0|−1|

Normal empty/timeout leaves the caller's message bytes unchanged; invalid-queue paths differ and clear the payload word. The host harness models the active local queue, not invalid/deletion states or real pthread timing.

A message is four little-endian32-bit words: class, family-specific subcommand, event/value, optional owned payload pointer. On the HMI path, class0 and class0x41002 dispatch separately. After handling, a nonzero payload is released with **`rq_mem_Free(1,payload)`**. The real ARM call explicitly supplies both arguments; decompiler output that omits the second argument is misleading. Dequeue itself does not release payload; a full-queue `SendT` timeout leaves ownership with its caller. The harness uses opaque32-bit tokens, never dereferences guest pointers, and has mandatory service callbacks.

## A real heartbeat reaches the draw flag

The drawing loop's initial timed wait is500ms. Its timeout fallback creates the effective envelope `(0,0,10,0)`. It then drains at most15 nonblocking messages, for16 dispatches total before frame processing.

We executed only the bounded original ARM dispatcher/heartbeat slice under Unicorn, against synthetic memory, and observed:

- `(0,0,10,0)` returns1 and sets HMI byte **0x26c98a2=1**, through the event10 jump-table target0x2a9c0.
- Class0x41002 reaches the command-handler boundary0x2b054.
- Owned command and unknown-class cases both call the free boundary with pool1 and the exact payload token.

Command/error/free callees were intercepted test boundaries; they were not original service executions. The heartbeat branch itself executed its real instructions. `FUN_0002b1f8` checks that byte and returns early when unset; with it set, it clears it and proceeds toward the update/drawing calls. This establishes a concrete scheduling boundary, **not proof of a first screen or a complete initialized GUI**.

## Harness and handoff to the graphics work

`HmiHarness` is a deterministic **host-side model**, not an ARM ABI replacement or wall-clock scheduler. It waits for an explicit display-ready signal, preserves the unusual receive statuses, limits each batch to16 messages, and requires heartbeat/command/diagnostic/release callbacks. Exceptions propagate rather than become fabricated initialization/render success. Cleanup on Python callback exceptions is a harness policy, not a claimed C exception path.

The display-bridge work can use the native offsets and envelope contract above. A future real ARM adapter must preserve guest pointer ownership, resolve the actual startup services, and signal flag2/1 only when its display initialization has succeeded. The Python model itself does not connect to Mesa or the original executable.

Inspect the exact baseline and perform an explicitly synthetic replay into a **new** output file:

```sh
.venv/bin/python tools/ca01_hmi_startup.py \\
 --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \\
 --system-library ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \\
 --output /tmp/NEW-startup-report.json --synthetic-replay
.venv/bin/python -m unittest discover -s tests -p test_hmi_startup.py -v
```

Both original binary SHA-256 values are checked before static profile decoding. File-backed virtual reads reject BSS/unmapped ranges instead of inventing data. The replay explicitly supplies a synthetic ready event and reports that no application or pixels were produced.

## Verification and remaining work

18 focused tests pass; the combined repository suite (including the concurrently developed graphics tests) passed93 tests. Cases cover envelope bounds, FIFO/wraparound/full queues, return conventions, ownership, readiness, bounded batches, ELF mapping/bounds and wrong-baseline rejection. A separate reviewer found no actionable issues; real pthread scheduling, POSIX IPC, original startup, allocators and rendering remain untested.

Fresh Ghidra projects, full decompilation, exact instruction traces, probe scripts and logs are preserved outside Git at `../system-audit/ca01-hmi-startup-20261023/`. The Ghidra script here uses shared-object analysis addresses with base0x10000; subtract that base for ELF-relative addresses. HMI addresses are its original ELF virtual addresses.

Next: recover the real configuration/parent handshake and trace the system-task activation conditions, then implement an ARM-side service subset only where those contracts are proved. No vendor files, other-chat bridge files, physical radio or remote branch was changed by this work.
''')
print('Wrote startup/IPC evidence and handoff; full vendor decompilation remains outsideGit.')
