# CA01 bounded guest pthread bridge — 2026-10-23

## Result and limits

Original task initialization, task-record creation, activation, task-start and
selected HMI entrypoints now execute in one Unicorn guest. The `pthread_create`
service creates a concrete guest context before returning success. Each context
has its own64KiB mapped stack,256-byte scoped TLS allocation and unique32-bit
pthread alias. Scheduling is cooperative and bounded; **no native host pthread
or original Linux process is launched**. This is a research compatibility model,
not full POSIX, an installed radio runtime, or proof of a Toyota GUI boot.

The normal cases leave the original parent flag unset. Additional exploration
cases explicitly supply flag1 as a **test fixture**. They do not claim authentic
parent synchronization, recovered `ipasz.conf`, or configured post-init services.
No display-ready flag is forced. Original source inputs remain unchanged.

## Original code executed

| Original operation | Canonical ELF address / configuration |
|---|---|
| `fs_tsk_Init` | `0x20518`; allocates96 original80-byte task records |
| `rq_tsk_Create` | `0x21494`; copies actual48-byte HMI task profiles |
| `fc_sys_AccOnStop` | `0x22bdc`; explicitly invoked activation handler, calls Start and writes state2 |
| `rq_tsk_Start` | `0x213a4`; original pthread attribute setup and pthread_create call |
| `fs_tsk_WDTimerStart` | `0x20278`; original immediate return remains executed |
| `fs_flg_Init` / `rq_flg_Create` | `0x1aa68` / `0x1b550`; creates configured flags with zero bits |
| HMI task39 entry | `0x2b5b8`, profile priority8 -> virtual SCHED_FIFO priority12 |
| HMI task40 entry | `0x2b22c`, initial profile priority0 -> virtual SCHED_OTHER priority0 |
| HMI task41 entry | `0xf694`, profile priority19 -> virtual SCHED_FIFO priority1 |

Configured task profiles3/10 are also available to the bounded start operation.
The activation handler is invoked explicitly by the test driver. The outer
ACC/power-change dispatch is not running; an activation test is not evidence of
real ignition behavior. A new child does not execute reentrantly inside
pthread_create: the scheduler dispatches its saved context after the caller
returns and completes its original state update.

Original queue, task-ID, status-message and flag functions remain original ARM
instructions. Virtual pthread_self/GetTid aliases and Linux gettid do not truncate
host pointers. TLS is implemented only for the verified rq_tsk_GetTid caller;
other TLS requirements stop. pthread attribute ownership, supported scheduling
parameters, output-slot identity, entrypoint identity and thread limits are
validated. EAGAIN/resource failure schedules no phantom child and the original
error path stops at its diagnostic.

Virtual services store thread names (PR_SET_NAME), cancellation type, scheduling
policy/priority and niceness without changing the host. Cancellation requests,
join/detach, general syscalls and unsupported prctl/TLS operations remain
unimplemented boundaries. These callbacks do not supply missing initialization
successes. Yielded wait contexts preserve their private stacks, and an invalid
resume budget cannot consume a pending wait or acquire its mutex.

## Verified barriers and actual dependency messages

With the correct startup-mode1 fixture, original tasks39/40/41 execute, generate
their own `(0,3,task_id,0)` status envelopes and wait on the original flag1
condition. Status messages are not invented by host worker threads in this path.

Explicit parent-ready exploration shows:

- Task40 resumes original code, changes its virtual scheduling policy through
  original rq_tsk_ChgPol, then waits on original flag2. No draw processing starts.
- Task39, with the real recovered group provider bound, calls original
  rq_tsk_WaitInit and generates `(0,5,39,10)`. It waits on a real original
  one-slot guest queue with a60000ms original deadline.
- Original system status handlers and init-wait registration handlers can consume
  the real queued status messages and release that dependency. The original
  continuation consumes the reply and destroys the private queue.
- Task10 continues until the unimplemented virtual getpid interface needed by
  original process-ID lookup. No arbitrary process table/PID is supplied.
- Task41 continues until original semaphore diagnostic `0x14000200`; the
  semaphore manager has not been initialized in this resource subset. This is
  explicit missing runtime setup, not evidence of a missing semaphore binary.

## Next precise initialization boundary

After original task10 status releases task39's group wait, original HMI helper
`0x2a50c` invokes original `rq_sys_GetVclPara` at `0x16888`. That function attempts
a256-byte memcpy from an unpopulated source pointer. The saved boundary is:

- service: `memcpy`
- destination: private guest stack
- source: **0**
- size: **0x100**
- original caller return: **0x2a52c**

The bridge refuses that read; it does not create zero-filled vehicle parameters.
The next useful investigation is the common/shared-memory initialization that
supplies the vehicle-parameter block and process-registration tables. An empty
emulator pointer does not establish that the data is missing on the actual radio.
Original display-provider `sysDisMngInit` and factory menu assets remain separate
unresolved requirements; no pixel/frame result is claimed.

## Binding the real recovered group library

Optional `--group` accepts only SHA-256
`c87538f1de097ef01c8f169971d922068a9f7c2c87faaa1fb9a036cd14dc87ef`.
The provider maps at bias0x20000000. Supported original REL/GOT relocations bind
its sysc services to recovered sysc code and callbacks to original HMI exports.
No original text or PLT instructions are patched.

HMI's COPY symbols `bf_grp_VramImage` (2MiB) and `st_rect` (8 bytes) receive the
actual provider's initial data/BSS contents. Group references interpose to the
executable COPY definitions, matching normal ELF ownership. Without the provider,
those unknown COPY ranges remain guarded rather than being accepted as available
zero-filled application state. Loading/relocating the provider does not claim
all of its original startup constructors or device dependencies completed.

## Correction to the previous startup-mode fixture

The prior task-barrier helper wrote `bf_sys_SysMng+0x24`. That is the wrong word
for the original status barrier. Original ARM memory tracing establishes:

1. PC `0x1e080` reads GOT slot `0x3194c`, containing the relocated private-state
   base `0x13a6a4`.
2. PC `0x1e084` reads startup mode at that base+0x24: **canonical0x13a6c8**,
   emulated address **0x1013a6c8**.

The old write targeted emulated0x1013a724 instead. It left the real mode0, so the
old helper's otherwise valid wait/release tests did not exercise mode1 as claimed.
The helper now uses shared constant STARTUP_MODE_ADDRESS in
`tools/ca01_startup_trace.py`; a regression verifies the correct word is1 and
that the unrelated manager word remains0. Older saved traces remain historical
snapshots; the new source hashes and mode-read evidence supersede that fixture
claim. No firmware bytes were changed to correct the fixture.

## Reproduction and validation

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_guest_threads.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_task_barriers.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
.venv/bin/python tools/ca01_guest_threads.py \
  --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \
  --sysc ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
  --group ../system-audit/ca01-updater-independent-20261022/06-libipas_grp.so \
  --output /tmp/ca01-guest-threads-new-trace.json
```

The output must be a new file. HMI and sysc use the existing canonical SHA-256
gates. Group bytes, when supplied, are checked before any guest initialization.
Only small code/evidence reports belong in Git; all recovered binaries remain in
the existing external research directories.

Verified:18/18 new guest-thread tests,14/14 task-barrier tests (including the
mode regression), and **223/223 full-suite tests passed**, no failures or skips.
The full run took35.985 seconds; `git diff --check` passed. Evidence:
`evidence/ca01-guest-threads-20261023.json`.

Existing exporter, original queue and other uncommitted work is preserved.
Nothing was committed, pushed, installed on or executed against the vehicle.

## Common-memory follow-up

The producer and pointer initialization are now traced in
[CA01_COMMON_MEMORY_AND_VEHICLE_PARAMETERS.md](CA01_COMMON_MEMORY_AND_VEHICLE_PARAMETERS.md).
The real producer is recovered `libipas_sysp.so`; the vehicle block is region16
at `/SHM_SYS_COM + 0x2ddb8`, loaded from flash offset `0xb0000`. Binding recovered
`libComFlmLb.so` reaches original named-semaphore25 diagnostic `0xb6000006`.
An independent original flash initializer stops at `/dev/flash` open. These
are isolated original-code probes, not full parent startup or supplied radio
parameters. The existing guest-thread NULL-source guard remains unchanged.
