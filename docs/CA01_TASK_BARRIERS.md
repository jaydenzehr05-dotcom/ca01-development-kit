# CA01 original task barriers and parent protocol — 2026-10-23

## Development order and scope

Proceed from original task wait/release, to the parent synchronization contract,
to display initialization. A successful local protocol fixture is not an
original process boot. Authentic `ipasz.conf`, inherited production objects,
post-init callbacks and display providers remain missing.

This work adds `tools/ca01_task_barriers.py` and
`tests/test_ca01_task_barriers.py`; it extends the existing queue runtime by
subclassing/composition. Previous exporter, threaded startup, queue and research
work is preserved. No radio access, firmware changes, installation, commit or
push occurred.

## Original task dependency wait/release

The following functions execute from hash-gated original `libipas_sysc.so`:

| Function | Canonical ELF address | Observed role |
|---|---:|---|
| `rq_tsk_WaitInit` | `0x20f04` | Increments waiter count and creates registration message |
| `rq_tsk_BlockBegin` | `0x20d04` | Sends registration, waits up to60000ms on private queue, deletes queue |
| `fc_sys_RcvInitWait` | `0x22d98` | Registers a dependency or immediately acknowledges an initialized target |
| `fc_sys_InitWaitNotAct` | `0x21650` | Stores target at task record+4 |
| `fc_sys_InitWaitAct` | `0x22d60` | Decrements waiter count and replies to existing initialized-target waiter |
| `fc_sys_RcvTskCond` | `0x23078` | Dispatches supplied task status by original task state |
| `fc_sys_TskCondActInit` | `0x22e44` | Releases matching dependency waiters and sets target state3 |
| `rq_tsk_BlockEnd` | `0x20b68` | Sends the original zero-filled16-byte reply |

The concrete fixture has task40 wait for task39. Original code produces
`(0,5,40,39)` on queue1 and waits on dynamically allocated private queue95
(capacity1, slot16). The fourth word here is the target ID, not a pool pointer;
message interpretation depends on the message type. It must not be freed merely
because it is nonzero.

The original system handler records the target, and a supplied status0 for
task39 releases the correct waiter. Original ARM code then consumes the reply,
deletes queue95 and clears task40's block-queue field. The wait count returns0.
An unrelated task10 status cannot release the waiter. If the target is already
state3, the original immediate-acknowledgement branch works. Timeout follows the
original60000ms deadline and stops at diagnostic `0x11001220`; it never becomes
successful readiness.

**Fixture limits:** Task-table identities, initial state2 values and startup
mode1 are explicitly supplied. Original task bodies and `pthread_create` have
not run. The system handlers are called with fixture status messages; no claim
is made that task39 actually initialized its hardware. Other enabled task states
remain pending, so the global all-tasks-ready barrier is not bypassed.

## Parent synchronization with actual local eventfds

Original `fc_sys_SycSynWait` (`0x216b4`) and original process-ID/eventfd getters
execute. Fresh Linux eventfds exist only in this local process. The fixture uses
nonblocking/CLOEXEC host handles so blocked guest reads suspend safely; the
original production C eventfd is blocking and is inherited without CLOEXEC.
This test does not reproduce `fork`/`exec` inheritance or original process setup.

Guest `read`/`write` are restricted to these registered8-byte eventfd operations.
An empty read preserves the suspended guest CPU and stack. Supplying a token
allows the original comparison loop to resume. Unknown descriptors are refused.
All local eventfds close when the fixture exits, including on setup errors.

- Cached process ID3, descriptor records and expected token42 are **synthetic
  values**, not values recovered from `ipasz.conf`.
- ARM memory-read instrumentation identifies `bf_zsy_PrcMng` as the actual
  descriptor-block pointer read by the getters. The unrelated
  `bf_sys_PrcMng` global is left unchanged.
- The expected signed32 token is read from `tb_sys_PrcInf` table+0x44 and sign
  extended to64 bits. A separate test verifies expected token-2 against actual
  eventfd counter `0xfffffffffffffffe`.
- Child notification writes its process ID3 to the P eventfd.
- With C empty, the original function stays suspended. Wrong token41 is consumed
  but rejected; a later token42 allows the function to return.
- **eventfd is a counter, not a packet queue.** Writes42+42 produce84 and remain
  rejected when42 is expected. Writes20+22 produce42 and satisfy the comparison.
  Correct parent code must account for accumulated counters.

Returning from this isolated handshake does not execute `fc_sys_SycSynInit`,
its configured post-init callbacks, or its final `rq_flg_Set(1,1)`. Global
startup/display readiness is not modified. Authentic configuration values and
parent setup remain necessary for a full original startup.

## Exact display-provider boundary

The isolated original HMI wrapper at `0x16094` resets its three display
buffer-descriptor records, then tail-calls the unresolved `sysDisMngInit`
import at PLT `0xcf14`. The trace stops there. It is an isolated wrapper
execution, not proof that full task39 startup reached that point. No display
provider is substituted and no ready flag or Toyota frame is produced.

The next display-side requirement is the authentic provider and its startup
contract. A similarly named library or the existing Mesa pbuffer bridge does
not establish that implementation or hardware initialization.

## Task-creation correction

Original `fs_tsk_WDTimerStart` at `0x20278` is exactly the four bytes
`1e ff 2f e1` (`bx lr`). A bounded execution runs one instruction, returns and
calls no service. `fs_tsk_WDTimerCreate` is also an immediate return in the
reviewed decompilation; only Start has a saved original-instruction execution
proof here. Do not invent a watchdog-start service dependency for this build.

The next meaningful task-creation work is the original `rq_tsk_Start`
`pthread_create` handoff: correct32-bit guest identities, actual execution of
recovered task entrypoints in shared guest state, cancellation/lifetime,
scheduling and explicit first missing-service stops. Returning a made-up success
from `pthread_create` would not implement that contract.

## Validation and reproduction

Dedicated tests cover original wait/release, wrong-target rejection, already
initialized targets, original timeout diagnostics, missing/wrong/correct parent
tokens, signed token extension, counter accumulation, eventfd cleanup, and the
missing display import.

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_task_barriers.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
.venv/bin/python tools/ca01_task_barriers.py \
  --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \
  --sysc ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
  --output /tmp/ca01-task-barriers-new.json
```

The output must be a new file. Input hashing is inherited from the original
queue runtime: HMI `cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503`,
sysc `a1f2812d0b1776fa79dcb9ebddd5dca2d16443f77db19c35f4aac2cbabc302b4`.
Original binaries remain outside Git. Small trace metadata is saved in
`evidence/ca01-task-barriers-20261023.json`.

Verified results: **13/13 dedicated tests and 204/204 full regressions passed**, zero failures or skips. Final full run:32.154 seconds. `git diff --check` passed. Changes remain uncommitted and unpushed.

## Correction from guest pthread execution

The earlier mode1 fixture wrote the wrong structure word. Original ARM memory
tracing now identifies the correct emulated word as0x1013a6c8, via GOT0x3194c.
The helper has been corrected and a new regression checks that word and leaves
the unrelated bf_sys_SysMng+0x24 untouched. Earlier saved traces/test counts above
are historical; see `CA01_GUEST_PTHREAD_BRIDGE.md` and the new guest-thread
evidence for the correction and the current223-test verification.
