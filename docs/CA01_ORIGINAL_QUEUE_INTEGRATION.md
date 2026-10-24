# CA01 original ARM queue integration — 2026-10-23

## Scope and result

This extends the existing offline startup work. It runs the recovered queue
implementation itself under Unicorn, with explicitly emulated libc/pthread
services. It does not launch original Toyota threads, satisfy parent process
synchronization, load a factory configuration, initialize a display, or access
radio hardware. No commit or push is part of this work.

Source inputs are SHA-256 gated before parsing or emulation:

| Original file | SHA-256 |
|---|---|
| `06-PROC_HMI` | `cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503` |
| `06-libipas_sysc.so` | `a1f2812d0b1776fa79dcb9ebddd5dca2d16443f77db19c35f4aac2cbabc302b4` |

Both reside outside Git in
`../system-audit/ca01-updater-independent-20261022/`.

## Four implementation checkpoints

1. **First service boundary traced:** original `rq_msg_Create`, canonical ELF
   `0x1d11c`, calls `pthread_mutex_lock` with the original global mutex at
   canonical `0x13a598`. The caller resumes at `0x1d148`. Emulated addresses add
   `0x10000000`; the `0x60043000` import address is a harness trap, not a device
   function address. Original `fs_sys_CnfEntry` and `fs_msg_Init` register the
   HMI profile, initialize that mutex and allocate 96 manager records.
2. **Controlled service layer:** guest allocations and memory copies are
   bounded; mutex ownership, initialization and destruction are checked.
   Condition waits suspend CPU context and preserve the guest stack, releasing
   the mutex. Another cooperative actor can run original ARM send/receive;
   resume reacquires the same mutex. A deterministic virtual CLOCK_REALTIME
   supplies ARM32 timespecs. This is a scoped emulator model, not binary-compatible
   host pthread objects written into guest memory or proof of native scheduling.
3. **Original queue execution:** creation, SendT, ReceiveT, ReceiveP, blocking
   Receive and deletion execute recovered ARM instructions. The guest code owns
   allocation layout, ring indexes, copies, thresholds and return values. Tests
   cover 64x16 FIFO/wraparound, full queues, timed waits, EINTR retry, timespec
   rollover, blocked producer/consumer interleavings and multiple waiting
   consumers rechecking the original predicate. The Python layer contains no
   replacement FIFO. Message representation remains the shared `Message` class.
4. **Startup/draw integration:** `OriginalThreadedStartupBridge` reuses the
   existing native host identity fixtures and original ARM GetTid checks, then
   transports status envelopes through original ARM queue1. Its draw queue40
   also uses original ARM operations. Original HMI configuration specifies
   capacity64/slot16 for both queues. All five modeled identities can reach
   state3, but flag1 and flag2 remain false and drawing remains blocked. An
   independent original-queue demo queues `(0,0,10,0)` and proves the unready
   draw harness leaves it unconsumed. Positive tests use explicitly named
   fixture callbacks for parent/display readiness; they do not establish
   original services succeeded.

## New verified details and corrections

Manager records are **0x88 (136) bytes**, distinct from the 16-byte message
slots and 80-byte task records:

| Offset | Meaning observed in original instructions |
|---:|---|
| `0x00` | Queue state (1 active, 2 reserved for deletion) |
| `0x08` | Slot bytes |
| `0x0c` | Capacity |
| `0x10` | Current count |
| `0x14` / `0x18` | Read/write indexes |
| `0x1c` | Allocated ring-buffer pointer |
| `0x20` | Watermark state |
| `0x24` / `0x28` | High/low thresholds |
| `0x2c` | Guest mutex object |
| `0x48` | Guest condition object |

- Timed send success is0; full/expired timed send is-1. Timed receive success
  is0 and timeout is-1. Poll ReceiveP returns **-1 when it dequeues a message**
  and **-2 when empty**; these unusual values are not normalized away.
- Dynamic `rq_msg_Create(-1,1,16)` searches free IDs downward: 95 then94 in
  the isolated 96-slot profile.
- Original `rq_tsk_GetBlockObj` **allocates on every call** and stores the new
  ID at task-record `+8`; it does not reuse a cached queue. An initial test
  assumed reuse, failed, and was corrected against the decompilation and
  original execution. No vendor code was modified to satisfy that assumption.
- The creation path uses VFP threshold calculations. The emulator explicitly
  enables VFP; no threshold instructions are patched out.
- Crossing queue watermarks invokes original diagnostic calls. A narrowly
  scoped `model_queue_watermark_log` sink captures and validates the original
  seven argument words against the queue record. It accepts only five known
  queue notification codes. It is an explicit diagnostic substitution;
  original TLS/log-driver machinery is not claimed. Other diagnostics halt.
- Payload words are copied byte-for-byte as opaque guest tokens. Normal queue
  transport does not dereference or free their targets. The existing gated
  draw dispatcher still owns its release callback and tests verify exactly
  one release after dispatch, never before readiness.

## Payload-pool dependency resolved locally

Initially `fc_msg_Clear` reached original `rq_mem_Free` at canonical `0x1b800`,
which emitted diagnostic `0x15000300`: pool1 was outside the uninitialized
manager's count. That failure is retained as a negative test.

Further decompilation and execution resolved this without bypassing the check:
original `fs_mem_Init` uses count8 from HMI setup+0x2c and allocates 20-byte
manager records. The embedded memory profile has pool1 row `(1,1,272,512)`.
Original `rq_mem_Create` marks that pool active and selects fixed-size mode;
original `rq_mem_Alloc` calls the emulated libc malloc for272 bytes. The512
profile field is preserved, but the inspected allocation code does not enforce
it as a count of preallocated slots. This is an original malloc-backed wrapper,
not an inferred external shared-memory pool implementation.

The opt-in `initialize_payload_pools` runs those original functions using the
actual embedded records. Tests verify ordinary dequeue leaves the payload
allocated, original `fc_msg_Clear` calls original `rq_mem_Free`, reserved queue
deletion frees incoming and queued payloads plus ring storage, and the gated
draw harness invokes original pool release only after fixture readiness.
Double-free is rejected by the bounded guest allocator. No pool function is
intercepted to manufacture success; only libc memory operations are modeled.
Arbitrary payload integers remain opaque and cannot be freed as owned memory.

## Remaining real dependencies

Parent synchronization from authentic `ipasz.conf`, inherited kernel objects,
post-init callbacks, original pthread_create/task bodies, watchdogs and display
initialization remain unresolved. Known source does not establish their live
configuration. Native interprocess queues and a full Toyota GUI are not running.

The next bounded reverse-engineering work should trace original task
wait/release and parent synchronization, retaining the existing readiness
barriers. More bulk AI review is not needed to identify this next boundary.

## Saved local AI work

The read-only saved supervisor status at 2026-10-23T22:03:36Z reported47 indexed
ELF inputs, 59,009 discovered candidates, 58,994 decompiled candidates, 15 failed
candidates and 51,632 searchable bodies. It reported68 focused review batches.
These aggregate different binaries/versions and are not unique-function or
verified-source counts. Useful here: the hash-matched sysc decompilation under
`../system-audit/ca01-critical-decompilation-20261023/sysc1127-verified/`;
its queue pseudocode was checked against original ARM execution.

No local-AI jobs were started, stopped or controlled by this integration. Bulk
AI reviews are not needed for this next bounded phase; saved results suffice.

## Reproduction and validation

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_original_queue.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
.venv/bin/python tools/ca01_original_queue.py \
  --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \
  --sysc ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
  --output /tmp/ca01-original-queue-new-trace.json
```

Optional `--runtime-library` points to a previously compiled native
`src/ca01_hmi_ipc.c` harness library and adds the threaded-identity integration
report. Output uses exclusive creation and refuses an existing file. No build,
network request or firmware execution is triggered by importing the module.

Evidence: `evidence/ca01-original-queue-integration-20261023.json`. The generated
thread ordering may vary; accepted task sets, return contracts and barriers
must remain consistent. Verification: **27/27 dedicated queue tests passed; 191/191 full regression tests passed**, zero failures or skips. `git diff --check` passed. The full suite completed in44.000 seconds. Changes remain uncommitted and unpushed.
