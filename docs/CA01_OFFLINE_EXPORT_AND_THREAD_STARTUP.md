# CA01 offline USB exporter and task/thread startup progress — 2026-10-23

This work was performed solely on the authorized local WSL research machine.
It does **not** establish a path for executing third-party code on the 2017
Toyota RAV4 Fujitsu Ten CA01 head unit. There is no new KWI, signature-bypass
attempt, vehicle flash, Git commit or remote push.

The ongoing **PROC_SYSTEM diagnostic execution-entrypoint investigation is
owned by the separate Codex work**, and is deliberately outside this scope.

## 1. Hardened read-only USB exporter

Maintained source: `tools/ca01_usb_exporter.c`.
Production research build script: `tools/build_ca01_usb_exporter.sh`.
Test suite: `tests/test_ca01_usb_exporter.py`.

This supersedes the weaker historical snapshot under
`research/independent-audit/2026-10-23/ca01-service-access-assessment-20261023/`;
that old source is preserved unchanged for provenance.

### Security/containment behavior

- Path access is anchored to open directory **file descriptors** using
  `openat(..., O_NOFOLLOW | O_DIRECTORY)` on **every** path component. No
  `realpath()`-then-unchecked-reopen and no untrusted path string concatenation
  is used for file enumeration.
- Leaf symlinks and directory symlinks are skipped/rejected; opened source file
  descriptors are `fstat`-checked as regular files. Other device types and
  special files are not copied.
- Destination must be an **already existing, empty directory**, never the same
  directory/inode as the source. All selected source subtrees are checked for
  destination overlap **before** creating output. Each recursively opened source
  directory is also checked in both ancestry directions against the destination,
  rejecting nested destination aliases before creating their output. Destination parents are opened
  with `O_NOFOLLOW`; new files use `O_CREAT|O_EXCL`, not overwrite/truncate.
- The production `--copy` mode refuses to write to the source root's
  filesystem. It also requires a path under `/mnt/usb1/`, verifies
  `/mnt/usb1` is a distinct mounted device from `/mnt`, and checks that
  the destination device matches that mount. **USB identity is not cryptographically
  established** by device numbers. An operator still has to verify the medium.
- `--copy` is required for output; dry-run is the default. There is a
  128 MiB per-file limit, 512 MiB total byte limit, 16,384 file cap, directory
  recursion bound, `fsync` and failed-file cleanup. Source writes, mount
  changes, network services, radio driver configuration and firmware updates
  are not part of the tool.
- `--test-allow-same-device` is compiled in **only when**
  `CA01_OFFLINE_TEST` is defined for synthetic offline fixtures; it is
  absent in the standard ARM production research build.

This protects against symlink traversal of parent directories as well as leaf
files. It does **not** defend against malicious privileged concurrent filesystem
remount/rename attacks, unexpected device failure, filesystem bugs, or a
misidentified USB mount. It remains offline-only pending actual hardware access,
mount and runtime verification.

### Older-kernel ABI

The original static glibc build emitted a **Linux 3.2 ABI requirement**, which
is newer than the **2.6.35.7** kernel version referenced in original CA01
source and `snap.sh` module paths. The replacement is freestanding and linked
with `-nostdlib -static`; it uses only direct **ARM EABI** Linux syscalls
(`openat`, `mkdirat`, `fstat64`, `getdents64`, `unlinkat`, `read`,
`write`, `fsync`, `close`, `exit`). These syscall interfaces existed
by Linux 2.6.35.7, but kernel/hardware compatibility is **still unproven**.

The compilation targets ARMv5TE instructions with soft-float ABI. QEMU-arm
executed the produced freestanding binary against synthetic files, and ELF
verification found **no glibc NEEDED entry or Linux 3.2 ABI note**. The correct
ARM-specific `O_DIRECTORY`/`O_NOFOLLOW` values come from the ARM
`asm/fcntl.h` header, rather than mistaken x86 host flag constants.

Offline build (no vehicle or firmware touched):

```sh
sh tools/build_ca01_usb_exporter.sh
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_usb_exporter.py' -v
```

The ARM binary output is intentionally **outside Git**, under
`../system-audit/ca01-service-access-assessment-20261023/`.
It is **not** an update file or USB autorun payload.

## 2. Original ARM task and queue integration

Hash-gated original source inputs (outside Git):
`../system-audit/ca01-updater-independent-20261022/06-PROC_HMI` and
`06-libipas_sysc.so`. Code runs under Unicorn on WSL, **not** on the car.

### Threaded bridge

`tools/ca01_threaded_startup.py` creates real **host** pthread-backed Python
threads for task fixtures `3, 10, 39, 40, 41`. Each host pthread identity
is mapped to a unique 32-bit **guest fixture token** (never blindly truncated
from a 64-bit host pointer). The real guest ARM instructions for
`rq_tsk_GetTid` at canonical `0x20bf4` execute on a separate Unicorn
instance for each test thread, reading original 80-byte task table entries
and a guest TLS cache cell. Both cold lookup and cached-path results must agree.

Only verified task identities enqueue the original-shaped
`(0,3,task_id,0)` **16-byte** status envelope. This is a **synthetic
host queue-1 transport**, not an implementation of the original
`rq_msg_Create`. The HMI draw queue `0x28` remains the separate native
C pthread ring already in `src/ca01_hmi_ipc.c`. The existing
`StartupSequence.task_initialized` transition is applied only after a
valid recognized status envelope.

Parent IPC, `ipasz.conf` startup semantics, task-0x27 display initialization,
flag2, hardware graphics and app startup **remain unresolved and blocked**.
No service is marked ready merely because guest thread ID lookup succeeded.

Negative tests inject an unrecognized guest pthread token and a full bounded
queue; neither is allowed to release readiness.

### Original task-start and block-queue CPU call boundaries

`tools/ca01_original_task_boundaries.py` independently executes bounded,
SHA-gated original ARM instructions:

- `rq_tsk_Start` at `0x213a4` reads its 80-byte guest task record,
  routine pointer at `+0x14`, priority at `+0x18`, and calls
  `pthread_create` with output slot at `+0x40`. Imported pthread
  **attribute** calls return explicit fixture success for this one probe.
  The original call is deliberately **trapped at pthread_create**, never
  executed. Priority 0 yielded policy 0/priority 0, while priority 5 yielded
  policy 1/priority 15. No vendor watchdog or guest worker is launched.
- `rq_tsk_GetBlockObj` at `0x20e70` actually invokes original
  `rq_tsk_GetTid`; it requests `rq_msg_Create(-1,1,16)`. The genuine
  `rq_msg_Create` depends on an unresolved `pthread_mutex_lock`.
  A **clearly named, test-only interception** at that function entry returns
  an inert guest token, allowing original ARM caller instructions to store
  the token at record offset `+8`. No functioning message queue or
  `rq_tsk_BlockBegin` wait is claimed.

These two original-code probes demonstrate the *call contracts* that a future
controlled host-side service implementation would have to satisfy. Neither
pretends that original threads, timer services or GUI readiness exist.

## Test commands and current known limitations

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_threaded_startup.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_original_task_boundaries.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
```

Regression coverage includes original ARM ABI pointers, TLS identity,
pthread attr policies, stubbed queue-token storage, queue readiness gates,
symlink parents, mount checks, quota limits, overwrites, and QEMU-arm
no-libc export against synthetic files.

**Outstanding:** legitimate service execution path (being investigated
separately), actual on-radio kernel/ABI verification, authentic manufacturer
libraries `libipas_fls.so`/`libdisplay_if.so` and original
`.mui`/`.mra` assets, true queue service and `ipasz.conf` parent
process synchronization. Avoid unverified custom KWI updates, vehicle
diagnostic writes, or assuming a complete working original GUI.
