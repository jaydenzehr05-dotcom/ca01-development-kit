# CA01 three-binary decompilation — 2026-10-23

Actual C-like exports now exist for `PROC_DISPLAY` (1134), `PROC_SYSTEM`
(1127) and `libipas_sysc.so` (1127). Original source files were not changed.
This is static decompilation plus bounded execution checks, not original source
recovery, a byte-exact recompilable project, full semantic understanding or a
successful factory GUI boot. No hardware access, commit or push occurred.

## Recovered code and coverage

| Binary | `.text` bodies decompiled | `.text` failures | Import thunks exported separately | Other executable functions |
| --- | ---: | ---: | ---: | ---: |
| libipas_sysc.so | 584 | 0 | 376 | 2 |
| PROC_SYSTEM | 1,193 | 0 | 410 | 2 |
| PROC_DISPLAY 1134, broad pass | 6,160 | 8 | 536 | 2 |

Counts are Ghidra-discovered functions, not a percentage of the complete binary.
Unwind ranges and automatic functions are not one-to-one. Automatic discovery
may miss or incorrectly merge functions. Generated external placeholders are
excluded; real `.plt` thunks are counted separately. Initial exploratory exports
that included artificial external placeholders remain only as dated artifacts.

The display broad analysis hit its360-second auto-analysis budget. Decompilation
then attempted all6,706 discovered executable entries; eight exceeded8 seconds
per function. The output is preserved rather than declaring a complete analysis.

Display timeouts, canonical addresses:
`0x23968`, `0xfdf50`, `0x119ee0`, `0x181b30`, `0x2059cc`, `0x218134`,
`0x3b1028`, `0x3b922c`. These are recorded failures, not empty recovered bodies.

A second, scoped pass seeded verified ARM PLT slots and60 unwind-derived
startup/file/queue candidates. It decompiled56 selected entries successfully.
Four candidates overlapped existing function bodies (`0x23f568`, `0x270930`,
`0x270b00`, `0x27184c`) and were not forcibly split. This pass includes the
previously undiscovered display main function at `0x3e28e8` and gives imported
calls meaningful names. Its output overlaps the broad pass:23 have new distinct successful entries,
for a union of6,183 display code-entry reconstructions. Do not add56 to6,160.

Each export has an address/name/status manifest and `functions.tsv` index.
Independent Ghidra checks validate original file backing and the original/current
entry byte for every broad exported entry. Further final checks hash-gate the
actual source file and validate the focused export. These are entry-byte checks,
not an assertion that each complete function body or inferred type is correct.
Library decompilation uses Ghidra image base0x10000; subtract that from its
addresses for canonical ELF-relative `libipas_sysc.so` addresses. Executable
addresses need no subtraction. Ghidra's automatically selected ARM language ID
is not proof the physical processor is ARMv8.

## New findings: original system runtime

`rq_tsk_GetTid` (canonical `0x20bf4`) calls `pthread_self` and uses a TLS cached
id plus the global task table. Records are80 bytes; pthread identity is at
record+0x40. A stale cached id is checked against current identity before the
original function searches table records and updates TLS. A cached -1 returns
-1 immediately, even if a matching record exists. A cache value0 causes search.

`rq_tsk_Start` (`0x213a4`) passes the record+0x40 slot to `pthread_create` and
uses the routine pointer at record+0x14. This identifies how actual thread
creation and identity lookup connect. It is not a completed implementation of
that lifecycle, scheduling policy or watchdog behavior.

`rq_tsk_GetBlockObj` (`0x20e70`) obtains the caller id, requests a queue with
`rq_msg_Create(-1,1,16)` and stores the result in its task record+8.
`rq_tsk_BlockBegin` (`0x20d04`) sends the original request and waits using
`rq_msg_ReceiveT(...,60000)` before cleanup. These paths remain separate from
the HMI draw queue and its500ms loop. Existing real WaitInit envelope evidence
`(0,5,39,10)` still applies; readiness has not been manufactured.

The new `tools/ca01_task_identity.py` actually executes original GetTid with
explicit guest thread identities/table rows/TLS memory. Its table length96 comes
from the canonical embedded HMI configuration. Tests demonstrate original search
and stale-cache correction returning39, unknown-thread return-1, and cached-1
behavior. It does not hardcode GetTid's return, create original pthreads, send a
queue message, initialize task10, or implement full TLS. The existing trace
engine's unresolved-TLS guards remain intact; the resolver is an explicit fixture.

## New findings: PROC_SYSTEM

The executable entry passes main address `0x3bc88` to libc. That original main
registers configuration at `0x7bbe4`, then calls the master initialization
routine `0x2f2cc(1)`.

The decompiled master path includes configuration loading, process/common/diagnostic
and task initialization, IPC/SHM/PSM setup, configured object creation loops,
pre-initialization callbacks, enabled child-process creation, selected process
start conditions and transition into its service loop. `rq_prc_Start` in sysc
contains actual fork/execv, signal-mask and path-resolution calls. Together these
are concrete targets for recovering the missing parent/thread/launch context;
they are not evidence that the necessary ipasz.conf values have been recovered.

No successful original process creation or IPC startup is claimed. No original
system supervisor was launched against host services or devices.

## New findings: PROC_DISPLAY

Focused main `0x3e28e8` registers `0x42c49c` and calls `SysPowerOn(3)`.
Unlike PROC_HMI, this binary has no direct EGL, GLES or sysDisMng import names.
Its imports, configuration and selected workers show media/radio/Bluetooth/Wi-Fi
and UI-data coordination. This supports investigating its IPC/services rather
than assuming from its filename that it is the direct pixel compositor.
This is a scoped role inference, not a complete process specification.

The embedded profile has96 task slots and27 enabled rows. Configured task51
enters `0x45194`; its original prctl name is `tsk_btc_Main` and its receive loop
uses queue46 (`0x2e`). Function `0x3e1a0c`, named `tsk_wms_Main` by its prctl
string, receives queue62, but it is not one of the currently enabled profile
entries. Compiled routines can exist without being enabled in this profile.

All28 enabled queue records here specify16-byte messages, but their capacities
range from1 through512. Table row31 names queue32; row32 names queue31.
Task id, queue id and row index are NOT interchangeable. The existing HMI-only
queue decoder correctly rejects this different profile; it must not be widened
silently or treated as a universal decoder. Our fixed HMI64-slot queue remains
HMI-scoped, not a complete implementation of these display queues.

## Analysis-tool repair

`tools/ca01_arm_calls.py` replaces the earlier one-pass coverage assumption.
It accounts for every aligned ARM text word, including undecodable gaps and
conditional direct calls, with canonical hashes and exception-index checks.
It counts28,625 direct import-call candidates in each display version, versus
the earlier88 captured before decoding stopped after6,192 bytes. It finds529
import names. System and sysc candidates number3,775 and2,012 respectively.

These are static instruction candidates, not reachable-call counts: literal
data can decode as instructions and indirect callbacks are excluded. Equal
call counts do not prove function or behavioral equivalence between versions.
No Thumb unwind entries were observed in these four scanned binaries; this is
not proof that every byte is ARM code.

## Files added and reproduction

Repository additions:
- `tools/ghidra/CA01DecompileBatch.java`: bounded C-like exporter, explicit
  function-status inventory, file-origin gate, scoped selection and thunk counts.
- `tools/ghidra/CA01VerifyDecompilation.java`: source hash and per-entry file-byte checks.
- `tools/ghidra/CA01SeedFunctions.java`: scoped research-project disassembly/function seeds.
- `tools/ca01_arm_calls.py` and five regression tests.
- `tools/ca01_task_identity.py` and five original-ARM regression tests.
- Compact evidence, this report and local execution plan.

Generated C, projects and firmware remain outside Git:
`/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/`.
Final exports are `sysc1127-verified/`, `system1127-verified/`,
`display1134/`, and `display1134-focused/`. Use `INDEX.md` there to navigate.
The original `run_target.sh` preserves bounded initial-import commands; for an
existing project use `-process '*' -readOnly -noanalysis` plus the exporter
with a new output directory. Omit readOnly only when intentionally adding seeds
to these disposable research projects. Never overwrite the original firmware.

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
.venv/bin/python tools/ca01_arm_calls.py /path/to/original.elf \
  --sha256 EXPECTED_SHA256 --output /absolute/new/calls.json
.venv/bin/python tools/ca01_task_identity.py \
  --hmi ../system-audit/ca01-updater-independent-20261022/06-PROC_HMI \
  --sysc ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
  --output /absolute/new/identity.json
```

## Next concrete work

1. Connect original fs_tsk_Init/rq_tsk_Create/rq_tsk_Start to real controlled
   pthread/TLS services, respecting actual configuration and queue ids. Use the
   original GetTid contract as the test oracle, without faking task readiness.
2. Trace the decompiled PROC_SYSTEM master initialization and process-start
   conditions against the configuration parser and inherited eventfd handshakes.
3. Build the display worker/queue dependency map from the selected functions and
   embedded profile. Resolve shared/overlapping function boundaries and the eight
   decompiler timeouts in small batches; then do a function-level1127/1134 diff.
4. Keep asset-loader reconstruction separate from asset replacement. Replacing
   images/fonts is feasible in principle, but menu files can encode navigation,
   state and resource relationships. Their expected formats still need recovery.

The previously missing factory filesystem, configuration values, authentic file/
display/pool libraries and full original menu assets remain missing. This work
makes available binaries more understandable; it does not create absent files.
No additional installation was needed; existing Ghidra/Unicorn/Capstone sufficed.

## Final verification and Git state

The final combined suite passed135 tests with zero failures. The independent
review found two accounting/original-file-backing issues; both were corrected
and re-reviewed. Final source hash/entry checks passed for the original files.
No external tooling installation was required.

Baseline main HEAD remains db49463. This development cycle is uncommitted and
unpushed. Original generated C/project artifacts are outside Git; only tools,
tests, compact evidence and documentation are in the working tree.
