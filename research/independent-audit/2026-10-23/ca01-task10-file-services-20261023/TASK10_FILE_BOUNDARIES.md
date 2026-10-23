# CA01 genuine task-10 and file-service continuation — 2026-10-23

**Outcome:** Bounded original ARM system and scene functions executed further, with explicit and narrowly controlled synthetic service boundaries. A genuine Toyota factory menu has **not** rendered. No original firmware files were changed or executed on hardware. No tracked Codex repo source was modified, committed, reset or pushed.

## Source provenance

- Canonical recovered `06-PROC_HMI`, SHA-256 `cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503`
- Genuine recovered `06-libipas_sysc.so`, SHA-256 `a1f2812d0b1776fa79dcb9ebddd5dca2d16443f77db19c35f4aac2cbabc302b4`
- Genuine recovered `06-libipas_grp.so`, SHA-256 `c87538f1de097ef01c8f169971d922068a9f7c2c87faaa1fb9a036cd14dc87ef`
- Read-only original ELF PT_LOAD bytes mapped into Unicorn. Prior `ca01-development-kit/tools/ca01_startup_trace.py` and `ca01_scene_boundary.py` provide the bounded stop-on-unknown infrastructure. All new probes are **here** under `system-audit/ca01-task10-file-services-20261023/`.

## 1. Original type.txt reader: optional failure path verified dynamically

`probe_type_txt_fallback.py` actually executes original HMI code at `0x3ec98`.

- `rq_fls_Open("type.txt","r",...)` is intercepted with a nonzero **open failure** status; it is not represented as an authentic file-library success.
- The original ARM reader invokes `memcpy` to write the literal `"(none)\0"`, and then returns. The generic guest-memory copy is an explicitly bounded service.
- Both 7-byte and 16-byte destination-length fixtures pass. The original routine executes **21 instructions** on each. No `rq_fls_Read` or `rq_fls_Close` is invoked after the failed open.
- This proves the missing `type.txt` need not block this **particular original caller**. It does **not** prove that any other missing file, font, or MRA resource is optional.

`probe_scene_after_missing_type.py` connects that legitimate failure branch into original HMI scene constructor `0x4058c`, with prior verified clock and semaphore fixtures.

- Original scene trace advances from its former block at `rq_fls_Open("type.txt","r")` to the **next unresolved call `fs_mpl_Create` at the HMI PLT address `0xce3c`**, caller return `0x57d08`.
- **356 original ARM instructions** execute in that bounded scene initialization, compared with the earlier 249-instruction open boundary in the startup report.
- No fake file handle or content is supplied.

## 2. Precise next allocator dependency

The original `FUN_00057cc0` wrapper prepares a stack descriptor and calls `fs_mpl_Create` with:

- **Pool identifier 1**
- Raw descriptor first two fields: **13** and **0x80000** (524,288); function pointers and zero values follow. Exact vendor field meanings still need implementation evidence.
- The wrapper does not inspect the return value; it immediately returns to its caller.

`probe_scene_with_pool_config.py` adds **one explicit test-only `fs_mpl_Create` boundary** that validates those fields, records them, and returns 0. It does **not** allocate usable vendor memory or claim a successful authentic allocator. Under that extra synthetic boundary, scene initialization advances to the **next unresolved `sysDisMngInit` at PLT `0xcf14`, caller return `0x2bb14`** (393 original ARM instructions). Codex's separate original-code renderer already exercises graphics with modeled display services; this experiment does not repeat or replace it.

### Authentic implementation availability

`check_vendor_service_symbols.py` verifies SHA-256 hashes of **all 59 complete recovered files** and inspects every recovered ELF symbol table. `rq_tsk_WaitInit`, `rq_tsk_GetTid`, `rq_tsk_GetBlockObj`, and `rq_tsk_BlockBegin` have authentic implementations in recovered `libipas_sysc.so` (also duplicated in `libipas_sysp.so`). The targeted `rq_fls_Open` and `fs_mpl_Create` **have no definition in the 59 complete recovered files**. This does not establish absence on the original radio or in unrecovered components. Do not claim a reconstructed file or memory-pool driver.

## 3. Real original task-10 wait function entered

`probe_task10_real_waitinit.py` binds the group-library call to original `rq_tsk_WaitInit` at sysc ELF `0x20f04` (mapped with bias `0x10000000`). It executes through actual original HMI `pt_grp_Init` and group initialization and enters the **real wait function**, without replacing it with success.

The next boundary is **`pthread_self`**, called by real `rq_tsk_GetTid`, because the original initialized pthread/task-table context is missing. **Task 10 remains uninitialized** and no readiness is signaled. This is a stronger original-path result than merely intercepting `rq_tsk_WaitInit` at the library boundary.

`probe_waitinit_envelope.py` separately tests original sysc `rq_tsk_WaitInit(10)` with explicit synthetic downstream *task id 39* and *block queue object 64* inputs. The original ARM instructions themselves construct a four-word (16-byte) envelope:

```text
queue id = 1
message  = (0, 5, 39, 10)
bytes    = 16
```

The trace **stops before executing `rq_tsk_BlockBegin`**; it captures the original message from guest stack at the trapped call. No queue message was actually sent, no wait returned and neither task was marked initialized. This is a validated call contract for a future correctly initialized task/queue runtime, not an emulated successful startup.

## 4. Resource search and practical blockers

The original scene still depends on the genuine file driver and memory-pool driver plus the MC resource tree and fonts. Previous probes enumerate 13 original MRA names including `CmA.mra`, `OnsTrans.mra`, and 534 MUI filename references. Only three distinct language XMLs are complete in the current recoveries; previous searches through 80,310 supplier-source archive names found none of the missing graphical target filenames.

Because `libipas_fls.so`, the authentic memory-pool implementation, and original MC/font resources are still missing, a **genuine full menu cannot be verified from the current project files**. Bypassing those dependencies by making up a filesystem, memory allocator, or fake Toyota menu is not an acceptable substitute.

### Best next milestones for Codex

1. Recover an authentic matching factory-rootfs dump / compatible firmware component providing `libipas_fls.so`, `fs_mpl_Create`, and `/opt/ftl/gui/MC/...` / font assets. Do this through legitimate, read-only acquisition; never flash or modify the car.
2. Advance task-10 activation by setting up the actual original process/task system context and pthread identity map: `rq_tsk_GetTid` determines id from `pthread_self`, TLS and the task table. Use real state transitions and queue1, not a hardcoded WaitInit success.
3. Once authentic libraries are recovered, bind their imported service names with verified ARM ABI, and integrate with the already demonstrated QEMU/Mesa original HMI graphics slices.
4. Treat missing `type.txt` as an observed nonfatal case only for the original reader at `0x3ec98`. The `fs_mpl_Create` and `sysDisMngInit` results are bounded discovery checkpoints and cannot certify full startup.

## Repeat tests

Run in WSL:

```bash
bash /home/starlight/projects/rav4-radio/system-audit/ca01-task10-file-services-20261023/run_all_checks.sh
```

The script re-runs independent original ARM source-hash checks, optional file fallback, two bounded scene paths, genuine sysc WaitInit entry, original 16-byte waiter envelope, and all 59 recovered-file service-symbol scans. It checks the expected halt reason after each experiment. **It does not install or push anything.**

Evidence:
- `type-txt-original-arm-proof.json`
- `scene-after-type-fallback.json`
- `scene-after-synthetic-pool-config.json`
- `original-task10-wait-boundary.json`
- `waitinit-original-envelope.json`
- `vendor-service-availability.json`
- `results/*.log` and `results/script-sha256.txt`

**Verdict:** Authentic code execution advanced two steps past the earlier file boundary and one step into the real task readiness implementation. The original Toyota home screen remains unavailable with current resources and startup services.
