# CA01: UU.11.34-first complete decompilation policy

Updated 2026-10-23, after inspecting original and current Ghidra function-coverage DBs.

## Directives

- Preserve every original ELF and every existing original-output snapshot. **Never delete old decompilations merely because the executable code is identical.**
- Prefer *verified latest* UU.11.34 machine code when possible.
- Suppress only **queued** decompilation and AI review work for the older UU.11.27 version when both ELF `.text` sections are SHA-256 identical.
- The **19** old/new executable pairs with identical `.text` are byte-equivalent for machine code. The **two** genuine changed pairs are `PROC_DISPLAY` and `PROC_VRS`, so retain both versions for comparison.
- As applied on October 23, **13 queued redundant old-version decompilations** and **6 queued old-version focused reviews** were marked `skipped_identical_text`; original files and already-finished work remain.
- See exact SHA pair crosswalk and applied job list: `version-preference-20261023.json`.
- Other original binaries are **not** presumed identical unless independently checked.
- Original boot, device-driver, kernel, GUI and data components require identification or extraction; they are not ARM ELF decompilation candidates.

## Failure analysis

Previously indexed: **59,009 discovered function entries**, **58,994 decompiled**, **15 failed** and **0 budget-omitted** among the **47 indexed** ELF SHA inputs. Per function:
- **13 Ghidra 8-second per-function timeouts.**
- **2 Ghidra conditional-execution illegal-op errors**, in newer `PROC_DTV` (0x15790) and newer `PROC_TMD` (0x19520).
- The older `PROC_HMI` 0x186210 failure is code-identical to newer HMI, so only the newer-version retry is prioritized.
- Original `PROC_DISPLAY` UU.11.27 full-job failure arose from **simultaneous Ghidra project-lock collision**, after the primary Ghidra process completed a partial export. The partial export has been restored as its initial Ghidra artifact, **3,019 completed / 5,575 catalogued; 2,552 omitted, 4 timeout failures**. Its pending functions are now resumed in separate Ghidra projects.
- **New evidence October 23 at 22:33 UTC:** a targeted 45-second-function limit recovered newer `PROC_HMI` function 0x00186210, previously failed at 8 seconds. Recovery output is under `results/64f5d905a42aa844/ghidra/failed-retry-01/merged-decomp`; original manifests/source remain immutable.
- The separate Capstone ARM/Thumb alternative-instruction evidence for `PROC_DTV` and `PROC_TMD` lives in `illegal-arm-function-triage-20261023.json`. The original entry prologues decode as ARM instructions; Ghidra errors may occur deeper within code, so root cause is not conclusively established from entry disassembly.

## Implementation

1. `version_policy.py`: SHA-verify ELF inputs, hash literal `.text` content, mark old redundant *queued* jobs skipped. Compare/dedup result saved in `version-preference-20261023.json`.
2. `salvage_existing_display.py`: preserve previously partial old DISPLAY export despite collision from a second Ghidra process, do not restart completed functions.
3. `CA01DecompileRetry.java`: generated, separate selection-only Ghidra pass; extends per-function timeout from 8 to **45 seconds** and retains actual Ghidra error text.
4. `retry_failed.py`: schedules up to two failed addresses per Ghidra pass, with at most three completed attempts per address and 24 bounded per-file rounds. Uses unique Ghidra project names/dirs, original ELF hash checks, immutable new merged manifests and functions.tsv; reindexes only after actual success.
5. `supervisor.py`: adds `repair` job kind and repeated, uniquely named `resume` jobs until pending count is zero or 15 passes, with fail-closed scheduling for evidence-preserving retries. **Does not push, use Codex, modify original files or write the live vehicle.**
6. `failed-function-inventory-20261023.json`: exact error messages, candidate function names and byte counts for all previously failed entries.
7. `test_retry_policy.py`: six offline automated tests; all passed, including version preference and immutable function retry merge.
8. `research_report.py` and `CURRENT_STATUS.md`: job/coverage checkpoints for the active supervisor.

## How to check locally (read-only commands)

```sh
cd /home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023
python3 supervisor.py status
cat CURRENT_STATUS.md
```

The supervisor's `loop` is again running and will process queued jobs locally. The operator's manual local-AI OFF remains authoritative. To request graceful supervisor stop, use `python3 supervisor.py stop`, allowing the bounded current Ghidra job to finish.

## Limits

No count here means "the entire Toyota factory software has been reconstructed." The KWI continuation does not include complete recoverable GUI MC scene assets, original driver/provider libraries or root filesystem. Functions that continue failing after finite retries remain **explicitly failed**, rather than being relabeled as successfully decompiled. Future review may need ARM instruction/p-code analysis, alternate function-boundary recovery or actual donor eMMC data. The old and new binary versions are both retained for provenance.
