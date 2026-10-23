# CA01 critical binary decompilation plan

Goal: produce address-indexed C-like exports and verified startup findings for
PROC_DISPLAY, PROC_SYSTEM and libipas_sysc.so, without modifying original bytes.

- Preserve clean main baseline db49463 and existing independent research.
- Use new external Ghidra projects; no deletion or reuse of locked projects.
- Export function inventory, decompilation success/failure, and resolved thunk
  calls; record analysis/time budgets and hashes. Generated C remains outside Git.
- Repair callsite coverage with regression tests for invalid instruction gaps,
  unwind-table bounds and ARM PLT mapping; preserve uncertainty about embedded data.
- Independently inspect decompiled task/thread, process and display paths; validate
  important conclusions against ARM instructions and existing controlled traces.
- Run relevant tests, then full regression suite; update status/evidence.
- No radio access, firmware writes, invented startup success, commit or remote push.
