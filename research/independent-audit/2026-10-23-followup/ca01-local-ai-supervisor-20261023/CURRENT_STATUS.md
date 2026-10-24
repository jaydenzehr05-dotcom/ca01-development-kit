# Toyota CA01 independent research — live generated status
Generated: 2026-10-23T22:59:28+00:00

- Checkpointed jobs: **236 done / 328 scheduled**, 68 queued, 0 running.
- Indexed ELF inputs: **47**.
- Ghidra-discovered function candidates: **59009**, decompiled: **58994**, failed: **15**, not attempted: **0**.
- Indexed searchable actual function bodies: **51632**.
- AI review jobs completed: 127; focused review batches completed: 79.
- Distinct exact source function addresses sent to the model: **256**.
- **Warning:** decompiled, indexed and AI-reviewed are different; none proves authentic original source reconstruction.
- Codex involvement: **none**; original firmware and repository were not modified by this research supervisor.

## Tasks by kind/status

| Type/status | Count |
|---|---:|
| decompile_done | 49 |
| decompile_skipped_identical_text | 13 |
| focus_done | 79 |
| focus_queued | 40 |
| focus_skipped_identical_text | 6 |
| identify_done | 10 |
| identify_queued | 18 |
| index_done | 46 |
| index_queued | 3 |
| repair_done | 1 |
| repair_queued | 6 |
| resume_done | 3 |
| resume_failed | 5 |
| resume_queued | 1 |
| review_done | 48 |

## Highest unattempted function counts

| Binary | Discovered | Decompiled | Not attempted | Failed | Searchable bodies |
|---|---:|---:|---:|---:|---:|
| ./opt/ftl/apl/PROC_HMI | 8355 | 8354 | 0 | 1 | 8105 |
| ./opt/ftl/apl/PROC_HMI | 8355 | 8354 | 0 | 1 | 8105 |
| PROC_DISPLAY | 6706 | 6698 | 0 | 8 | 6160 |
| ./opt/ftl/apl/PROC_DTV | 4477 | 4475 | 0 | 2 | 4275 |
| ./opt/ftl/apl/PROC_AUDIO | 3385 | 3385 | 0 | 0 | 3208 |
| ./opt/ftl/apl/PROC_AUDIO | 3383 | 3383 | 0 | 0 | 3206 |
| ./opt/ftl/apl/PROC_CDDB | 2802 | 2802 | 0 | 0 | 2724 |
| ./opt/ftl/apl/PROC_MMP | 2385 | 2384 | 0 | 1 | 2061 |
| ./opt/ftl/apl/PROC_DVDDECK | 1816 | 1816 | 0 | 0 | 1767 |
| ./opt/ftl/apl/PROC_VRS | 1621 | 1620 | 0 | 1 | 1445 |
| ./opt/ftl/apl/PROC_SYSTEM | 1607 | 1607 | 0 | 0 | 1195 |
| ./opt/ftl/apl/PROC_SYSTEM | 1605 | 1605 | 0 | 0 | 1193 |
| ./opt/ftl/apl/PROC_UIEIF | 1123 | 1123 | 0 | 0 | 873 |
| ./opt/ftl/apl/PROC_UIEIF | 1123 | 1123 | 0 | 0 | 873 |

## Currently running

- Nothing is currently active.

## Failed jobs

- resume:4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004: Command '['/home/starlight/projects/rav4-radio/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-1/projects', 'CA01_RESUME_4755da50d439', '-import', '/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY', '-scriptPath', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023', '-postScript', 'CA01DecompileBatch.java', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-1/isola
- resume:4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004:02: Command '['/home/starlight/projects/rav4-radio/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-2/projects', 'CA01_RESUME_4755da50d439', '-import', '/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY', '-scriptPath', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023', '-postScript', 'CA01DecompileBatch.java', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-2/isola
- resume:4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004:03: Command '['/home/starlight/projects/rav4-radio/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-3/projects', 'CA01_RESUME_4755da50d439', '-import', '/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY', '-scriptPath', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023', '-postScript', 'CA01DecompileBatch.java', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-3/isola
- resume:4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004:04: Command '['/home/starlight/projects/rav4-radio/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-4/projects', 'CA01_RESUME_4755da50d439', '-import', '/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY', '-scriptPath', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023', '-postScript', 'CA01DecompileBatch.java', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-4/isola
- resume:4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004:05: Command '['/home/starlight/projects/rav4-radio/tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-5/projects', 'CA01_RESUME_4755da50d439', '-import', '/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY', '-scriptPath', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023', '-postScript', 'CA01DecompileBatch.java', '/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/4755da50d4396cb2/ghidra/resume-5/isola

## Interpretation

No full Toyota factory GUI has been rendered. Original proprietary driver implementations
and menu assets remain missing. The known EXT3/eMMC layout clues do not
amount to a recovered eMMC filesystem image.

Research scripts run as separate, read-only userspace processes against
SHA-256-verified archived binaries. The model's JSON observations are
hypotheses, not validated original software behavior.
