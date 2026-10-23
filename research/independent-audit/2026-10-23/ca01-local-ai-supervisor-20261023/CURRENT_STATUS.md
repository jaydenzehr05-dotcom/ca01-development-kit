# Toyota CA01 independent research — live generated status
Generated: 2026-10-23T21:13:25+00:00

- Checkpointed jobs: **192 done / 272 scheduled**, 80 queued, 0 running.
- Indexed ELF inputs: **43**.
- Ghidra-discovered function candidates: **52627**, decompiled: **52612**, failed: **15**, not attempted: **0**.
- Indexed searchable actual function bodies: **46173**.
- AI review jobs completed: 89; focused review batches completed: 43.
- Distinct exact source function addresses sent to the model: **180**.
- **Warning:** decompiled, indexed and AI-reviewed are different; none proves authentic original source reconstruction.
- Codex involvement: **none**; original firmware and repository were not modified by this research supervisor.

## Tasks by kind/status

| Type/status | Count |
|---|---:|
| decompile_done | 47 |
| decompile_queued | 15 |
| focus_done | 43 |
| focus_queued | 42 |
| identify_done | 10 |
| identify_queued | 18 |
| index_done | 43 |
| index_queued | 4 |
| resume_done | 3 |
| review_done | 46 |
| review_queued | 1 |

## Highest unattempted function counts

| Binary | Discovered | Decompiled | Not attempted | Failed | Searchable bodies |
|---|---:|---:|---:|---:|---:|
| ./opt/ftl/apl/PROC_HMI | 8355 | 8354 | 0 | 1 | 8105 |
| ./opt/ftl/apl/PROC_HMI | 8355 | 8354 | 0 | 1 | 8105 |
| PROC_DISPLAY | 6706 | 6698 | 0 | 8 | 6160 |
| ./opt/ftl/apl/PROC_DTV | 4477 | 4475 | 0 | 2 | 4275 |
| ./opt/ftl/apl/PROC_AUDIO | 3383 | 3383 | 0 | 0 | 3206 |
| ./opt/ftl/apl/PROC_CDDB | 2802 | 2802 | 0 | 0 | 2724 |
| ./opt/ftl/apl/PROC_MMP | 2385 | 2384 | 0 | 1 | 2061 |
| ./opt/ftl/apl/PROC_DVDDECK | 1816 | 1816 | 0 | 0 | 1767 |
| ./opt/ftl/apl/PROC_VRS | 1621 | 1620 | 0 | 1 | 1445 |
| ./opt/ftl/apl/PROC_SYSTEM | 1607 | 1607 | 0 | 0 | 1195 |
| ./opt/ftl/apl/PROC_UIEIF | 1123 | 1123 | 0 | 0 | 873 |
| ./opt/ftl/lib/libipas_grp.so | 1116 | 1116 | 0 | 0 | 648 |
| ./opt/ftl/lib/libipas_sysc.so | 962 | 962 | 0 | 0 | 584 |
| ./opt/ftl/lib/libipas_sysp.so | 925 | 925 | 0 | 0 | 582 |

## Currently running

- Nothing is currently active.

## Failed jobs

- No permanently failed jobs in the checkpoint database.

## Interpretation

No full Toyota factory GUI has been rendered. Original proprietary driver implementations
and menu assets remain missing. The known EXT3/eMMC layout clues do not
amount to a recovered eMMC filesystem image.

Research scripts run as separate, read-only userspace processes against
SHA-256-verified archived binaries. The model's JSON observations are
hypotheses, not validated original software behavior.
