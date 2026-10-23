# Independent CA01 research snapshot — October 23, 2026

This directory preserves the reproducible standalone WSL research from several
recent CA01 investigations alongside the **latest local Codex work**, which is
stored in its normal `tools/`, `tests/`, `docs/` and `evidence/` locations.

## Important scope

- **These files are local research snapshots, not an operational firmware update.**
- In some scripts, paths are intentionally absolute references to the
  authorized original machine:
  `/home/starlight/projects/rav4-radio/system-audit/<audit-dir>/`.
  They are not portable without adapting input/output paths.
- Many experiments use QEMU/Unicorn, synthetic RAM, isolated Ghidra projects
  and partial firmware-derived data. **No original radio GUI was booted.**
- Reverse engineered Ghidra "decompiled.c" does not reproduce original
  vendor source. Recovered original binary blobs remain outside this archive.
- LLM "model-review.json" reports are **hypotheses only**; they do not prove
  actual machine-code semantics or full coverage.
- The independent supervisor runs from its **external** system-audit directory.
  The copy here must NOT be started as a second independent worker. Git does
  not contain its active queues, SQLite databases, firmware inputs or generated
  work output.
- Files preserved from an older research worktree may be stale compared with
  the newer `main`. They are under `older-research-worktree-differences/`
  only to avoid losing historical differences.

## Directories

| Subdirectory | Research preserved |
| --- | --- |
| `ca01-1134-firmware-analysis-20261023/` | Original 1127/1134 file- and instruction-level comparison; KWI component recovery and validation helpers |
| `ca01-1134-filesystem-tools-20261023/` | Storage/eMMC/ext3 path decompilation; failed generic extractor findings |
| `ca01-critical-decompilation-20261023/` | Codex Ghidra export audit metadata, selected function manifests and tests |
| `ca01-hmi-egl-bridge-20261023/` | Window/pbuffer bridge tests and original EGL callbacks |
| `ca01-hmi-display-abi-20261023/` | Native HMI window/plane buffer contract and resource inventory |
| `ca01-task10-file-services-20261023/` | Original task/queue boundaries, allocator and file-service dependencies |
| `ca01-original-gui-progress-20261023/` | Real ARM scene loader boundaries, MRA and GUI progress |
| `ca01-startup-integration-20261023/` | Process launch, parser startup/IPC evidence |
| `ca01-hmi-startup-20261023/` | HMI lifecycle, task and shared queue research |
| `ca01-hmi-ghidra-20261022/` | Original GUI startup Ghidra call graph and decompiled excerpts |
| `ca01-local-ai-supervisor-20261023/` | Independent self-contained supervisor Python source; dated report |
| `local-ai-model-review-snapshot.json` | Date-bound 89 local AI reviews (not all functions and not verified) |
| `ca01-service-access-assessment-20261023/` | Cryptographic updater verification, USB+Bluetooth entrypoint investigation, prototype ARM file exporter |
| `ca01-service-access-assessment-20261023/fcc-docs/` | Three publicly available, SHA-256 checked Fujitsu Ten FT0049A/B FCC photo exhibits |
| `ca01-libsecurity-search-20261022/` | Attempts to locate missing security service, signature recovery tools |
| `ca01-additional-recovery-20261022/` | Partial kernel/recovered payload manifests |
| `ca01-consolidation-20261022/` | Older integration provenance and isolated compatibility logs |
| `ca01-progress-review-20261023/` | Gap review as of the prior analysis checkpoint |
| `older-research-worktree-differences/` | Historical text differences preserved without replacing current integration |

## Manifest and exclusions

See [archive file inventory and SHA-256](../../../evidence/ca01-independent-audit-snapshot.json).
It includes 514 copied artifact entries, their exact originating paths, and a
large-artifact path list.

The original `.kwi` files, the source archives released separately, complete
recovered `PROC_*` binaries and shared libraries, the extracted GUI language
files, Ghidra's multi-MB C reconstructions, installed ARM emulation rootfs,
original vendor script and the active AI SQLite databases all remain under
their pre-existing machine-local paths. **Their inclusion is not asserted.**

More complete narrative and known limitations:
[CA01 2026-10-23 research consolidation](../../../docs/CA01_RESEARCH_CONSOLIDATION_20261023.md).

## Offline read-only USB exporter reproduction

The original source is `ca01-service-access-assessment-20261023/ca01_readonly_exporter.c`.
On an offline machine with Linux GCC, the optional ARM cross-compiler and
QEMU user emulator, run the original simulated test (it creates executable
build outputs in that source directory):

```sh
python3 research/independent-audit/2026-10-23/ca01-service-access-assessment-20261023/test_offline_exporter.py
```

The main repo's `tests/test_ca01_usb_exporter.py` instead compiles into temporary
directories; it is included in normal `unittest discover`. **None of these
programs are usable firmware images or proof of execution on the CA01 unit.**
