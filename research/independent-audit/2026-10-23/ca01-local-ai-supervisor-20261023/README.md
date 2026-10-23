# Toyota CA01 — Independent local AI supervisor (no Codex)

This research queue works from existing **verified, original CA01 firmware bytes**
and local Ghidra scripts. It is wholly separate from the CA01 Git checkout.

**No Codex process, plugin, agent, task delegation, Git commit or push is used.**
The `local-codex-worker` folder name appears only because it currently hosts
the **local llama.cpp server and its authenticated Windows loopback bridge**;
that historical directory name does not mean Codex participates. The local
model never receives an executable shell or file-writing tool.

## Already working

- Sources identified from the actual 1127 and 1134 SHA-256 manifests.
- SQLite queue survives process restarts and saves per-source results.
- Three earlier Ghidra exports reused rather than repeated.
- One read-only isolated Ghidra analysis at a time, 2 CPUs,
  3 GiB Java heap budget, 300-second hard subprocess timeout.
- Read-only original file verification on *every* new job.
- Local Qwen only reviews small pseudocode excerpts, writes structured
  **hypotheses** and never controls tools or code execution.
- Zero automatic commits, pushes, installs, hardware access, or firmware flashing.
- Manual Off on the Local AI tray prevents research jobs from starting.
- Missing files remain explicitly **unavailable**, not reconstructed by guesswork.

## Use from WSL

```bash
cd /home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023
bash start.sh
bash status.sh
bash stop.sh
python3 supervisor.py reset-stop
bash start.sh
```

The worker now follows this expanded path: verified original files ->
bounded Ghidra initial decompilation -> **selected retry of skipped entries**
-> **complete function inventory and searchable SQLite index** ->
ranked passive Qwen reviews of separate functions -> checkpointed reports.

**New status:** `CURRENT_STATUS.md` tracks actual Ghidra-discovered,
decompiled, failed and not-attempted function counts, plus the distinct source
addresses actually seen by the local model. It is regenerated after each job.
`function_coverage.sqlite3` has a full-text index of bounded source bodies,
with original addresses and content SHA-256. The verified ELF bytes stay
read-only. The active SQLite state remains `progress.sqlite3`.

The model first reviews resource-loading, filesystem, display, startup and
recovery call paths. Up to 16 additional selected functions per binary are
then reviewed in two-function batches, with source-code snippets verified
against the indexed C-like output. This is initial prioritized semantic
review, **not an assertion that every function is understood**.

Large Ghidra files receive one separate selected-address retry for functions
which the original time budget skipped, with preserved manifest provenance.
The result is non-destructively merged with the initial decompilation.
Failed functions remain explicitly marked as failed; no missing Toyota
proprietary libraries are inferred to exist.

No Codex interaction, automated Git activity, or car firmware installation is
part of this workflow.

To run a single job for controlled testing: `python3 supervisor.py once`.
To verify current model connectivity: `python3 supervisor.py smoke`.

The durable log is `activity.log`. Queue state is `progress.sqlite3`.
Outputs are under `results/<SHA-256-prefix>/`: Ghidra manifests and C-like
reconstructions, extracted candidate strings and separate JSON model reviews.

## Boundaries and interpretation

**Decompiled is not fully reverse-engineered.** Ghidra detects plausible
functions and reconstructs C-like pseudocode with occasional wrong types,
missed entry points and timeouts. Qwen's summaries are untrusted leads and
must be verified against the recovered instruction bytes before adoption.

The factory GUI and original missing files are not yet recovered. EXT3/eMMC
partitions are strongly supported by original `PROC_REPRO` ARM code, but
we do not have a complete partition dump. Automated repeated KWI
signature-scanning cannot manufacture missing bytes or authentic drivers.

The queue may idle after inspecting every available known source; it then
checks periodically for newly recovered sources. It will not download, bypass
signatures, flash a vehicle, overwrite original binaries, or resolve missing
proprietary files without additional authentic input.

The supervisor process is independent of ChatGPT and does not itself report
back into this conversation. Inspect `status.sh` or `activity.log`.

## Resource behavior

The model is the pre-existing Windows Vulkan `llama.cpp` process, not a
second AI server. Its tray owns the memory/VRAM guards and manual On/Off.
The supervisor only runs **one** local task at a time, uses isolated
Ghidra projects, and avoids direct host device files. To pause at the next
job boundary run `bash stop.sh`.

Research model / prompts can be refined by editing `model_review.py` while
the local queue is stopped. All other files in the original CA01 repository
remain unchanged and uncommitted.
