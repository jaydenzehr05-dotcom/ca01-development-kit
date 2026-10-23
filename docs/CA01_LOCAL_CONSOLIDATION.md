# Verified local CA01 consolidation

The local main integration combines the published research commit `a562b3b`, all20 subsequent research worktree files, the11 emulator files from main, and the supplied related-firmware investigation. Main started at `e30031d`; there was no existing unpushed integration commit to amend. One local integration commit is used. The research branch/history and its uncommitted contents are preserved unchanged; no remote branch is updated.

## Preserved research and artifacts

- All59 complete recovered firmware files retain their original sizes and SHA-256 hashes:21 ARM executables,20 ARM shared libraries,18 other files.
- All82 preserved partial-recovery artifacts and39 security-search artifacts match their manifests. Complete files and partial/unknown data remain distinct.
- Original1127 KWI and both manufacturer source archives retain their original SHA-256 values.
- The new DENSO TEN source ZIP and four bulletins match their five download-manifest hashes; all95 ZIP CRCs pass; all63 selected source files match the nested archive bytes.
- The source archive/kernel comparison and Evo Bluetooth interfaces are integrated with explicit compatibility limits and corrected unsupported claims. See [related firmware/sources](CA01_RELATED_FIRMWARE_AND_SOURCES.md).
- Original-source release links remain in README. Large archives, recovered Toyota binaries, root filesystems, images and runtime logs stay outside Git. The two small pre-existing self-authored ARM probes remain intentional emulation fixtures; the old dist ZIP is labelled historical.

Before integration, working-file archives, hashes, branches, HEADs, staged/unstaged diffs and statuses were recorded for both worktrees. The snapshots and new runtime/graphics verification logs are preserved under:

`/home/starlight/projects/rav4-radio/system-audit/ca01-consolidation-20261022/`

## Tests and actual runtime checks

The complete integrated suite passes **71/71 tests**, with zero failures. Four new regressions were observed failing before the interpreter validation fix and passing afterward. The sandbox now rejects static executables, custom interpreters, malformed program-header ranges, and static shared objects posing as approved trace targets. All executable trace inputs require the canonical `/lib/ld-linux.so.3` interpreter before staging.

Fresh Bubblewrap/QEMU loader traces succeeded for all three approved programs:

| Target | Resolved names | Unresolved names |
|---|---:|---:|
| PROC_HMI |15|17|
| PROC_DISPLAY |22|47|
| PROC_REPRO |13|18|

These are runtime-loader observations including reachable transitive libraries, not direct DT_NEEDED totals or proof applications can execute. The recovery-only inventory still has89 absent required names across41 ELFs. The installed ARMEL filesystem comparison reports78 unresolved unique names; it is a filename comparison, not a full ABI test. Debian ARMEL and ARMhf shell fixtures both passed basic QEMU checks; their `uname` output reflects the host kernel and does not prove a full ARM system boot.

A freshly cross-compiled self-authored graphics diagnostic ran offline in Bubblewrap without vendor files or host GPU/display devices. Mesa softpipe reports EGL1.4 / OpenGL ES-CM1.1. The800×480 output passed an exhaustive384,000-pixel comparison; PPM SHA-256 is `31d1e86be3ee064feda143cdaebf0755d4bacb0971f345d607d942698fdc3312`. This is a diagnostic pattern, not the Toyota GUI. The existing external PNG was visually inspected and matches that pattern.

A separate self-authored ARM guard called both constructor and main in normal isolated execution, while loader-trace mode skipped both. Actual recovered Toyota targets were inspected only with trace mode in the read-only, offline sandbox. No physical radio or flash-writing tool was used.

The original graphics source and all original middleware research are preserved. The historical Zig graphics-startup failure remains unresolved; the working diagnostic uses the distribution GCC cross compiler.

## Current limits and next steps

1. Obtain legitimately accessible additional firmware/rootfs material containing `libsecurity.so`, vendor IPC/system libraries and graphics interfaces. No1134/Plus/Premium image has been obtained.
2. Match newer Evo source interfaces to actual CA01 binary callers before considering any isolated service fixture. No new provider or ABI compatibility is established.
3. Use the working authored renderer to investigate legacy GLES/OpenVG/display integration once dependencies are understood. The stock Toyota GUI and original kernel/rootfs boot remain unverified.

Machine-readable verification: `evidence/ca01-local-consolidation.json`. The full test command is recorded there. Source and runtime capabilities remain separate from firmware authentication, hardware compatibility and deployment. Nothing was pushed.
