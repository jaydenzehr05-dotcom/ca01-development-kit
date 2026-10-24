# CA01 startup and completed-corpus follow-up — 2026-10-23

This integrates the existing Codex startup work and relevant newer GPT/local
research into the existing `main` history, based on `0ede6b5`. The earlier
514-artifact consolidation remains unchanged. This follow-up preserves the
original local research directories and the separate updater research worktree.
No physical-radio access, firmware modification, flashing or security-validation
change was performed.

## New integrated work

- Original ARM queue execution, guest task/thread identities, task readiness and
  parent synchronization probes now share the verified 16-byte message contract.
  The queue preserves 64 entries, FIFO behavior, original timeout/error paths and
  payload ownership. Bounded service models stop at unknown operations.
- Original producer/common-memory and parent semaphore parsing/creation are
  exercised with explicitly synthetic configuration. The real semaphore setup
  reaches the flash-read boundary; an uninitialized descriptor is never treated
  as successful hardware initialization. The 208-file source audit found no
  verified NOR parameter source.
- The maintained USB exporter supersedes the older archived prototype. It uses
  directory descriptors, nofollow opens, bounded copies and a freestanding ARM
  EABI build. Review identified a nested destination/bind-alias overlap case.
  A new regression reproduced recursive self-copying before the fix; every
  opened child is now checked for output overlap before creating its destination.
  The direct-walker regression models the alias inode without requiring a mount.
  It does not claim physical mount or radio verification.
- The completed-corpus review independently distinguishes all **66,205 exported
  catalogue entries** from verified source or runnable firmware. It preserves
  the final retry provenance and records the stale HMI `0x186210` search-index
  selection, truncated FTS prefixes and remaining decompiler uncertainties.
- New bounded original ARM probes verify DISPLAY scalar/blob record serialization
  into HMI parser arguments, stopping at original handler entry. Resource-format
  matcher evidence also identifies the MB/MT decoder selection. Neither result
  establishes a working property store, production transport, scene or factory GUI.

See [completed-corpus findings](CA01_COMPLETED_CORPUS_REVIEW_20261023.md),
[original queue integration](CA01_ORIGINAL_QUEUE_INTEGRATION.md),
[guest threads](CA01_GUEST_PTHREAD_BRIDGE.md),
[parent/barrier handling](CA01_TASK_BARRIERS.md),
[common memory](CA01_COMMON_MEMORY_AND_VEHICLE_PARAMETERS.md), and
[parent semaphore/flash-source audit](CA01_PSM_STARTUP_AND_FLASH_SOURCE_AUDIT.md).
Individual earlier reports retain their historical test counts and then-current
uncommitted/no-push observations; this document describes the integrated release.

## New GPT research snapshot and provenance

`research/independent-audit/2026-10-23-followup/` contains **115 new or changed
source/evidence files** (608,786 bytes before its README). These include retry
and Ghidra scripts, completion reports, bounded manual TMD reconstruction,
diagnostic-access analysis, missing-provider searches and corpus-audit tools.
The **38 new/changed model review results are unverified hypotheses**.
No local model was started or delegated to during consolidation.

`evidence/ca01-independent-audit-followup-20261023.json` records original paths,
sizes and hashes; 109 exact-content references avoid duplicate copies, and three
superseded baseline references resolve to final annotated traces. Prior artifacts
remain intact. Archived scripts retain original local dependencies and paths;
some can launch tools or update research state and must not be executed implicitly.

Full generated decompilations, Ghidra projects, recovered original executables,
large firmware/source archives, live SQLite research databases, compiled exporter
outputs and rendered frames remain outside Git. The final coverage report and
`evidence/ca01-completed-corpus-audit-20261023.json` identify selected external
C/manifest paths and hashes. This release adds no new original-firmware blobs.

## Fresh release verification

- Full maintained suite: **258 passed**, zero failures or skips, 36.717 seconds.
  Command: `.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v`.
  Local log: `/tmp/ca01-publish-regression-20261023.log`.
- Exporter: 17 tests, including host and ARM/QEMU synthetic copies, no-glibc ABI
  checks, refusal paths and the new recursive-walk overlap regression.
- Archived retry/version policy: six tests passed against the archived modules;
  existing idle research DB read in immutable/read-only mode. No supervisor,
  Ghidra retry, local model or index update was launched.
- Four fresh original ARM record handoff checks passed: two positive serializer/
  parser cases and two diagnostic negative cases. These stop at handler entry.
- All 115 copied archive/source SHA-256 hashes, 109 deduplication references and
  three superseded trace references verified; archived JSON and Python syntax
  parsed successfully. No credentials found in the scoped token-pattern review.
- Independent runtime review found no substantive issues in queue/thread/common
  memory/barrier/PSM code. Exporter review found the overlap defect described above;
  its failing regression and correction are included. The independent reviewer
  confirmed the correction and reran all 17 exporter tests with no remaining
  substantive findings.

## Remaining blockers and next useful work

The strongest next executable milestone is original HMI property-store
initialization at `0xf03c`, then scalar/blob store mutation with ownership and
negative checks. The verified record handoff is its input boundary. Keep the
missing `hmiDrwInfSetLib` envelope/transport provider separate from that milestone.

Authentic `ipasz.conf`, NOR vehicle/profile bytes, display/file/security service
providers and factory MUI/MRA/font assets remain unrecovered. Complete export of
available functions cannot recreate those missing original data bytes. The stale
HMI search-source selection needs a separately controlled derived-index update;
this release preserves the live research database unchanged. Full original GUI
startup and a verified read-only radio execution channel remain unachieved.
