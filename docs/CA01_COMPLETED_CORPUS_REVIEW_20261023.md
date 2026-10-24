# CA01 completed-decompilation review and new verified findings

This review audits the new completed export corpus, compares original versions,
and investigates practical progress toward original GUI execution. It preserves
the existing work-in-progress, original firmware, research databases and local-AI
state. No vendor executable ran on the host or radio. Original ARM instructions
ran only in bounded Unicorn slices with explicit memory-service models.

## Conclusion

The new outputs help substantially with **targeted code analysis and protocol
reconstruction**. They complete the discovered-entry export queue and make the
large display dispatchers and a previously missing HMI decoder body available.
They do not supply missing factory filesystem/configuration/flash data or
proprietary runtime providers. There is still no complete original menu startup.

A concrete new result is verified original DISPLAY serialization into HMI's
original property-record parser. Scalar and blob cases decoded their expected
arguments; invalid category and capacity cases stopped at original diagnostics.
The probe stops at the property-handler entry: it does **not** claim property
store mutation, shared IPC transport, scene evaluation, readiness or rendering.

## Scope and independently verified coverage

The current report is
`system-audit/ca01-local-ai-supervisor-20261023/MANUAL_EXECUTABLE_COVERAGE.json`.
Its generated timestamp is2026-10-23T23:45:10Z. `CURRENT_STATUS.md` is an older
snapshot and should not be treated as the final coverage result.

All 62 indexed original ELF input files were SHA-256 checked. The 49 selected
completed exports were independently checked against their expected input SHA,
manifest counts, function addresses and actual C-body markers. Every selected
catalogue entry has exactly one body marker; no missing markers or duplicate
addresses were found.

| Exported entry class | Count |
|---|---:|
| `.text` function candidates | 58,162 |
| PLT/import thunks | 7,945 |
| Other executable entries | 98 |
| Total completed entries | **66,205** |

These are versioned catalogue entries, not 66,205 unique verified source
implementations. There are 43,862 UU.11.34 entries and 22,343 retained UU.11.27
entries; 15,147 old entries repeat implementations from identical-code pairs.
Thirteen older redundant inputs were skipped by the prior workflow after
matching `.text` hashes.

All 21 paired executable comparisons were independently rechecked. Nineteen
pairs have identical `.text`; only `PROC_DISPLAY` and `PROC_VRS` differ in code.
The identical-code pairs have identical `.data` and `.dynsym`; small `.rodata`
changes are build date/time metadata. Example HMI:
`Nov 10 2017 17:05:22` -> `Apr 23 2018 18:25:48`.
Finishing a second decompilation of identical instructions does not add new
firmware functionality. The two genuinely changed pairs merit semantic diffing.

## Quality issues discovered

### One recovered function is absent from the current search index

The export report contains all 66,205 outputs, but the read-only SQLite index
currently reports66,204 decompiled and1 failed. The discrepancy is new HMI:

- Input SHA: `64f5d905a42aa844d60fcf2a3aed752ce5fd9df04e54a1a565d81b64307af62b`.
- Address: **`0x186210`**, original entry/body record 16,840 bytes.
- Latest recovered output:
  `results/64f5d905a42aa844/ghidra/failed-retry-01/merged-decomp/decompiled.c`.
- Index still selects older
  `results/64f5d905a42aa844/ghidra/merged-resume-1-reconciled/decompiled.c`,
  whose record for that address failed and has no body.

This is a stale index selection, not a failure to recover the output. The
indexed source and body hashes themselves remain consistent with the older
files they point to. No database was changed during this review. Future
research should use the current report-selected source, or narrowly reindex
that source while retaining the old export.

The FTS index only stores the first21,000 characters per body. Some 188 indexed
bodies exceed that limit, leaving approximately 4.05 million characters outside
FTS prefixes. A search-index miss does not establish absence from the full C.

### Completion is not semantic verification

Of 58,162 text-body regions, 4,200 contain Ghidra warning comments and 1,023 contain
"Could not recover" uncertainty, commonly jump-table recovery warnings. These
are review indicators, not a count of proven incorrect functions. Indirect
calls, unknown arguments, `extraout_` and `unaff_` values still require ARM-level
checking. No byte-range analysis proves that every true function in `.text`
has been discovered; inline literals/tables, overlapping or discontiguous
function bodies also prevent treating function byte sums as code coverage.

Eight DISPLAY entries have different byte counts in final manifests versus
supplemental C headers. The retry merges retained some original boundary/style
metadata. A24-byte header at old DISPLAY `0x119ee0`, for example, accompanies
117,750 characters of C that follow jump/tail targets outside that tiny body.
Independent disassembly confirms those branch targets. It is **not** evidence
of a24-byte empty replacement or proven truncation. Preserve original and retry
boundaries/options separately before relying on a reconstructed signature.
Some per-kind manifest summaries are also stale after merges; this review
recomputed totals from individual entries/section classes.

Predication-disabled Ghidra passes did not change firmware bytes, but their
output is not automatically equivalent source. The seven old manual TMD
validation cases concern a separate hand reconstruction, not the Ghidra body
counted by the completed corpus. Those tests must not be represented as proof
of all 66,205 outputs or of the counted TMD C body.

## What the final two DISPLAY functions do

### `PROC_DISPLAY`11.34 `0x23968`

This is a command dispatcher. Original ARM reads the message payload pointer at
message+12, checks payload length, obtains a word from payload+8 through
`fs_cnv_NtoWord`, and dispatches command IDs 0x10..0x23a through a 555-entry jump
table. There are 155 distinct targets, including a common default. Parent
`0x24c40` routes subtype0xf013 here. Several Ghidra apparent string literals are
actually small integer constants; independent original-byte disassembly was
used to resolve them.

This supplies protocol/state-machine logic for analysis. It does not contain
the missing graphics initialization or a newly recovered menu-resource archive.

### `PROC_DISPLAY`11.34 `0x2059cc`

The contiguous entry gate is 116 bytes, despite its much larger merged C-like
output. It checks a global guard and routes message+8 values 0/2 into existing
tail targets `0x205900` and `0x204a74`. The latter paths relate to media/USB/iPod/
LS1 operations. A large reconstructed body does not imply a hidden framebuffer
or complete screen definition. No graphics-provider or original asset recovery
was found in these last two functions.

## New authentic DISPLAY -> HMI record contract

Original DISPLAY11.34 scalar serializer **`0x27d3a4`** and blob serializer
**`0x27ddb0`** produce the same packed record layout:

| Record offset | Original field |
|---|---|
| +0 | LE16 total length = payload bytes+7 |
| +2 | Category byte |
| +3 | Domain/page byte; semantic label remains tentative |
| +4 | LE16 property identifier |
| +6 | Type 0 scalar, type1 blob |
| +7 | Payload bytes |

Raw producer buffer is at `0x12f66c0`; used length and record count are 16-bit
fields at `0x13046ee` and `0x13046f0`. Original validator `0x27d310` allows
category 0/domain<2, category 1/domain<126, category 2/domain<3. Original code
requires the current and resulting used offset to be<= `0xe02d`. Decompiler
strings such as `"DiagReq"` in these comparisons are mistyped numeric addresses.
These bounds were verified against actual ARM instructions.

Original HMI parser **`0xf3b0`** reads the same fields:

- Type 0 reads the unaligned LE32 value at record+7 and calls original scalar
  property handler **`0xe6c4(category,domain,property,value)`**.
- Type 1 calls original blob handler
  **`0xe214(category,domain,property,record+7,total_length-7)`**.

The bounded original-code probe verifies:

1. Scalar value `0x12345678`, category 1, domain 2, property `0x1234`: exact record
   `0b00010234120078563412`, then exact arguments at original HMI handler entry.
2. A 17-byte blob: exact original serialization, exact pointer/length/content
   decoded at the original blob handler entry.
3. Invalid category 3: original diagnostic `0xf0000030`, no completed record.
4. Insufficient remaining capacity: original diagnostic `0xf0000021`, no completed
   record.

Only bounded real memcpy is provided on the producer path; unknown imports
stop. Producer and parser execute in separate hash-gated Unicorn guests. The
probe carries record bytes between those guests explicitly. It does not
implement the absent production IPC service or manufacture a screen.

### Transport and state-store limits

DISPLAY submit `0x28fd04` calls missing-provider `hmiDrwInfSetLib` with ID 8/9,
raw buffer and length. It notifies with `hmiDrwInfSetNty` and toggles the ID only
when the low return byte is zero, then clears the raw batch buffer. HMI's
queue 0x29 path receives message 0x41002/subtype 2, maps shared IDs 8/9, locks/copies,
and parses a separate batch envelope: count LE16, copy length LE32, records +6.

**The raw producer buffer is not proven to contain that six-byte envelope.**
Its actual construction/transport belongs to the missing interface provider.
The record-only probe deliberately does not label a fabricated envelope as
original transport success. Original HMI store initializer **`0xf03c`** creates
its counters and sentinels; that is the correct next integration entry before
checking real property-store changes. Zero BSS is not a substitute initializer.

Additional recovered `libDIS_IF.so` notification wrappers use separate 40-byte
IPC headers with subtypes 0x10/0x11/0x12 and pool 2 payload ownership. These are
not HMI's 16-byte queue envelopes. Some wrappers ignore the send return value,
so their return 0 alone would not prove delivery. Exact excerpts and Capstone
proofs are retained with this review.

## Newly available HMI `0x186210`

The recovered large body contains stream-reading/resource-decoder logic, not
a direct missing OS service. Its input factory `0x17a380` consults a table at
`0x59fe48`: matcher `0x18a594` selects decoder `0x186210` for signature **`MB`**;
matcher `0x18a568` selects decoder `0x1844ac` for **`MT`**. The pointers and literal
bytes were checked against the original HMI. Four original-ARM matcher cases
(two accepted signatures and two cross-rejections) passed using bounded real
memcmp. Full decoder execution was not attempted, and these signatures alone
do not establish the complete MRA/MUI container schema.

This body is useful for following resource serialization/decoding and building
future format tests once real sample assets are available. It does not recover
the original asset bytes or establish the image of a factory screen.

## Blockers rechecked against all 62 original ELFs

A fresh dynamic-export check found no recovered definition for:
`sysDisMngInit`, `sysDisMngMemAlloc`, `rq_fls_Open`, `fs_drv_MemInit`,
`sysSecStartUp`, `hmiDrwInfSetLib`, or `hmiDrwInfSetNty`.
Recovered `libComFlmLb.so` still supplies `fs_flm_Read`. This is a statement
about this recovered input set, not proof those services are absent on a radio.

| Requirement | What completed decompilation adds | Still unresolved |
|---|---|---|
| `ipasz.conf` | Reader/parser and creation semantics are inspectable | Actual file contents and launch-directory context |
| NOR vehicle/profile data | Original read sites/ranges are known | Verified bytes for 0xb0000/0xc0000/0xd0000 |
| Display/HMI service transport | Exact record producers and consumers | Provider/envelope implementation and authentic IPC startup |
| Graphics/file services | More call sites and contracts | Missing providers and device behavior |
| Menu appearance | Code and resource-name/state references | Actual MUI/MRA/fonts and complete scene inputs |
| Runtime initialization | Wider task/process/state logic | Authentic parent configuration and completion of prerequisite services |

The previous 208-file source audit remains relevant: completed decompilation
introduced new C-like outputs, not new original NOR/config/menu files. No
replacement filename or renamed library resolves those missing inputs.

## Recommended next development work

1. Correct the stale HMI search-source selection and preserve accurate retry
   options/boundaries in a derived research catalogue. Keep existing exports.
2. Extend the new verified record handoff through original `0xf03c` initialization
   and original scalar/blob property stores, asserting changed values and
   ownership. This is the strongest next original-code integration milestone.
3. Trace the missing `hmiDrwInfSetLib` service/envelope contract separately from
   scene/asset decoding. `libhmi_if.so` is a candidate dependency; its exact
   provider ownership remains unverified without the library. Continue acquisition of authentic configuration,
   verified offline NOR data and menu resources in parallel with code analysis.

Do not spend another broad pass attempting already completed identical-code
exports, and do not report fixture rectangles or property messages as factory
home-screen success. A useful runtime subset can advance incrementally while
these specific absent inputs remain explicit.

## Artifacts, validation and Git state

Durable raw reports, diagnostic scripts, excerpts and original-byte proofs live
under `../system-audit/ca01-completed-corpus-analysis-20261023/`. Small source-
identity/coverage and bounded-execution reports are also under `evidence/`.

Validation this review: 62 original ELF hashes; 49 selected manifest/body checks;
21 version comparisons; all indexed source/body checks in independent audit;
four original property-record cases and four original MT/MB matcher cases.
Eight bounded original-ARM cases passed. No factory startup/rendering test
passed or was claimed. The existing 257-test application regression milestone
belongs to the preceding implementation turn; it is not relabeled as testing
all 66,205 C-like outputs. Runtime implementation files were unchanged here.

The current repository remains `main`, HEAD `0ede6b5`, with prior uncommitted work
preserved. This review adds documentation/small evidence only. No commit, push,
production deployment, radio access, firmware patch, AI restart or index change
was performed.
