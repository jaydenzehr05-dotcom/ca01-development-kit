# Original parent semaphore setup and offline flash-source audit

The semaphore-25 blocker is now traced through original configuration parsing,
original `PROC_SYSTEM` creation-loop instructions and original named-semaphore
wrappers. The execution uses explicitly synthetic configuration names and
values; the actual radio's `ipasz.conf` remains unrecovered. A scoped audit of
208 recorded files found no verified NOR parameter source.

## Implemented checkpoints

- [x] Recover producer parser allocation, row addressing and token behavior.
- [x] Execute the real parent semaphore-creation loop against parser output.
- [x] Implement bounded virtual named semaphore ownership, count changes,
  unlink/create behavior and timed-wait failure without host IPC.
- [x] Trace original vehicle-parameter loading beyond semaphore25 to
  semaphore6 and the exact unresolved flash-read ioctl.
- [x] Audit held manifests and statically investigate the original flash-image
  tools to distinguish usable image metadata from misleading filename/offset
  or embedded-signature matches.
- [x] Add regression tests for missing configuration, row-vs-ID behavior,
  real original wrapper behavior, first unknown operation, and source audit.
- [ ] Recover authentic configuration, flash-device state and parameter bytes.
  Those requirements are not marked successful by the test fixtures.

## Configuration and creation contract

The recovered producer `libipas_sysp.so` exports these ELF-relative functions:

| Function | Address | Verified behavior |
|---|---|---|
| `fc_cnf_Init` | `0xb86c` | Opens relative `ipasz.conf` with mode `r` |
| `fc_cnf_Main` | `0xb728` | Parses section transitions and dispatches rows |
| `fc_cnf_ReadyTypPsm` | `0xb5ec` | Allocates/zeros `0x800` bytes for64 rows |
| `fc_cnf_LoadTypPsm` | `0xb144` | Appends32-byte rows; stores enabled word, numeric word and24-byte name field |
| `fs_psm_Init` | `0x25a80` | Zeros the64-entry semaphore-handle table |
| `rq_psm_Create` | `0x25ea4` | Unlinks the supplied name, then calls `sem_open(name,0xc2,0666,1)` and stores its handle by supplied slot |
| `rq_psm_Take` | `0x25cc8` | Rejects missing handles; otherwise uses a30-second realtime timed wait |

The numeric word parsed from `psmid=...` **does not select the table slot**.
The row's sequential position does. Original parser tests set the numeric word
to51 while enabling rows6 and25. The real parent loop creates slots6 and25;
slot51 remains disabled. Fixture spellings satisfy the observed parser offsets;
they are not claimed as recovered production configuration text. Original
parser prefix matching and lack of general bounds validation are unchanged;
the fixture adapter accepts only bounded synthetic rows and names.

The parent loop resides in original `PROC_SYSTEM` helper `0x2f2cc`. The isolated
slice is **`0x2f410` through before `0x2f4f4`**, where the SHM-creation loop starts.
It iterates all64 row positions and calls `rq_psm_Create(index,name)` only for
rows whose enabled word equals1. Original text is unchanged. The probe maps
hash-verified executable bytes, supplies the parsed pointer at the executable's
`tb_sys_PsmInf` COPY-input location, and binds only the three PLT dependencies
needed by this slice. It stops at the end marker before subsequent startup.
It does not claim full ELF loading/interposition, constructors, earlier
hardware checks, process creation, inherited descriptors or real parent boot.

The virtual semaphore backend creates owned guest handles with **initial count1
from the original sem_open arguments**. Original take/give wrappers decrease
and increase those counts. With no concurrent actor posting an empty semaphore,
the virtual clock reaches the original deadline, returns ETIMEDOUT110 via
modeled errno, and original code reaches diagnostic `0xb6000007`. Missing handles
still produce original diagnostic `0xb6000006`. No unknown wait returns success.

## Next original operations reached

After original parsing, manager initialization and the parent creation slice:

1. With only fixture slot25 enabled, original `rq_sys_LoadVclPara` passes that
   lock, enters real recovered `fs_drv_FlmRead`, then stops at diagnostic
   **`0xb6000006`, slot6**.
2. With fixture slots6 and25 enabled, it reaches unresolved **`ioctl`** with
   request **`0x4004ff10`**. The original three-word request contains destination
   `0x4002ddb8`, source flash address/offset **`0xb0000`**, length **`0x100`**.
   The mapping address is an emulator choice; the offset and length are original.
3. The descriptor is **0 and uninitialized**. This is an isolated exploratory
   loader call, not a successful flash initialization or valid device request.
   The ioctl is never forwarded to the host and no data is returned.
4. An independent original `fs_drv_FlmInit` call still stops at
   **`open("/dev/flash",2)`**. No success or chip kind is invented to bypass it.

The `last_ioctl` report labels `initialized_device=false`. No authentic config,
flash contents, display readiness, Toyota pixels or full startup is claimed.
The common-memory content-read guard remains intact.

## Offline source audit and fresh Ghidra findings

`tools/ca01_flash_parameter_audit.py` reads the recorded complete recovery
manifests for1127,1134 and additional recovery, plus both versions' component
and carved-payload manifests. It verifies each assessed file against its
recorded size and SHA-256. Historical `/tmp` paths are resolved only to the
matching basename beside the manifest; every such resolution is recorded and
then hash/size verified. It does not scan every file on the workstation or
repeat the prior recursive manufacturer-source archive search.

Result: **208 files checked, zero hash/size/read errors, zero candidate NOR
image headers, zero verified parameter sources.** The signature occurs in six
copies of the two recovered utilities, at internal executable data offsets;
none starts with an image header. Large raw/KWI/carved-payload files are not
assigned a NOR base address merely because their size includes `0xb0000`.

Fresh Ghidra analysis of recovered `FlashImageCreater` and `FlashImageWriter`
finished without decompilation failures. Their discovered entries comprise
**39 text bodies,59 import thunks and4 other executable entries**. This does
not establish complete function discovery or semantic correctness of every
reconstruction. Neither executable was run.

Verified static image-format facts:

- Creator `0x93bc` writes a **128-byte header**, followed by the selected input
  bytes. Its device-read helper `0x94ac` uses end-minus-start as the range length.
- Creator `0x97d0` uses the same flash-read ioctl `0x4004ff10` and a three-word
  request; its main can alternatively package an existing input file. The
  creator therefore does not establish that a named output was read from radio
  hardware. Unused write/erase code is also present; do not treat it as an
  approved safe acquisition executable.
- Writer `0xa590` reads128 bytes and compares the beginning as a C string to
  **`13Cy-NOR-FLASH-IMAGE`**. Writer `0xa61c` prints start/end at header offsets
  `0x20`/`0x24`, model/destination at `0x28`/`0x2c`, CRC32 at `0x30` and a version
  string at `0x34`. Creator `0x9df8` sets the CRC field at `0x30`.
- These are facts about the recovered utility's format. A header match alone
  would not verify CRC, model compatibility, authenticity or applicability to
  this unit. The audit deliberately does not promote a header candidate into
  a verified parameter source.

The needed read-only data remains:256 bytes at `0xb0000`, profile table bytes
`0xc0000..0xc25f3`, and `0xd0000..0xda260`, with independent provenance and
correct NOR address mapping. A matching offline image could supply them; none
is established in the inspected inventories. Do not extract KWI file offsets
with those numbers as a substitute.

## Reproduction and evidence

```sh
.venv/bin/python tools/ca01_psm_startup.py \
  --sysp ../system-audit/ca01-updater-independent-20261022/06-libipas_sysp.so \
  --flash ../system-audit/ca01-updater-independent-20261022/06-libComFlmLb.so \
  --system ../system-audit/ca01-updater-independent-20261022/06-PROC_SYSTEM \
  --output /tmp/ca01-psm-new-trace.json
.venv/bin/python tools/ca01_flash_parameter_audit.py \
  --research-root /home/starlight/projects/rav4-radio \
  --output /tmp/ca01-parameter-source-new-audit.json
```

Compact evidence is saved as `evidence/ca01-psm-startup-20261023.json` and
`evidence/ca01-flash-parameter-source-audit-20261023.json`. Full generated Ghidra
reconstructions/manifests and logs remain outside Git under
`../system-audit/ca01-psm-and-flash-source-20261023/`. No original binaries or
large firmware/source archives are added to the repository.

Next: authentic `ipasz.conf` names/rows and a verified offline NOR data source
remain the useful acquisition targets. The original semaphore setup is now
understood and tested; additional synthetic successes will not recover those
bytes. Missing display services and factory GUI assets remain separate needs.

## Final verification and repository state

All11 new original-parser/PSM tests and6 source-audit tests passed. The final
full suite passed **257 tests with zero failures or skips in37.727 seconds**.
Independent review identified one duplicate manifest-identity conflict bug; a
failing regression reproduced it, the fix passed, and the reviewer confirmed
it resolved with no remaining substantive findings. The reviewed208-file audit
still reports zero errors and zero candidate NOR headers.

Original producer, parent, flash-library and both utility hashes were rechecked
and unchanged. `git diff --check` and new-file whitespace checks passed. The
change in `ca01_common_memory.py` adds an overridable approved-function whitelist
for the derived research probe; the default allowed functions and content guards
remain unchanged. Earlier evidence is preserved as historical snapshots; the
new evidence includes current implementation hashes.

Everything remains uncommitted in the existing `main` working tree at HEAD
`0ede6b5`. Prior exporter, queue, startup and other-chat work was preserved. No
Git remote action, vehicle access, firmware change or security bypass occurred.
