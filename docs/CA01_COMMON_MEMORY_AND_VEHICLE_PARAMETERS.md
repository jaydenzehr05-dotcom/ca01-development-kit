# CA01 common memory and vehicle-parameter producer

This continues the NULL-source boundary in `CA01_GUEST_PTHREAD_BRIDGE.md`.
Original ARM instructions now identify the pointer initializer, shared-memory
layout, real producer, flash-read arguments and first unresolved semaphore.
No authentic vehicle parameters were recovered or fabricated. No full startup,
radio access, host IPC, firmware change or rendered Toyota frame is claimed.

## Investigation and implementation checkpoints

- [x] Trace the original getter and identify its pointer writer.
- [x] Compare the recovered producer and consumer libraries without assuming
  their identically named exports have interchangeable behavior.
- [x] Execute original mapping and pointer-initialization slices against bounded
  virtual shared memory; retain missing-object and unverified-data barriers.
- [x] Bind the genuine recovered flash provider and record its first blocking
  operation; independently inspect its device-initialization boundary.
- [x] Test original layout agreement, byte-exact explicitly synthetic copies,
  missing initialization and rejection of unsupported inputs.
- [ ] Complete the full parent process/configuration/IPC startup. This remains
  outside the verified slices below and cannot be inferred from their success.

## Verified producer and consumer roles

| Operation | `libipas_sysp.so` producer | `libipas_sysc.so` consumer |
|---|---|---|
| `fc_sys_InitComAdr` | ELF `0x16548`; unlinks `/SHM_SYS_COM`, opens with `0xc2` (`O_RDWR|O_CREAT|O_EXCL`), mode 0666 | ELF `0x171b0`; opens the existing object with `2` (`O_RDWR`) |
| Mapping | Truncates to `0x208000`, maps read/write/shared | Same length/protection/sharing |
| `fs_sys_ExPreInit` | ELF `0x1648c`; links common-memory regions into private globals | ELF `0x170f4`; corresponding links |
| `rq_sys_LoadVclPara` | ELF `0x18010`; real flash-backed loader | ELF `0x165d4`; genuine one-instruction `bx lr` |
| `rq_sys_GetVclPara` | ELF `0x15c20`; copies 256 bytes | ELF `0x16888`; copies 256 bytes |

These roles are independently verified for these functions. They are not a claim
that the libraries are drop-in replacements. `PROC_SYSTEM` names
`libipas_sysp.so` as a direct dependency. Ghidra's shared-library listings add
`0x10000` to the ELF-relative addresses above; the execution probe adds its own
explicit `0x10000000` library bias.

Original `fs_sys_ExPreInit` calls `fs_sys_GetComAdr(16, &bf_sys_VclPara, 256)`.
Both original libraries construct exactly the same 60-entry region table.
Region 16 has offset **`0x2ddb8`**, length **`0x100`**, in `/SHM_SYS_COM`.
The producer trace records the pointer write at emulated PC `0x10016430` within
the original getter, storing `0x4002ddb8` into its private `bf_sys_VclPara`.
The `0x40000000` mapping address is an emulator choice; the offset and length
come from the original ARM region-layout code and its embedded table.

Mapping and pointer setup fix the explanation for the NULL source. They do not
supply valid parameter bytes. A freshly created POSIX object is zero-filled;
that alone is not evidence of an initialized vehicle profile. The new probe
rejects reads of those bytes unless a test explicitly labels the region as a
synthetic fixture. Such fixture data is always reported as unauthentic.

The enclosing consumer `fs_sys_InitCom` still stops first at missing
`fs_drv_MemInit`. Calling its recovered subfunctions independently is an
explicit research slice, not a successful enclosing initialization.

## Actual producer read and flash dependency

Original producer `rq_sys_LoadVclPara` first calls:

```c
fs_flm_Read(vehicle_parameter_destination, 0x000b0000, 0x100);
```

The first argument is the region-16 destination. The second is a flash address/
offset argument, not a pointer to an input file and not an offset into the KWI.
The saved trace reaches this exact import when no flash provider is bound.

The correct provider, **`libComFlmLb.so`**, is already recovered. With its
hash-verified ELF mapped and original GOT relocations resolved, execution enters:

1. Producer `rq_sys_LoadVclPara`.
2. Recovered `fs_flm_Read` at ELF `0x12e0`.
3. Recovered `fc_flm_CheckRange`, validating against the 8 MiB address range.
4. Producer's original `rq_psm_Take(25)`.
5. Original diagnostic **`0xb6000006`, semaphore 25**, because that named
   semaphore slot is uninitialized.

The probe stops at the original diagnostic entry and records its arguments. It
never returns an invented logging success or continues into force-standby.
No semaphore token was invented and no flash read occurred. The existing parsed
process/named-semaphore configuration and initialization remain required.

In a separate isolated probe, original `fs_drv_FlmInit` at ELF `0xfac` reaches
`open("/dev/flash", 2)` at emulated return address `0x20000ff8` and stops.
There is no host `open`, device creation, ioctl or flash action. Earlier static
research identifies the subsequent chip-kind ioctl `0x8001ff01`, while the
read wrapper uses `0x4004ff10` and semaphore 6. Those later operations were not
reached by the new initialization probe; see `CA01_HARDWARE_INTERFACES.md`.

The producer's nearby `rq_sys_SetVclTypAll` additionally reads flash ranges
`0xc0000`/`0x25f4` bytes and `0xd0000`/`0xa261` bytes into the type/profile
region. These are **static Ghidra observations**, not additional executed reads.
Completing the producer will require these tables too, not merely the first
256 bytes. No matching original flash snapshot has been established here.

## Probe, fixtures and limits

`tools/ca01_common_memory.py` runs single-library slices, optionally binding the
real flash provider. It validates SHA-256 before ELF parsing/emulation, uses
explicit supported ARM relocations, limits instructions/time, traps unknown
services, and models only the exact virtual shared-memory contract. It never
patches vendor text. Consumer and producer are separate guests; this does not
establish live cross-process mapping, parent handshakes, constructors, task
activation, display readiness or complete startup.

An exact-length snapshot may be supplied through the Python test interface.
Snapshot presence alone does not mark its content as verified. Explicit fixture
labels allow a selected region's reads for synthetic byte-copy tests only.
The CLI has no fixture-unblocking option and never supplies real vehicle data.

Run from the repository:

```sh
.venv/bin/python tools/ca01_common_memory.py \
  --sysc ../system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so \
  --sysp ../system-audit/ca01-updater-independent-20261022/06-libipas_sysp.so \
  --flash ../system-audit/ca01-updater-independent-20261022/06-libComFlmLb.so \
  --output /tmp/ca01-common-memory-new-trace.json
.venv/bin/python -m unittest discover -s tests -p 'test_ca01_common_memory.py' -v
```

Outputs use exclusive creation. Input libraries remain unchanged. The saved
trace is `evidence/ca01-common-memory-20261023.json`.

## Next useful work

Recover or trace the parent named-semaphore configuration and initialization
before resuming the real producer beyond semaphore 25. A verified offline NOR
snapshot or independently recovered original parameter/profile tables would
then permit a bounded read-only flash model. Until then, retain the content
barrier; a generic all-zero profile would hide the real dependency. Factory
menu assets and `sysDisMngInit` remain separate unresolved GUI requirements.

## Validation

All **17 focused common-memory/flash-provider tests** passed. The complete
regression suite passed **240 tests, zero failures or skips**, in 35.688 seconds.
The four original HMI/SYSC/SYSP/flash input hashes were rechecked and unchanged.
`git diff --check` passed; new files were also checked for trailing whitespace.
Changes remain uncommitted on `main`, HEAD `0ede6b5`. No remote action occurred.

## Parent semaphore follow-up

[CA01_PSM_STARTUP_AND_FLASH_SOURCE_AUDIT.md](CA01_PSM_STARTUP_AND_FLASH_SOURCE_AUDIT.md)
records original producer parsing and the original parent creation-loop slice.
With explicitly synthetic rows6/25, the loader reaches the unresolved flash-read
ioctl; its descriptor is uninitialized. Authentic configuration and flash data
remain absent. A scoped208-file hash-verified audit found no candidate NOR image
header or verified parameter source. The240-test result above is the earlier
common-memory milestone; the follow-up report records its own validation.
