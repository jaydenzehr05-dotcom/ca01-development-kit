# CA01 Path A — original-code access trace, 2026-10-23

## Result

No legitimate execution channel for the exporter has been established. This
pass narrows the candidates with original-code evidence. It does not prove a
service interface is absent from the full installed radio, because its factory
root filesystem and service configuration remain unavailable.

New positive finding: the recovered UI interface process DOES contain explicit
SLIP/IP networking over Bluetooth-backed serial devices. Earlier statements
that there was no evidence of IP over Bluetooth were too broad. There is still
no established SSH, login shell, maintenance file-export endpoint or mechanism
for launching an arbitrary program through that connection.

Originals were read only. No vehicle, network interface, Bluetooth service,
serial console, USB drive, flash device or recovered executable was accessed
or run. No exporter or emulator startup code was modified. The existing commit
0ede6b5af0f9e727ff467d490704f0bb2bfb52b9 was pushed at the user's request before
this separate investigation; the new results are external local artifacts.

## 1. USB backup import: unsuitable for read-only diagnostic execution

Original PROC_SYSTEM function0x2f2cc invokes0x2eb74 before configuration loading.
The latter opens `/dev/flash` read/write and checks a factory-state marker before
it attempts USB backup recovery. Function0x2ead0 tries VFAT at `/mnt/usb1` and
requires `13PFBACKUPDB.KWI` there.

Its actual operation is archive IMPORT into `/var/backup`, optional deletion
of existing backup entries from a companion list, version-file rename, and
flash erase/copy state updates. It is not a generic USB executable launcher,
read-only export command, or safe entrypoint for this task. No recovery archive
was fabricated and no marker was changed or proposed for activation.

The raw source excerpts are in `system-selected.c.txt`. The exact flash-marker
value is deliberately not presented as an activation instruction; the path has
been excluded from the read-only plan based on its writes.

## 2. Kernel-console lead: real names, missing interactive-login proof

The verified original1127 Boot component has environment data:

`con=console=ttyUSB0,115200 console=ttySC2,115200`

Other environment strings include `${con}` and an `/sbin/init` selection.
These are compiled boot-environment values, not a measurement of the installed
unit's active bootargs. They identify potential kernel-console names/baud rate;
they do not identify board pins, voltage levels, a getty, login credentials,
or an accessible interactive shell.

The recovered set does not provide complete `/sbin/init`, `/etc/inittab`, init
scripts or service configuration to settle the login question. A referenced
USB serial console is not proof an arbitrary USB connection to a computer works.
No connector, cable or test pad was probed.

Original libipas_sysc's `rq_sio_Open` (canonical0x1614c, Ghidra0x2614c) opens
indexed serial-device paths and configures raw termios and worker tasks. Its
TTY names are protocol/device APIs, not evidence of a login service. Likewise
`rq_drc_ReadStdout` (canonical0x19ac0) delegates to `fc_drc_RbfRead`, a diagnostic
ring-buffer reader. The name does not imply an interactive shell.

## 3. Ethernet lead: boot-gated networking, no recovered login server

The original `snap.sh` reads `/proc/cmdline`. Only when the parsed syslog type
is `NET` does it select an `ip=` address. Within its QuickBoot resume path,
when QuickBoot is enabled and the address differs from its none sentinel, it
loads `smc91x` and configures `eth0`.

This is evidence of an optional configured Ethernet/logging path. The script
does not start sshd, dropbear, telnetd or getty. It also performs storage,
graphics-driver and QuickBoot operations elsewhere: it must not be run as a
harmless network diagnostic. We did not change boot parameters or run it.
Exposed hardware, driver availability, actual configuration and login services
remain unverified.

## 4. Bluetooth/IP: genuine new software lead, phone-app context

Original1127 `PROC_UIEIF` SHA-256:
`e5eb7a2861f8747d82616f34a84023e4865d13944fe0cd3cd513a2e516e229f4`.

Its original ARM instructions load literal arguments and call `system` for:
- SLIP attachment over `/dev/ttyBT2` or `/dev/ttyBT3`.
- `sl0` with192.168.1.2/192.168.1.1 point-to-point addresses and MTU4096.
- Link teardown and slattach termination.

All six command-call sites were independently checked from MOVW/MOVT register0
argument loads followed by BL to the verified system PLT slot. Exact bytes,
addresses and strings are in `arm-network-witness.json`. No command was run.
The Ghidra handler contains noncontiguous basic blocks; its byte-count field
must not be treated as one contiguous address interval.

The selected original C-like functions0xdb54 and0xef38 show state-dependent
connection/service selection with these real resource labels:
- `Wireless iAP`
- `Peer Communication Framework`
- `HTTPServer`

The original queue15 dispatcher at0xf128 (`tsk_dmn_UifMng`) routes internal
messages to these handlers. They are not commands exposed on the external
Bluetooth link merely because their internal message cases are known.

The phone/application connection code uses `rq_apc_Cnct`, `rq_apc_AppInfNsw`
and `fd_uif_SetUieInf`. No definitions for these functions exist among the
hash-verified complete recovered ELFs. `libipas_apc.so` is explicitly required
by UIEIF and unrecovered; the original UI data provider is also missing.
`disBlSvcSetReq` is defined in recovered `libDIS_IF.so` at canonical0x7d44;
its wrapper requests service configuration via IPC rather than providing a
shell or a network request handler itself.

This supports a phone-app transport interpretation. The actual advertised
services, permitted peers/authentication, protocol request handlers and any
file functionality still need original provider code or legitimate documentation.
The HTTPServer label alone does not establish a web maintenance interface,
a port number, arbitrary filesystem access or permission to execute a program.
No Bluetooth profile probing, pairing, packet injection, port scan or network
connection was performed.

## 5. Existing process/script launch: internal mechanism, no user-facing hook

`rq_prc_Start` (canonical0x25450, Ghidra0x35450) resolves a configured process
pathname, forks and uses execv or a configured script branch. The path and mode
come from the original process table, loaded through `ipasz.conf` and the
system supervisor. Neither that real configuration nor a supported interface
for adding an exporter entry has been recovered.

The presence of fork/exec does not provide a way for a user to launch a new
program on stock firmware. Editing startup configuration would be a different
operation from establishing an existing read-only service interface; it was
not attempted as part of Path A.

## Candidate status and next evidence needed

| Candidate | Verified | Missing prerequisite / result |
| --- | --- | --- |
| USB mass storage | VFAT handling and backup recovery | No generic launch; recovered recovery path writes internal state, excluded |
| Serial console | Boot environment ttyUSB0/ttySC2 values | Active bootargs, physical mapping and actual getty/login configuration |
| Optional Ethernet | Boot/script-gated interface configuration | Exposed hardware and authenticated maintenance service |
| Bluetooth application networking | Original SLIP setup, service labels and internal dispatch | Missing APC/UI provider, external protocol/authentication and diagnostic endpoint |
| Configured script/process execution | Original fork/exec and configured script branch | Authentic config plus supported operator-accessible launch interface |

The most promising remaining software-only investigation is the original
phone/application provider and early-init/login configuration. Specific new
acquisition targets are `libipas_apc.so`, its corresponding UI configuration
provider, `/sbin/init`, `/etc/inittab` or equivalent startup/service files,
and the actual `ipasz.conf`/launch directory. These are requirements to resolve,
not evidence they all exist under those paths on the installed unit.

If these cannot be recovered from legitimate related material, Path A remains
conditional. A matching donor's read-only complete filesystem acquisition is
still the fallback for obtaining both missing services and menu assets. No
physical or vehicle action has been undertaken or authorized by this trace.

## Reproduce and validation

Run only the static verification script, not the original shell script:

```sh
/home/starlight/projects/rav4-radio/ca01-development-kit/.venv/bin/python \
 /home/starlight/projects/rav4-radio/system-audit/ca01-path-a-access-trace-20261023/verify_access_paths.py
```

The script checks59 complete recovery records representing56 distinct paths,
original hashes, the selected decompilation provenance, six ARM command-argument
witnesses, USB backup write operations, console strings and the QuickBoot/network
predicates. It writes only its own evidence files. It never executes original
firmware, shell text, a device operation or an AI worker.

Ghidra output remains C-like reconstruction with inferred types. Static branch
presence is not proof of runtime activation. Negative string searches are bounded
to the recovered subset, not the full factory filesystem.
