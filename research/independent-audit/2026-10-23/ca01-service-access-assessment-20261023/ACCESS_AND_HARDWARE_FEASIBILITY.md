# Toyota CA01: Read-only Diagnostic Access + Physical Hardware Assessment

2026-10-23. This report reflects original, hash-gated firmware source evidence plus the public FCC exhibits.
No original KWI was edited; no vehicle connection, flash/update or main Git operation occurred. Codex was not used.

## Answer

Adding a minimalist diagnostic function would be a technically reasonable objective **after** confirming a
permitted way to launch additional code. An unsigned "fake" CA01 update is not currently a plausible
low-risk deployment method. The recovered updater uses AES/RSA public-key initialization,
SHA-256 hashing and RSA-PSS signature checks. There is no verified vendor signing key, accepted
third-party plugin package, or exposed diagnostic shell. A minimal new file still needs to be
authenticated and started; it does not inherently avoid changing the boot/run configuration.

At present the best output channel is existing host-mode USB mass storage, not a new USB gadget
driver, wireless SSH, or an ordinary host-to-host USB cable.

## Original-firmware evidence (validated read-only, source addresses)

| Evidence | Original file | Meaning / limitation |
|---|---|---|
| 0x1e94c, 0x1e9c0 | PROC_REPRO | Public-key initialization and SHA-256/RSA-PSS verification routine |
| 0xa9bc and 0xdec0 | PROC_REPRO | Calls hash/signature verify after AES processing; errors "Sign Check" |
| 0x2ead0 | PROC_SYSTEM | Tries mount(..., "/mnt/usb1", "vfat", ...) |
| 0x2eb74 | PROC_SYSTEM | USB path /mnt/usb1/13PFBACKUPDB.KWI extracted to /var/backup; *import*, not exporting root filesystem |
| 0x468e0 | PROC_SYSTEM | libusb-0.1 enumeration and usb_open |
| 0x1b048 | PROC_REPRO | /dev/mmcblk0p1/p2 EXT3, /var/verup, bind-mount of existing / |
| 0x1b2b8 | PROC_REPRO | mkfs.ext3 and selected partition updater operation |
| 0x159f8 / 0x15c44 | PROC_REPRO | /dev/mmcblk0p3 EXT3 mounted at /opt/ftl/cddb |
| /dev/mmcblk0p5 | Original snap.sh | Backup volume, mounted as tfat at /var/backup in QuickBoot path |
| /dev/mmcblk0p6 | Original snap.sh | Logs volume, tfat at /var/log |
| /dev/mmcblk0p8 | Original snap.sh | FUSE backup/cache storage used for previous volumes |
| /dev/mtdblock0 | Original snap.sh | Created with mkfs.ext2 and mounted at /var/db; do not assume persistent NOR |
| 2.6.35.7 module paths | Original snap.sh | Snapshot of expected driver module tree, not proof of current installed kernel |
| syslog_typ=NET, smc91x, ifconfig eth0 | Original snap.sh | Optional diagnostic Ethernet path controlled by kernel boot parameters; no exposed RJ45 proved |
| USB host stack and Bluetooth firmware component | multiple originals | Existing physical interfaces, no proof of USB gadget, SPP, PAN, PPP or SSH support |

The original Ghidra reconstruction is C-like pseudocode, not byte-exact recovered C source.

## Hardware

The radio assembly 86140-0R170 is confirmed for 2017 RAV4/Entune Audio IDs 100573/100581
in Toyota parts records. Used matching units show Fujitsu Ten FCC models FT0049A/FT0049B.
FCC FT0049B exhibits show physically separate audio, CPU, left/right switch, Bluetooth PCBs.
The Bluetooth board uses a shielded ALPS UGXZE-102A module. A removable service SD slot
or exact eMMC pinout was NOT demonstrated by these photographs. The motherboard is populated
with multiple SMD ICs and board-to-board ribbon/edge connectors, but their electrical roles
cannot be reliably inferred from the low-resolution photographs.

Actual board/circuit schematics, manufacturing test-point map, board power/ground pinout
and electrical memory part number remain unavailable in primary public exhibits.
FCC FT0049B lists a long-term confidentiality request; its public filings expose
board photographs, RF testing, labels and an operating manual, not an official netlist.

Do not treat SD/microSD found on NAVIGATION-equipped RAV4 variants as evidence that
this non-navigation 86140-0R170 has a removable card.

## Downloaded official FCC exhibits (unchanged originals)

* fcc-docs/BABFT0049B-CPU-boards.pdf
  - https://fccid.io/BABFT0049B/Internal-Photos/05-2-Internal-Photo-Equipment-FT0049B-1938910.pdf
  - SHA256 e379eda2096a5ca8cf3df9c541d853b07757225b974503100cab6ecd32c91ea5
* fcc-docs/BABFT0049B-Bluetooth-ALPS-UGXZE-102A.pdf
  - https://fccid.io/BABFT0049B/Internal-Photos/05-3-External-Internal-Photo-Bluetooth-FT0049B-1938911.pdf
  - SHA256 ecffa7d318cb283e268832dc5dbd1121f35e49e23dcecda3e9399af11a612ea7
* fcc-docs/BABFT0049A-boards.pdf
  - https://fccid.io/BABFT0049A/Internal-Photos/TempConfidential-05-2-Internal-Photo-FT0049A-Rev01-1938326.pdf
  - SHA256 bf86aaefc8ce7c986b6aa9d4ee2f526c649cae0ce238c30adda19deac220c5d1

FCC exhibit listing:
https://fccid.io/BABFT0049B
https://fccid.io/BABFT0049A

Toyota 2017 RAV4 *vehicle wiring* diagrams (not motherboard schematics) are available
through subscription Toyota TIS: https://techinfo.toyota.com/
Official Toyota support confirms Repair Manuals and Electrical Wiring Diagrams are included.

## Built now: isolated USB read-only exporter PoC

* Source: ca01_readonly_exporter.c
* Host test binary: ca01_readonly_exporter_host
* Statically linked ARM EABI5 test build: ca01_readonly_exporter_armel_static
* Tests: test_offline_exporter.py and offline-exporter-test.json

The fixed-whitelist program recursively reads original GUI/resources/fonts/libraries
and selected configuration paths, copies only to an explicit existing output directory,
performs a dry-run by default, refuses nonempty destinations/overwrites, skips symlinks
and never writes to input paths. It neither starts a service nor enables wireless access.

SYNTHETIC ROOTFS + QEMU ARM tests PASS: six fabricated files copied byte-identically;
host dry-run leaves destination empty; symlinks not followed; re-run overwrite refused.

IMPORTANT COMPATIBILITY GAP: the cross compiler's static glibc binary is reported
as targeting Linux 3.2.0 minimum, while snap.sh references modules for 2.6.35.7.
The ACTUAL radio kernel version is unknown. This prototype must NOT be treated as
binary-compatible with the vehicle merely because it ran under host QEMU. Build a
2.6-compatible/static-musl or syscall-limited variant only after verifying kernel,
instruction set, EABI and a legitimate execution channel.

Absolutely no update payload, KWI repack, signature bypass, vehicle flash
or production release is included.

## Workable routes, ranked

1. Identify legitimate read-only factory/service options first; firmware menus could provide
   diagnostics but no hidden root backup feature is established.
2. An EXACT-MODEL donor or the removable original unit on a protected bench:
   inspect board revision/PCB photos/chip package, then probe documented low-voltage
   service UART, JTAG or eMMC ISP only after identifying ground/voltage and signals.
   Reconstruct full eMMC image offline; first choice is non-destructive ISP.
3. A separately authorized shell/serial/maintenance launch path could run a one-shot
   read-only USB file exporter. The existing host USB mass-storage path is more realistic
   than converting port into gadget/peripheral mode.
4. Bluetooth access: test actual exposed SDP services/paired-phone profiles first.
   Classic HFP/A2DP/PBAP alone are NOT equivalent to RFCOMM serial terminal,
   PPP or BNEP TCP/IP, and SSH over Bluetooth is unproven.
5. User-installed modified KWI: BLOCKED PENDING proof of accepted vendor signature
   or other authorized update extension; high risk of bricking. Do not try it on
   installed/working head unit.

## Concrete stop/go checklist

- [ ] Photograph *your specific* radio rear label; match Toyota 86140-0R170,
      FT0049A/B FCC ID and PCB revision before relying on FCC photos.
- [ ] In software only, map full original signature verification chain; no production writes.
- [ ] Confirm authentic runtime kernel version; crosscheck static libc min version.
- [ ] If removing a spare/donor unit, obtain detailed, sharp both-side CPU PCB photos,
      silk-screen component reference IDs, storage manufacturer markings and exposed connectors.
- [ ] Check whether board has documented service access; identify levels using
      professional low-voltage measurement before connecting UART adapter.
- [ ] Confirm a safe shell/exec entrypoint before staging any diagnostic program.
- [ ] If no entrypoint, obtain full read-only eMMC acquisition with all partitions,
      boot0/boot1 if accessible, and SHA256 evidence. Preserve private data.
- [ ] No speculative USB-host-to-host cables, RF stack modifications, test-pad shorting,
      CAN changes, partition writes or unsigned firmware flashes.

Next software-only work: exact call graphs for update signature scope and user-accessible
maintenance modes; determine known original kernel version from downloaded original boot
resources without guessing. Next hardware work: motherboard revision matching and chip
identification from a donor photo. Do not touch Codex repo, Git push, or car firmware.
