# COROLLA RADIO REBUILD — MASTER FILE

Start here, Jayden and Trystan. This is our editable project map, initial layout and evidence ledger. Unknowns remain open as more data arrives.

## Goal and present state
Build the replacement display/interface and required radio services, ultimately aiming for a verified USB-stick firmware update accepted by the factory updater. CarPlay is desired but not implemented. **No verified installable custom Toyota firmware package exists in this project yet.**

## Project map

| Item | Location / status |
| --- | --- |
| Master file | `00_START_HERE_COROLLA_RADIO_MASTER.md` |
| Proposed layout | `config/radio-layout.json` |
| Hardware targets | `config/radio-targets.json` |
| Analysis code and tests | `tools/`, `src/`, `tests/`, `evidence/` |
| Existing inventory | `SYSTEM_INVENTORY.md` |
| New updater research | `research/ca01-firmware-updater`, reviewed at a562b3b |
| Pi interface | Local branch `feature/pi-interface`; pi-interface/ untracked at review; integration pending |
| Original archives | GitHub release original-source-archives |

The new JSON files are proposed design inputs; the existing interface does not consume them yet. Other branches are not merged by this document change.

## Separate hardware targets

| Field | Jayden | Trystan |
| --- | --- | --- |
| Vehicle | 2019 Corolla SE 1.8L manual sedan | 2017 RAV4 base, user-reported |
| Model ID | 15TBDANA-CA02 | Unknown; photo needed |
| Hard No. | 86140-02521 | Unknown |
| Faceplate | 100639 | Unknown |
| Software | UU.21.34 | Unknown |
| Evidence | User photographs | Vehicle description only |

CA01 1127 is an analysis reference. Compatibility with CA02 is unknown. Do not infer radio identity from trim or transmission.

Pi development host: Raspberry Pi 4 Model B Rev 1.5, about 4 GB RAM, Bookworm, kernel 6.12.109+rpt-rpi-v8. Its probe reported an 800 x 480, 16-bit framebuffer and touchscreen input. This is Pi evidence, not a measurement of Toyota's framebuffer.

## Initial interface layout v0.1

Reference canvas: 800 x 480, confirmed on the Pi. Target-radio adaptation remains open.

| Region | Bounds | Proposed use |
| --- | --- | --- |
| Header | x0 y0, 800 x 52 | Page title, back/menu, connection status |
| Content | x0 y52, 800 x 364 | Page controls, lists, camera/content area |
| Footer | x0 y416, 800 x 64 | Navigation/source/status controls as required |

Pages: Audio sources/FM; Phone/Bluetooth; Car/trip information; Setup/general/display/sound; Software information; developer-only Radio Lab.

Provide on-screen equivalents for AUDIO, SETUP, CAR and PHONE buttons. Proposed minimum touch target: 48 x 48 pixels. Reverse-camera presentation is a separate state with explicit source/availability. Validate spacing against photos and the actual display.

Show unavailable or simulation status until CarPlay, FM, camera, phone and vehicle services have working adapters. Show live Pi information separately from the photographed Toyota identifiers. Production update control stays disabled until acceptance and recovery are demonstrated.

This is a starting design, not a pixel-verified factory recreation. Additional screenshots and measurements can change all layout choices.

## Architecture

UI -> common service contracts -> host-specific adapters.

Define display/input, audio, phone/projection, camera, vehicle signals and updater-status interfaces. Pi adapters provide host observations or explicitly marked simulation. Toyota adapters require verified device contracts and runtime evidence. Keep analysis tools, application runtime and the eventual firmware packager separate.

## Evidence and unknowns

- Observed in user-supplied Pi output: both source archives extracted, ARM probe exit 0 and seven inspector tests passed.
- Available source includes Linux/Renesas/Fujitsu Ten drivers. Exact production configuration is not established.
- Updater branch reports 59 complete recovered files, including PROC_REPRO and six GUI files. This master-file change inspected that report but did not independently reproduce recovery.
- Updater research reports AES prefix processing and SHA256/RSA-PSS verification. Full authenticated decoding/repacking remains unproven.
- Missing/unverified: libsecurity.so, full matching CA02 runtime, kernel configuration, partition map, launch/recovery path and CA01/CA02 compatibility.
- Pi interface execution does not establish Toyota OS emulation or USB update acceptance.

## Milestones

| Stage | Status | Completion evidence |
| --- | --- | --- |
| Shared starting point | Started | Master/layout/targets published; collaborator access checked |
| Interface consolidation | Pending | Preserve and commit local UI; smoke-test on Pi |
| Service contracts | Pending | Defined inputs/outputs; honest unavailable states; adapter tests |
| Repeatable analysis | Partial | Independently reproduce recovery hashes/tests from exact inputs |
| CA02 validation | Pending | Matching system evidence, identifiers, configuration and partition map |
| Minimal radio execution | Pending | Verified launch, recovery and display/input test on matching bench hardware |
| Package construction | Blocked | Proven container/transforms/authentication and update/partition semantics |
| USB installation | Blocked | Matching bench unit accepts package, restarts correctly and supports demonstrated recovery |

A KWI filename, parser test or Pi demo is insufficient to complete the last three stages. No runnable flash command is defined yet.

## Next work

1. Preserve and commit the current Pi interface without overwriting concurrent edits.
2. Wire in the layout configuration and verify 800 x 480 rendering.
3. Collect Trystan's model/hardware/version/faceplate photos.
4. Reproduce updater-branch tests and recovery; record commits and hashes.
5. Trace recovered GUI dependencies and the missing security-library interface.
6. Establish matching hardware and recovery evidence before packaging an update.

## Keeping this file current

Record each discovery with target, source path, commit or SHA-256, method, result and limitations. Mark it observed, reported, inferred or unknown. Use null for unknown JSON fields, not guessed defaults. Link supporting evidence rather than replacing it with this summary.

| Date | Change |
| --- | --- |
| 2026-10-22 | Initial master, proposed layout and target registry; installation remains unverified |
