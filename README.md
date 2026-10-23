# CA01 development kit — first milestone

Working reference: **15TBDANA-CA01**, using the two source archives you supplied
and identified as coming directly from the head unit.

This kit provides a working firmware inspector and a compiled, read-only ARM
Linux probe. It is an initial development deliverable, not a Google Maps app or
an installable Toyota update. Launching our own executable on the physical radio
is the next unresolved dependency.

## Included

| File | Purpose |
| --- | --- |
| `tools/ca01_inspect.py` | Validates the observed KWI container and extracts its ten components unchanged. |
| `build/radio-probe-arm` | Small, static ARM Linux EABI executable that queries system and display information. |
| `src/radio_probe.c` | Complete source for that executable. |
| `build_probe.sh` | Reproducible build command using Zig 0.13.0. |
| `evidence/ca01-1127-inspection.json` | Results from inspecting the actual Toyota CA01 1127 file. |
| `evidence/source-audit.json` | Source archive fingerprints and the files supporting the development target. |
| `evidence/validation.json` | What was tested and the limits of that validation. |
| `tests/` | Container error handling and ARM instruction-emulation tests. |

The Toyota firmware and the full source archives are not bundled again.

## What the supplied source establishes

- Linux source version **2.6.35.7**.
- ARM/R-Mobile A1 board support and Fujitsu Ten board definitions.
- An available U-Boot configuration named
  `rma1_13PF_1m_dabase_us_secure_config`.
- Source definitions for the `uImage_T_DAB_US_1M` boot image and an **800 × 480**
  main display. Pixel depth is selected by kernel configuration.

CA01 contains the same boot-image name, a `mem=256M` setting and a
`U-Boot 2010.09.113PF-SB` banner. These make that source configuration a useful
development candidate. They do not prove that the published source reproduces
every byte of the installed firmware or that the active display uses a particular
pixel depth. The probe is designed to read the active values once it can run.

Manufacturer source page for these archive names:
<https://www.denso-ten.com/jp/support/source/oem/13t/index.html>

## Inspect CA01 on a computer

Requires Python 3.9 or newer; no third-party Python packages are needed.

The reviewed reference is:

```text
15TBDANA-CA01_1127.kwi
15,164,495 bytes
SHA-256: 39431b79ed849be627c13be586019ceaab34470a534b76c385f73f1748d367ca
```

Official download used for this analysis:
<https://www.toyota.com/firmware-download/15TBDANA-CA01_1127.kwi>

From the extracted kit directory, with your firmware file at the indicated path:

```sh
python3 tools/ca01_inspect.py /path/to/15TBDANA-CA01_1127.kwi
python3 tools/ca01_inspect.py /path/to/15TBDANA-CA01_1127.kwi --extract components
```

The extraction directory must be new. The inspector reads the input file and
writes byte-exact component copies and a manifest. It does not decompress,
repackage, sign or install firmware. Structural validation and SHA-256 hashes
are not a Toyota signature-verification implementation. Support is limited to
the observed CA01 layout; other KWI formats can differ.

## The ARM probe

The executable has no dynamic loader or libc dependency. It uses the Linux ARM
EABI calls present in the supplied kernel headers. It reads six `/proc` files
and queries framebuffer dimensions using `FBIOGET_VSCREENINFO`.

It reports:

- kernel version, CPU information and memory information;
- registered framebuffer and input devices;
- mounted filesystems;
- visible and virtual screen dimensions and pixel depth, when accessible.

It writes only to standard output. It does not draw, change camera/GPIO state,
modify files, access the network or alter firmware. It requires a working way
to launch a Linux executable on the radio. Copying it to a USB drive alone does
not provide that launch path, and it is not a file for the firmware-update menu.

## Rebuild and run the automated checks on a computer

Install Zig **0.13.0** separately, then:

```sh
ZIG=/absolute/path/to/zig sh build_probe.sh
```

The Python `ziglang==0.13.0` package can also supply this compiler in an isolated
environment. The original U-Boot tree expects a different, older toolchain; this
build script builds only our standalone probe, not U-Boot or the kernel.

For the test dependencies, create a local virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Eleven checks passed. Seven exercise container boundaries, malformed files and
non-overwriting extraction. Four execute the ARM binary in Unicorn with mocked
Linux syscalls, covering normal display queries, missing files, interrupted and
short reads/writes, and an unsupported framebuffer query. The mock reports
800 × 480; this is test data, not a measurement taken from the radio.

The inspector was also run against the real CA01 file on your computer. All ten
extracted components matched their recorded sizes and SHA-256 hashes, and the
input firmware remained unchanged.

## Next development milestone

Trace the firmware's application-launch and update mechanisms, using the
extracted middleware and GUI components alongside the supplied source. The
required result is a verified route for launching our probe on the Linux side.
After that, collect the real display/input output and implement a minimal
display test before choosing the maps implementation.

No physical-radio execution, update-signature acceptance, recovery procedure,
Google Maps installation or camera-control change has been demonstrated by this
kit. The probe's successful emulation establishes its behavior under the mocked
Linux interface, not those capabilities.

## Original source archive downloads

Both original uploads are available unchanged as [GitHub release assets](https://github.com/jaydenzehr05-dotcom/ca01-development-kit/releases/tag/original-source-archives):

- [20130619_LE2355.tgz](https://github.com/jaydenzehr05-dotcom/ca01-development-kit/releases/download/original-source-archives/20130619_LE2355.tgz) — 92,427,701 bytes.
- [OSS_SOFT_PACK.tgz](https://github.com/jaydenzehr05-dotcom/ca01-development-kit/releases/download/original-source-archives/OSS_SOFT_PACK.tgz) — 231,704,880 bytes.

SHA-256 fingerprints are recorded in the release notes and `evidence/source-audit.json`.

## Additional system-layer research and read-only diagnostics

This checkout also includes a **read-only CA01 system-analysis toolkit**.
It does **not** claim a bootable Toyota replacement OS or a working vehicle
installer.

- [Driver and hardware interface map](docs/CA01_HARDWARE_INTERFACES.md)
- [Boot / rollback / recovery source audit](docs/CA01_BOOT_RECOVERY_AUDIT.md)
- [REA + Ghidra configuration and commands](docs/CA01_REA_GHIDRA_SETUP.md)
- [Update-component wrapper experiments](docs/CA01_PAYLOAD_FORMAT.md)
- [System availability and missing dependencies](SYSTEM_INVENTORY.md)

New diagnostics and utilities:

- `src/ca01_hw_probe.c` and `build_hw_probe.sh` build a static, 32-bit ARM
  system probe. It reads Linux information, framebuffer characteristics and
  button events (mocked in tests). It is **not** an update file.
- `tools/ca01_source_contracts.py` generates line-numbered evidence from
  the manufacturer source archive without copying the whole archive.
- `tools/ca01_payload_carve.py` tests a length-field hypothesis using
  separate byte-exact trailing sequences. `tools/ca01_rea_batch.py`
  runs the read-only REA/Unblob extractor against those derived files.
- `tools/rea_ca01.sh` runs the locally installed REA 6.7.0 with Ghidra
  12.1.4 and Java 21. `tools/ghidra/run_boot_ghidra.sh` surveys the
  raw boot component with **explicitly unverified** ARM import assumptions.
- Evidence files in `evidence/` record findings and limitations.

To build the new diagnostic:

```sh
ZIG=/absolute/path/to/zig sh build_hw_probe.sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

Nineteen automated checks passed locally after these additions. The hardware
probe was evaluated only with **mocked ARM syscalls**; it has not been
executed on a car radio. Reading certain special hardware-register
diagnostic files could have side effects even with read-only system calls,
so do not run the probe on a physical radio before reviewing its handlers.

Do not flash modified firmware, assume secure boot is bypassed, or treat
a rescue-mode string as a tested hardware recovery method.

## Independent firmware-updater research

The isolated updater investigation recovered59 complete local files, including the original `PROC_REPRO` updater and both BIOS files. Neither `rma1_hwreg` nor `vigilancer` has been recovered. Validated binary analysis identifies a64,000-byte AES prefix, SHA256/RSA-PSS calls and pathname removal followed by tar replacement; exact security-library parameters and successful authentication remain unverified. Recovered vendor binaries are not committed.

- [Update framing and reproducible evidence](docs/CA01_UPDATE_FORMAT_RESEARCH.md)
- [Source and actual updater call graphs](docs/CA01_UPDATER_CALL_GRAPH.md)
- [Missing targets and recovered-file inventory](docs/CA01_MISSING_EXECUTABLES.md)
- `tools/ca01_update_research.py`: read-only structural evidence.
- `tools/ca01_experimental_decode.py`: bounded symbolic DEFLATE suffix research, known-byte provenance and safe complete-file exports.
- `evidence/ca01-tool-installation.json`: verified local DiE3.21 installation and limitations.

The tools do not flash, execute recovered programs, bypass signatures, or claim a complete offline updater decoder. Detailed limitations and reproduction commands are in the reports.
