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
