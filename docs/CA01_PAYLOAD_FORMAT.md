# CA01 component wrapper investigation (1127)

The CA01 Development Kit's main inspector separates ten KWI update components.
The separate `ca01_payload_carve.py` tool examines **possible inner payloads**
without modifying the original bytes. It is an experimental structural
hypothesis, not a verified vendor format decoder.

## Length-field observation

Interpreting little-endian bytes 8-11 as a trailing size gives these exact
non-negative leading lengths:

| Component | Leading bytes | Trailing bytes |
|---|---:|---:|
| SH Base | 24 | 892,764 |
| Middleware | 524 | 718,892 |
| Kernel | 12 | 1,808,826 |
| Device Driver | 12 | 236,692 |
| Bluetooth | 12 | 633,249 |
| Audio | 12 | 9,382,975 |
| GUI | 12 | 529,963 |
| Voice Recognition | 12 | 577,794 |
| Boot | 48 | 381,224 |
| BootSig | 36 | 320 |

These measured offsets suggest variable component headers. The first
12 bytes are **not** always the complete wrapper. The 524-byte middleware
prefix is a noteworthy next reverse-engineering target.

## REA/Unblob second pass

After losslessly carving the trailing sequences into a separate directory,
we ran REA's `extract-firmware` provider on each of the ten derived payloads.
All ten completed and returned **zero recognized nested extraction subtasks**.
This does not mean the sections contain no files or no code. It means none
of the current standard-format recognizers extracted a known nested format.

Evidence inputs and results in local `../system-audit/`:
- `component-wrapper-survey.json`
- `carved-payloads/manifest.json`
- `rea-inner-payloads/summary.json`

## Reproduction

```sh
python3 tools/ca01_payload_carve.py /path/to/original-extracted-components \
  /path/to/NEW-empty-output-directory
python3 tools/ca01_rea_batch.py \
  --inputs /path/to/carved-payloads \
  --repo /path/to/ca01-development-kit \
  --output /path/to/NEW-rea-results-directory
```

All output directories must be absent; files are not overwritten.
Do not turn these derived payloads into a KWI update or flash them.

## What is still unknown

- Meaning of nonlength header bytes, hashes and signatures.
- Compression, encryption, transformation, or delta-update semantics.
- Whether middleware sections contain full programs or partial replacements.
- Actual key(s), package decoder and eMMC filesystem layout.
- Acceptance of any modified package by the production boot chain.
