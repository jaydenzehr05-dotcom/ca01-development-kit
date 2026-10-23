# CA01 firmware update format research

Research target: original `15TBDANA-CA01_1127.kwi`, SHA-256 `39431b79ed849be627c13be586019ceaab34470a534b76c385f73f1748d367ca`, 15,164,495 bytes. Originals remain outside Git and are opened read-only. No firmware, recovered vendor binary, vehicle state or signing material is modified or published by this investigation.

Confidence vocabulary: **confirmed binary** means directly measured bytes or a validated binary-derived operation; **confirmed source** means an identified original source path/function; **strongly inferred** means supported interpretation that still lacks the complete vendor implementation; **unknown** means unresolved. Codec validity does not establish cryptographic authenticity or installability.

## Outer KWI framing — confirmed binary

The first 848 bytes form a big-endian metadata structure. At offset0 the word848 matches the metadata boundary; offset4 holds the exact file length. Length-prefixed ASCII records identify `15TBDANA-CA01`, the `name`/`DA`/`data` keys, `UU1127`, ten component labels and `UU.11.27` versions. A raw version word is0x1127, and each `update` value is0. The recovered `PROC_REPRO` verifier reads592 metadata bytes and256 signature bytes; its SHA256/RSA-PSS call path identifies the signature role of offsets592–847. That role is now confirmed by binary analysis; no actual cryptographic verification has been executed.

At848 the bytes `ff ff 00 04` precede ten **little-endian** `(size, relative_offset)` pairs. Bytes932–1091 are zero-reserved in this specimen. The component data base is1092. Every component's start equals1092+relative_offset; all ten are contiguous and account for the entire file. The metadata component-offset list is independently contiguous. Recovered `FUN_00019f58` also reads the following244 bytes and extracts security selector IDs at metadata+2/+3: file offsets850 and851, RSA selector0 and AES selector4. These are IDs passed to the security library, not disclosed key bytes. These structural invariants are checked by the existing narrow `ca01_inspect.py`, not guessed from magic strings.

The exact offset, width, byte order, raw value and confidence for **every parsed metadata field** are recorded in `evidence/ca01-update-format.json`. Reserved words, directory discriminators, `update=0` and several component operation details remain unresolved; this is not a claim to have the vendor's full schema.

| Component | File offset | Size | Inferred inner prefix | Trailing bytes |
|---|---:|---:|---:|---:|
| SH Base | 1092 | 892788 | 24 | 892764 |
| Middle ware | 893880 | 719416 | 524 | 718892 |
| Kernel | 1613296 | 1808838 | 12 | 1808826 |
| Device Driver | 3422134 | 236704 | 12 | 236692 |
| Bluetooth | 3658838 | 633261 | 12 | 633249 |
| Audio | 4292099 | 9382987 | 12 | 9382975 |
| GUI | 13675086 | 529975 | 12 | 529963 |
| Voice Recognition | 14205061 | 577806 | 12 | 577794 |
| Boot | 14782867 | 381272 | 48 | 381224 |
| BootSig | 15164139 | 356 | 36 | 320 |

## Common component wrapper — observed fields and structural inference

Bytes0–11 parse as little-endian `<u16,u16,u32,u32>`. The final word equals the length of the trailing data, leaving a specimen-dependent leading prefix. The first word fits a **record count**, rather than requiring ten distinct component type IDs:

- When the word at+4 is0: prefix size =12 + count×12. SH Base has1 record, Boot3, BootSig2.
- When that word is1: prefix size =12 + count×256. Middleware has2 records, the other six such components have0.

This relation fits **all ten** components exactly. The recovered updater `FUN_0000f2a0` confirms the mode1 pathname count and list width. Other raw descriptor roles remain separately qualified. The second16-bit field is not yet identified as a checksum, version or other value. Tested additive-byte/LE16 sums, low CRC32 and CRC16-CCITT variants over common prefix/payload ranges did not match it consistently. This does not identify or exclude a vendor-specific checksum or a checksum over decoded data.

The 12-byte records are exposed as raw triples. Some values resemble source offsets, lengths and flash addresses, but their exact roles and overlap/adjustment rules require the real updater. They are not installation commands.

Middleware records begin at relative+12 and+268. Each is256 bytes and begins with00, followed by `./opt/ftl/bin/rma1_hwreg` or `./opt/ftl/bin/vigilancer`, then padding. Text begins at+13 and+269. Absolute component file start is893880; the trailing data starts894404. Leading00 must not be silently discarded as a proven action byte. Recovered `FUN_0000f2a0` and the shared install loop show removal-before-archive semantics: each record is traversed at256-byte strides, record byte0 is skipped when appending the pathname, and the generated command uses `rm -fR `. The completion path then switches to `tar zxf ... -C ...`. These names therefore are **not** proof that two executable files immediately follow. No such command was executed here.

## Leading64000-byte boundary

The SH Base and Boot trailing data show a sharp transition at relative64000 (`0xfa00`) to readable SH/ARM code and strings. At the Boot boundary the next16 bytes are `07c6ffeb0b00a0e3c510a0e3290100eb`; SH Base begins `20e524d4184503662845c380c6800b42`. The first64000 bytes have near-uniform byte distributions. Initially this was a bounded leading-region hypothesis. Actual recovered updater code now confirms AES calls capped at64000 bytes (`FUN_0000a9bc`, ARM comparison at0x0000a9f8), followed by stitching the untouched tail, removing returned padding and256 signature bytes, then SHA256/RSA-PSS calls. This identifies AES from code, **not entropy**. The exact AES mode/key provisioning remains unknown behind `libsecurity.so`. Standard stream probes at the inner starts reject zlib/gzip/raw-DEFLATE; that does not exclude a compressed suffix behind an unknown transformed prefix.

`ca01_update_research.py` records hashes on both sides, nearby bytes, 4KiB entropy windows and unvalidated format-marker offsets. None of those raw markers are promoted to recovered binaries. Previous automatic raw-Ghidra entrypoints at component offset0 are especially unreliable: those bytes are wrapper/transformed material.

## Gzip-shaped trailers and partial DEFLATE

All seven mode1 components end with eight bytes shaped like a gzip `(CRC32,ISIZE)` trailer followed by256 opaque bytes. Every ISIZE is an exact multiple of10240, consistent with tar record blocking. Footer shape alone is an inference; the full gzip CRC cannot be verified until the missing leading region is decoded.

| Component | Candidate gzip ISIZE | Confidence |
|---|---:|---|
| Middle ware | 1802240 | strongly inferred framing |
| Kernel | 1822720 | strongly inferred framing |
| Device Driver | 552960 | strongly inferred framing |
| Bluetooth | 1863680 | strongly inferred framing |
| Audio | 23592960 | strongly inferred framing |
| GUI | 2723840 | strongly inferred framing |
| Voice Recognition | 2785280 | strongly inferred framing |

A new symbolic DEFLATE suffix decoder tracks missing32KiB history as distinct unknown variables instead of pretending zero-filled dictionary bytes are original. It propagates unknowns through backreferences and cross-checks output with independent zlib under three different dictionaries. Known bytes are dictionary-independent; holes stay explicitly unknown. Candidate block alignments still need component/framing corroboration, and no complete-gzip CRC or signature acceptance is claimed.

Middleware resynchronization at payload byte69313, bit6 reaches the final DEFLATE block at bit5749023 (next byte718628), immediately before the compatible eight-byte trailer and256 opaque bytes. It yields1,647,494 bytes, with23,993 unknown bytes. Its final1,588,548 bytes are dictionary-independent, SHA-256 `fd1b6c671ab50ee99465d79af24100af0bf02e0b4c6a4f1dae6e475edc58cdee`. Renesas multimedia strings appear. No complete target executable has been established from that suffix. See the recovery report for additional components and validated file-level results.

## Reproduction

```sh
python3 tools/ca01_update_research.py /path/to/15TBDANA-CA01_1127.kwi \
  --components /path/to/byte-exact-components --output /path/to/NEW-report.json
python3 tools/ca01_experimental_decode.py /path/to/02-middle-ware.bin \
  --payload-offset 524 --start-byte 69313 --start-bit 6
```

The inspector has no input-write/extract/installation operation. Its output file uses exclusive creation. The experimental decoder's optional artifact directory must be new and includes an explicit known-byte mask; zero-filled partial artifacts must never be executed or flashed. Tests use synthetic streams and the pre-existing tiny structural metadata fixture; no new firmware body fixture is committed.

## Source and external corroboration

`CA01_UPDATER_CALL_GRAPH.md` separates available family boot/rollback and installed-uImage source checks from the newly recovered original KWI updater binary. The supplied archives were searched recursively; generic Linux compression or U-Boot TFTP-update routines are not evidence of a CA01 decode call chain.

The official [Denso Ten source page](https://www.denso-ten.com/jp/support/source/oem/13t/index.html) links both held archives. Toyota's [1127 bulletin](https://static.nhtsa.gov/odi/tsbs/2018/MC-10129998-9999.pdf) identifies the original file. A [later same-product bulletin, page8](https://static.nhtsa.gov/odi/tsbs/2020/MC-10173804-9999.pdf) identifies1134 as a promising legitimate comparison; the guessed direct download returnedHTTP403, so no later binary comparison was performed.

[KarpelesLab/kwi](https://github.com/KarpelesLab/kwi) targets Panasonic/Aisin AW LOADING.KWI, with a different manifest/rootfs layout. It is a useful exclusion, not a CA01 decoder. [Binwalkv3](https://github.com/ReFirmLabs/binwalk), [Unblob](https://unblob.org/handlers/), [DetectItEasy](https://github.com/horsicq/Detect-It-Easy) and [TrID](https://mark0.net/soft-trid-e.html) provide format recognition; absence of a recognition result cannot decide encryption versus compression/delta data. Tool installation and actual scan outcomes are recorded separately, not inferred from configuration. No private dumps were uploaded.

## Still unknown

The AES mode/key provisioning, successful full decryption, actual authentication acceptance, second16-bit header field, raw-descriptor details, complete package reconstruction and final production installation transaction remain unresolved. The actual updater has been recovered and its prefix-AES/SHA256/RSA-PSS/remove-then-tar paths are now identified; detailed binary addresses and confidence are in `CA01_UPDATER_CALL_GRAPH.md`. Component framing alone cannot distinguish full replacement from all possible patch formats. The partial DEFLATE/tar evidence supports real file-bearing archive content in some components, not a universal no-patches claim. No radio was accessed, modified or flashed.
