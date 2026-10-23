# CA01 missing executables and validated recovery

## Requested files

| Target | Status | Evidence |
|---|---|---|
| `/opt/ftl/bin/rma1_hwreg` | **Not recovered** | Middleware pathname removal record; absent from recursively searched source and validated recovered files. |
| `/opt/ftl/bin/vigilancer` | **Not recovered** | Same record mechanism and absence checks. |
| `/opt/ftl/boot/bios.bin` | **Complete bytes recovered** | Entire known TAR header/data from Audio; hash below. |
| `/opt/ftl/boot/s-bios.bin` | **Complete bytes recovered** | Same validated provenance. |
| `/boot/uImage_T_DAB_US_1M` | **No complete file recovered** | Installed load target confirmed in source/boot strings; Kernel payload incompletely decoded. |

The actual updater **`/opt/ftl/apl/PROC_REPRO`** was recovered instead. Its valid ARM ELF enabled static identification of the64,000-byte AES prefix, SHA256/RSA-PSS, key selectors and remove-then-tar installation. No program was executed and no authentication acceptance was demonstrated.

## Validated recovery

59 complete regular files:47 Audio,6 GUI and6 Voice;41 ELF32 little-endian ARM files. Every recovered file has a checksum-valid512-byte USTAR header, valid bounds, **all header and content bytes independent of missing dictionary history**, and SHA-256. Partial artifacts with any unknown content are not exported as complete files. Three independent zlib histories crosscheck symbolic provenance. This establishes byte-level recovery, not trusted installability: full gzip CRC and vendor signatures remain unverified.

Recovered bodies stay local outside Git under `/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/`; only tools and metadata are committed. All59 original path/size/hash records are in `evidence/ca01-middleware-partial.json`. The actual Audio CLI independently reproduced all47 expected tuples.

| Selected file | Bytes | SHA-256 |
|---|---:|---|
| `./opt/ftl/boot/bios.bin` | 77544 | `9337508604e644ba558f3a5808a91fce4751c5fa6453dd5d8d9dfaa82e79b87b` |
| `./opt/ftl/boot/s-bios.bin` | 7796 | `cb97bb7ba20143f8e731f719c6888d5443b963695efe1369e90f0d1e59d2dbef` |
| `./opt/ftl/bin/FlashImageCreater` | 15252 | `48bb5513f542d276568bd6ab77e4790fc1480031ae92a934a34b95f7d0626b70` |
| `./opt/ftl/bin/FlashImageWriter` | 18524 | `40ec8efe0e22c5acb5a1add4da44cd2ff2f8b2cd55ccfcd8900b25d3a5d146fa` |
| `./opt/ftl/apl/PROC_REPRO` | 168592 | `47a48311b513bffaa3c8f41e9c3ebcc05ae3525e8efe069c714f5e8341fbb771` |

`PROC_REPRO`, FlashImageWriter and FlashImageCreater are ELF32 little-endian ARM executables. Their complete dynamic import/export lists, linked libraries, entry addresses, static-symbol status and observed `/dev` strings are recorded in `evidence/ca01-recovered-inventory.json`. Path strings are observations, not proof hardware was accessed. BIOS bytes remain raw; no format/architecture/bootability was invented from filenames. Neither missing target has recovered functions/imports/hardware behavior to report.

## Actual updater and remaining blocker

Ghidra analyzed the **valid recovered ELF**, not an opaque component imported as code at zero. Generated `FUN_...` labels are address labels, not vendor symbol names. See `CA01_UPDATER_CALL_GRAPH.md` and `evidence/ca01-updater-binary-paths.json` for exact addresses and ARM instructions.

The middleware two pathname records are **removal entries processed before archive replacement**, not proof of two immediately following executable images. `FUN_0000f2a0` reads the count and256-byte strides; the install loop skips each leading record byte and constructs `rm -fR ...`, followed by `tar zxf ... -C ...`. No such command was executed here.

The updater imports `libsecurity.so` and `sysAes*`, `sysSha256*`, `sysRsa*` routines. RSA/AES selector IDs0/4 and an opaque initialization constant are not underlying keys or a full crypto specification. `libsecurity.so` was not recovered, so exact mode/key provisioning and a fully validated offline prefix decoder remain unavailable. No signing bypass was attempted.

## Reproduce safely

```sh
python3 tools/ca01_experimental_decode.py /path/to/components/06-audio.bin \
  --payload-offset 12 --start-byte 71041 --start-bit 2 \
  --artifact-directory /path/to/NEW-LOCAL-DIRECTORY
```

The output directory must be new. It contains explicitly untrusted partial bytes, a known-byte mask, metadata and complete files under flat offset-numbered names. Original TAR names never control output paths; files are created without executable permissions (subject to the caller's umask), no links are followed, and no existing output is overwritten. GUI/Voice block offsets are in the evidence. Actual recovered binaries stay out of Git.

No radio was accessed, flashed or modified; no recovered program ran; no vehicle data was uploaded. Runtime partition state, bootability, successful signature/CRC verification and final production update transaction remain unverified. Available source rollback functions are documented separately from the proprietary updater's actual binary paths.
