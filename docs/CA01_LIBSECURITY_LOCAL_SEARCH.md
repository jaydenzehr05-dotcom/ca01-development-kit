# Local search for the missing security library

This additional pass did **not** recover `libsecurity.so` or another complete
file. It identified the leading Audio fragment as an incomplete ELF tail and
established that its executable code and dynamic symbol names are unavailable.
No originals were modified, firmware executed, radio accessed, or Git push made.

## Earlier stored-block boundaries

The prior earlier-boundary scan covered fixed and dynamic DEFLATE blocks. This
pass also checked stored blocks by searching complementary 16-bit LEN/NLEN pairs
and testing every legal preceding bit alignment while preserving byte alignment.
The examined intervals start at payload byte 64000 and end just beyond the
current best resynchronization start.

| Component | End of tested length-field interval | LEN/NLEN pairs | Valid continuations |
|---|---:|---:|---:|
| Middleware | 69315 | 0 | 0 |
| Audio | 65705 | 0 | 0 |
| Driver | 90139 | 0 | 0 |
| Bluetooth | 101517 | 1 | 0 |
| GUI | 67617 | 0 | 0 |
| Voice | 67956 | 0 | 0 |

Bluetooth's pair at 97401 did not decode to the expected endpoint. These results
close the stored-block gap for the tested cleartext intervals; they do not decode
the encrypted prefix or establish what files it contains.

## Audio's leading incomplete library

Before the first recovered tar header, the earlier Audio suffix contains a fully
known 26-entry ELF32 section table at output offset **1090812**. The matching
section-name table starts at **1090593**. Its internally consistent file offsets
imply the incomplete ELF began **105988 bytes before** the available suffix.
The file header and tar header are missing, so this is a structural inference,
not a recovered complete file or verified filename.

| Section | Inferred original file offset | Size | Availability |
|---|---:|---:|---|
| `.dynsym` | 1500 | 3024 | Entirely missing |
| `.dynstr` | 4524 | 3108 | Entirely missing |
| `.text` | 9160 | 26084 | Entirely missing |
| `.rodata` | 35252 | 1158504 | Partially available |
| `.dynamic` | 1194808 | 232 | Fully known |
| `.shstrtab` | 1196581 | 219 | Fully known |

The dynamic table independently agrees with the section addresses and sizes.
It has two DT_NEEDED references, at missing string-table offsets 2995 and 3009,
and no DT_SONAME entry. Those numeric offsets do not identify the dependencies.
No exported names or code can be recovered from this fragment's missing
`.dynstr`, `.dynsym`, and `.text`. Reconstructing a synthetic ELF header would
not restore those bytes or establish the library's identity.

The leading region has entropy approximately 2.57 bits/byte, including its
explicitly marked unknown zero-filled bytes. It is predominantly read-only
data, rather than a newly recovered executable implementation. The section table
and data suggest a data-heavy library; assigning a graphics/font/security name
would exceed the evidence.

## Middleware and nested-container checks

The fully known 1588548-byte Middleware suffix contains Renesas multimedia and
codec strings. Its entropy is approximately 5.42 bits/byte. Neither this region
nor Audio's leading fragment contains known bytes matching `libsecurity`,
`sysAes`, `sysRsa`, `sysSha256`, or `sysSec`, the tested AES S-box prefix, or the
tested SHA-256 constant prefix. These are bounded pattern checks, not proof that
cryptographic code cannot exist in another representation or unavailable bytes.

Known bytes were also searched for ELF, gzip, xz, bzip2, ZIP, SquashFS, CPIO,
ROMFS, cramfs, JFFS2, UBI, uImage, zImage, and SQLite markers. The only container
candidates were five two-byte JFFS2 matches in Middleware; all failed node-length
bounds and both tested CRC interpretations. No nested container was established.
A tar-header scan independent of USTAR magic, using six octal checksum digits
and two NUL/space terminators, found no valid header in either region.

Evidence with exact offsets, source hashes, section records, and rejected
candidates: `evidence/ca01-libsecurity-local-search.json`.
Reproduction scripts and string extracts: `/tmp/ca01-libsecurity-local/`.
Previously preserved complete files and partial-byte masks remain untouched.
