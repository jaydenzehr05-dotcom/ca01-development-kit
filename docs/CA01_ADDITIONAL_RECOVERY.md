# Additional CA01 suffix recovery

The complete-file inventory remains **59 files, 41 ELF files**. This pass recovered
an additional **1,649,059-byte kernel-component suffix** and earlier Audio/Voice
suffix bytes. It did not recover `libsecurity.so`, another complete executable,
or a complete kernel image. Originals were read only; no firmware was executed,
no hardware accessed, and no Git commit or push performed.

## Kernel result

The earlier scan stopped at payload byte120000. Extending fixed/dynamic candidate
scanning through the remaining payload, over all eight bit alignments, found17
EOF-reaching candidates. A further stored-block LEN/NLEN scan found an earlier
valid continuation at **payload byte166990, bit1**, with payload offset12 in
`03-kernel.bin`. Stored-block byte alignment means starts at bits1 through5
produce equivalent output; the actual original block boundary is not established.

The existing symbolic decoder and three independent zlib dictionary substitutions
agree on all **1,649,059 output bytes**, with **zero unknown bytes**. SHA256:
`1dc1e69bdf3f43cd6a482f84465eb90bb031253e00eac617d07ccab3caef6038`.
The endpoint is payload byte1808562. The following hypothetical gzip footer has
ISIZE1822720 and CRC32 `6570dc49`; that implies173661 missing prefix bytes if the
footer interpretation is correct. Neither full CRC nor authenticity is verified.
The decoded suffix contains no ELF, USTAR, gzip-header, or `libsecurity` marker.
It remains a suffix fragment, not a complete file or installable kernel.

Reproduce using the existing tool with a new artifact destination:

```sh
python3 tools/ca01_experimental_decode.py \
 /home/starlight/projects/rav4-radio/stock-firmware/components/03-kernel.bin \
 --payload-offset 12 --start-byte 166990 --start-bit 1 \
 --artifact-directory /tmp/NEW_CA01_KERNEL_SUFFIX
```

## Earlier Audio and Voice starts

Scanning all alignments before previous starts found Audio byte65703 bit7 and
Voice byte67954 bit6. The original component probe selected the first successful
bit alignment, which need not be the earliest compressed-byte position. No
production decoder change is needed: this is candidate-selection improvement.

| Component | Output bytes | Unknown bytes | Complete entries | New complete files |
|---|---:|---:|---:|---:|
| Audio |23439868|16062|47|0|
| Voice |2451203|155644|6|0|

Audio adds14248 output bytes; Voice adds92510. All extracted path/size/SHA256
triples exactly match prior recoveries. Audio's fully known contiguous suffix
starts at output44268. Its first known checksum-valid tar header is
`./opt/ftl/lib/libipas_grp.so` at1092092. No header or ELF start identifies the
leading partial library, so assigning it a filename would be speculation.

## Incomplete Driver files and links

Both Driver headers are fully known, but `cachedmem.ko` has9426 unknown bytes
out of85949, and `dmamem.ko` has1258 unknown bytes out of88975. Neither is complete.
Their zero-filled hashes in the evidence identify partial artifacts only.

All fully known checksum-valid headers were examined regardless of tar type:
51 Audio,11 Voice,3 Driver,15 GUI. They contain only directories and regular
files; no symbolic-link or hard-link header establishes a `libsecurity.so` target.
This count includes headers whose content remains incomplete.

## Limits and artifacts

All ten raw components were searched for gzip, ELF, USTAR, SquashFS, and literal
`libsecurity.so` markers, with no hits. Middleware's previously verified tail
also lacks ELF/USTAR markers. Negative marker searches cannot establish absence
inside encrypted prefixes, compressed content, non-ELF images, or missing data.
The fixed/dynamic scanner requires32768 output bytes from the first65536 input
bytes and EOF near the hypothesized footer, so its negative results are bounded
by those candidate filters. It is not a general proof that no resynchronization
exists. The kernel stored-header scan additionally preserves byte alignment.

Metadata: `evidence/ca01-additional-recovery.json`.
Scratch scripts, full reports, decoded fragments and known-byte masks:
`/tmp/ca01-more-recovery/` (especially `kernel-earlier/`, `audio/`, `voice/`,
`driver/`). No fragment is counted as a complete recovered file. Full reports
record source hashes, symbolic provenance, zlib crosschecks and checked entry
hashes; all output artifacts retain explicit partial/untrusted labeling.

## Durable preservation and classification

All82 artifacts (including duplicate verified complete entries, fragments, masks
and reports) were copied without overwrites to
`/home/starlight/projects/rav4-radio/system-audit/ca01-additional-recovery-20261022/`.
Every size and SHA256 was reread and checked against `SHA256-MANIFEST.json`.
This is82 stored artifacts, not82 recovered firmware files.

Kernel suffix entropy is7.979366 bits/byte (first1MiB:7.968197), with1581
trailing zero bytes. It has no searched uImage, ARM zImage, gzip, xz, bzip2,
SquashFS, ELF, Linux-version, Linux, or newc-initramfs marker, and only two
printable runs of16 or more bytes. No uncompressed-kernel identity is claimed.
