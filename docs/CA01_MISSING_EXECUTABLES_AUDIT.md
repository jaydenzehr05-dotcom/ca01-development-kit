# CA01 exact missing-source targets — 2026-10-22

## Scope and confidence
Analyzed local official 1127 KWI extraction and file-name manifests of the two downloaded Denso Ten source archives. This is a **partial named target list**, not an exhaustive inventory of files installed on the head unit. Most update payloads remain opaque.

## Named file paths absent from supplied GPL source manifests

| File path | Evidence | What we know |
|---|---|---|
| /opt/ftl/bin/rma1_hwreg | 02-middle-ware.bin, raw offset 0x0d | Full path embedded in unencoded middleware component header; likely deployment target, executable type NOT independently checked |
| /opt/ftl/bin/vigilancer | 02-middle-ware.bin, raw offset 0x10d | Full path embedded in unencoded middleware component header; likely deployment target, executable type NOT independently checked |
| /opt/ftl/boot/bios.bin | 09-boot.bin, U-Boot strings | Bootloader explicitly references loading this file |
| /opt/ftl/boot/s-bios.bin | 09-boot.bin, U-Boot strings | Bootloader explicitly references loading this file |
| /boot/uImage_T_DAB_US_1M | 09-boot.bin, U-Boot environment | Bootloader references this Linux image; kernel source is available, exact built image is not |
| /dev/mmcblk0p1 and /dev/mmcblk0p2 | 09-boot.bin strings | Root partition paths, **not files lacking source code** |

**Not recovered** means no separately verified installed image/executable was isolated by the current REA/Unblob/strings workflows. A path referenced within a binary does not guarantee its existence on the user's particular production radio.

## Component groups whose actual inner file names are still unknown

- 01-sh-base.bin (SH base firmware)
- 03-kernel.bin (kernel image)
- 04-device-driver.bin (device driver update)
- 05-bluetooth.bin (Bluetooth update)
- 06-audio.bin (audio update)
- 07-gui.bin (GUI update)
- 08-voice-recognition.bin (voice recognition update)

The proprietary update container sections are not reliably decoded as ELF, squashfs, ext3 filesystems or tar archives. Names of proprietary application binaries within them CANNOT YET BE STATED. Source archive listing was indexed but does not reproduce a manifest of installed target device files.

## New format observation

The middleware component starts with 12 bytes of metadata, then a 256-byte pathname area, then a second 256-byte pathname area. The two readable pathname strings are at raw offsets 13 (0x0d) and 269 (0x10d). The inferred payload starts at offset 524. It remains unknown whether payload is one compressed archive for both targets, a single object with two destinations, or another vendor-specific arrangement. Do not imply separate binaries were recovered just because two pathnames appear.

## Reproduction

```sh
strings -a -n 12 stock-firmware/components/02-middle-ware.bin | head
strings -a -n 12 stock-firmware/components/09-boot.bin
grep -i -e rma1_hwreg -e vigilancer system-audit/*.manifest.txt
```

## Next recovery methods (software first)

1. Compare headers and payloads of legally acquired 1127 and 1134 updates to identify component-delta/update semantics and potentially additional target paths.
2. Inspect update loader code from unencoded U-Boot and manufacturer source: where and how each KWI section is interpreted.
3. Use REA/Ghidra on **properly decoded** executable ELF images (and vendor bootloader) rather than forcing arbitrary encrypted bytes into ARM code.
4. Acquire a legitimate read-only installed rootfs filesystem backup or rootfs directory listing from a compatible bench head unit. This would reveal exact program names/libraries/init configs absent from archives. Do not request physical extraction on the installed vehicle without recovery plan.
5. Request full firmware/service material from manufacturer where available. Published FOSS code is not a full proprietary application source release.

No radio firmware was modified.
