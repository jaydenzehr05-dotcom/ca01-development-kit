#!/usr/bin/env python3
"""Read-only inspection of the observed 15TBDANA-CA01 KWI layout.

This is a component-boundary inspector, not an updater, signer or decompressor.
Uses only Python's standard library. The input is never opened for writing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

REFERENCE_SHA256 = "39431b79ed849be627c13be586019ceaab34470a534b76c385f73f1748d367ca"
MODEL = "15TBDANA-CA01"
LABELS = ["SH Base", "Middle ware", "Kernel", "Device Driver", "Bluetooth",
          "Audio", "GUI", "Voice Recognition", "Boot", "BootSig"]


class FormatError(ValueError):
    pass


def inspect_bytes(data):
    """Validate the observed container structure and return metadata.

    Structural checks and SHA-256 fingerprints do NOT verify Toyota signatures.
    Unknown versions must satisfy the same narrow layout to be inspected.
    """
    def word(pos, endian=">"):
        if pos < 0 or pos + 4 > len(data):
            raise FormatError("Truncated integer")
        return struct.unpack_from(endian + "I", data, pos)[0]

    header_size, declared_size = word(0), word(4)
    if declared_size != len(data):
        raise FormatError("Declared file size does not match actual size")
    if not 256 <= header_size <= min(len(data), 65536):
        raise FormatError("Unsupported header size")

    def string(pos):
        length = word(pos)
        end = pos + 4 + length
        if length > 512 or end > header_size:
            raise FormatError("String extends outside metadata header")
        try:
            value = data[pos + 4:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise FormatError("Non-ASCII metadata") from exc
        return value, end

    model, pos = string(8)
    if model != MODEL:
        raise FormatError("This inspector supports only " + MODEL)
    if word(pos) != 1 or word(pos + 4) != pos + 8:
        raise FormatError("Unsupported metadata directory")
    pos += 8
    key, pos = string(pos)
    name, pos = string(pos)
    data_key, pos = string(pos)
    if (key, name, data_key) != ("name", "DA", "data"):
        raise FormatError("Unsupported metadata keys")
    if word(pos) != 1 or word(pos + 8) != 0:
        raise FormatError("Unsupported data metadata")
    version_number = word(pos + 4)
    if word(pos + 12) != header_size or word(pos + 16) != 1:
        raise FormatError("Payload pointer does not match header boundary")
    tag, pos = string(pos + 20)
    count = word(pos)
    pos += 4
    if count != len(LABELS):
        raise FormatError("Expected the observed ten-component layout")
    offsets = [word(pos + i * 4) for i in range(count)]
    expected_metadata_offset = pos + count * 4
    metadata = []
    for i, offset in enumerate(offsets):
        if offset != expected_metadata_offset:
            raise FormatError("Noncontiguous or overlapping metadata records")
        key, cursor = string(offset)
        label, cursor = string(cursor)
        update_key, cursor = string(cursor)
        if (key, label, update_key) != ("nam" + str(i + 1), LABELS[i], "update"):
            raise FormatError("Unexpected component metadata")
        update_value = word(cursor)
        version, cursor = string(cursor + 4)
        metadata.append((label, version, update_value))
        expected_metadata_offset = cursor
    # 256 trailing bytes are opaque; their cryptographic meaning is unverified.
    if expected_metadata_offset + 256 != header_size:
        raise FormatError("Unexpected metadata trailer length")
    payload_header_size = 244
    payload_base = header_size + payload_header_size
    if data[header_size:header_size + 4] != bytes.fromhex("ffff0004"):
        raise FormatError("Unexpected payload header marker")
    table_end = header_size + 4 + count * 8
    if payload_base > len(data) or any(data[table_end:payload_base]):
        raise FormatError("Unexpected reserved payload-header bytes")
    components = []
    next_relative = 0
    for i, (label, version, update_value) in enumerate(metadata):
        size = word(header_size + 4 + i * 8, "<")
        relative = word(header_size + 8 + i * 8, "<")
        start, end = payload_base + relative, payload_base + relative + size
        if relative != next_relative or size < 12 or end > len(data):
            raise FormatError("Invalid, overlapping or out-of-bounds component")
        part = data[start:end]
        slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
        components.append({
            "index": i + 1, "name": label, "version": version,
            "update_value_raw": update_value,
            "offset": start, "offset_hex": hex(start), "size": size,
            "sha256": hashlib.sha256(part).hexdigest(),
            "first_12_bytes_hex": part[:12].hex(),
            "filename": f"{i + 1:02d}-{slug}.bin",
        })
        next_relative += size
    if payload_base + next_relative != len(data):
        raise FormatError("Trailing bytes outside component table")
    digest = hashlib.sha256(data).hexdigest()
    evidence = []
    patterns = [rb"U-Boot [ -~]+", rb"uImage_T_DAB_US_1M",
                rb"ddr=mem=[ -~]+", rb"root_emmc=[ -~]+",
                rb"l_init=[ -~]+", rb"HI7750/4[ -~]+"]
    for pattern in patterns:
        for match in re.finditer(pattern, data):
            evidence.append({"offset": match.start(), "text": match.group().decode("ascii")})
    return {
        "model": model.rstrip("\0"), "package_tag": tag,
        "version_field_hex": hex(version_number),
        "file_size": len(data), "sha256": digest,
        "matches_reviewed_CA01_1127": digest == REFERENCE_SHA256,
        "signature_verification": "not implemented; authenticity not established by structural checks",
        "header_size": header_size, "payload_base": payload_base,
        "components": components, "static_string_evidence": evidence,
    }


def extract(data, report, destination):
    """Write byte-exact components to a NEW directory; never overwrite a folder."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    for component in report["components"]:
        start = component["offset"]
        with (destination / component["filename"]).open("xb") as output:
            output.write(data[start:start + component["size"]])
    with (destination / "manifest.json").open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--extract", type=Path, help="New folder for unchanged component bytes")
    args = parser.parse_args()
    try:
        data = args.firmware.read_bytes()
        report = inspect_bytes(data)
        if args.extract:
            extract(data, report, args.extract)
    except (OSError, FormatError) as exc:
        print("Inspection failed: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
