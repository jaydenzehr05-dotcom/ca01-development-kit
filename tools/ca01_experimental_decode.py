#!/usr/bin/env python3
"""Read-only, bounded DEFLATE *suffix* research with unknown-byte provenance.

This is not a KWI decryptor or a complete gzip/archive recovery tool.
Starting at an independently identified DEFLATE block, model the missing 32 KiB
history as distinct unknown variables. Literals and backreferences propagate
provenance exactly. Reaching BFINAL establishes a syntactically valid suffix;
it does not establish a gzip CRC, signature, authenticity or installability.
Only metadata is emitted by default. Optional local artifacts use zero-filled
holes accompanied by an explicit known-byte mask. Never execute that artifact.
"""
from __future__ import annotations

import argparse
from array import array
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
import struct
import zlib


class DecodeError(ValueError):
    """Invalid/truncated stream, invalid parameters, or resource limit."""


class Bits:
    def __init__(self, data: bytes, start: int):
        if not 0 <= start < len(data) * 8:
            raise DecodeError("start bit outside input")
        self.data = data
        self.pos = start

    def read(self, count: int) -> int:
        if self.pos + count > len(self.data) * 8:
            raise DecodeError("truncated input")
        value = 0
        for index in range(count):
            value |= ((self.data[self.pos // 8] >> (self.pos % 8)) & 1) << index
            self.pos += 1
        return value

    def align(self) -> None:
        self.pos = (self.pos + 7) // 8 * 8


class Huffman:
    def __init__(self, lengths: list[int]):
        counts = [0] * 16
        for length in lengths:
            if not 0 <= length <= 15:
                raise DecodeError("invalid Huffman length")
            if length:
                counts[length] += 1
        code = 0
        next_code = [0] * 16
        self.table = {}
        self.max_length = max(lengths, default=0)
        for length in range(1, 16):
            code = (code + counts[length - 1]) << 1
            next_code[length] = code
        for symbol, length in enumerate(lengths):
            if length:
                code = next_code[length]
                next_code[length] += 1
                if code >= 1 << length:
                    raise DecodeError("oversubscribed Huffman tree")
                reversed_code = int(f"{code:0{length}b}"[::-1], 2)
                self.table[(reversed_code, length)] = symbol

    def read(self, bits: Bits) -> int:
        code = 0
        for length in range(1, self.max_length + 1):
            code |= bits.read(1) << (length - 1)
            if (code, length) in self.table:
                return self.table[(code, length)]
        raise DecodeError("invalid Huffman symbol")


LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
               31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
DISTANCE_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
                 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
                 6145, 8193, 12289, 16385, 24577]
DISTANCE_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                  6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11,
                     4, 12, 3, 13, 2, 14, 1, 15]


def read_trees(bits: Bits, kind: int) -> tuple[Huffman, Huffman]:
    if kind == 1:
        return Huffman([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8), Huffman([5] * 32)
    literals = bits.read(5) + 257
    distances = bits.read(5) + 1
    code_count = bits.read(4) + 4
    if literals > 286 or distances > 32:
        raise DecodeError("reserved dynamic tree count")
    code_lengths = [0] * 19
    for index in CODE_LENGTH_ORDER[:code_count]:
        code_lengths[index] = bits.read(3)
    tree = Huffman(code_lengths)
    lengths = []
    while len(lengths) < literals + distances:
        symbol = tree.read(bits)
        if symbol < 16:
            lengths.append(symbol)
        elif symbol == 16:
            if not lengths:
                raise DecodeError("repeat without prior code length")
            lengths.extend([lengths[-1]] * (bits.read(2) + 3))
        elif symbol == 17:
            lengths.extend([0] * (bits.read(3) + 3))
        else:
            lengths.extend([0] * (bits.read(7) + 11))
    if len(lengths) != literals + distances:
        raise DecodeError("code length overflow")
    if lengths[256] == 0:
        raise DecodeError("missing end-of-block code")
    return Huffman(lengths[:literals]), Huffman(lengths[literals:])


@dataclass
class SuffixResult:
    # Negative values identify original missing-history slots [-32768, -1].
    symbols: array
    start_bit: int
    end_bit: int
    blocks: list[dict]

    def materialize(self, dictionary: bytes | None = None) -> bytes:
        """Substitute a caller's history, or zero-fill holes; never infer bytes."""
        if dictionary is not None and len(dictionary) != 32768:
            raise DecodeError("substitution dictionary must have exactly 32768 bytes")
        return bytes(value if value >= 0 else
                     (dictionary[value + 32768] if dictionary is not None else 0)
                     for value in self.symbols)

    def known_mask(self) -> bytes:
        return bytes(value >= 0 for value in self.symbols)

    def metadata(self) -> dict:
        last_unknown = max((i for i, value in enumerate(self.symbols) if value < 0), default=-1)
        suffix = bytes(value for value in self.symbols[last_unknown + 1:])
        unknown = sum(value < 0 for value in self.symbols)
        return {
            "status": "partial_untrusted_deflate_suffix",
            "start_bit": self.start_bit,
            "end_bit": self.end_bit,
            "end_byte_ceil": (self.end_bit + 7) // 8,
            "output_size": len(self.symbols),
            "known_bytes": len(self.symbols) - unknown,
            "unknown_bytes": unknown,
            "unique_unknown_history_slots": len({value for value in self.symbols if value < 0}),
            "known_contiguous_suffix_start": last_unknown + 1,
            "known_contiguous_suffix_size": len(suffix),
            "known_contiguous_suffix_sha256": hashlib.sha256(suffix).hexdigest(),
            "zero_filled_output_sha256": hashlib.sha256(self.materialize()).hexdigest(),
            "blocks": self.blocks,
            "limits": ["Missing prefix and unknown history are not recovered.",
                       "No gzip CRC or package signature is verified.",
                       "Complete individual entries require independent header, bounds and mask checks."],
        }


def decode_suffix(data: bytes, start_bit: int = 0,
                  max_output: int = 32 * 1024 * 1024) -> SuffixResult:
    """Decode one bounded raw DEFLATE suffix with symbolic 32 KiB history."""
    if max_output < 1:
        raise DecodeError("output limit must be positive")
    bits = Bits(data, start_bit)
    output = array("i")
    history = list(range(-32768, 0))
    position = 32768
    blocks = []

    def emit(value: int) -> None:
        nonlocal position
        if len(output) >= max_output:
            raise DecodeError("output limit exceeded")
        output.append(value)
        history[position & 32767] = value
        position += 1

    while True:
        block_start = bits.pos
        final, kind = bits.read(1), bits.read(2)
        if kind == 3:
            raise DecodeError("reserved block type")
        if kind == 0:
            bits.align()
            size, complement = bits.read(16), bits.read(16)
            if size ^ complement != 65535:
                raise DecodeError("stored size complement mismatch")
            for _ in range(size):
                emit(bits.read(8))
        else:
            literals, distances = read_trees(bits, kind)
            while True:
                symbol = literals.read(bits)
                if symbol < 256:
                    emit(symbol)
                elif symbol == 256:
                    break
                elif symbol > 285:
                    raise DecodeError("reserved length symbol")
                else:
                    index = symbol - 257
                    length = LENGTH_BASE[index] + bits.read(LENGTH_EXTRA[index])
                    distance_symbol = distances.read(bits)
                    if distance_symbol >= 30:
                        raise DecodeError("reserved distance symbol")
                    distance = DISTANCE_BASE[distance_symbol] + bits.read(DISTANCE_EXTRA[distance_symbol])
                    for _ in range(length):
                        emit(history[(position - distance) & 32767])
        blocks.append({"start_bit": block_start, "end_bit": bits.pos,
                       "final": bool(final), "kind": kind, "output_end": len(output)})
        if final:
            return SuffixResult(output, start_bit, bits.pos, blocks)


def _aligned_zlib_input(data: bytes, start_bit: int, literal: int) -> tuple[bytes, int]:
    """Prepend valid blocks while preserving original stored-block byte alignment.

    Empty fixed-Huffman blocks occupy10bits. For odd offsets, a fixed block
    emitting one9-bit literal occupies19bits. Choose a combination whose length
    modulo8 equals the original start offset, then splice only the discarded
    low bits of the original first byte. Original suffix bytes stay aligned.
    """
    start_byte, shift = divmod(start_bit, 8)
    if not 0 <= start_byte < len(data):
        raise DecodeError("crosscheck start outside input")
    emitted = int(shift % 2 != 0)
    prelude = []
    if emitted:
        # Fixed codes144..255 have9bits; their canonical codes start at400.
        if not 144 <= literal <= 255:
            raise DecodeError("alignment literal must have a9-bit fixed code")
        code = 400 + literal - 144
        prelude = [0, 1, 0] + [int(bit) for bit in f"{code:09b}"] + [0] * 7
    empty_count = ((shift - len(prelude)) % 8) // 2
    prelude += ([0, 1, 0] + [0] * 7) * empty_count
    packed = bytearray((len(prelude) + 7) // 8)
    for index, bit in enumerate(prelude):
        packed[index // 8] |= bit << (index % 8)
    assert len(prelude) % 8 == shift
    if not shift:
        return bytes(packed) + data[start_byte:], emitted
    low_mask = (1 << shift) - 1
    first = (packed[-1] & low_mask) | (data[start_byte] & (255 ^ low_mask))
    return bytes(packed[:-1]) + bytes([first]) + data[start_byte + 1:], emitted


def zlib_crosscheck(data: bytes, result: SuffixResult) -> list[dict]:
    """Validate symbolic propagation without changing DEFLATE byte alignment."""
    checks = []
    dictionaries = [("zeros", bytes(32768)), ("ones_ff", bytes([255]) * 32768),
                    ("incrementing", bytes(range(256)) * 128)]
    for index, (name, dictionary) in enumerate(dictionaries):
        literal = 144 + index
        selected, emitted = _aligned_zlib_input(data, result.start_bit, literal)
        if emitted:
            # After the prelude literal, the full rolling history equals this
            # target dictionary. Vary its final byte across all three checks.
            dictionary = dictionary[:-1] + bytes([literal])
            initial = b"\x00" + dictionary[:-1]
            name += f"_last_{literal:02x}"
        else:
            initial = dictionary
        try:
            inflater = zlib.decompressobj(-15, zdict=initial)
            # One extra byte catches length mismatch without unbounded allocation.
            output = inflater.decompress(selected, len(result.symbols) + emitted + 1)
        except zlib.error as error:
            raise DecodeError(f"independent zlib crosscheck failed: {name}: {error}") from error
        expected_prefix = bytes([literal]) if emitted else b""
        if (not inflater.eof or output[:emitted] != expected_prefix or
                output[emitted:] != result.materialize(dictionary)):
            raise DecodeError(f"independent zlib crosscheck failed: {name}")
        checks.append({"dictionary": name, "eof": True,
                       "output_size": len(output) - emitted,
                       "alignment_prelude_output_bytes": emitted,
                       "symbolic_output_matches": True})
    return checks


def validated_tar_entries(result: SuffixResult) -> list[dict]:
    """Find checksum-valid USTAR entries whose entire bytes are history-independent.

    This does not assert full-archive recovery. Names are evidence only, never
    filesystem destinations. Strict header/size/mask validation is conservative.
    """
    output, mask = result.materialize(), result.known_mask()
    entries = []
    for match in re.finditer(b"ustar", output):
        header_offset = match.start() - 257
        if header_offset < 0:
            continue
        header = output[header_offset:header_offset + 512]
        if len(header) != 512 or not all(mask[header_offset:header_offset + 512]):
            continue
        checksum = header[148:156].strip(b"\x00 ")
        size_field = header[124:136].strip(b"\x00 ")
        if (not checksum or not size_field or
                any(value not in b"01234567" for value in checksum + size_field)):
            continue
        actual = sum(header[:148]) + 8 * 32 + sum(header[156:])
        if int(checksum, 8) != actual:
            continue
        size = int(size_field, 8)
        data_offset, end = header_offset + 512, header_offset + 512 + size
        if header[156] not in (0, 48) or end > len(output):
            continue
        if not all(mask[data_offset:end]):
            continue
        name = header[:100].split(b"\x00", 1)[0]
        if header[257:265] == b"ustar\x0000":
            prefix = header[345:500].split(b"\x00", 1)[0]
            if prefix:
                name = prefix + b"/" + name
        blob = output[data_offset:end]
        record = {
            "archive_path": name.decode("utf-8", errors="replace"),
            "partial_header_offset": header_offset,
            "partial_data_offset": data_offset,
            "size": size,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "header_checksum_valid": True,
            "header_and_entire_contents_dictionary_independent": True,
            "elf": blob.startswith(b"\x7fELF"),
        }
        if record["elf"] and len(blob) >= 20:
            record["elf_class"] = {1: "ELF32", 2: "ELF64"}.get(blob[4], "unknown")
            record["elf_data_encoding"] = {1: "little", 2: "big"}.get(blob[5], "unknown")
            if blob[5] in (1, 2):
                record["elf_machine"] = int.from_bytes(blob[18:20], record["elf_data_encoding"])
                record["elf_type"] = int.from_bytes(blob[16:18], record["elf_data_encoding"])
        entries.append(record)
    return entries


def export_artifacts(directory: Path, result: SuffixResult, report: dict) -> None:
    """Write only into a NEW directory; original tar paths cannot direct writes."""
    directory.mkdir(parents=True, exist_ok=False)
    output = result.materialize()
    (directory / "UNTRUSTED.partial.bin").write_bytes(output)
    (directory / "known-byte-mask.bin").write_bytes(result.known_mask())
    recovered = directory / "recovered"
    recovered.mkdir()
    exported = []
    for entry in validated_tar_entries(result):
        # Flat names, unique offset prefixes, no permissions/link restoration.
        basename = entry["archive_path"].replace("\\", "/").rsplit("/", 1)[-1]
        basename = re.sub(r"[^a-zA-Z0-9_.-]", "_", basename)[:100] or "unnamed"
        target = recovered / f"{entry['partial_data_offset']:08x}-{basename}"
        start = entry["partial_data_offset"]
        with target.open("xb") as destination:
            destination.write(output[start:start + entry["size"]])
        exported.append({**entry, "local_file": str(target.resolve())})
    (directory / "recovered-manifest.json").write_text(json.dumps(exported, indent=2) + "\n")
    (directory / "metadata.json").write_text(json.dumps(report, indent=2) + "\n")


def inspect(path: Path, payload_offset: int, start_byte: int, start_bit: int,
            max_output: int) -> tuple[SuffixResult, dict]:
    original = path.read_bytes()
    if not 0 <= payload_offset < len(original):
        raise DecodeError("payload offset outside input")
    if not 0 <= start_bit <= 7 or start_byte < 0:
        raise DecodeError("invalid suffix byte/bit offset")
    data = original[payload_offset:]
    result = decode_suffix(data, start_byte * 8 + start_bit, max_output)
    report = result.metadata()
    report.update({"input_path": str(path.resolve()), "input_sha256": hashlib.sha256(original).hexdigest(),
                   "payload_offset": payload_offset, "payload_size": len(data),
                   "component_end_byte_ceil": payload_offset + (result.end_bit + 7) // 8,
                   "zlib_crosschecks": zlib_crosscheck(data, result),
                   "fully_known_tar_entries": validated_tar_entries(result)})
    end = (result.end_bit + 7) // 8
    trailer = data[end:]
    report["trailing_bytes"] = len(trailer)
    if len(trailer) >= 8:
        crc, size = struct.unpack_from("<II", trailer)
        report["unverified_gzip_footer_hypothesis"] = {
            "offset": end, "crc32_hex": f"{crc:08x}", "isize": size,
            "remaining_after_footer": len(trailer) - 8,
            "crc_verified": False,
            "note": "Footer interpretation is a hypothesis; no gzip header/prefix decoded.",
        }
    return result, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--payload-offset", type=int, default=0)
    parser.add_argument("--start-byte", type=int, required=True)
    parser.add_argument("--start-bit", type=int, default=0)
    parser.add_argument("--max-output", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--artifact-directory", type=Path,
                        help="NEW local directory for partial bytes + known mask + metadata; never execute")
    args = parser.parse_args()
    result, report = inspect(args.input, args.payload_offset, args.start_byte, args.start_bit, args.max_output)
    if args.artifact_directory:
        export_artifacts(args.artifact_directory, result, report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
