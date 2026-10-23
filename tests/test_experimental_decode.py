"""Synthetic fixtures only; no proprietary firmware bytes are embedded."""
import hashlib
import io
import tarfile
import random
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from ca01_experimental_decode import (DecodeError, decode_suffix, inspect, zlib_crosscheck,
                                      validated_tar_entries, export_artifacts)


def compressed(data, level=6, strategy=zlib.Z_DEFAULT_STRATEGY, dictionary=None):
    kwargs = {"level": level, "wbits": -15, "strategy": strategy}
    if dictionary is not None:
        kwargs["zdict"] = dictionary
    encoder = zlib.compressobj(**kwargs)
    return encoder.compress(data) + encoder.flush()


def shift_fixture(data, shift):
    """Prefix unrelated bits, keeping all original Huffman bits intact."""
    result = bytearray(len(data) + 1)
    for index, value in enumerate(data):
        result[index] |= (value << shift) & 255
        result[index + 1] |= value >> (8 - shift)
    return bytes(result)


class ExperimentalSuffixTests(unittest.TestCase):
    def test_full_stored_fixed_and_dynamic_streams_match_zlib(self):
        rng = random.Random(1134)
        text = b"synthetic decoding fixture\n" * 3000 + bytes(rng.randrange(256) for _ in range(5000))
        cases = [(0, zlib.Z_DEFAULT_STRATEGY, 0), (6, zlib.Z_FIXED, 1),
                 (9, zlib.Z_DEFAULT_STRATEGY, 2)]
        for level, strategy, expected_kind in cases:
            with self.subTest(kind=expected_kind):
                raw = compressed(text, level=level, strategy=strategy)
                result = decode_suffix(raw)
                self.assertEqual(result.materialize(), text)
                self.assertEqual(result.metadata()["unknown_bytes"], 0)
                self.assertEqual(result.metadata()["known_contiguous_suffix_size"], len(text))
                self.assertEqual(result.metadata()["known_contiguous_suffix_sha256"], hashlib.sha256(text).hexdigest())
                self.assertIn(expected_kind, [block["kind"] for block in result.blocks])
                self.assertTrue(all(row["symbolic_output_matches"] for row in zlib_crosscheck(raw, result)))

    def test_differential_generated_fixtures(self):
        rng = random.Random(64000)
        for index in range(16):
            dictionary = bytes(rng.randrange(256) for _ in range(32768))
            repeated = dictionary[-rng.randrange(100, 5000):] * rng.randrange(1, 5)
            text = repeated + bytes(rng.randrange(256) for _ in range(300))
            raw = compressed(text, level=1 + index % 9, dictionary=dictionary)
            result = decode_suffix(raw)
            self.assertEqual(result.materialize(dictionary), text)
            self.assertEqual(len(zlib_crosscheck(raw, result)), 3)

    def test_missing_dictionary_remains_explicit_and_propagates(self):
        dictionary = bytes(range(256)) * 128
        text = dictionary[-4000:] * 8 + b"independent literal island" * 100
        raw = compressed(text, dictionary=dictionary)
        result = decode_suffix(raw)
        self.assertGreater(result.metadata()["unknown_bytes"], 0)
        self.assertEqual(result.materialize(dictionary), text)
        self.assertEqual(len(result.known_mask()), len(text))
        self.assertTrue(all(value in (0, 1) for value in result.known_mask()))
        self.assertEqual(len(zlib_crosscheck(raw, result)), 3)
        for known, actual, expected in zip(result.known_mask(), result.materialize(), text):
            if known:
                self.assertEqual(actual, expected)

    def test_interior_block_uses_missing_history_without_inventing_prefix(self):
        prefix = bytes(range(256)) * 128
        suffix = prefix[-1000:] * 40 + b"new literal values" * 3000
        encoder = zlib.compressobj(wbits=-15)
        before = encoder.compress(prefix) + encoder.flush(zlib.Z_SYNC_FLUSH)
        after = encoder.compress(suffix) + encoder.flush()
        result = decode_suffix(before + after, len(before) * 8)
        self.assertEqual(result.materialize(prefix), suffix)
        self.assertGreater(result.metadata()["unknown_bytes"], 0)
        self.assertEqual(len(zlib_crosscheck(before + after, result)), 3)

    def test_bit_offset_huffman_streams(self):
        # Fixed Huffman stream avoids DEFLATE stored-block byte-alignment changes.
        text = b"bit-aligned fixture " * 50
        raw = compressed(text, strategy=zlib.Z_FIXED)
        for shift in range(1, 8):
            with self.subTest(shift=shift):
                packed = shift_fixture(raw, shift)
                result = decode_suffix(packed, shift)
                self.assertEqual(result.materialize(), text)
                self.assertEqual(result.end_bit, decode_suffix(raw).end_bit + shift)
                self.assertEqual(len(zlib_crosscheck(packed, result)), 3)

    def test_bit_offsets_preserve_missing_dictionary_history(self):
        dictionary = bytes(range(256)) * 128
        text = dictionary[-1000:] * 10
        raw = compressed(text, strategy=zlib.Z_FIXED, dictionary=dictionary)
        for shift in range(1, 8):
            with self.subTest(shift=shift):
                packed = shift_fixture(raw, shift)
                result = decode_suffix(packed, shift)
                self.assertGreater(result.metadata()["unknown_bytes"], 0)
                self.assertEqual(result.materialize(dictionary), text)
                self.assertEqual(len(zlib_crosscheck(packed, result)), 3)

    def test_stored_blocks_preserve_original_alignment_at_every_bit_start(self):
        for start in range(8):
            # BFINAL1/BTYPE00 begins at start; LEN must begin at original byte8.
            raw = bytes([1 << start]) if start <= 5 else bytes([1 << start, 0])
            raw += struct.pack("<HH", 3, 65532) + b"ABC"
            with self.subTest(start=start):
                result = decode_suffix(raw, start)
                self.assertEqual(result.materialize(), b"ABC")
                self.assertEqual(len(zlib_crosscheck(raw, result)), 3)

    def test_crosscheck_wraps_zlib_errors(self):
        raw = compressed(b"synthetic errors")
        result = decode_suffix(raw)
        with patch("ca01_experimental_decode.zlib.decompressobj", side_effect=zlib.error("fixture")):
            with self.assertRaises(DecodeError):
                zlib_crosscheck(raw, result)

    def test_trailer_is_reported_as_unverified(self):
        text = b"generated report fixture" * 500
        raw = compressed(text)
        trailer = struct.pack("<II", zlib.crc32(text), len(text)) + b"opaque suffix" * 20
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.bin"
            original = b"WRAPPER" + raw + trailer
            path.write_bytes(original)
            result, report = inspect(path, 7, 0, 0, 100000)
            self.assertEqual(report["input_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(report["unverified_gzip_footer_hypothesis"]["isize"], len(text))
            self.assertFalse(report["unverified_gzip_footer_hypothesis"]["crc_verified"])
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(result.materialize(), text)

    def test_safe_complete_entry_recovery_and_nonoverwrite(self):
        payload = b"synthetic executable content" * 30
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            info = tarfile.TarInfo("../../outside.bin")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        result = decode_suffix(compressed(archive.getvalue()))
        entries = validated_tar_entries(result)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["archive_path"], "../../outside.bin")
        self.assertEqual(entries[0]["sha256"], hashlib.sha256(payload).hexdigest())
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "new"
            export_artifacts(destination, result, result.metadata())
            recovered = list((destination / "recovered").iterdir())
            self.assertEqual(len(recovered), 1)
            self.assertEqual(recovered[0].read_bytes(), payload)
            self.assertFalse((Path(folder) / "outside.bin").exists())
            with self.assertRaises(FileExistsError):
                export_artifacts(destination, result, result.metadata())

    def test_tar_checksum_bounds_and_unknown_bytes_are_required(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            info = tarfile.TarInfo("fixture.bin")
            info.size = 1000
            tar.addfile(info, io.BytesIO(b"A" * 1000))
        valid = decode_suffix(compressed(archive.getvalue()))
        self.assertEqual(len(validated_tar_entries(valid)), 1)
        valid.symbols[512] = -1
        self.assertEqual(validated_tar_entries(valid), [])
        valid.symbols[512] = ord("A")
        valid.symbols[0] ^= 1
        self.assertEqual(validated_tar_entries(valid), [])
        truncated = decode_suffix(compressed(archive.getvalue()[:700]))
        self.assertEqual(validated_tar_entries(truncated), [])

    def test_invalid_parameters_and_output_limit(self):
        raw = compressed(b"A" * 10000)
        for start, limit in [(-1, 100), (len(raw) * 8, 100), (0, 0), (0, 99)]:
            with self.subTest(start=start, limit=limit):
                with self.assertRaises(DecodeError):
                    decode_suffix(raw, start, limit)
        with self.assertRaises(DecodeError):
            decode_suffix(raw).materialize(b"short")

    def test_truncation_reserved_block_and_stored_complement_rejected(self):
        for malformed in [b"", b"\x07", b"\x01\x01\x00\x00\x00A",
                          compressed(b"truncate me" * 500)[:-2]]:
            with self.subTest(data=malformed[:8]):
                with self.assertRaises(DecodeError):
                    decode_suffix(malformed)


if __name__ == "__main__":
    unittest.main()
