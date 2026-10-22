#!/usr/bin/env python3
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from ca01_inspect import FormatError, inspect_bytes, extract


def fixture():
    # Original metadata + synthetic zero component payloads: no firmware content.
    report = json.loads((ROOT / "evidence/ca01-1127-inspection.json").read_text())
    header = (ROOT / "tests/ca01-1127-header.bin").read_bytes()
    return bytearray(header + bytes(report["file_size"] - len(header)))


class InspectorTest(unittest.TestCase):
    def test_ten_components_and_full_coverage(self):
        report = inspect_bytes(fixture())
        self.assertEqual(len(report["components"]), 10)
        self.assertEqual(report["payload_base"], 1092)
        self.assertFalse(report["matches_reviewed_CA01_1127"])
        self.assertEqual(report["components"][-1]["offset"] + report["components"][-1]["size"], report["file_size"])

    def test_truncated_file(self):
        with self.assertRaises(FormatError):
            inspect_bytes(fixture()[:-1])

    def test_wrong_model(self):
        data = fixture()
        data[24] = ord("2")
        with self.assertRaises(FormatError):
            inspect_bytes(data)

    def test_overlapping_components(self):
        data = fixture()
        struct.pack_into("<I", data, 848 + 8 + 8, 0)
        with self.assertRaises(FormatError):
            inspect_bytes(data)

    def test_out_of_bounds_component(self):
        data = fixture()
        struct.pack_into("<I", data, 848 + 4, 0xffffffff)
        with self.assertRaises(FormatError):
            inspect_bytes(data)

    def test_bad_metadata_pointer(self):
        data = fixture()
        struct.pack_into(">I", data, 89, 0xffffffff)
        with self.assertRaises(FormatError):
            inspect_bytes(data)

    def test_extraction_and_no_overwrite(self):
        data = fixture()
        report = inspect_bytes(data)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "components"
            extract(data, report, target)
            self.assertEqual(len(list(target.iterdir())), 11)
            with self.assertRaises(FileExistsError):
                extract(data, report, target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
