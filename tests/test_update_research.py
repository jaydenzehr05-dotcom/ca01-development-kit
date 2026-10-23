import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from ca01_update_research import analyze_component, analyze_package, probe_zlib, write_report
from ca01_inspect import FormatError


def component(payload=b'synthetic contents', prefix=b'', kind=0, flag=1):
    return struct.pack('<HHII', kind, 0x1234, flag, len(payload)) + prefix + payload


def package():
    header = bytearray((ROOT / 'tests/ca01-1127-header.bin').read_bytes())
    pieces = [component(bytes([i]) * (40 + i)) for i in range(10)]
    cursor = 0
    for i, part in enumerate(pieces):
        struct.pack_into('<II', header, 848 + 4 + i*8, len(part), cursor)
        cursor += len(part)
    struct.pack_into('>I', header, 4, len(header) + cursor)
    return bytes(header) + b''.join(pieces)


class UpdateResearchTests(unittest.TestCase):
    def test_wrapper_fields_are_raw_not_claimed_codec_or_checksum(self):
        report = analyze_component(component(), base_offset=100)
        self.assertEqual(report['wrapper']['raw_u16_at_2'], 0x1234)
        self.assertEqual(report['wrapper']['raw_u32_at_4'], 1)
        self.assertEqual(report['payload']['absolute_offset'], 112)
        self.assertEqual(report['payload']['sha256'], hashlib.sha256(b'synthetic contents').hexdigest())
        self.assertEqual(report['recovery_status'], 'not_decoded')
        self.assertIn('unknown', report['wrapper']['semantics'])

    def test_fixed_path_regions_preserve_leading_marker(self):
        names = [b'./opt/ftl/bin/rma1_hwreg', b'./opt/ftl/bin/vigilancer']
        prefix = b''.join((b'\0' + name).ljust(256, b'\0') for name in names)
        report = analyze_component(component(prefix=prefix, kind=2), base_offset=100)
        self.assertEqual(report['payload']['relative_offset'], 524)
        self.assertEqual([p['text'] for p in report['path_regions']], [n.decode() for n in names])
        self.assertEqual(report['path_regions'][0]['text_absolute_offset'], 113)
        self.assertEqual(report['path_regions'][0]['leading_marker_hex'], '00')
        self.assertEqual(report['path_regions'][1]['region_relative_offset'], 268)
        self.assertTrue(report['wrapper']['record_shape']['matches_prefix_size'])

    def test_bad_wrapper_length_rejected(self):
        for data in [b'x', struct.pack('<HHII', 2, 0, 1, 0), struct.pack('<HHII', 2, 0, 1, 99)]:
            with self.subTest(data=data), self.assertRaises(FormatError):
                analyze_component(data)

    def test_stream_probe_requires_eof_and_is_bounded(self):
        stream = zlib.compress(b'synthetic repeated data' * 10)
        self.assertEqual(probe_zlib(stream)['status'], 'complete_stream')
        self.assertNotEqual(probe_zlib(stream[:-2])['status'], 'complete_stream')
        self.assertEqual(probe_zlib(zlib.compress(b'Z' * 100000), max_output=50)['status'], 'output_limit')
        self.assertNotEqual(probe_zlib(b'not compressed')['status'], 'complete_stream')

    def test_package_fields_offsets_and_full_component_coverage(self):
        data = package()
        report = analyze_package(data)
        self.assertEqual(report['input']['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(len(report['components']), 10)
        self.assertEqual(report['metadata']['opaque_trailer']['size'], 256)
        self.assertEqual(report['metadata']['opaque_trailer']['absolute_offset'], 592)
        self.assertEqual(report['components'][0]['payload']['absolute_offset'], 1104)
        self.assertEqual(report['metadata']['fields'][0]['offset'], 0)
        self.assertEqual(report['components'][-1]['end_offset'], len(data))

    def test_window_evidence_measured_without_encryption_claim(self):
        report = analyze_component(component(bytes(range(256)) * 260))
        self.assertEqual(report['payload']['windows'][0]['offset'], 0)
        self.assertEqual(report['payload']['windows'][0]['size'], 4096)
        self.assertEqual(report['payload']['windows'][0]['entropy_bits_per_byte'], 8)
        self.assertIn('does not establish encryption', report['payload']['entropy_limit'])
        self.assertEqual(report['payload']['boundary_64000']['offset'], 64000)

    def test_output_does_not_overwrite_or_mutate_inputs(self):
        data = package()
        original = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'report.json'
            write_report(analyze_package(data), dest)
            before = dest.read_bytes()
            with self.assertRaises(FileExistsError):
                write_report({'wrong': True}, dest)
            self.assertEqual(dest.read_bytes(), before)
        self.assertEqual(hashlib.sha256(data).hexdigest(), original)

    def test_raw_descriptor_and_gzip_footer_candidates_stay_unverified(self):
        raw = component(b'raw bytes', prefix=struct.pack('<III', 24, 9, 0x100000), kind=1, flag=0)
        report = analyze_component(raw)
        self.assertTrue(report['wrapper']['record_shape']['matches_prefix_size'])
        self.assertEqual(report['wrapper']['raw_descriptors'][0]['raw_u32_le'], [24, 9, 0x100000])
        payload = b'opaque' + struct.pack('<II', 0x12345678, 20480) + bytes(256)
        report = analyze_component(component(payload))
        footer = report['payload']['gzip_trailer_candidate']
        self.assertEqual(footer['candidate_gzip_isize'], 20480)
        self.assertTrue(footer['isize_multiple_of_10240'])
        self.assertIn('CRC not verified', footer['meaning'])
