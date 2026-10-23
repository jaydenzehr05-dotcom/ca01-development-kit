"""Synthetic files only. No vendor code is executed by these unit tests."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from ca01_loader_sandbox import stage_verified_elfs, build_trace_command, parse_trace


def elf(kind=2, machine=40, interpreter=b"/lib/ld-linux.so.3\0"):
    data = bytearray(128)
    data[:6] = b'\x7fELF\x01\x01'
    struct.pack_into('<HH', data, 16, kind, machine)
    if interpreter is not None:
        struct.pack_into('<I', data, 28, 52)
        struct.pack_into('<HH', data, 42, 32, 1)
        struct.pack_into('<IIIIIIII', data, 52, 3, 96, 0, 0, len(interpreter), len(interpreter), 4, 1)
        data[96:96 + len(interpreter)] = interpreter
    return bytes(data)


class LoaderSandboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'recovered'
        self.source.mkdir()
        self.manifest = self.source / 'manifest.json'
        self.output = self.root / 'vendor'

    def row(self, name='PROC_HMI', kind=2):
        p = self.source / name
        p.write_bytes(elf(kind))
        p.chmod(0o444)
        return dict(local_path=str(p), archive_path='./opt/ftl/' + ('apl/' if kind == 2 else 'lib/') + name,
                    size=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                    ELF=True, header_checksum_valid=True,
                    header_and_entire_contents_dictionary_independent=True)

    def save(self, rows):
        self.manifest.write_text(json.dumps({'files': rows}))

    def test_copies_bytes_without_changing_original_permissions(self):
        rows = [self.row(), self.row('libexample.so', 3)]
        self.save(rows)
        result = stage_verified_elfs(self.manifest, self.output)
        self.assertEqual(len(result), 2)
        self.assertEqual((self.output / 'opt/ftl/apl/PROC_HMI').read_bytes(), elf())
        self.assertEqual((self.source / 'PROC_HMI').stat().st_mode & 0o777, 0o444)
        self.assertEqual((self.output / 'opt/ftl/apl/PROC_HMI').stat().st_mode & 0o777, 0o555)
        self.assertEqual((self.output / 'opt/ftl/lib/libexample.so').stat().st_mode & 0o777, 0o444)

    def test_bad_hash_rejected_before_any_output(self):
        row = self.row(); row['sha256'] = '0' * 64; self.save([row])
        with self.assertRaises(ValueError):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_path_traversal_rejected(self):
        row = self.row(); row['archive_path'] = './opt/ftl/../../escape'; self.save([row])
        with self.assertRaises(ValueError): stage_verified_elfs(self.manifest, self.output)

    def test_absolute_path_rejected(self):
        row = self.row(); row['archive_path'] = '/etc/shadow'; self.save([row])
        with self.assertRaises(ValueError): stage_verified_elfs(self.manifest, self.output)

    def test_outside_source_rejected(self):
        row = self.row(); outside = self.root / 'outside'; outside.write_bytes(elf())
        row['local_path'] = str(outside); self.save([row])
        with self.assertRaises(ValueError): stage_verified_elfs(self.manifest, self.output)

    def test_partial_bytes_rejected(self):
        row = self.row(); row['header_and_entire_contents_dictionary_independent'] = False
        self.save([row])
        with self.assertRaises(ValueError): stage_verified_elfs(self.manifest, self.output)

    def test_wrong_architecture_rejected(self):
        row = self.row(); p = Path(row['local_path']); p.chmod(0o644); p.write_bytes(elf(machine=3))
        row['sha256'] = hashlib.sha256(p.read_bytes()).hexdigest(); self.save([row])
        with self.assertRaises(ValueError): stage_verified_elfs(self.manifest, self.output)

    def test_duplicates_rejected(self):
        row = self.row(); self.save([row, row.copy()])
        with self.assertRaises(ValueError): stage_verified_elfs(self.manifest, self.output)

    def test_existing_output_is_not_overwritten(self):
        self.save([self.row()]); self.output.mkdir()
        with self.assertRaises(FileExistsError): stage_verified_elfs(self.manifest, self.output)

    def replace_elf(self, row, data):
        p = Path(row['local_path']); p.chmod(0o644); p.write_bytes(data)
        row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.save([row])

    def test_static_executable_rejected_before_output(self):
        row = self.row(); self.replace_elf(row, elf(interpreter=None))
        with self.assertRaisesRegex(ValueError, 'interpreter'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_custom_interpreter_rejected_before_output(self):
        row = self.row(); self.replace_elf(row, elf(interpreter=b'/opt/custom-loader\0'))
        with self.assertRaisesRegex(ValueError, 'interpreter'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_out_of_bounds_program_headers_rejected(self):
        row = self.row(); data = bytearray(elf()); struct.pack_into('<I', data, 28, 4096)
        self.replace_elf(row, bytes(data))
        with self.assertRaisesRegex(ValueError, 'program header'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_approved_target_cannot_be_static_shared_object(self):
        row = self.row(); self.replace_elf(row, elf(kind=3, interpreter=None))
        with self.assertRaisesRegex(ValueError, 'interpreter'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_command_enforces_isolation_trace_only_and_guest_base(self):
        cmd = build_trace_command(Path('/example/rootfs'), Path('/example/vendor'), 'PROC_HMI')
        for token in ['--unshare-all', '--new-session', '--clearenv', '--ro-bind', '--cap-drop', 'ALL',
                      'LD_TRACE_LOADED_OBJECTS=1', '-B', '0x100000000']:
            self.assertIn(token, cmd)
        self.assertNotIn('--share-net', cmd)
        self.assertNotIn('--dev-bind', cmd)
        self.assertEqual(cmd[-1], '/opt/ftl/apl/PROC_HMI')

    def test_unknown_program_refused(self):
        with self.assertRaises(ValueError):
            build_trace_command(Path('/example/rootfs'), Path('/example/vendor'), 'FlashImageWriter')

    def test_missing_libraries_cannot_be_success_even_with_zero_exit(self):
        result = parse_trace(0, 'libc.so.6 => /lib/libc.so.6 (0x1000)\nlibx.so => not found\nlibx.so => not found\n', '')
        self.assertTrue(result['inspection_succeeded'])
        self.assertFalse(result['all_listed_dependencies_resolved'])
        self.assertEqual(result['missing_libraries'], ['libx.so'])
        self.assertEqual(result['resolved_libraries'], {'libc.so.6': '/lib/libc.so.6'})

    def test_silent_result_is_not_a_success(self):
        self.assertFalse(parse_trace(0, '', '')['inspection_succeeded'])
        self.assertFalse(parse_trace(1, '', '')['inspection_succeeded'])

    def test_loader_error_not_overridden_by_some_library_output(self):
        result = parse_trace(127, 'libc.so.6 => /lib/libc.so.6 (0x1000)\n', 'version TEST not found')
        self.assertFalse(result['inspection_succeeded'])
        self.assertFalse(result['all_listed_dependencies_resolved'])

if __name__ == '__main__':
    unittest.main()
