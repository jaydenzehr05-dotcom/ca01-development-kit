"""Bounded ARM fixtures only; these tests never execute recovered applications."""
from pathlib import Path
import sys
import hashlib
from unittest.mock import patch
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from ca01_startup_trace import BoundedArmTrace, verify_inputs
try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
except ImportError:
    Uc = None

class InputGateTests(unittest.TestCase):
    def test_unrecognized_bytes_rejected_before_emulation(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            verify_inputs(b'not canonical hmi', b'not canonical sysc')

    def test_sysc_hash_checked_after_matching_hmi_fixture(self):
        fixture = b'synthetic HMI hash-gate fixture'
        with patch('ca01_startup_trace.HMI_SHA256', hashlib.sha256(fixture).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'SYSC canonical SHA-256'):
                verify_inputs(fixture, b'wrong system library')

@unittest.skipIf(Uc is None, 'Optional Unicorn runtime is not installed')
class TrapTests(unittest.TestCase):
    def engine(self, code, imports=None):
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, code)
        return BoundedArmTrace(uc, [(0x1000, 0x1000 + len(code))], imports or {})

    def test_import_trap_stops_before_imported_instruction(self):
        # bx r0; then a fixture pretending to be an unimplemented service.
        t = self.engine(bytes.fromhex('10ff2fe1'), {0x2000: 'fopen'})
        r = t.run(0x1000, 0x2000)
        self.assertEqual(r['halt_reason'], 'unimplemented_import')
        self.assertEqual(r['boundary']['symbol'], 'fopen')
        self.assertEqual(r['instructions'], 1)
        self.assertFalse(r['returned'])

    def test_syscall_is_halted_before_svc(self):
        t = self.engine(bytes.fromhex('000000ef'))
        r = t.run(0x1000, 0)
        self.assertEqual(r['halt_reason'], 'unimplemented_syscall')
        self.assertEqual(r['instructions'], 0)

    def test_instruction_bound_never_becomes_a_successful_return(self):
        t = self.engine(bytes.fromhex('feffffea'))  # b .
        r = t.run(0x1000, 0, instruction_limit=7)
        self.assertEqual(r['halt_reason'], 'instruction_limit')
        self.assertEqual(r['instructions'], 7)
        self.assertFalse(r['returned'])

    def test_unapproved_guest_code_is_not_executed(self):
        t = self.engine(bytes.fromhex('10ff2fe1'))
        r = t.run(0x1000, 0x1004)
        self.assertEqual(r['halt_reason'], 'unapproved_code_address')
        self.assertEqual(r['instructions'], 1)

    def test_real_return_reaches_only_guest_sentinel(self):
        t = self.engine(bytes.fromhex('1eff2fe1'))  # bx lr
        r = t.run(0x1000, 0)
        self.assertEqual(r['halt_reason'], 'returned')
        self.assertTrue(r['returned'])

    def test_external_data_is_not_read_as_synthesized_zero(self):
        t = self.engine(bytes.fromhex('001090e5'), {0x2000: 'unknown_object'})  # ldr r1,[r0]
        r = t.run(0x1000, 0x2000)
        self.assertEqual(r['halt_reason'], 'unimplemented_external_data')
        self.assertEqual(r['boundary']['symbol'], 'unknown_object')
        self.assertFalse(r['returned'])

    def test_tls_relocation_read_is_explicitly_blocked(self):
        t = self.engine(bytes.fromhex('001090e5'))
        t.blocked_reads[0x1004] = 'fixture TLS relocation'
        r = t.run(0x1000, 0x1004)
        self.assertEqual(r['halt_reason'], 'unimplemented_relocation')
        self.assertFalse(r['returned'])

    def test_invalid_bounds_rejected(self):
        t = self.engine(bytes.fromhex('feffffea'))
        for n in (0, -1, 1000001):
            with self.assertRaises(ValueError):
                t.run(0x1000, 0, instruction_limit=n)

if __name__ == '__main__':
    unittest.main()
