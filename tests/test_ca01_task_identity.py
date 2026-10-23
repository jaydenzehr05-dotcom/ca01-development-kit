from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_task_identity import run_identity_probe
BASE=ROOT.parent/'system-audit/ca01-updater-independent-20261022'

@unittest.skipUnless((BASE/'06-PROC_HMI').is_file(),'Local original fixtures required')
class IdentityTests(unittest.TestCase):
 def probe(self,thread,cached=-2):
  return run_identity_probe((BASE/'06-PROC_HMI').read_bytes(),(BASE/'06-libipas_sysc.so').read_bytes(),{3:0x1234,39:0x5678},thread,cached)
 def test_original_table_search_finds_task39_and_updates_tls(self):
  r=self.probe(0x5678)
  self.assertEqual(r['returned_task_id'],39);self.assertEqual(r['tls_after'],39)
  self.assertEqual(r['task_count'],96)
  self.assertFalse(r['full_startup']);self.assertFalse(r['queue_send_performed'])
 def test_stale_cached_id_is_rechecked_against_actual_thread_identity(self):
  self.assertEqual(self.probe(0x5678,3)['returned_task_id'],39)
 def test_unknown_thread_returns_minus_one(self):
  self.assertEqual(self.probe(0x9999)['returned_task_id'],-1)
 def test_cached_minus_one_is_preserved_even_with_a_matching_table_row(self):
  r=self.probe(0x5678,-1)
  self.assertEqual(r['returned_task_id'],-1);self.assertEqual(r['tls_after'],-1)
 def test_wrong_binary_rejected(self):
  with self.assertRaises(ValueError):run_identity_probe(b'bad',b'bad',{39:0x5678},0x5678,-2)
