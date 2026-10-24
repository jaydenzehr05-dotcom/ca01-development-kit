"""Original producer parser, real parent PSM loop, and virtual named semaphores."""
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from ca01_psm_startup import PsmStartupProbe,configuration_fixture
ORIG=ROOT.parent/'system-audit/ca01-updater-independent-20261022'
@unittest.skipUnless((ORIG/'06-PROC_SYSTEM').is_file(),'Original ARM fixtures required')
class PsmStartupTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.sysp=(ORIG/'06-libipas_sysp.so').read_bytes();cls.flash=(ORIG/'06-libComFlmLb.so').read_bytes();cls.system=(ORIG/'06-PROC_SYSTEM').read_bytes()
 def probe(self):return PsmStartupProbe(self.sysp,flash_data=self.flash)
 def configured(self,enabled=(6,25),numeric=51):
  p=self.probe();p.set_configuration_fixture(configuration_fixture(enabled,numeric_id=numeric),'synthetic semaphore fixture')
  self.assertTrue(p.run('fs_cnf_Load')['returned']);self.assertTrue(p.run('fs_psm_Init')['returned']);return p
 def test_default_configuration_remains_missing(self):
  p=self.probe();r=p.run('fs_cnf_Load');self.assertEqual(r['boundary']['symbol'],'fopen');self.assertFalse(p.named.objects)
 def test_original_parser_uses_sequential_rows_not_numeric_ids(self):
  p=self.configured(numeric=51);self.assertEqual(p.record(25)['numeric_id'],51)
  self.assertEqual(p.record(25)['enabled'],1);self.assertEqual(p.record(25)['name'],'/ca01_fixture_25')
  self.assertEqual(p.record(51)['enabled'],0)
 def test_original_parent_loop_creates_selected_rows(self):
  p=self.configured();r=p.run_parent_psm_slice(self.system)
  self.assertEqual(r['halt_reason'],'psm_loop_boundary')
  self.assertEqual([x['slot'] for x in p.created_slots],[6,25]);self.assertEqual(set(p.named.objects),{'/ca01_fixture_06','/ca01_fixture_25'})
  self.assertEqual([x['initial'] for x in p.named.events if x['operation']=='open'],[1,1])
 def test_invalid_parent_binary_is_rejected(self):
  p=self.configured()
  with self.assertRaisesRegex(ValueError,'SHA-256'):p.run_parent_psm_slice(b'bad')
 def test_loader_passes_semaphore25_then_stops_at_semaphore6(self):
  p=self.configured(enabled=(25,));p.run_parent_psm_slice(self.system)
  p.run('fc_sys_InitComAdr');p.run('fs_sys_ExPreInit');r=p.run('rq_sys_LoadVclPara')
  self.assertEqual(r['boundary']['symbol'],'rq_drc_ErrorTraceP');self.assertEqual(r['boundary']['arguments'][2:4],[0xb6000006,6])
  self.assertTrue(any(x['symbol']=='fs_drv_FlmRead' for x in r['function_entries']))
 def test_both_initialized_locks_reach_first_actual_flash_ioctl(self):
  p=self.configured();p.run_parent_psm_slice(self.system)
  p.run('fc_sys_InitComAdr');p.run('fs_sys_ExPreInit');r=p.run('rq_sys_LoadVclPara')
  self.assertEqual(r['boundary']['symbol'],'ioctl');request=p.last_ioctl(r)
  self.assertEqual(request['request'],0x4004ff10);self.assertEqual(request['words'][1:],[0xb0000,256])
  self.assertFalse(request['initialized_device']);self.assertEqual(request['descriptor'],0)
  self.assertFalse(p.report()['authentic_configuration']);self.assertFalse(p.report()['full_startup'])
 def test_flash_initialization_still_requires_a_real_backend(self):
  p=self.configured();r=p.run('fs_drv_FlmInit');self.assertEqual(r['boundary']['symbol'],'open')
  self.assertEqual(p.trace._guest_string(r['boundary']['arguments'][0]),'/dev/flash')
 def test_original_take_and_give_modify_virtual_counts(self):
  p=self.configured();p.run_parent_psm_slice(self.system)
  p.run('rq_psm_Take',25);self.assertEqual(p.named.count('/ca01_fixture_25'),0)
  p.run('rq_psm_Give',25);self.assertEqual(p.named.count('/ca01_fixture_25'),1)
 def test_empty_semaphore_reaches_original_timeout_diagnostic(self):
  p=self.configured();p.run_parent_psm_slice(self.system);p.run('rq_psm_Take',25)
  r=p.run('rq_psm_Take',25);self.assertEqual(r['boundary']['arguments'][2:4],[0xb6000007,25])
  self.assertEqual(p.named.count('/ca01_fixture_25'),0)
 def test_missing_fixture_label_and_unsafe_fixture_rows_rejected(self):
  p=self.probe()
  with self.assertRaises(ValueError):p.set_configuration_fixture(configuration_fixture((25,)),'')
  for slots in ((64,),(-1,),(25,25)):
   with self.assertRaises(ValueError):configuration_fixture(slots)
  with self.assertRaises(ValueError):p.set_configuration_fixture(b'[PSM]\nnum=1\nname='+b'x'*128,'synthetic')
 def test_fixture_is_explicit_in_report(self):
  p=self.configured();p.run_parent_psm_slice(self.system);r=p.report()
  self.assertTrue(r['configuration_fixture']);self.assertFalse(r['authentic_configuration']);self.assertFalse(r['host_ipc']);self.assertFalse(r['hardware_access'])
if __name__=='__main__':unittest.main()
