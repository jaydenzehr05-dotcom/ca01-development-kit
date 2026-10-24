"""Original ARM producer/consumer common-memory contracts; no host IPC."""
from pathlib import Path
import hashlib,struct,sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_common_memory import CommonMemoryProbe,SHARED_BYTES,SHARED_BASE,SYSP_SHA256
ORIG=ROOT.parent/'system-audit/ca01-updater-independent-20261022'
@unittest.skipUnless((ORIG/'06-libipas_sysp.so').is_file(),'Canonical recovered libraries required')
class CommonMemoryTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.hmi=(ORIG/'06-PROC_HMI').read_bytes();cls.sysc=(ORIG/'06-libipas_sysc.so').read_bytes()
  cls.sysp=(ORIG/'06-libipas_sysp.so').read_bytes()
 def parent(self):return CommonMemoryProbe(self.sysp,role='producer')
 def child(self,snapshot=None):return CommonMemoryProbe(self.sysc,role='consumer',snapshot=snapshot)
 def test_producer_hash_is_verified_before_emulation(self):
  with self.assertRaisesRegex(ValueError,'SHA-256'):CommonMemoryProbe(b'bad',role='producer')
  self.assertEqual(hashlib.sha256(self.sysp).hexdigest(),SYSP_SHA256)
 def test_consumer_cannot_create_missing_parent_memory(self):
  p=self.child();r=p.run('fc_sys_InitComAdr')
  self.assertEqual(r['halt_reason'],'service_error');self.assertIn('missing',r['boundary']['error'].lower())
  self.assertFalse(p.backend.exists);self.assertEqual(p.pointer('bf_sys_VclPara'),0)
 def test_original_producer_creates_and_lays_out_common_memory(self):
  p=self.parent();r=p.run('fc_sys_InitComAdr');self.assertTrue(r['returned'],r)
  calls=r['service_calls'];self.assertEqual([x['symbol'] for x in calls if x['symbol'] in ('shm_unlink','shm_open','ftruncate','mmap')],['shm_unlink','shm_open','ftruncate','mmap'])
  op=next(x for x in calls if x['symbol']=='shm_open');self.assertEqual(op['arguments'][1:3],[0xc2,0o666])
  self.assertEqual(p.region(16),dict(index=16,address=SHARED_BASE+0x2ddb8,offset=0x2ddb8,size=256))
  self.assertEqual(p.backend.size,SHARED_BYTES)
 def test_pointer_is_written_by_original_preinitializer(self):
  p=self.parent();p.run('fc_sys_InitComAdr');self.assertEqual(p.pointer('bf_sys_VclPara'),0)
  self.assertTrue(p.run('fs_sys_ExPreInit')['returned']);self.assertEqual(p.pointer('bf_sys_VclPara'),p.region(16)['address'])
  self.assertTrue(p.pointer_writes)
 def test_unloaded_vehicle_content_remains_blocked_after_mapping(self):
  p=self.parent();p.run('fc_sys_InitComAdr');p.run('fs_sys_ExPreInit')
  r=p.run('rq_sys_GetVclPara',p.scratch)
  self.assertEqual(r['halt_reason'],'service_error');self.assertIn('unverified',r['boundary']['error'].lower())
 def test_real_loader_reaches_missing_flash_read_with_exact_arguments(self):
  p=self.parent();p.run('fc_sys_InitComAdr');p.run('fs_sys_ExPreInit');r=p.run('rq_sys_LoadVclPara')
  self.assertEqual(r['halt_reason'],'unimplemented_import');self.assertEqual(r['boundary']['symbol'],'fs_flm_Read')
  self.assertEqual(r['boundary']['arguments'][:3],[p.region(16)['address'],0xb0000,256])
  self.assertEqual(p.pointer('bf_sys_VclPara'),p.region(16)['address'])
 def test_consumer_loader_is_a_real_noop_not_a_flash_read(self):
  p=self.child();r=p.run('rq_sys_LoadVclPara');self.assertTrue(r['returned']);self.assertEqual(r['instructions'],1)
  self.assertEqual(r['service_calls'],[])
 def test_synthetic_snapshot_round_trip_is_byte_exact_and_labeled(self):
  data=bytearray(SHARED_BYTES);payload=bytes(range(256));data[0x2ddb8:0x2deb8]=payload
  p=self.child(bytes(data));self.assertTrue(p.run('fc_sys_InitComAdr')['returned']);self.assertTrue(p.run('fs_sys_ExPreInit')['returned'])
  p.verify_fixture_region(16,'synthetic byte-pattern test')
  r=p.run('rq_sys_GetVclPara',p.scratch);self.assertTrue(r['returned'],r)
  self.assertEqual(bytes(p.uc.mem_read(p.scratch,256)),payload)
  report=p.report();self.assertFalse(report['full_startup']);self.assertFalse(report['authentic_vehicle_data']);self.assertTrue(report['fixture_regions'])
 def test_snapshot_length_and_role_validation(self):
  for snapshot in (b'',b'bad'):
   with self.assertRaises(ValueError):self.child(snapshot)
  with self.assertRaises(ValueError):CommonMemoryProbe(self.sysp,role='anything')
 def test_mapping_requires_exact_shared_memory_contract(self):
  p=self.parent()
  with self.assertRaises(ValueError):p.backend.open('/other',0xc2,0o666)
  with self.assertRaises(ValueError):p.backend.open('/SHM_SYS_COM',0x42,0o666)
  fd=p.backend.open('/SHM_SYS_COM',0xc2,0o666)
  with self.assertRaises(ValueError):p.backend.truncate(fd,SHARED_BYTES+1)
  with self.assertRaises(ValueError):p.backend.truncate(fd+1,SHARED_BYTES)
 def test_blank_snapshot_does_not_become_verified_data(self):
  p=self.child(bytes(SHARED_BYTES));p.run('fc_sys_InitComAdr');p.run('fs_sys_ExPreInit')
  r=p.run('rq_sys_GetVclPara',p.scratch);self.assertIn('unverified',r['boundary']['error'].lower())

 def test_producer_and_consumer_use_identical_original_region_layouts(self):
  parent=self.parent();parent.run('fc_sys_InitComAdr')
  child=self.child(bytes(SHARED_BYTES));child.run('fc_sys_InitComAdr')
  self.assertEqual([parent.region(i) for i in range(60)],[child.region(i) for i in range(60)])
  self.assertLessEqual(max(r['offset']+r['size'] for r in parent.report()['regions']),SHARED_BYTES)
 def test_consumer_full_initializer_stops_before_missing_driver(self):
  p=self.child();r=p.run('fs_sys_InitCom')
  self.assertEqual(r['boundary']['symbol'],'fs_drv_MemInit');self.assertEqual(p.backend.events,[])
 def test_consumer_hash_and_flash_role_are_checked(self):
  with self.assertRaisesRegex(ValueError,'SHA-256'):CommonMemoryProbe(self.sysp,role='consumer')
  with self.assertRaisesRegex(ValueError,'flash.*SHA-256'):
   CommonMemoryProbe(self.sysc,role='consumer',flash_data=(ORIG/'06-libComFlmLb.so').read_bytes())

@unittest.skipUnless((ORIG/'06-libComFlmLb.so').is_file(),'Canonical flash library required')
class FlashProviderTests(unittest.TestCase):
 def probe(self):
  return CommonMemoryProbe((ORIG/'06-libipas_sysp.so').read_bytes(),role='producer',flash_data=(ORIG/'06-libComFlmLb.so').read_bytes())
 def test_invalid_provider_is_rejected_before_mapping(self):
  with self.assertRaisesRegex(ValueError,'flash.*SHA-256'):
   CommonMemoryProbe((ORIG/'06-libipas_sysp.so').read_bytes(),role='producer',flash_data=b'bad')
 def test_actual_flash_initializer_stops_at_device_open(self):
  p=self.probe();r=p.run('fs_drv_FlmInit')
  self.assertEqual(r['halt_reason'],'unimplemented_import');self.assertEqual(r['boundary']['symbol'],'open')
  self.assertEqual(p.trace._guest_string(r['boundary']['arguments'][0]),'/dev/flash')
  self.assertEqual(r['boundary']['arguments'][1],2);self.assertFalse(p.report()['hardware_access'])
 def test_bound_loader_enters_recovered_flash_code_and_original_psm(self):
  p=self.probe();p.run('fc_sys_InitComAdr');p.run('fs_sys_ExPreInit');r=p.run('rq_sys_LoadVclPara')
  names=[x['symbol'] for x in r['function_entries']]
  self.assertIn('fs_flm_Read',names);self.assertIn('fc_flm_CheckRange',names);self.assertIn('rq_psm_Take',names)
  self.assertEqual(r['halt_reason'],'unimplemented_import');self.assertEqual(r['boundary']['symbol'],'rq_drc_ErrorTraceP')
  self.assertEqual(r['boundary']['arguments'][2:4],[0xb6000006,25])

if __name__=='__main__':unittest.main()
