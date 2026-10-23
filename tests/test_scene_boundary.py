from pathlib import Path
import sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_scene_boundary import inspect_scene_boundary,ConfiguredSemaphores
HMI=ROOT.parent/'system-audit/ca01-updater-independent-20261022/06-PROC_HMI'

class SemaphoreServiceTests(unittest.TestCase):
 def test_locking_has_state_and_never_fakes_a_busy_success(self):
  s=ConfiguredSemaphores([1]);self.assertEqual(s.take(None,[1,16383,0,0]),0)
  with self.assertRaisesRegex(RuntimeError,'would block'):s.take(None,[1,16383,0,0])
  self.assertEqual(s.give(None,[1,0,0,0]),0)
  self.assertEqual(s.take(None,[1,16383,0,0]),0)
 def test_undeclared_semaphore_does_not_get_created(self):
  s=ConfiguredSemaphores([1])
  with self.assertRaises(ValueError):s.take(None,[2,0,0,0])

class SceneBoundaryTests(unittest.TestCase):
 def test_group_hash_mismatch_is_rejected(self):
  if not HMI.is_file():self.skipTest('Local original HMI fixture required')
  with tempfile.TemporaryDirectory() as folder:
   group=Path(folder)/'wrong.so';group.write_bytes(b'wrong group')
   with self.assertRaisesRegex(ValueError,'Group library SHA-256'):inspect_scene_boundary(HMI,group_library=group)
 def test_wrong_hmi_is_rejected(self):
  with tempfile.TemporaryDirectory() as folder:
   p=Path(folder)/'bad';p.write_bytes(b'not canonical')
   with self.assertRaisesRegex(ValueError,'SHA-256'):inspect_scene_boundary(p)
 @unittest.skipUnless(HMI.is_file(),'Local original HMI fixture required')
 def test_authentic_group_library_reaches_real_display_task_wait(self):
  group=HMI.with_name('06-libipas_grp.so')
  if not group.is_file():self.skipTest('Recovered group library required')
  r=inspect_scene_boundary(HMI,group_library=group)
  boundary=r['task39_initialization']['boundary']
  self.assertEqual(boundary['symbol'],'rq_tsk_WaitInit')
  self.assertEqual(boundary['arguments'][0],10)
  entries=[x['symbol'] for x in r['task39_initialization']['function_entries']]
  self.assertIn('rq_grp_Init',entries);self.assertIn('pt_grp_Init',entries)
 @unittest.skipUnless(HMI.is_file(),'Local original HMI fixture required')
 def test_original_clock_and_memory_reach_precise_resource_service(self):
  sysc=HMI.with_name('06-libipas_sysc.so')
  if not sysc.is_file():self.skipTest('Original system library required')
  r=inspect_scene_boundary(HMI,provide_clock=True,system_library=sysc)
  self.assertIn('clock_gettime',[call['symbol'] for call in r['scene_update']['service_calls']])
  boundary=r['scene_initialization']['boundary']
  self.assertEqual(boundary['symbol'],'rq_fls_Open')
  self.assertEqual(boundary['guest_strings'],['type.txt','r'])
 @unittest.skipUnless(HMI.is_file(),'Local original HMI fixture required')
 def test_real_heartbeat_precedes_blocked_scene_update(self):
  r=inspect_scene_boundary(HMI)
  self.assertTrue(r['heartbeat']['returned']);self.assertEqual(r['pending_after_heartbeat'],1)
  self.assertFalse(r['scene_update']['returned'])
  self.assertFalse(r['full_scene_rendered'])
  self.assertEqual(r['task39_initialization']['boundary']['symbol'],'rq_grp_Init')
  self.assertEqual(r['missing_resources']['mui_directory'],'/opt/ftl/gui/MC/mui/')
  self.assertIn('CmA.mra',r['missing_resources']['mra_names'])
