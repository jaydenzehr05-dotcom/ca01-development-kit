"""Original task wait/release and parent eventfd protocol; no radio startup."""
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_task_barriers import TaskBarrierHarness,ParentHandshake,display_init_boundary
from ca01_original_queue import QueueWait,QueueBlocked
from ca01_hmi_startup import Message
ORIG=ROOT.parent/'system-audit/ca01-updater-independent-20261022'
@unittest.skipUnless((ORIG/'06-PROC_HMI').is_file() and (ORIG/'06-libipas_sysc.so').is_file(),
                     'Canonical original ARM ELF fixtures required')
class TaskBarrierTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.hmi=(ORIG/'06-PROC_HMI').read_bytes();cls.sysc=(ORIG/'06-libipas_sysc.so').read_bytes()
 def test_mode_fixture_uses_actual_original_status_reader(self):
  h=TaskBarrierHarness(self.hmi,self.sysc)
  self.assertEqual(h.q.read_words(0x1013a6c8,1)[0],1)
  self.assertEqual(h.q.read_words(h.q.defined['bf_sys_SysMng']+0x24,1)[0],0)
 def test_original_wait_registers_and_blocks(self):
  h=TaskBarrierHarness(self.hmi,self.sysc);w,event=h.begin_wait(40,39)
  self.assertIsInstance(w,QueueWait);self.assertEqual(event,Message(0,5,40,39))
  self.assertEqual(w.deadline_ns-h.q.now_ns,60_000_000_000)
  self.assertEqual(h.wait_count,1);self.assertEqual(h.wait_target(40),39)
  with self.assertRaises(QueueBlocked):h.q.resume(w)
 def test_correct_original_task_initialization_releases_and_deletes_private_queue(self):
  h=TaskBarrierHarness(self.hmi,self.sysc);w,_=h.begin_wait(40,39);private=h.block_queue(40)
  h.initialize_task(39);h.q.resume(w)
  self.assertEqual(h.state(39),3);self.assertEqual(h.wait_count,0)
  self.assertEqual(h.block_queue(40),0);self.assertEqual(h.q.state(private)['enabled'],0)
  self.assertEqual(h.wait_target(40),0)
 def test_unrelated_initialization_cannot_release_waiter(self):
  h=TaskBarrierHarness(self.hmi,self.sysc);w,_=h.begin_wait(40,39)
  h.initialize_task(10)
  with self.assertRaises(QueueBlocked):h.q.resume(w)
  self.assertEqual(h.state(39),2)
 def test_already_initialized_target_releases_immediately(self):
  h=TaskBarrierHarness(self.hmi,self.sysc);h.initialize_task(39);w,_=h.begin_wait(40,39)
  h.q.resume(w);self.assertEqual(h.wait_count,0)
 def test_original_sixty_second_timeout_stops_at_error_instead_of_ready(self):
  h=TaskBarrierHarness(self.hmi,self.sysc);w,_=h.begin_wait(40,39)
  h.q.advance_time(60000)
  with self.assertRaisesRegex(RuntimeError,'11001220'):h.q.resume(w)
  self.assertEqual(h.state(39),2)
 def test_parent_eventfd_correct_token_returns_and_notifies_parent(self):
  with ParentHandshake(self.hmi,self.sysc,process_id=3,expected_token=42) as p:
   p.signal(42);result=p.begin();self.assertIsInstance(result,int)
   self.assertEqual(p.parent_notification(),3);self.assertTrue(p.protocol_returned)
 def test_parent_missing_token_stays_blocked_then_can_resume(self):
  with ParentHandshake(self.hmi,self.sysc,process_id=3,expected_token=42) as p:
   wait=p.begin();self.assertIsInstance(wait,QueueWait)
   self.assertFalse(p.protocol_returned)
   with self.assertRaises(QueueBlocked):p.resume(wait)
   p.signal(42);p.resume(wait);self.assertTrue(p.protocol_returned)
 def test_wrong_token_is_consumed_but_cannot_release_parent_barrier(self):
  with ParentHandshake(self.hmi,self.sysc,process_id=3,expected_token=42) as p:
   p.signal(41);w=p.begin();self.assertIsInstance(w,QueueWait)
   self.assertFalse(p.protocol_returned);p.signal(42);p.resume(w);self.assertTrue(p.protocol_returned)
 def test_eventfd_accumulates_writes_rather_than_queueing_packets(self):
  with ParentHandshake(self.hmi,self.sysc,process_id=3,expected_token=42) as p:
   p.signal(42);p.signal(42);w=p.begin();self.assertIsInstance(w,QueueWait)
   self.assertEqual(p.read_values,[84]);self.assertFalse(p.protocol_returned)
 def test_eventfd_sum_can_equal_expected_token(self):
  with ParentHandshake(self.hmi,self.sysc,process_id=3,expected_token=42) as p:
   p.signal(20);p.signal(22);p.begin();self.assertEqual(p.read_values,[42]);self.assertTrue(p.protocol_returned)
 def test_negative_expected_token_is_sign_extended_to_64_bits(self):
  with ParentHandshake(self.hmi,self.sysc,process_id=3,expected_token=-2) as p:
   p.signal(0xfffffffffffffffe);p.begin();self.assertTrue(p.protocol_returned)
 def test_eventfds_are_closed_with_fixture(self):
  import os
  with ParentHandshake(self.hmi,self.sysc,process_id=3,expected_token=42) as p:
   descriptors=(p.parent_fd,p.child_fd)
  for descriptor in descriptors:
   with self.assertRaises(OSError):os.fstat(descriptor)
  with self.assertRaises(ValueError):p.begin()
 def test_display_init_halts_at_missing_real_provider(self):
  r=display_init_boundary(self.hmi,self.sysc)
  self.assertEqual(r['halt_reason'],'unimplemented_import');self.assertEqual(r['boundary']['symbol'],'sysDisMngInit')
  self.assertFalse(r['display_ready'])
if __name__=='__main__':unittest.main()
