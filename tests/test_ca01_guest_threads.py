"""Bounded original ARM pthread-create handoff and recovered task execution."""
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_guest_threads import GuestPthreadBridge
from ca01_original_queue import QueueBlocked
from ca01_hmi_startup import Message
ORIG=ROOT.parent/'system-audit/ca01-updater-independent-20261022'
@unittest.skipUnless((ORIG/'06-PROC_HMI').is_file() and (ORIG/'06-libipas_sysc.so').is_file(),
                     'Canonical original ARM ELF fixtures required')
class GuestThreadTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.hmi=(ORIG/'06-PROC_HMI').read_bytes();cls.sysc=(ORIG/'06-libipas_sysc.so').read_bytes()
 def bridge(self,**kw):return GuestPthreadBridge(self.hmi,self.sysc,**kw)
 def test_original_create_copies_actual_profile_and_start_writes_pthread_slot(self):
  b=self.bridge();thread=b.start_task(39)
  self.assertEqual(thread.entry,0x2b5b8);self.assertEqual(thread.policy,1);self.assertEqual(thread.priority,12)
  self.assertEqual(b.read_words(b.task_table+39*80+64,1)[0],thread.alias)
  self.assertTrue(any(e['symbol']=='fs_tsk_WDTimerStart' for e in b.history[-1]['trace']['function_entries']))
  self.assertEqual(thread.status,'runnable');self.assertEqual(b.poll(1),(-2,None))
 def test_distinct_bounded_stacks_tls_and_aliases(self):
  b=self.bridge();a=b.start_task(40);c=b.start_task(41)
  self.assertNotEqual(a.alias,c.alias);self.assertNotEqual(a.stack_base,c.stack_base)
  self.assertNotEqual(a.tls,c.tls)
  b.uc.mem_write(c.stack_base+32,b'private-stack')
  b.run_task(40)
  self.assertEqual(bytes(b.uc.mem_read(c.stack_base+32,13)),b'private-stack')
 def test_original_identity_cold_and_cached(self):
  b=self.bridge();b.start_task(39)
  self.assertEqual(b.probe_identity(39),39);self.assertEqual(b.probe_identity(39),39)
 def test_real_draw_task_reports_status_and_waits_on_original_parent_flag(self):
  b=self.bridge();b.start_task(40);r=b.run_task(40)
  self.assertEqual(r['status'],'waiting');self.assertGreater(r['instructions'],0)
  self.assertEqual(b.poll(1),(-1,Message(0,3,40,0)))
  self.assertEqual(b.flag_value(1),0);self.assertEqual(b.flag_value(2),0)
  with self.assertRaises(QueueBlocked):b.resume_task(40)
 def test_explicit_fixture_flag1_only_reaches_display_flag2_wait(self):
  b=self.bridge();b.start_task(40);b.run_task(40)
  b.call('rq_flg_Set',1,1) # Explicit fixture, NOT original parent synchronization.
  r=b.resume_task(40);self.assertEqual(r['status'],'waiting')
  self.assertEqual(b.threads[40].policy,1);self.assertEqual(b.threads[40].priority,1)
  self.assertEqual(b.flag_value(2),0)
  self.assertEqual(b.threads[40].wait.condition,b.flag_condition(2))
 def test_two_real_task_contexts_wait_without_stack_or_tls_corruption(self):
  b=self.bridge();b.start_task(40);b.start_task(41)
  self.assertEqual(b.run_task(40)['status'],'waiting');self.assertEqual(b.run_task(41)['status'],'waiting')
  self.assertEqual({b.poll(1)[1].event,b.poll(1)[1].event},{40,41})
  self.assertEqual(b.probe_identity(40),40);self.assertEqual(b.probe_identity(41),41)
  b.call('rq_flg_Set',1,1);b.resume_task(40)
  self.assertEqual(b.resume_task(41)['status'],'blocked')
  self.assertEqual(b.flag_value(2),0)
 def test_init_task_halts_at_real_unimplemented_service(self):
  b=self.bridge();b.start_task(39);self.assertEqual(b.run_task(39)['status'],'waiting')
  b.call('rq_flg_Set',1,1) # Explicit parent-ready fixture, not authentic synchronization.
  r=b.resume_task(39)
  self.assertEqual(r['status'],'blocked');self.assertIn(r['halt_reason'],('unimplemented_import','service_error','unimplemented_relocation'))
  self.assertFalse(r['display_ready']);self.assertEqual(b.flag_value(2),0)
 def test_scheduling_uses_recovered_fifo_priorities(self):
  b=self.bridge()
  for task in (40,41,39):b.start_task(task)
  self.assertEqual(b.runnable_order(),[39,41,40])
 def test_duplicate_and_unconfigured_task_start_are_rejected(self):
  b=self.bridge();b.start_task(40)
  with self.assertRaises(ValueError):b.start_task(40)
  for value in (0,1,95,96,-1):
   with self.assertRaises(ValueError):b.start_task(value)
 def test_resource_limit_does_not_return_fake_create_success(self):
  b=self.bridge(max_threads=1);b.start_task(40)
  with self.assertRaisesRegex(RuntimeError,'11000101'):b.start_task(41)
  self.assertEqual(set(b.threads),{40});self.assertEqual(b.read_words(b.task_table+41*80+64,1)[0],0)
 def test_instruction_budget_preserves_real_guest_context(self):
  b=self.bridge();b.start_task(40);r=b.run_task(40,instruction_limit=1)
  self.assertEqual(r['status'],'runnable');self.assertEqual(r['halt_reason'],'instruction_limit')
  self.assertEqual(b.run_task(40)['status'],'waiting')
 def test_no_host_thread_or_missing_service_success_is_claimed(self):
  b=self.bridge();b.start_task(40);b.run_task(40);r=b.report()
  self.assertFalse(r['native_pthreads']);self.assertFalse(r['full_startup']);self.assertFalse(r['display_ready'])
 def test_invalid_resume_budget_does_not_destroy_wait(self):
  b=self.bridge();b.start_task(40);b.run_task(40);w=b.threads[40].wait
  b.call('rq_flg_Set',1,1)
  with self.assertRaises(ValueError):b.resume_task(40,instruction_limit=0)
  self.assertFalse(w.consumed);self.assertEqual(b.resume_task(40)['status'],'waiting')
 def test_real_group_provider_executes_instead_of_an_unimplemented_alias(self):
  group=(ORIG/'06-libipas_grp.so').read_bytes()
  b=self.bridge(group_data=group);b.start_task(39);b.run_task(39)
  b.call('rq_flg_Set',1,1);r=b.resume_task(39)
  self.assertTrue(any(x['symbol']=='rq_grp_Init' for x in r['function_entries']))
  self.assertNotEqual(r['boundary'].get('symbol'),'rq_grp_Init')
  self.assertEqual(set(b.group_binding['copy_symbols']),{'bf_grp_VramImage','st_rect'})
  self.assertEqual(b.flag_value(2),0)
 def test_unverified_group_library_is_rejected(self):
  with self.assertRaisesRegex(ValueError,'Group.*SHA-256'):self.bridge(group_data=b'wrong')
 def test_original_activation_handler_marks_task_started(self):
  b=self.bridge();b.start_task(40)
  self.assertEqual(b.uc.mem_read(b.task_table+40*80,1)[0],2)
  self.assertEqual(b.history[-1]['function'],'fc_sys_AccOnStop')
 def test_real_group_wait_can_be_released_by_original_system_dispatch(self):
  group=(ORIG/'06-libipas_grp.so').read_bytes();b=self.bridge(group_data=group)
  for task in (39,10):b.start_task(task);self.assertEqual(b.run_task(task)['status'],'waiting')
  b.call('rq_flg_Set',1,1) # Explicit parent fixture only.
  self.assertEqual(b.resume_task(39)['status'],'waiting');b.resume_task(10)
  envelopes=[]
  while True:
   status,message=b.poll(1)
   if status==-2:break
   envelopes.append(message)
   if message.subcommand==3:b.call('fc_sys_RcvTskCond',message.event,message.payload,actor='system')
   elif message.subcommand==5:b.call('fc_sys_RcvInitWait',message.event,message.payload,actor='system')
   else:self.fail('Unexpected original status event')
  self.assertIn(Message(0,5,39,10),envelopes)
  r=b.resume_task(39);self.assertEqual(r['status'],'blocked')
  self.assertEqual(r['boundary'].get('symbol'),'memcpy')
  self.assertEqual(r['boundary']['arguments'][1:3],[0,256])
  self.assertEqual(r['boundary']['caller_return'],'0x2a52c')
  self.assertNotEqual(r['boundary'].get('symbol'),'rq_grp_Init');self.assertEqual(b.flag_value(2),0)
 def test_unknown_bytes_fail_before_emulation(self):
  with self.assertRaisesRegex(ValueError,'SHA-256'):GuestPthreadBridge(b'wrong',self.sysc)
if __name__=='__main__':unittest.main()
