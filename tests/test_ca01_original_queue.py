"""Original ARM queue code with explicit emulated libc/pthread services only."""
from pathlib import Path
import sys,unittest,tempfile,subprocess
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_original_queue import OriginalQueueRuntime, QueueWait, QueueBlocked, trace_create_boundary, startup_queue_demo
from ca01_hmi_startup import Message, HmiHarness, StartupBlocked
ORIG=ROOT.parent/'system-audit/ca01-updater-independent-20261022'

@unittest.skipUnless((ORIG/'06-PROC_HMI').is_file() and (ORIG/'06-libipas_sysc.so').is_file(),
                     'Canonical original ARM ELF fixtures required')
class OriginalQueueTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.hmi=(ORIG/'06-PROC_HMI').read_bytes();cls.sysc=(ORIG/'06-libipas_sysc.so').read_bytes()
  cls.work=tempfile.TemporaryDirectory(prefix='ca01-original-queue-')
  cls.runtime_library=Path(cls.work.name)/'libca01_ipc.so'
  subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared','-pthread',
    '-I',str(ROOT/'src'),str(ROOT/'src/ca01_hmi_ipc.c'),'-o',str(cls.runtime_library)],check=True,capture_output=True)
 @classmethod
 def tearDownClass(cls):cls.work.cleanup()
 def runtime(self):return OriginalQueueRuntime(self.hmi,self.sysc)
 def test_first_boundary_is_real_global_mutex(self):
  r=trace_create_boundary(self.hmi,self.sysc)
  self.assertEqual(r['boundary']['symbol'],'pthread_mutex_lock')
  self.assertEqual(r['boundary']['caller_return'],'0x1001d148')
  self.assertEqual(r['boundary']['arguments'][0],0x1013a598)
 def test_hash_gate(self):
  with self.assertRaisesRegex(ValueError,'SHA-256'):OriginalQueueRuntime(b'wrong',self.sysc)
 def test_original_initializer_and_create(self):
  q=self.runtime();self.assertEqual(q.create(40,64),40)
  self.assertEqual(q.state(40)['capacity'],64);self.assertEqual(q.state(40)['slot_bytes'],16)
  self.assertEqual(q.state(40)['count'],0)
  self.assertEqual(q.queue_count,96)
  self.assertTrue(any(x['function']=='fs_msg_Init' for x in q.history))
  self.assertTrue(any(x['function']=='rq_msg_Create' for x in q.history))
  self.assertFalse(any(n.startswith('rq_msg_') for n in q.trace.services))
 def test_full_fifo_wrap_and_original_poll_codes(self):
  q=self.runtime();q.create(40,64)
  for i in range(64):self.assertEqual(q.send(40,Message(0x41002,i,9,0x12340000+i)),0)
  self.assertEqual(q.send(40,Message(1,2,3,4)), -1)
  for i in range(64):self.assertEqual(q.poll(40),(-1,Message(0x41002,i,9,0x12340000+i)))
  self.assertEqual(q.poll(40),(-2,None))
  for i in range(80):
   m=Message(4,5,i,0x98765432);self.assertEqual(q.send(40,m),0);self.assertEqual(q.receive(40,5),(0,m))
  self.assertEqual(q.state(40)['count'],0)
 def test_timed_receive_uses_original_minus_one_and_preserves_buffer(self):
  q=self.runtime();q.create(40,64);before=q.now_ns
  self.assertEqual(q.receive(40,25),(-1,None))
  self.assertEqual(q.now_ns-before,25_000_000)
  self.assertTrue(any(c['symbol']=='pthread_cond_timedwait' for r in q.history for c in r['trace']['service_calls']))
 def test_blocked_original_receive_resumes_after_original_send(self):
  q=self.runtime();q.create(40,64);out=q.buffer(bytes(16))
  wait=q.call('rq_msg_Receive',40,out,actor='consumer')
  self.assertIsInstance(wait,QueueWait)
  with self.assertRaises(QueueBlocked):q.resume(wait)
  m=Message(0,0,10,0x87654321);q.send(40,m)
  self.assertIsInstance(q.resume(wait),int)
  self.assertEqual(bytes(q.uc.mem_read(out,16)),m.pack())
 def test_full_sender_resumes_after_original_receive(self):
  q=self.runtime();q.create(40,1)
  one=Message(1,2,3,4);two=Message(5,6,7,8);q.send(40,one)
  wait=q.call('rq_msg_SendT',40,q.buffer(two.pack()),16,500,actor='producer')
  self.assertIsInstance(wait,QueueWait)
  self.assertEqual(q.poll(40),(-1,one));self.assertEqual(q.resume(wait),0)
  self.assertEqual(q.poll(40),(-1,two))
 def test_dynamic_block_queue_capacity_one(self):
  q=self.runtime();self.assertEqual(q.create(-1,1),95);self.assertEqual(q.create(-1,1),94)
  self.assertEqual(q.state(95)['capacity'],1)
 def test_delete_destroys_resources_and_frees_only_queue_buffer(self):
  q=self.runtime();q.create(40,64);pointer=q.state(40)['buffer'];q.call('rq_msg_Delete',40)
  self.assertEqual(q.state(40)['enabled'],0);self.assertIn(pointer,q.freed)
 def test_invalid_api_shapes_rejected_without_queue_writes(self):
  q=self.runtime()
  for args in [(0,64),(96,64),(40,0),(40,4097)]:
   with self.assertRaises(ValueError):q.create(*args)
  q.create(40,64)
  with self.assertRaises(ValueError):q.create(40,64)
 def test_unknown_guest_import_still_blocks(self):
  q=self.runtime()
  with self.assertRaisesRegex(RuntimeError,'blocked'):
   q.call('rq_msg_ReceiveT',0,q.buffer(bytes(16)),0)
 def test_real_block_object_allocates_each_call_and_stores_original_slot(self):
  q=self.runtime();q.configure_tasks({39:0x5678})
  result=q.block_object(39)
  self.assertEqual(result['queue'],95);self.assertEqual(result['record_value'],95)
  second=q.block_object(39);self.assertEqual(second['queue'],94);self.assertEqual(second['record_value'],94)
  self.assertEqual(q.state(95)['capacity'],1)
  self.assertTrue(any(e['symbol']=='rq_msg_Create' for x in q.history for e in x['trace']['function_entries']))
 def test_watermark_logs_are_captured_instead_of_silenced(self):
  q=self.runtime();q.create(40,64)
  for i in range(64):q.send(40,Message(0,0,i,0))
  self.assertTrue(any(x['words'][2]==0x12000440 for x in q.diagnostics))
  for i in range(64):q.poll(40)
  self.assertTrue(any(x['words'][2]==0x12000820 for x in q.diagnostics))
 def test_pending_wait_cannot_be_reused(self):
  q=self.runtime();q.create(40,1);out=q.buffer(bytes(16))
  w=q.call('rq_msg_ReceiveT',40,out,5,actor='reader');q.advance_time(5)
  self.assertEqual(q.resume(w),-1)
  with self.assertRaises(ValueError):q.resume(w)
 def test_payload_pool_cleanup_is_a_remaining_real_boundary(self):
  q=self.runtime();q.create(40,1);q.send(40,Message(1,2,3,0x12345678))
  with self.assertRaisesRegex(RuntimeError,'blocked'):q.call('fc_msg_Clear',40)
  self.assertTrue(any(e['symbol']=='rq_mem_Free' for e in q.trace.entries))
 def test_two_receivers_recheck_original_empty_predicate(self):
  q=self.runtime();q.create(40,1)
  a=q.call('rq_msg_Receive',40,q.buffer(bytes(16)),actor='a')
  b=q.call('rq_msg_Receive',40,q.buffer(bytes(16)),actor='b')
  q.send(40,Message(0,0,10,0));q.resume(a)
  again=q.resume(b);self.assertIsInstance(again,QueueWait)
  with self.assertRaises(QueueBlocked):q.resume(again)
 def test_original_draw_transport_waits_for_both_barriers_and_owns_payload(self):
  from ca01_original_queue import OriginalQueueTransport
  q=self.runtime();q.create(40,64);releases=[]
  h=HmiHarness(queue_transport=OriginalQueueTransport(q,40),heartbeat=lambda m:None,
   command=lambda m:None,diagnostic=lambda m:None,release_payload=lambda pool,p:releases.append((pool,p)))
  h.startup.create_resources();h.startup.apply_power_state(True)
  for task in (3,10,39,40,41):h.startup.task_initialized(task)
  heartbeat=Message(0,0,10,0xabcdef01);h.queue.send(heartbeat)
  with self.assertRaises(StartupBlocked):h.step(timeout_ms=0)
  self.assertEqual(len(h.queue),1);self.assertFalse(h.draw_pending);self.assertEqual(releases,[])
  # Explicit positive fixture callbacks, not original parent/display services.
  h.startup.release_startup_barrier(lambda:True)
  with self.assertRaises(StartupBlocked):h.step(timeout_ms=0)
  h.startup.complete_display_initialization(lambda:True)
  h.step(timeout_ms=0);self.assertTrue(h.draw_pending)
  self.assertEqual(releases,[(1,0xabcdef01)]);self.assertEqual(len(h.queue),0)
 def test_original_transport_timeout_heartbeat_after_fixture_readiness(self):
  from ca01_original_queue import OriginalQueueTransport
  q=self.runtime();q.create(40,64)
  h=HmiHarness(queue_transport=OriginalQueueTransport(q,40),heartbeat=lambda m:None,
   command=lambda m:None,diagnostic=lambda m:None,release_payload=lambda pool,p:None)
  h.startup.create_resources();h.startup.apply_power_state(True)
  for task in (3,10,39,40,41):h.startup.task_initialized(task)
  h.startup.release_startup_barrier(lambda:True);h.startup.complete_display_initialization(lambda:True)
  result=h.step(timeout_ms=500)
  self.assertTrue(result['timeout_heartbeat']);self.assertTrue(h.draw_pending)
 def test_native_identity_threads_use_original_arm_status_queue(self):
  from ca01_original_queue import OriginalThreadedStartupBridge
  bridge=OriginalThreadedStartupBridge(self.hmi,self.sysc,runtime_library=self.runtime_library)
  r=bridge.run()
  self.assertEqual(r['errors'],[]);self.assertEqual(r['native_threads_registered'],5)
  self.assertEqual(set(r['status_tasks_accepted']),{3,10,39,40,41})
  self.assertTrue(r['original_queue1_functions_executed']);self.assertEqual(r['original_queue1_capacity'],64)
  self.assertFalse(r['draw_ready']);self.assertFalse(r['parent_sync_verified'])
  self.assertFalse(r['original_pthread_create_executed']);self.assertFalse(r['full_startup'])
 def test_native_identity_fault_cannot_cross_original_status_queue(self):
  from ca01_original_queue import OriginalThreadedStartupBridge
  r=OriginalThreadedStartupBridge(self.hmi,self.sysc,runtime_library=self.runtime_library).run(guest_identity_faults={39:0xdeadbeef})
  self.assertNotIn(39,r['status_tasks_accepted']);self.assertEqual(r['task_states']['39'],2)
  self.assertFalse(r['draw_ready'])
 def test_original_timedwait_retries_eintr_without_losing_mutex(self):
  q=self.runtime();q.create(40,64);calls=[];real=q.trace.services['pthread_cond_timedwait']
  def interrupt_once(u,args):
   calls.append(1)
   return 4 if len(calls)==1 else real(u,args)
  q.trace.services['pthread_cond_timedwait']=interrupt_once
  self.assertEqual(q.receive(40,5),(-1,None));self.assertEqual(len(calls),2)
 def test_original_timespec_rollover_and_no_early_timeout(self):
  q=self.runtime();q.create(40,64);q.now_ns=1000_995_000_000
  w=q.call('rq_msg_ReceiveT',40,q.buffer(bytes(16)),25,actor='reader')
  self.assertEqual(w.deadline_ns,1001_020_000_000)
  q.advance_time(24)
  with self.assertRaises(QueueBlocked):q.resume(w)
  q.advance_time(1);self.assertEqual(q.resume(w),-1)
 def test_original_profile_initializes_pool_and_clear_frees_real_payload(self):
  q=self.runtime();q.initialize_payload_pools();q.create(40,64)
  pointer=q.allocate_payload(b'original queue ownership')
  self.assertEqual(q.allocations[pointer],272)
  q.send(40,Message(1,2,3,pointer));q.call('fc_msg_Clear',40)
  self.assertIn(pointer,q.freed);self.assertEqual(q.state(40)['count'],0)
  self.assertTrue(any(e['symbol']=='rq_mem_Free' for e in q.trace.entries))
 def test_original_receive_transfers_payload_until_explicit_free(self):
  q=self.runtime();q.initialize_payload_pools();q.create(40,64)
  pointer=q.allocate_payload(b'keep me');message=Message(0x41002,7,0,pointer)
  q.send(40,message);self.assertEqual(q.receive(40,0),(0,message))
  self.assertNotIn(pointer,q.freed);self.assertEqual(bytes(q.uc.mem_read(pointer,7)),b'keep me')
  q.call('rq_mem_Free',1,pointer);self.assertIn(pointer,q.freed)
  with self.assertRaisesRegex(RuntimeError,'blocked'):q.call('rq_mem_Free',1,pointer)
 def test_original_reserved_delete_releases_both_incoming_and_queued_payloads(self):
  q=self.runtime();q.initialize_payload_pools();q.create(40,64)
  first=q.allocate_payload(b'queued');second=q.allocate_payload(b'incoming');ring=q.state(40)['buffer']
  q.send(40,Message(1,2,3,first));q.call('rq_msg_DelRsrv',40)
  self.assertEqual(q.send(40,Message(1,2,3,second)),0)
  self.assertTrue({first,second,ring}.issubset(q.freed));self.assertEqual(q.state(40)['enabled'],0)
 def test_gated_draw_dispatch_releases_original_pool_payload(self):
  from ca01_original_queue import OriginalQueueTransport
  q=self.runtime();q.initialize_payload_pools();q.create(40,64);pointer=q.allocate_payload(b'event')
  h=HmiHarness(queue_transport=OriginalQueueTransport(q,40),heartbeat=lambda m:None,
   command=lambda m:None,diagnostic=lambda m:None,release_payload=lambda pool,p:q.call('rq_mem_Free',pool,p))
  h.startup.create_resources();h.startup.apply_power_state(True)
  for task in (3,10,39,40,41):h.startup.task_initialized(task)
  h.queue.send(Message(0,0,10,pointer))
  with self.assertRaises(StartupBlocked):h.step(timeout_ms=0)
  self.assertNotIn(pointer,q.freed)
  h.startup.release_startup_barrier(lambda:True);h.startup.complete_display_initialization(lambda:True)
  h.step(timeout_ms=0);self.assertIn(pointer,q.freed);self.assertTrue(h.draw_pending)
 def test_real_queue_transport_does_not_release_readiness(self):
  r=startup_queue_demo(self.hmi,self.sysc)
  self.assertEqual(r['accepted_tasks'],[3,10,39,40,41]);self.assertEqual(r['queue1_capacity'],64)
  self.assertEqual(r['heartbeat_words'],[0,0,10,0]);self.assertFalse(r['draw_before_ready'])
  self.assertFalse(r['flag1']);self.assertFalse(r['flag2']);self.assertFalse(r['full_startup'])
  self.assertTrue(r['original_queue_functions_executed']);self.assertEqual(r['draw_queue_count'],1)
if __name__=='__main__':unittest.main()
