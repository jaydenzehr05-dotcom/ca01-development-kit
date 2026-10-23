"""Synthetic startup/queue contracts; no recovered application execution."""
from pathlib import Path
import sys, unittest, struct, tempfile, subprocess
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from ca01_hmi_startup import Message, LocalQueue, HmiHarness, StartupBlocked, decode_queue_table, ElfImage, inspect_configuration

class HmiStartupTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(prefix="ca01-ipc-tests-")
  cls.library=Path(cls.temp.name)/"libca01_ipc.so"
  root=Path(__file__).resolve().parents[1]
  subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror","-fPIC","-shared","-pthread","-I",str(root/"src"),str(root/"src/ca01_hmi_ipc.c"),"-o",str(cls.library)],check=True)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def ready(self):
  s=self.h.startup;s.create_resources();s.apply_power_state(True)
  for task in (3,10,39,40,41):s.task_initialized(task)
  s.release_startup_barrier(lambda:True)
  s.complete_display_initialization(lambda:True)
 def setUp(self):
  self.events=[]
  self.h=HmiHarness(runtime_library=self.library,heartbeat=lambda m:self.events.append(('heartbeat',m.event)),
   command=lambda m:self.events.append(('command',m.subcommand)),
   diagnostic=lambda m:self.events.append(('unknown',m.code)),
   release_payload=lambda pool,pointer:self.events.append(('free',pool,pointer)))
 def test_message_is_exact_four_little_endian_words(self):
  m=Message(0x41002,7,10,0x12345678)
  self.assertEqual(m.pack(),struct.pack('<4I',0x41002,7,10,0x12345678))
  self.assertEqual(Message.unpack(m.pack()),m)
 def test_message_bounds_and_truncation_rejected(self):
  for n in [-1,1<<32]:
   with self.assertRaises(ValueError):Message(n,0,0,0)
  with self.assertRaises(ValueError):Message.unpack(bytes(15))
 def test_nonblocking_success_is_minus_one_empty_minus_two(self):
  q=LocalQueue(2,runtime_library=self.library);m=Message(1,2,3,4);q.send(m)
  self.assertEqual(q.receive_p(),(-1,m));self.assertEqual(q.receive_p(),(-2,None))
 def test_timed_dequeue_and_synthetic_timeout_have_distinct_status(self):
  q=LocalQueue(2,runtime_library=self.library);m=Message(1,2,3,4);q.send(m)
  self.assertEqual(q.receive_t(),(0,m));self.assertEqual(q.receive_t(),(-1,None))
 def test_ring_wraparound_and_full_do_not_overwrite(self):
  q=LocalQueue(2,runtime_library=self.library);a,b,c=[Message(i,0,0,0) for i in range(3)]
  self.assertEqual(q.send(a),0);self.assertEqual(q.send(b),0);self.assertEqual(q.send(c),-1)
  self.assertEqual(q.receive_p(),(-1,a));q.send(c)
  self.assertEqual(q.receive_p(),(-1,b));self.assertEqual(q.receive_p(),(-1,c))
 def test_waiting_for_display_gate_does_not_consume_message(self):
  self.h.queue.send(Message(0x41002,7,0,0))
  with self.assertRaises(StartupBlocked):self.h.step(timeout_ms=0)
  self.assertEqual(len(self.h.queue),1);self.assertEqual(self.events,[])
 def test_timeout_after_ready_delivers_event_ten(self):
  self.ready();r=self.h.step(timeout_ms=0)
  self.assertEqual(self.events,[('heartbeat',10)]);self.assertTrue(r['timeout_heartbeat'])
  self.assertFalse(r['toyota_application_started']);self.assertFalse(r['pixels_rendered'])
 def test_command_dispatch_frees_owned_payload_after_callback(self):
  self.ready();self.h.queue.send(Message(0x41002,7,0,0x1234));self.h.step(timeout_ms=0)
  self.assertEqual(self.events,[('command',7),('free',1,0x1234)])
 def test_unknown_dispatch_still_releases_payload(self):
  self.ready();self.h.queue.send(Message(99,0,0,0x1234));self.h.step(timeout_ms=0)
  self.assertEqual(self.events,[('unknown',99),('free',1,0x1234)])
 def test_callback_failure_is_not_reported_as_render_success(self):
  self.h.command=lambda m:(_ for _ in ()).throw(RuntimeError('unimplemented'))
  self.ready();self.h.queue.send(Message(0x41002,7,0,0x1234))
  with self.assertRaisesRegex(RuntimeError,'unimplemented'):self.h.step(timeout_ms=0)
  self.assertEqual(self.events,[('free',1,0x1234)])
 def test_frame_batch_is_bounded_to_sixteen_messages(self):
  self.ready()
  for i in range(17):self.h.queue.send(Message(0x41002,i,0,0))
  r=self.h.step(timeout_ms=0);self.assertEqual(r['dispatched'],16);self.assertEqual(len(self.h.queue),1)
 def test_queue_flood_timeout_retains_caller_payload(self):
  for i in range(64):self.h.queue.send(Message(1,i,0,0))
  self.assertEqual(self.h.queue.send(Message(0x41002,1,0,0x1234)),-1)
  self.assertEqual(self.events,[])
 def test_decode_queue_table_uses_sixteen_byte_records(self):
  data=struct.pack('<8I',0,0,0,0,1,1,64,16)
  self.assertEqual(decode_queue_table(data,2),[dict(index=1,queue_id=1,capacity=64,slot_bytes=16)])
 def test_invalid_queue_profile_rejected(self):
  with self.assertRaises(ValueError):decode_queue_table(struct.pack('<4I',1,0,64,12),1)
  with self.assertRaises(ValueError):decode_queue_table(bytes(15),1)
 def test_power_edge_controls_task_activation(self):
  s=self.h.startup
  with self.assertRaises(StartupBlocked):s.apply_power_state(True)
  s.create_resources()
  self.assertEqual(s.states[39],1);self.assertEqual(s.states[40],1)
  s.apply_power_state(False);self.assertEqual(s.states[39],1)
  s.apply_power_state(True)
  self.assertEqual(s.states[39],2);self.assertEqual(s.states[40],2)
  before=list(s.trace);s.apply_power_state(True);self.assertEqual(s.trace,before)
 def test_display_initialization_cannot_skip_status_or_parent_barrier(self):
  s=self.h.startup;s.create_resources();s.apply_power_state(True)
  with self.assertRaises(StartupBlocked):s.complete_display_initialization(lambda:True)
  for task in (3,10,39,40,41):s.task_initialized(task)
  with self.assertRaises(StartupBlocked):s.release_startup_barrier(lambda:False)
  self.assertFalse(s.flag1)
  s.release_startup_barrier(lambda:True)
  with self.assertRaises(StartupBlocked):s.complete_display_initialization(lambda:None)
  self.assertFalse(s.flag2)
  s.complete_display_initialization(lambda:True);self.assertTrue(s.flag2)
 def test_heartbeat_sets_pending_but_never_draws_before_readiness(self):
  self.h.queue.send(Message(0,0,10,0));drawn=[]
  with self.assertRaises(StartupBlocked):self.h.draw_frame(lambda:drawn.append(1))
  with self.assertRaises(StartupBlocked):self.h.step(timeout_ms=0)
  self.assertFalse(self.h.draw_pending);self.assertEqual(drawn,[])
  self.ready();self.h.step(timeout_ms=0);self.assertTrue(self.h.draw_pending)
  self.assertTrue(self.h.draw_frame(lambda:drawn.append(1)))
  self.assertFalse(self.h.draw_pending);self.assertEqual(drawn,[1])
  self.assertFalse(self.h.draw_frame(lambda:drawn.append(1)))
 def test_real_native_timed_receive_wakes_for_producer(self):
  import threading,time
  q=LocalQueue(2,runtime_library=self.library);m=Message(7,8,9,0xfedcba98)
  producer=threading.Thread(target=lambda:(time.sleep(.03),q.send(m)))
  producer.start()
  try:self.assertEqual(q.receive_t(timeout_ms=1000),(0,m))
  finally:producer.join()
 def test_full_send_waits_for_consumer_without_freeing_payload(self):
  import threading,time
  q=LocalQueue(1,runtime_library=self.library);first=Message(1,2,3,4)
  next_message=Message(5,6,7,0xfedcba98);q.send(first);received=[]
  consumer=threading.Thread(target=lambda:(time.sleep(.03),received.append(q.receive_p())))
  consumer.start()
  try:self.assertEqual(q.send(next_message,timeout_ms=1000),0)
  finally:consumer.join()
  self.assertEqual(received,[(-1,first)])
  self.assertEqual(q.receive_p(),(-1,next_message));self.assertEqual(self.events,[])
 def test_nonheartbeat_event_does_not_set_draw_pending(self):
  self.ready();self.h.queue.send(Message(0,1,10,0));self.h.step(timeout_ms=0)
  self.assertFalse(self.h.draw_pending)
 def test_native_timeout_preserves_all_output_bytes(self):
  import ctypes
  q=LocalQueue(2,runtime_library=self.library)
  out=(ctypes.c_uint32*4)(11,22,33,0xfedcba98)
  self.assertEqual(q.runtime.ca01_queue_receive_t(q.pointer,ctypes.byref(out),1),-1)
  self.assertEqual(list(out),[11,22,33,0xfedcba98])
 def fixture_image(self):
  ident=b'\x7fELF\x01\x01\x01'+bytes(9)
  header=struct.pack('<16sHHIIIIIHHHHHH',ident,2,40,1,0,52,0,0,52,32,1,40,0,0)
  ph=struct.pack('<8I',1,256,0x1000,0x1000,4,8,4,4096)
  return header+ph+bytes(256-len(header)-len(ph))+b'abcd'
 def test_virtual_read_uses_segment_file_offset(self):
  e=ElfImage(self.fixture_image());self.assertEqual(e.read(0x1000,4),b'abcd')
 def test_bss_and_cross_boundary_reads_rejected(self):
  e=ElfImage(self.fixture_image())
  for a,n in [(0x1004,4),(0x1002,4),(0x9000,4)]:
   with self.assertRaises(ValueError):e.read(a,n)
 def test_wrong_firmware_digest_rejected_before_profile_decode(self):
  import tempfile
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'wrong';p.write_bytes(self.fixture_image())
   with self.assertRaisesRegex(ValueError,'SHA-256'):inspect_configuration(p,p)
 def test_missing_configuration_is_explicit_in_startup_report(self):
  r=self.h.startup_requirements()
  self.assertIn('ipasz.conf',r['required_external_files'])
  self.assertIn('parent_sync',r['unmodeled_services'])
  self.assertFalse(r['sys_power_on_implemented'])

if __name__=='__main__':unittest.main()
