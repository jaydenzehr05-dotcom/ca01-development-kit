"""Synthetic startup/queue contracts; no recovered application execution."""
from pathlib import Path
import sys, unittest, struct
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from ca01_hmi_startup import Message, LocalQueue, HmiHarness, StartupBlocked, decode_queue_table

class HmiStartupTests(unittest.TestCase):
 def setUp(self):
  self.events=[]
  self.h=HmiHarness(heartbeat=lambda m:self.events.append(('heartbeat',m.event)),
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
  q=LocalQueue(2);m=Message(1,2,3,4);q.send(m)
  self.assertEqual(q.receive_p(),(-1,m));self.assertEqual(q.receive_p(),(-2,None))
 def test_timed_dequeue_and_synthetic_timeout_have_distinct_status(self):
  q=LocalQueue(2);m=Message(1,2,3,4);q.send(m)
  self.assertEqual(q.receive_t(),(0,m));self.assertEqual(q.receive_t(),(-1,None))
 def test_ring_wraparound_and_full_do_not_overwrite(self):
  q=LocalQueue(2);a,b,c=[Message(i,0,0,0) for i in range(3)]
  self.assertEqual(q.send(a),0);self.assertEqual(q.send(b),0);self.assertEqual(q.send(c),-1)
  self.assertEqual(q.receive_p(),(-1,a));q.send(c)
  self.assertEqual(q.receive_p(),(-1,b));self.assertEqual(q.receive_p(),(-1,c))
 def test_waiting_for_display_gate_does_not_consume_message(self):
  self.h.queue.send(Message(0x41002,7,0,0))
  with self.assertRaises(StartupBlocked):self.h.step()
  self.assertEqual(len(self.h.queue),1);self.assertEqual(self.events,[])
 def test_timeout_after_ready_delivers_event_ten(self):
  self.h.signal_display_ready();r=self.h.step()
  self.assertEqual(self.events,[('heartbeat',10)]);self.assertTrue(r['timeout_heartbeat'])
  self.assertFalse(r['toyota_application_started']);self.assertFalse(r['pixels_rendered'])
 def test_command_dispatch_frees_owned_payload_after_callback(self):
  self.h.signal_display_ready();self.h.queue.send(Message(0x41002,7,0,0x1234));self.h.step()
  self.assertEqual(self.events,[('command',7),('free',1,0x1234)])
 def test_unknown_dispatch_still_releases_payload(self):
  self.h.signal_display_ready();self.h.queue.send(Message(99,0,0,0x1234));self.h.step()
  self.assertEqual(self.events,[('unknown',99),('free',1,0x1234)])
 def test_callback_failure_is_not_reported_as_render_success(self):
  self.h.command=lambda m:(_ for _ in ()).throw(RuntimeError('unimplemented'))
  self.h.signal_display_ready();self.h.queue.send(Message(0x41002,7,0,0x1234))
  with self.assertRaisesRegex(RuntimeError,'unimplemented'):self.h.step()
  self.assertEqual(self.events,[('free',1,0x1234)])
 def test_frame_batch_is_bounded_to_sixteen_messages(self):
  self.h.signal_display_ready()
  for i in range(17):self.h.queue.send(Message(0x41002,i,0,0))
  r=self.h.step();self.assertEqual(r['dispatched'],16);self.assertEqual(len(self.h.queue),1)
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
 def test_missing_configuration_is_explicit_in_startup_report(self):
  r=self.h.startup_requirements()
  self.assertIn('ipasz.conf',r['required_external_files'])
  self.assertIn('parent_sync',r['unmodeled_services'])
  self.assertFalse(r['sys_power_on_implemented'])

if __name__=='__main__':unittest.main()
