"""Offline proofs of original ARM task/thread and blocking-queue call contracts.

All source inputs must match canonical SHA256. pthread_create is never
implemented; only test-only pthread attributes and synthetic guest queue
token are injected, not actual device queues or startup services.
"""
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from ca01_original_task_boundaries import (
    probe_pthread_create_boundary,probe_block_queue_slot
)

ORIG=ROOT.parent/"system-audit/ca01-updater-independent-20261022"
HMI=ORIG/"06-PROC_HMI"
SYSC=ORIG/"06-libipas_sysc.so"

@unittest.skipUnless(HMI.is_file() and SYSC.is_file(),
                     "Canonical original ARM ELF sources required")
class OriginalTaskBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hmi=HMI.read_bytes()
        cls.sysc=SYSC.read_bytes()

    def test_original_start_traps_at_pthread_create_exact_task_field(self):
        result=probe_pthread_create_boundary(self.hmi,self.sysc,
                     task=39,priority=0,guest_entry=0x33334444)
        self.assertEqual(result["halt_reason"],"unimplemented_import")
        self.assertEqual(result["task_table_slots"],96)
        self.assertEqual(result["record_bytes"],80)
        self.assertEqual(result["pthread_output_slot"],hex(0x50000000+39*80+64))
        self.assertEqual(result["pthread_create_arguments"][0],result["pthread_output_slot"])
        self.assertEqual(result["pthread_create_arguments"][2],hex(0x33334444))
        self.assertFalse(result["original_pthread_create_executed"])
        self.assertFalse(result["original_watchdog_started"])

    def test_original_start_priority_zero_uses_nonrealtime_policy(self):
        calls=probe_pthread_create_boundary(self.hmi,self.sysc,priority=0)["attribute_calls"]
        policy=next(x for x in calls if x["service"]=="pthread_attr_setschedpolicy")
        param=next(x for x in calls if x["service"]=="pthread_attr_setschedparam")
        inherit=next(x for x in calls if x["service"]=="pthread_attr_setinheritsched")
        self.assertEqual(policy["args"][1],0)
        self.assertEqual(param["priority_value"],0)
        self.assertEqual(inherit["args"][1],1)

    def test_original_start_priority_five_uses_realtime_priority_fifteen(self):
        calls=probe_pthread_create_boundary(self.hmi,self.sysc,priority=5)["attribute_calls"]
        policy=next(x for x in calls if x["service"]=="pthread_attr_setschedpolicy")
        param=next(x for x in calls if x["service"]=="pthread_attr_setschedparam")
        self.assertEqual(policy["args"][1],1)
        self.assertEqual(param["priority_value"],15)

    def test_original_block_object_stores_explicit_guest_queue_token(self):
        report=probe_block_queue_slot(self.hmi,self.sysc,task=39,
                                      guest_pthread=0x5678,guest_queue_token=0x1234)
        self.assertEqual(report["queue_record_field"],8)
        self.assertEqual(report["requested_queue_shape"],["0xffffffff",1,16])
        self.assertEqual(report["stored_queue_token"],"0x1234")
        self.assertEqual(report["tls_after"],39)
        self.assertGreater(report["original_arm_instructions_executed"],0)
        self.assertFalse(report["original_rq_msg_create_implemented"])
        self.assertFalse(report["host_queue1_created"])
        self.assertFalse(report["actual_block_wait_performed"])
        self.assertFalse(report["full_startup"])

    def test_wrong_input_and_invalid_fixtures_refused(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            probe_block_queue_slot(b"not original",self.sysc)
        with self.assertRaises(ValueError):
            probe_pthread_create_boundary(self.hmi,self.sysc,task=96)
        with self.assertRaises(ValueError):
            probe_pthread_create_boundary(self.hmi,self.sysc,priority=-1)
        with self.assertRaises(ValueError):
            probe_block_queue_slot(self.hmi,self.sysc,guest_queue_token=0)

if __name__=="__main__":
    unittest.main()
