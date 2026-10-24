"""Original ARM task-ID lookup connected to native pthread-host fixtures.

All guest instructions execute under Unicorn; status queue1 is a host-only
16-byte transport, not an implemented Toyota native queue. No shell, network,
firmware flashing or original parent-process startup is performed.
"""
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from ca01_hmi_startup import Message,StartupBlocked
from ca01_threaded_startup import ThreadedStartupBridge,MODEL_TASKS

ORIG=ROOT.parent/"system-audit/ca01-updater-independent-20261022"
HMI=ORIG/"06-PROC_HMI"
SYSC=ORIG/"06-libipas_sysc.so"

@unittest.skipUnless(HMI.is_file() and SYSC.is_file(),
                     "Original canonical ARM ELF fixtures unavailable")
class ThreadedStartupBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work=tempfile.TemporaryDirectory(prefix="ca01-threaded-startup-")
        cls.runtime=Path(cls.work.name)/"libca01_ipc.so"
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                        "-fPIC","-shared","-pthread","-I",str(ROOT/"src"),
                        str(ROOT/"src/ca01_hmi_ipc.c"),"-o",str(cls.runtime)],
                       capture_output=True,check=True)
        cls.hmi=HMI.read_bytes()
        cls.sysc=SYSC.read_bytes()
        cls.bridge=ThreadedStartupBridge(cls.hmi,cls.sysc,
                                         runtime_library=cls.runtime)
        cls.report=cls.bridge.run()

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    @classmethod
    def new_bridge(cls,**kwargs):
        return ThreadedStartupBridge(cls.hmi,cls.sysc,
                                    runtime_library=cls.runtime,**kwargs)

    def test_real_distinct_pthread_owners_registered(self):
        self.assertEqual(self.report["native_threads_registered"],5)
        self.assertEqual(len(self.bridge.status_source),5)
        owners=[row["host_pthread"] for row in self.bridge.status_source.values()]
        self.assertEqual(len(owners),len(set(owners)))
        self.assertTrue(all(owner>0 for owner in owners))
        self.assertEqual(set(self.bridge.aliases),set(MODEL_TASKS))
        self.assertEqual(len(set(self.bridge.aliases.values())),5)

    def test_original_arm_gettid_cold_and_cached_are_identical(self):
        self.assertEqual(self.report["errors"],[])
        self.assertEqual(len(self.report["per_task"]),5)
        for result in self.report["per_task"]:
            self.assertTrue(result["original_arm_identity_verified"])
            self.assertEqual(result["cold_task"],result["task"])
            self.assertEqual(result["warm_task"],result["task"])
            self.assertEqual(result["cold_tls_after"],result["task"])
            self.assertEqual(result["warm_tls_after"],result["task"])
            self.assertTrue(result["local_status_enqueued"])
        self.assertTrue(all(row["alias_basis"].startswith("unique bounded fixture")
                            for row in self.bridge.status_source.values()))

    def test_task_status_uses_exact_message_words_and_not_hmi_queue(self):
        expected={tuple((0,3,task,0)) for task in MODEL_TASKS}
        self.assertEqual({tuple(x) for x in self.report["status_envelopes"]},
                         expected)
        self.assertTrue(all(len(Message(*words).pack())==16
                            for words in self.report["status_envelopes"]))
        self.assertEqual(self.report["native_hmi_queue_entries"],0)
        self.assertTrue(self.report["synthetic_status_queue_only"])
        self.assertFalse(self.report["original_queue1_implemented"])

    def test_all_verified_status_records_still_do_not_open_parent_barrier(self):
        self.assertEqual(set(self.report["status_tasks_accepted"]),set(MODEL_TASKS))
        self.assertEqual(set(self.report["task_states"].values()),{3})
        self.assertFalse(self.bridge.h.startup.flag1)
        self.assertFalse(self.bridge.h.startup.flag2)
        self.assertFalse(self.report["draw_ready"])
        self.assertFalse(self.report["parent_sync_verified"])
        self.assertFalse(self.report["display_initialized"])
        self.assertFalse(self.report["original_pthread_create_executed"])
        self.assertFalse(self.report["original_toyota_app_started"])
        with self.assertRaises(StartupBlocked):
            self.bridge.h.startup.release_startup_barrier(lambda:False)
        with self.assertRaises(StartupBlocked):
            self.bridge.h.startup.complete_display_initialization(lambda:True)

    def test_unready_native_hmi_queue_retains_own_message(self):
        message=Message(0x41002,7,0,0x12345678)
        self.assertEqual(self.bridge.h.queue.send(message),0)
        with self.assertRaises(StartupBlocked):
            self.bridge.h.step(timeout_ms=0)
        self.assertEqual(len(self.bridge.h.queue),1)
        self.assertEqual(self.bridge.h.queue.receive_p(),(-1,message))
        self.assertFalse(self.bridge.h.display_ready)

    def test_unrecognized_guest_pthread_cannot_initialize_task(self):
        bridge=self.new_bridge()
        report=bridge.run(guest_identity_faults={39:0xABCDEF01})
        self.assertFalse(report["draw_ready"])
        self.assertEqual(report["task_states"]["39"],2)
        self.assertNotIn(39,report["status_tasks_accepted"])
        self.assertTrue(all(x[2]!=39 for x in report["status_envelopes"]))
        self.assertFalse(bridge.h.startup.flag1)
        task39=next(x for x in report["per_task"] if x["task"]==39)
        self.assertFalse(task39["original_arm_identity_verified"])

    def test_bounded_host_status_queue_backpressure_blocks_readiness(self):
        bridge=self.new_bridge(status_queue_capacity=1)
        report=bridge.run()
        self.assertLessEqual(len(report["status_tasks_accepted"]),1)
        self.assertTrue(any("fixture full" in x for x in report["errors"]))
        self.assertFalse(report["draw_ready"])
        self.assertTrue(any(value==2 for value in report["task_states"].values()))
        self.assertFalse(bridge.h.startup.flag1)

    def test_invalid_hashes_and_duplicate_task_id_fail_closed(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            ThreadedStartupBridge(b"invalid",self.sysc,runtime_library=self.runtime)
        with self.assertRaises(ValueError):
            self.new_bridge(task_ids=(3,3,39))
        with self.assertRaises(ValueError):
            self.new_bridge(task_ids=(3,999))
        with self.assertRaises(ValueError):
            self.new_bridge(status_queue_capacity=0)
        with self.assertRaises(RuntimeError):
            self.bridge.run()

if __name__=="__main__":
    unittest.main()
