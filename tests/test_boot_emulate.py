import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from ca01_boot_emulate import inspect
class BootHarnessTest(unittest.TestCase):
 def test_known_arm_return(self):
  # mov r0,#42 ; bx lr
  data=bytes.fromhex("2a00a0e31eff2fe1")
  r=inspect(data,0,0x20000000,15)
  self.assertEqual(r["stop_reason"],"returned_to_sentinel")
  self.assertEqual(r["final_r0"],"0x2a")
  self.assertFalse(r["faults"])
 def test_unknown_mmio_stops(self):
  # ldr r0,[r1] where r1 starts 0 -> unmapped
  r=inspect(bytes.fromhex("000091e5"),0,0x20000000,15)
  self.assertTrue(r["faults"])
  self.assertEqual(r["faults"][0]["kind"],"unmapped_access")
 def test_no_direct_image_mutation(self):
  # str r0,[pc,#0] ; attempts write into loaded image
  r=inspect(bytes.fromhex("00008fe500000000"),0,0x20000000,15)
  self.assertEqual(r["faults"][0]["kind"],"blocked_write")
 def test_stack_argument_changes_early_fault(self):
  # ldr r0,[r0] ; bx lr, stack-backed argument permits function to return.
  data=bytes.fromhex("000090e51eff2fe1")
  r=inspect(data,0,argument_mode="stack-buffer")
  self.assertEqual(r["stop_reason"],"returned_to_sentinel")
  self.assertEqual(r["argument_mode"],"stack-buffer")
 def test_alignment(self):
  with self.assertRaises(ValueError):inspect(b"\x00"*16,2)
if __name__=="__main__":unittest.main()
