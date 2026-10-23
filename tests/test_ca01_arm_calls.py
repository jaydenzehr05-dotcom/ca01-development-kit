import hashlib,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_arm_calls import scan_arm32_calls,decode_prel31,audit_elf

def branch(address,target,condition=14):
 return struct.pack('<I',(condition<<28)|0x0b000000|(((target-address-8)>>2)&0xffffff))

class ArmCallTests(unittest.TestCase):
 def test_undecodable_word_does_not_truncate_following_calls(self):
  code=branch(0x1000,0x2000)+b'\xff'*4+branch(0x1008,0x2000)
  r=scan_arm32_calls(code,0x1000,{0x2000:'service'})
  self.assertEqual(r['calls']['service'],['0x1000','0x1008'])
  self.assertEqual(r['visited_bytes'],len(code))
  self.assertEqual(r['undecodable_bytes'],4)
 def test_conditional_calls_preserved_and_non_import_calls_excluded(self):
  code=branch(0x1000,0x2000,0)+branch(0x1004,0x3000)
  r=scan_arm32_calls(code,0x1000,{0x2000:'service'})
  self.assertEqual(r['calls'],{'service':['0x1000']})
  self.assertEqual(r['direct_branch_calls'],2)
 def test_unaligned_or_partial_instruction_is_rejected(self):
  for code,address in [(b'abc',0x1000),(b'abcd',0x1001)]:
   with self.assertRaises(ValueError):scan_arm32_calls(code,address,{})
 def test_prel31_handles_negative_positive_and_high_flag(self):
  self.assertEqual(decode_prel31(0x7ffffffc,0x1000),0xffc)
  self.assertEqual(decode_prel31(0x80000004,0x1000),0x1004)
 def test_canonical_display_scan_visits_entire_text(self):
  path=ROOT.parent/'system-audit/ca01-updater-independent-20261022/06-PROC_DISPLAY'
  if not path.is_file():self.skipTest('Local original display fixture required')
  sha='4755da50d4396cb213eb905ed49d6118cd8f330d05a35aa928b1bef8b2045004'
  r=audit_elf(path,sha)
  self.assertEqual(r['scan']['visited_bytes'],r['text_bytes'])
  self.assertGreater(sum(map(len,r['scan']['calls'].values())),88)
  self.assertEqual(r['unwind_thumb_entries'],0)
  with self.assertRaisesRegex(ValueError,'SHA-256'):audit_elf(path,'0'*64)
