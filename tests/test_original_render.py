"""Native original-ARM rendering slice, never full application startup."""
from pathlib import Path
import hashlib, json, shutil, sys, tempfile, unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ca01_original_render import validate_capture, run_original_slice
BASE=ROOT.parent/'system-audit'
HMI=BASE/'ca01-updater-independent-20261022/06-PROC_HMI'
ARMEL=BASE/'gui-emulation/armel-rootfs'

class CaptureTests(unittest.TestCase):
 def test_bad_firmware_is_rejected_before_creating_output(self):
  with tempfile.TemporaryDirectory() as tmp:
   source=Path(tmp)/'wrong';source.write_bytes(b'not the baseline')
   out=Path(tmp)/'output'
   with self.assertRaisesRegex(ValueError,'SHA-256'):run_original_slice(source,out,ARMEL)
   self.assertFalse(out.exists())
 def test_cannot_label_flat_or_wrong_pixels_as_original_geometry(self):
  with self.assertRaises(ValueError):validate_capture(b'P6\n800 480\n255\n'+bytes(800*480*3),800,480,400,160)

@unittest.skipUnless(HMI.is_file() and ARMEL.is_dir() and shutil.which('arm-linux-gnueabi-gcc') and shutil.which('bwrap'),'Local recovered fixture and ARMEL toolchain required')
class OriginalArmTests(unittest.TestCase):
 def test_original_code_reaches_real_mesa_at_both_resolutions(self):
  with tempfile.TemporaryDirectory() as tmp:
   for width in (800,480):
    with self.subTest(width=width):
     r=run_original_slice(HMI,Path(tmp)/str(width),ARMEL,width=width)
     self.assertTrue(r['slice_completed']);self.assertFalse(r['full_application_started'])
     self.assertFalse(r['factory_menu_rendered'])
     self.assertEqual(r['frames'],3)
     self.assertEqual(len(r['captures']),3)
     self.assertEqual(r['original_gl_draw_calls'],3)
     self.assertEqual(r['original_gl_clear_calls'],3)
     self.assertEqual(r['original_frame_submissions'],3)
     self.assertEqual(r['buffer_handles'],[0xca010001,0xca010002,0xca010003])
     self.assertEqual(r['descriptor_tokens'],[0xcb010001,0xcb010002,0xcb010003])
 def test_failed_allocation_never_marks_graphics_ready(self):
  with tempfile.TemporaryDirectory() as tmp:
   r=run_original_slice(HMI,Path(tmp)/'alloc-fail',ARMEL,mode='alloc-fail')
   self.assertTrue(r['allocation_failure_observed'])
   self.assertFalse(r['slice_completed']);self.assertFalse(r['graphics_ready'])
   self.assertEqual(r['original_gl_draw_calls'],0)
   self.assertEqual(r['captures'],[])
 def test_unknown_callback_success_return_is_not_a_presented_frame(self):
  with tempfile.TemporaryDirectory() as tmp:
   r=run_original_slice(HMI,Path(tmp)/'invalid-callback',ARMEL,mode='invalid-callback')
   self.assertFalse(r['slice_completed']);self.assertTrue(r['graphics_ready'])
   self.assertEqual(r['original_frame_submissions'],0)
   self.assertEqual(r['captures'],[])
   self.assertIn('callback',r['error'])
