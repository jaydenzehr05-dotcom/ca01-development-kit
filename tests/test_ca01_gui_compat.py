"""Tests for the isolated CA01 synthetic display and HMI queue model.

These build and execute only our own C fixtures on the current host.
They never execute recovered Toyota code and require no display hardware.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
CC = shutil.which("cc") or shutil.which("gcc")


@unittest.skipUnless(CC, "A host C compiler is needed")
class Ca01GuiModelTests(unittest.TestCase):
    def test_buffer_layout_rotation_validation_and_ipc_model(self):
        with tempfile.TemporaryDirectory(prefix="ca01-native-model-") as folder:
            exe = Path(folder) / "ca01-model-test"
            compile_cmd = [
                CC, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                "-Wl,--wrap=calloc", "-pthread", "-I", str(REPO / "src"),
                str(REPO / "src/ca01_hmi_ipc.c"),
                str(REPO / "src/ca01_gui_compat.c"),
                str(REPO / "tests/ca01_gui_compat_native_test.c"),
                "-o", str(exe),
            ]
            build = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            test = subprocess.run([str(exe)], capture_output=True, text=True, timeout=20)
            self.assertEqual(test.returncode, 0, test.stdout + test.stderr)
            self.assertIn("CA01_GUI_MODEL_TEST_OK", test.stdout)


if __name__ == "__main__":
    unittest.main()
