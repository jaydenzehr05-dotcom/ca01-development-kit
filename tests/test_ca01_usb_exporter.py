"""Offline-only proof that the CA01 read-only USB exporter never alters source.

Compiles from archived C source into temporary directories. These tests cannot
install anything on the vehicle, and use an entirely synthetic source tree.
"""
from __future__ import annotations
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SRC=(ROOT/"research/independent-audit/2026-10-23"
    /"ca01-service-access-assessment-20261023/ca01_readonly_exporter.c")


class TestCA01OfflineUSBExporter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("cc") is None:
            raise unittest.SkipTest("C compiler unavailable")
        cls.build=tempfile.TemporaryDirectory(prefix="ca01-exporter-build-")
        cls.host=Path(cls.build.name)/"usb-exporter"
        subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-O2",
                        str(SRC),"-o",str(cls.host)],check=True,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        cls.arm=None
        if shutil.which("arm-linux-gnueabi-gcc") and shutil.which("qemu-arm"):
            cls.arm=Path(cls.build.name)/"usb-exporter-arm"
            subprocess.run(["arm-linux-gnueabi-gcc","-std=gnu11","-Wall",
                            "-Wextra","-O2","-static",str(SRC),"-o",str(cls.arm)],
                           check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix="ca01-exporter-test-")
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)/"fake-radio"
        self.usb=Path(self.directory.name)/"usb-drive"
        self.root.mkdir()
        self.usb.mkdir()
        self.samples={
            "opt/ftl/gui/MC/mui/Opening.mui":b"synthetic-not-genuine-Opening.mui",
            "opt/ftl/gui/MC/CmA.mra":b"synthetic-not-genuine-CmA.mra",
            "opt/ftl/gui/font/render.fnt":b"synthetic-font-test",
            "opt/ftl/lib/libipas_fls.so":b"synthetic-library-not-original",
            "etc/ipasz.conf":b"synthetic-config-file",
        }
        for path,content in self.samples.items():
            dst=self.root/path
            dst.parent.mkdir(parents=True,exist_ok=True)
            dst.write_bytes(content)
        unrelated=self.root/"personal-private-data.txt"
        unrelated.write_text("do not transfer")
        (self.root/"opt/ftl/gui/MC/cross-device.mra").symlink_to(unrelated)

    def invoke(self,arm=False,copy=False,destination=None):
        args=[str(self.arm if arm else self.host),
              "--source-root",str(self.root),
              "--destination",str(destination or self.usb)]
        if arm:args.insert(0,"qemu-arm")
        if copy:args.append("--copy")
        return subprocess.run(args,capture_output=True,text=True,timeout=20)

    def test_dry_run_does_not_write(self):
        before={n:hashlib.sha256((self.root/n).read_bytes()).hexdigest() for n in self.samples}
        result=self.invoke()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("DRY-RUN",result.stdout)
        self.assertFalse(list(self.usb.rglob("*")))
        self.assertEqual(before,{n:hashlib.sha256((self.root/n).read_bytes()).hexdigest() for n in self.samples})

    def test_copy_whitelisted_files_and_skip_symlink(self):
        result=self.invoke(copy=True)
        self.assertEqual(result.returncode,0,result.stderr)
        for n,content in self.samples.items():
            self.assertEqual((self.usb/n).read_bytes(),content)
        self.assertFalse((self.usb/"opt/ftl/gui/MC/cross-device.mra").exists())
        self.assertFalse((self.usb/"personal-private-data.txt").exists())

    def test_refuses_to_overwrite(self):
        self.assertEqual(self.invoke(copy=True).returncode,0)
        repeat=self.invoke(copy=True)
        self.assertNotEqual(repeat.returncode,0)
        self.assertIn("Refusing nonempty output directory",repeat.stderr)

    def test_rejects_destination_inside_source(self):
        inside=self.root/"opt/ftl/gui/MC"
        result=self.invoke(copy=True,destination=inside)
        self.assertNotEqual(result.returncode,0)

    def test_original_arm_binary_in_qemu(self):
        if self.arm is None:
            self.skipTest("ARM EABI cross compiler and qemu-arm are not installed")
        result=self.invoke(arm=True,copy=True)
        self.assertEqual(result.returncode,0,result.stderr)
        for n,content in self.samples.items():
            self.assertEqual((self.usb/n).read_bytes(),content)


if __name__=="__main__":
    unittest.main()
