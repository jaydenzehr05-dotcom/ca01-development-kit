"""Offline security regressions for the CA01 directory-fd exporter.

Every test uses synthetic host paths or QEMU. The production ARM binary is
not a radio update, is never run on physical hardware, and never accesses
the real CA01 files or device nodes.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"tools/ca01_usb_exporter.c"

class ExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("cc"):
            raise unittest.SkipTest("C compiler unavailable")
        cls.build=tempfile.TemporaryDirectory(prefix="ca01-export-tests-")
        cls.host=Path(cls.build.name)/"host"
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror","-O2",
                        "-DCA01_OFFLINE_TEST",str(SOURCE),"-o",str(cls.host)],
                       check=True,capture_output=True)
        cls.arm=None
        cls.arm_production=None
        if shutil.which("qemu-arm") and shutil.which("arm-linux-gnueabi-gcc"):
            common=["arm-linux-gnueabi-gcc","-std=gnu11","-Wall","-Wextra",
                    "-Werror","-O2","-march=armv5te","-marm","-mfloat-abi=soft",
                    "-ffreestanding","-fno-builtin","-fno-stack-protector",
                    "-fno-pie","-no-pie","-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables","-nostdlib","-static",
                    "-Wl,-e,_start","-Wl,--build-id=none","-DCA01_LEGACY_ARM"]
            cls.arm=Path(cls.build.name)/"arm-test"
            cls.arm_production=Path(cls.build.name)/"arm-production"
            for obj,extra in [(cls.arm,["-DCA01_OFFLINE_TEST"]),(cls.arm_production,[])]:
                result=subprocess.run(common+extra+[str(SOURCE),"-lgcc","-o",str(obj)],
                            capture_output=True,text=True)
                if result.returncode:
                    raise RuntimeError("Failed ARM legacy compilation: "+result.stderr)
    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="ca01-synthetic-")
        self.addCleanup(self.tmp.cleanup)
        base=Path(self.tmp.name)
        self.root=base/"radio"
        self.usb=base/"synthetic-usb"
        self.root.mkdir()
        self.usb.mkdir()
        self.payloads={
            "opt/ftl/gui/MC/mui/Opening.mui":b"fake opening scene",
            "opt/ftl/gui/MC/CmA.mra":b"fake resource archive",
            "opt/ftl/gui/font/font.fnt":b"fake font",
            "opt/ftl/lib/libipas_fls.so":b"fake runtime library",
            "etc/ipasz.conf":b"fake config",
        }
        for name,content in self.payloads.items():
            target=self.root/name
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(content)

    def run_export(self,copy=False,test_device=False,root=None,usb=None,arm=False,
                   production=False):
        cmd=[str(self.arm_production if production else self.arm if arm else self.host),
             "--source-root",str(root or self.root),
             "--destination",str(usb or self.usb)]
        if arm or production:cmd.insert(0,"qemu-arm")
        if copy:cmd.append("--copy")
        if test_device:cmd.append("--test-allow-same-device")
        return subprocess.run(cmd,capture_output=True,text=True,timeout=30)

    def assert_files_match(self):
        for name,data in self.payloads.items():
            self.assertEqual((self.usb/name).read_bytes(),data)

    def test_dry_run_has_no_side_effects(self):
        original={p:hashlib.sha256((self.root/p).read_bytes()).hexdigest()
                  for p in self.payloads}
        got=self.run_export()
        self.assertEqual(got.returncode,0,got.stderr)
        self.assertIn("DRY-RUN",got.stdout)
        self.assertFalse(list(self.usb.rglob("*")))
        self.assertEqual(original,{p:hashlib.sha256((self.root/p).read_bytes()).hexdigest()
                                    for p in self.payloads})

    def test_default_copy_refuses_same_filesystem(self):
        got=self.run_export(copy=True)
        self.assertNotEqual(got.returncode,0)
        self.assertIn("source filesystem",got.stderr)
        self.assertFalse(list(self.usb.rglob("*")))

    def test_test_only_copy_preserves_source(self):
        got=self.run_export(copy=True,test_device=True)
        self.assertEqual(got.returncode,0,got.stderr)
        self.assert_files_match()
        self.assertTrue((self.root/"etc/ipasz.conf").exists())

    def test_repeated_run_never_overwrites(self):
        self.assertEqual(self.run_export(copy=True,test_device=True).returncode,0)
        repeat=self.run_export(copy=True,test_device=True)
        self.assertNotEqual(repeat.returncode,0)
        self.assertIn("nonempty output directory",repeat.stderr)

    def test_leaf_symlink_not_followed(self):
        private=(Path(self.tmp.name)/"private.txt")
        private.write_bytes(b"not a scene")
        (self.root/"opt/ftl/gui/MC/trap.mra").symlink_to(private)
        got=self.run_export(copy=True,test_device=True)
        self.assertEqual(got.returncode,0,got.stderr)
        self.assertFalse((self.usb/"opt/ftl/gui/MC/trap.mra").exists())
        self.assert_files_match()

    def test_parent_symlink_under_selected_source_refused(self):
        external=Path(self.tmp.name)/"external"
        external.mkdir()
        (external/"secret.mra").write_bytes(b"not within the allowed root")
        (self.root/"opt/ftl/gui/MC/mui").rename(
            self.root/"opt/ftl/gui/MC/mui_old")
        (self.root/"opt/ftl/gui/MC/mui").symlink_to(external,target_is_directory=True)
        got=self.run_export(copy=True,test_device=True)
        self.assertEqual(got.returncode,0,got.stderr)
        self.assertFalse((self.usb/"opt/ftl/gui/MC/mui/secret.mra").exists())
        self.assertFalse((self.usb/"opt/ftl/gui/MC/mui").exists())
        self.assertEqual((self.usb/"opt/ftl/gui/MC/mui_old/Opening.mui").read_bytes(),
                         self.payloads["opt/ftl/gui/MC/mui/Opening.mui"])

    def test_symlinked_source_parent_cannot_escape_root(self):
        original=self.root/"opt/ftl/gui/MC"
        external=Path(self.tmp.name)/"external"
        external.mkdir()
        (external/"secret.mra").write_bytes(b"not in radio")
        shutil.rmtree(original)
        original.symlink_to(external,target_is_directory=True)
        got=self.run_export(copy=True,test_device=True)
        self.assertEqual(got.returncode,0,got.stderr)
        self.assertFalse((self.usb/"opt/ftl/gui/MC/secret.mra").exists())

    def test_symlinked_root_parent_rejected(self):
        alias=Path(self.tmp.name)/"link-to-radio"
        alias.symlink_to(self.root,target_is_directory=True)
        got=self.run_export(copy=True,test_device=True,root=alias)
        self.assertNotEqual(got.returncode,0)
        self.assertIn("symlinked parent",got.stderr)

    def test_symlinked_destination_parent_rejected(self):
        alias=Path(self.tmp.name)/"link-to-usb"
        alias.symlink_to(self.usb,target_is_directory=True)
        got=self.run_export(copy=True,test_device=True,usb=alias)
        self.assertNotEqual(got.returncode,0)
        self.assertFalse(list(self.usb.rglob("*")))

    def test_destination_within_selected_source_rejected(self):
        inner=self.root/"opt/ftl/gui/MC/export-target"
        inner.mkdir()
        got=self.run_export(copy=True,test_device=True,usb=inner)
        self.assertNotEqual(got.returncode,0)
        self.assertIn("overlaps selected source",got.stderr)

    def test_walk_rejects_destination_alias_before_creating_output(self):
        # Exercise the recursive walker directly: a bind-mounted destination
        # presents the same directory inode as this fixture. The top-level
        # pathname preflight is deliberately excluded from this regression.
        source=Path(self.tmp.name)/"walker-source"
        source.mkdir()
        destination=source/"destination-alias"
        destination.mkdir()
        fixture=Path(self.tmp.name)/"walk_guard.c"
        fixture.write_text(
            '#define main exporter_cli_main\n#include "'+str(SOURCE)+'"\n'
            '#undef main\nint main(int argc,char **argv){\n'
            ' if(argc!=3)return 9;\n'
            ' sourcefd=abs_dir(argv[1]);destfd=abs_dir(argv[2]);\n'
            ' KernelStat target;if(os_stat(destfd,&target)<0)return 9;\n'
            ' dest_dev=(uint64_t)target.st_dev;do_copy=true;\n'
            ' walk(sourcefd,destfd,0);\n'
            ' os_close(sourcefd);os_close(destfd);return failures?1:0;\n}\n')
        binary=Path(self.tmp.name)/"walk_guard"
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror","-O2",
                        "-DCA01_OFFLINE_TEST",str(fixture),"-o",str(binary)],
                       check=True,capture_output=True)
        got=subprocess.run([str(binary),str(source),str(destination)],
                           capture_output=True,text=True,timeout=30)
        self.assertNotEqual(got.returncode,0)
        self.assertIn("overlaps selected source",got.stderr)
        self.assertEqual(list(destination.iterdir()),[])

    def test_parent_dotdot_alias_rejected(self):
        got=self.run_export(copy=True,test_device=True,
                            usb=Path(self.tmp.name)/"radio/../synthetic-usb")
        self.assertNotEqual(got.returncode,0)

    def test_destination_with_existing_symlink_rejected(self):
        (self.usb/"spoof").symlink_to(self.root,target_is_directory=True)
        got=self.run_export(copy=True,test_device=True)
        self.assertNotEqual(got.returncode,0)
        self.assertIn("nonempty output directory",got.stderr)

    def test_sparse_oversized_source_is_not_copied(self):
        target=self.root/"opt/ftl/gui/MC/huge.mra"
        with target.open("wb") as f:f.truncate(129*1024*1024)
        got=self.run_export(copy=True,test_device=True)
        self.assertNotEqual(got.returncode,0)
        self.assertFalse((self.usb/"opt/ftl/gui/MC/huge.mra").exists())

    def test_arm_qemu_copies_synthetic_files(self):
        if self.arm is None:self.skipTest("ARM cross-compiler/qemu-arm absent")
        got=self.run_export(copy=True,test_device=True,arm=True)
        self.assertEqual(got.returncode,0,got.stderr)
        self.assert_files_match()

    def test_arm_production_copy_does_not_accept_test_bypass(self):
        if self.arm_production is None:self.skipTest("ARM compiler/qemu absent")
        got=self.run_export(copy=True,production=True)
        self.assertNotEqual(got.returncode,0)
        self.assertFalse(list(self.usb.rglob("*")))

    def test_arm_requires_no_glibc_or_linux_3_2_abi_note(self):
        if self.arm_production is None:self.skipTest("ARM compiler/qemu absent")
        elf=self.arm_production.read_bytes()
        self.assertTrue(elf.startswith(b"\x7fELF"))
        hdr=subprocess.run(["readelf","-n",str(self.arm_production)],
                           capture_output=True,text=True,check=True).stdout
        self.assertNotIn("ABI: 3.2",hdr)
        dyn=subprocess.run(["readelf","-d",str(self.arm_production)],
                           capture_output=True,text=True).stdout
        self.assertNotIn("(NEEDED)",dyn)
        undefined=subprocess.run(["nm","-u",str(self.arm_production)],
                                 capture_output=True,text=True).stdout
        self.assertEqual(undefined.strip(),"")
        got=self.run_export(production=True)
        self.assertEqual(got.returncode,0,got.stderr)


if __name__=="__main__":unittest.main()
