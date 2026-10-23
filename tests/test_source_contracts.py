import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from ca01_source_contracts import analyze_tar, TARGETS

class VendorSourceContractTests(unittest.TestCase):
    def make_archive(self,path,members):
        with tarfile.open(path,"w:gz") as t:
            for name,payload in members.items():
                data=payload.encode()
                info=tarfile.TarInfo(name)
                info.size=len(data)
                t.addfile(info,io.BytesIO(data))
    def test_find_annotated_input_and_diagnostic_interfaces(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"vendor.tgz"
            self.make_archive(p,{
                "./kernel/src/drivers/input/misc/ftenbb_asic_remocon.c":
                 'void event(){input_report_key(device, KEY_VOLUMEUP, 1);}\n',
                "kernel/src/drivers/mfd/ftenbb_asic-proc.c":
                 'parent = proc_mkdir("asic", NULL);\n',
            })
            report=analyze_tar(p)
            self.assertEqual(report["source_files_analyzed"],2)
            paths={a["path"]:a for a in report["sources"]}
            a=paths["kernel/src/drivers/input/misc/ftenbb_asic_remocon.c"]
            self.assertEqual(a["observations"][0]["line"],1)
            self.assertIn("input_events",a["observations"][0]["kinds"])
            self.assertIn("kernel/src/arch/arm/mach-shmobile/board-ftenbb.c",
                          report["not_found"])
    def test_ignore_unknown_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"vendor.tgz"
            self.make_archive(p,{"notes/unrelated.c":'input_report_key(x);\n'})
            report=analyze_tar(p)
            self.assertEqual(report["source_files_analyzed"],0)
            self.assertEqual(report["sources"],[])

if __name__=="__main__":unittest.main()
