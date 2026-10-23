import struct,tempfile,unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from ca01_payload_carve import carve_component,run
class CarveTests(unittest.TestCase):
    def make(self,p,prefix_size,payload):
        header=bytearray(prefix_size)
        struct.pack_into("<I",header,8,len(payload))
        p.write_bytes(bytes(header)+payload)
    def test_carves_declared_length_without_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);source=folder/"boot.bin"
            self.make(source,48,b"ARM_DATA")
            original=source.read_bytes()
            payload,info=carve_component(source)
            self.assertEqual(payload,b"ARM_DATA")
            self.assertEqual(info["observed_prefix_bytes"],48)
            self.assertEqual(source.read_bytes(),original)
    def test_non_overwriting_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);components=folder/"components";components.mkdir()
            self.make(components/"gui.bin",12,b"payload")
            result=folder/"derived"
            run(components,result)
            self.assertEqual((result/"gui.payload.bin").read_bytes(),b"payload")
            with self.assertRaises(FileExistsError):
                run(components,result)
    def test_bad_declared_payload_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"invalid.bin"
            self.make(path,12,b"abcd")
            data=bytearray(path.read_bytes())
            struct.pack_into("<I",data,8,900000)
            path.write_bytes(data)
            with self.assertRaises(ValueError):carve_component(path)
if __name__=="__main__":unittest.main()
