"""Regression checks for evidence-based dependency inventory, without execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'ca01_dependency_inventory.py'

class DependencyInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('dependency_inventory', TOOL)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def record(self, name, needed=(), exports=(), imports=(), machine='EM_ARM', soname=None):
        return dict(archive_path=name, elf=dict(machine=machine, bits=32, little_endian=True,
            soname=soname, needed=list(needed), imports=list(imports), exports=list(exports)))

    def test_missing_and_present_with_soname(self):
        rows=[self.record('/app', ['liba.so.1','missing.so']), self.record('/liba-real.so',soname='liba.so.1')]
        result=self.tool.link_inventory(rows)
        self.assertEqual(result['missing_libraries'], ['missing.so'])
        self.assertEqual(result['files'][0]['library_candidates']['liba.so.1'], ['/liba-real.so'])

    def test_incompatible_machine_does_not_satisfy_dependency(self):
        result=self.tool.link_inventory([self.record('/app',['liba.so']),self.record('/liba.so',machine='EM_X86_64')])
        self.assertEqual(result['missing_libraries'], ['liba.so'])

    def test_duplicate_candidates_are_preserved(self):
        result=self.tool.link_inventory([self.record('/app',['liba.so']),self.record('/one/liba.so'),self.record('/two/liba.so')])
        self.assertEqual(len(result['files'][0]['library_candidates']['liba.so']),2)

    def test_missing_strong_and_weak_imports_are_separate(self):
        rows=[self.record('/app',imports=[dict(name='required',binding='STB_GLOBAL'),dict(name='optional',binding='STB_WEAK'),dict(name='provided',binding='STB_GLOBAL')]),self.record('/lib.so',exports=['provided'])]
        r=self.tool.link_inventory(rows)['files'][0]
        self.assertEqual(r['no_observed_provider_strong'],['required'])
        self.assertEqual(r['no_observed_provider_weak'],['optional'])
        self.assertEqual(r['symbol_candidates']['provided'],['/lib.so'])

    def test_manifest_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data';p.write_bytes(b'abc')
            with self.assertRaisesRegex(ValueError,'SHA-256'):
                self.tool.inspect_record(dict(local_path=str(p),archive_path='/data',size=3,sha256='0'*64))

    def test_non_elf_keeps_hash_and_size(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data';p.write_bytes(b'abc')
            r=self.tool.inspect_record(dict(local_path=str(p),archive_path='/data',size=3,sha256=hashlib.sha256(b'abc').hexdigest()))
            self.assertIsNone(r['elf'])
            self.assertEqual(r['size'],3)

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required for controlled ELF fixture')
    def test_real_elf_imports_exports_and_device_strings(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.so'
            source='extern int unresolved(void); __attribute__((visibility("hidden"))) int hidden(void){return 1;} const char *device="/dev/example"; int exported(void){return unresolved();}'
            subprocess.run(['cc','-shared','-fPIC','-x','c','-','-Wl,-soname,fixture.so.1','-o',str(p)],input=source,text=True,check=True,capture_output=True)
            b=p.read_bytes()
            r=self.tool.inspect_record(dict(local_path=str(p),archive_path='/fixture.so',size=len(b),sha256=hashlib.sha256(b).hexdigest()))
            self.assertEqual(r['elf']['soname'],'fixture.so.1')
            self.assertIn('exported',r['elf']['exports'])
            self.assertNotIn('hidden',r['elf']['exports'])
            self.assertIn('unresolved',[s['name'] for s in r['elf']['imports']])
            self.assertIn('/dev/example',[s['text'] for s in r['observed_device_paths']])
            self.assertEqual(p.read_bytes(),b)

    def test_output_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'report';p.write_text('original')
            with self.assertRaises(FileExistsError): self.tool.write_report({},p)
            self.assertEqual(p.read_text(),'original')

if __name__=='__main__': unittest.main()
