"""Offline image evidence must not turn arbitrary KWI/ELF offsets into NOR data."""
import hashlib,struct,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from ca01_flash_parameter_audit import inspect_image,audit_records,MAGIC
class FlashParameterAuditTests(unittest.TestCase):
 def test_embedded_signature_in_executable_is_not_an_image(self):
  data=b'\x7fELF'+bytes(256)+MAGIC
  r=inspect_image(data);self.assertFalse(r['header_candidate']);self.assertTrue(r['signature_offsets']);self.assertFalse(r['verified_parameter_source'])
 def test_explicit_header_range_is_required_for_candidate_coverage(self):
  data=bytearray(128+256);data[:len(MAGIC)]=MAGIC
  struct.pack_into('<II',data,0x20,0xb0000,0xb0100)
  r=inspect_image(bytes(data));self.assertTrue(r['header_candidate']);self.assertEqual(r['candidate_coverage']['vehicle_parameters'],True)
  self.assertFalse(r['candidate_coverage']['profile_table_1']);self.assertFalse(r['verified_parameter_source']);self.assertFalse(r['crc_verified'])
 def test_size_alone_does_not_establish_flash_mapping(self):
  r=inspect_image(bytes(0x800000));self.assertFalse(r['header_candidate']);self.assertFalse(r['verified_parameter_source'])
 def test_truncated_header_payload_is_rejected(self):
  data=bytearray(128);data[:len(MAGIC)]=MAGIC;struct.pack_into('<II',data,0x20,0xb0000,0xb0100)
  self.assertFalse(inspect_image(bytes(data))['header_candidate'])
 def test_manifest_hash_and_size_are_verified(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'input';p.write_bytes(b'\x7fELF')
   records=[dict(path=str(p),size=4,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),provenance='synthetic')]
   r=audit_records(records);self.assertEqual(r['verified_files'],1);self.assertEqual(r['verified_parameter_sources'],0)
   records[0]['sha256']='0'*64;r=audit_records(records);self.assertEqual(r['verified_files'],0);self.assertEqual(len(r['errors']),1)
 def test_conflicting_duplicate_manifest_identity_is_not_silently_skipped(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'input';p.write_bytes(b'original')
   row=dict(path=str(p),size=8,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),provenance='synthetic')
   conflict=dict(row,sha256='0'*64)
   r=audit_records([row,conflict]);self.assertEqual(r['verified_files'],1)
   self.assertEqual(len(r['errors']),1);self.assertIn('Conflicting',r['errors'][0]['error'])
   r=audit_records([row,dict(row)]);self.assertEqual(r['verified_files'],1);self.assertEqual(r['errors'],[])
if __name__=='__main__':unittest.main()
