#!/usr/bin/env python3
"""Offline tests for conservative older-version skipping and immutable retries."""
import copy,hashlib,json,sqlite3,tempfile,unittest
from pathlib import Path
import retry_failed,version_policy
HERE=Path(__file__).resolve().parent

class VersionPolicyTest(unittest.TestCase):
    def test_verified_text_pairs_have_only_two_real_differences(self):
        cx=sqlite3.connect("file:"+str(HERE/"progress.sqlite3")+"?mode=ro",uri=True)
        cx.row_factory=sqlite3.Row
        pairs=version_policy.comparisons(cx)
        self.assertEqual(len(pairs),21)
        self.assertEqual(sum(bool(p["identical_text"]) for p in pairs),19)
        changed={p["archive_path"].split("/")[-1] for p in pairs if not p["identical_text"]}
        self.assertEqual(changed,{"PROC_DISPLAY","PROC_VRS"})

    def test_skipped_jobs_retain_original_inputs_and_evidence(self):
        cx=sqlite3.connect("file:"+str(HERE/"progress.sqlite3")+"?mode=ro",uri=True)
        cx.row_factory=sqlite3.Row
        skipped=[dict(r) for r in cx.execute("""SELECT j.key,j.kind,i.archive_path,i.version,j.status
                     FROM jobs j JOIN inputs i USING(sha256)
                     WHERE status='skipped_identical_text'""")]
        self.assertEqual(sum(x["kind"]=="decompile" for x in skipped),13)
        self.assertTrue(all(x["version"]=="1127" for x in skipped))
        self.assertEqual(len(skipped),19)
        self.assertTrue(all(x["archive_path"].split("/")[-1] not in
                 ("PROC_DISPLAY","PROC_VRS") for x in skipped))
        self.assertTrue((HERE/"version-preference-20261023.json").is_file())

class RetryMergeTest(unittest.TestCase):
    def setUp(self):
        self.root=tempfile.TemporaryDirectory(prefix="ca01-repair-unit-")
        self.addCleanup(self.root.cleanup)
        self.base=Path(self.root.name)/"old"
        self.part=Path(self.root.name)/"retry"
        self.target=Path(self.root.name)/"merged"
        self.base.mkdir();self.part.mkdir()
        self.sha="a"*64
        self.main={
            "sha256":self.sha,
            "functions_catalogued":2,
            "decompiled":1,"failed":1,"not_attempted":0,
            "functions":[
              dict(address="00000100",name="first",status="decompiled",bytes=24,
                   classification="text_body"),
              dict(address="00000200",name="failed",status="failed",bytes=200,
                   classification="text_body",error="process: timeout")]}
        self.supp={"sha256":self.sha,"functions_catalogued":1,
              "decompiled":1,"failed":0,"not_attempted":0,
              "functions":[dict(address="00000200",name="failed",status="decompiled",
                      bytes=200,calls=[],classification="text_body")]}
        (self.base/"manifest.json").write_text(json.dumps(self.main))
        (self.base/"decompiled.c").write_text("/* FUNCTION 00000100 first bytes=24 */\nvoid first(){}\n")
        (self.part/"manifest.json").write_text(json.dumps(self.supp))
        (self.part/"decompiled.c").write_text("/* FUNCTION 00000200 failed bytes=200 */\nvoid recovered(){}\n")
        self.before=hashlib.sha256((self.base/"manifest.json").read_bytes()).hexdigest()

    def test_immutable_successful_merge(self):
        new,problems=retry_failed.merge_success(self.base,self.part,self.target,
                                                  self.sha,["00000200"])
        self.assertEqual(new,self.target)
        self.assertEqual(problems,{})
        merged=json.loads((new/"manifest.json").read_text())
        self.assertEqual(merged["decompiled"],2)
        self.assertEqual(merged["failed"],0)
        self.assertEqual(merged["functions"][1]["decompile_source"],
                          "isolated_failed_only_45s_retry")
        self.assertIn("void recovered()", (new/"decompiled.c").read_text())
        self.assertEqual(hashlib.sha256((self.base/"manifest.json").read_bytes()).hexdigest(),
                         self.before)
        with self.assertRaises(FileExistsError):
            retry_failed.merge_success(self.base,self.part,self.target,self.sha,["00000200"])

    def test_unapproved_address_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError,"unapproved"):
            retry_failed.merge_success(self.base,self.part,self.target,self.sha,["00000999"])
        self.assertFalse(self.target.exists())

    def test_mismatching_elf_sha_rejected(self):
        with self.assertRaisesRegex(RuntimeError,"different ELF inputs"):
            retry_failed.merge_success(self.base,self.part,self.target,"b"*64,["00000200"])

    def test_inconsistent_success_body_not_accepted(self):
        (self.part/"decompiled.c").write_text("/* FUNCTION 00000500 unrelated */")
        with self.assertRaisesRegex(RuntimeError,"missing actual C body"):
            retry_failed.merge_success(self.base,self.part,self.target,self.sha,["00000200"])

if __name__=="__main__":unittest.main()
