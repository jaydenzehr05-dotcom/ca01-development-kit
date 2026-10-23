#!/usr/bin/env python3
"""Non-model, read-only integrity checks of focused reverse-engineering upgrade."""
import json,sys
from pathlib import Path
import coverage_index,model_review,supervisor
p=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-critical-decompilation-20261023/display1134/decompiled.c")
excerpts=model_review.extract_excerpts(p)
assert excerpts and len(excerpts)<=2,("Legacy display manifest still unreviewable",excerpts)
print("PASS legacy display source recognized",[(x["address"],x["name"]) for x in excerpts])
HMI="64f5d905a42aa844d60fcf2a3aed752ce5fd9df04e54a1a565d81b64307af62b"
candidate=coverage_index.candidates(HMI,6)
assert len(candidate)==6 and all(x["score"]>0 for x in candidate),candidate
samples=coverage_index.get_excerpts(HMI,[x["address"] for x in candidate[:2]])
assert len(samples)==2 and samples[0]["address"].startswith("000")
assert all("/* FUNCTION " in s["source"] for s in samples)
print("PASS focused Ghidra candidates ranked",[(x["address"],x["score"]) for x in candidate[:6]])
print("PASS SHA-bound source excerpts sampled",len(samples))
assert "focus" in supervisor.CATEGORIES and "index" in supervisor.CATEGORIES
assert supervisor.GH_SCRIPT.is_file()
assert all(Path(v).is_relative_to(supervisor.AUDIT) for v in
           [supervisor.OLD,supervisor.NEW])
print("PASS existing Ghidra and source boundaries retained")
