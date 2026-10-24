#!/usr/bin/env python3
"""Derive non-mutating Ghidra recovery script from pinned original batch script."""
from pathlib import Path
here=Path(__file__).resolve().parent
original=(here/"CA01DecompileBatch.java").read_text()
assert "public class CA01DecompileBatch extends GhidraScript" in original
assert "dec.decompileFunction(f,8,monitor)" in original
assert "args.length<2 || args.length>3" in original
new=original.replace("public class CA01DecompileBatch extends GhidraScript",
                     "public class CA01DecompileRetry extends GhidraScript")
new=new.replace('if(args.length<2 || args.length>3)', 'if(args.length!=3)')
new=new.replace("dec.decompileFunction(f,8,monitor)", "dec.decompileFunction(f,45,monitor)")
new=new.replace("public class CA01DecompileRetry",
    "// Targeted recovery only. Every address comes from SHA-bound failed original manifest.\n"
    "// 45s per function (instead of 8s); output is separate, non-destructive.\n"
    "public class CA01DecompileRetry")
outfile=here/"CA01DecompileRetry.java"
if outfile.exists():
    assert outfile.read_text()==new, "Refusing overwrite of different generated retry script"
else:
    outfile.write_text(new)
print("TARGETED_SCRIPT_READY",outfile,"bytes",outfile.stat().st_size)
