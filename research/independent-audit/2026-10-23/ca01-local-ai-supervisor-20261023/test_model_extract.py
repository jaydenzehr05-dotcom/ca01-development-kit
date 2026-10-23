import model_review
from pathlib import Path
s=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/672245e48f1f6d8e/ghidra/decomp/decompiled.c").read_text()
print("SOURCE",repr(s[160:235]))
print("REGEX",repr(model_review.FUNCTION_REGEX.pattern))
print("MATCHES",list((x.group(1),x.group(2)) for x in model_review.FUNCTION_REGEX.finditer(s))[:8])
print("EXCERPTS",[(x["address"],len(x["source"])) for x in model_review.extract_excerpts(Path("/home/starlight/projects/rav4-radio/system-audit/ca01-local-ai-supervisor-20261023/results/672245e48f1f6d8e/ghidra/decomp/decompiled.c"))])
