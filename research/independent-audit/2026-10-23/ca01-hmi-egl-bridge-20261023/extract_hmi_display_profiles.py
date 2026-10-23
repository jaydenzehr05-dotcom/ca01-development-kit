#!/usr/bin/env python3
"""Read-only extraction of Ghidra-identified PROC_HMI display tables."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path("/home/starlight/projects/rav4-radio")
SOURCE = ROOT / "system-audit/ca01-updater-independent-20261022/06-PROC_HMI"
EXPECTED_SHA256 = "cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503"
OUTPUT = Path(__file__).with_name("display-profiles.json")

image = SOURCE.read_bytes()
digest = hashlib.sha256(image).hexdigest()
if digest != EXPECTED_SHA256:
    raise RuntimeError(f"Firmware mismatch; refusing to interpret offset data: {digest}")
# PT_LOAD R E: virtual 0x00008000 corresponds to file offset 0.
LOAD_BASE = 0x8000
def u32(vaddr: int) -> int:
    offset = vaddr - LOAD_BASE
    if offset < 0 or offset + 4 > len(image):
        raise ValueError(f"Virtual address not file-backed: {vaddr:#x}")
    return struct.unpack_from("<I", image, offset)[0]

# Four literal-pool values referenced by Ghidra FUN_0002a548.
ptr_literals = {
    f"DAT_{vaddr:08x}": u32(vaddr)
    for vaddr in (0x0002A604, 0x0002A608, 0x0002A60C, 0x0002A610)
}
variants = {0x00295FE8}
for value in ptr_literals.values():
    variants.add(value)
    variants.add(value - 0x60)
records = []
for addr in sorted(variants):
    offset = addr - LOAD_BASE
    if offset < 0 or offset + 16 > len(image):
        raise ValueError(f"Profile outside file: {addr:#x}")
    words = struct.unpack_from("<I6H", image, offset)
    record = {
        "vaddr": f"0x{addr:08x}",
        "table_label_pointer": f"0x{words[0]:08x}",
        "profile_id_word_at_4": words[1],
        "candidate_outer_width_at_6": words[2],
        "candidate_outer_height_at_8": words[3],
        "window_width_at_10": words[4],
        "window_height_at_12": words[5],
        "unknown_word_at_14": words[6],
    }
    if not (16 <= words[4] <= 4096 and 16 <= words[5] <= 4096):
        raise RuntimeError(f"Unexpected HMI window dimensions at {addr:#x}: {words}")
    records.append(record)
output = {
    "source_sha256": digest,
    "elf_readonly_pt_load_vaddr": "0x00008000",
    "pointer_literals": {k: f"0x{v:08x}" for k, v in ptr_literals.items()},
    "interpretation": "FUN_0002b66c reads uint16 at +10 for width and +12 for height",
    "note": "Profile selection requires runtime rq_sys_GetVclPara; variant choice is unproven.",
    "records": records,
}
OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
for item in records:
    print(item["vaddr"], item["window_width_at_10"], "x", item["window_height_at_12"])
print("Wrote", OUTPUT)
