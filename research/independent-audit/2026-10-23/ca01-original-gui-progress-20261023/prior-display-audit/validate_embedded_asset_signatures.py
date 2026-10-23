#!/usr/bin/env python3
"""Validate claimed embedded image/font *magic* in the original Toyota HMI ELF.

A magic string alone is not proof of an embedded image. Validate PNG IHDR,
JPEG marker length, GIF dimensions, and OpenType SFNT table directory.
"""
import hashlib
import json
import struct
from pathlib import Path

HMI=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-updater-independent-20261022/06-PROC_HMI")
HASH="cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503"
OUT=Path(__file__).with_name("embedded-magic-validation.json")
image=HMI.read_bytes()
assert hashlib.sha256(image).hexdigest()==HASH

cases=[
    ("gif89a",0x59b8f8),
    ("jpeg",0x59ba40),
    ("png",0x59baac),
    ("png",0x59bb34),
    ("png",0x59bb50),
    ("otf",0x2366c0),
    ("otf",0x59f530)
]
results=[]
for kind,off in cases:
    area=image[off:off+128]
    if kind=="png":
        assert area[:8]==bytes.fromhex("89504e470d0a1a0a")
        length=int.from_bytes(area[8:12],"big")
        chunk=area[12:16]
        valid=chunk==b"IHDR" and length==13
        reason=f"First chunk {chunk!r}, length {length}; PNG requires IHDR length 13"
    elif kind=="jpeg":
        assert area[:4]==bytes.fromhex("ffd8ffe0")
        length=int.from_bytes(area[4:6],"big")
        valid=2<=length<65535 and area[6:11]==b"JFIF\x00"
        reason=f"APP0 length={length}, marker={area[2:4].hex()} (must be >=2)"
    elif kind=="gif89a":
        assert area[:6]==b"GIF89a"
        w,h=struct.unpack_from("<HH",area,6)
        valid=0<w<4096 and 0<h<4096
        reason=f"GIF header dimensions width={w}, height={h}; zero width invalid"
    elif kind=="otf":
        assert area[:4]==b"OTTO"
        tables=struct.unpack_from(">H",area,4)[0]
        valid=0<tables<200
        reason=f"SFNT numTables={tables}, expected 1..199 (font data table header)"
        if valid:
            for i in range(tables):
                entry=image[off+12+i*16:off+12+(i+1)*16]
                if len(entry)!=16:
                    valid=False;reason+="; missing table directory";break
                tag,checksum,position,length=struct.unpack(">4sIII",entry)
                if (not all(32<=x<127 for x in tag) or length==0 or
                    position+length>len(image)-off):
                    valid=False
                    reason+=f"; invalid table entry {i}: {tag!r}, off={position}, len={length}"
                    break
    results.append(dict(type=kind,file_offset=hex(off),structurally_valid=valid,
                        reason=reason))
if any(row["structurally_valid"] for row in results):
    raise RuntimeError("Possible genuine embedded asset found; manual recovery required")
OUT.write_text(json.dumps(dict(hmi_sha256=HASH,report=results,
    scope="7 signature-like occurrences checked; no validated embedded resource in these candidates",
    caveat="Only exact matching signature-like offsets, not a comprehensive decompression or asset-corpus audit"),indent=2)+"\n")
for row in results:
    print(row["type"],row["file_offset"],"INVALID",row["reason"])
print("PASS magic signatures rejected as genuine image/font headers; no extracted asset")
