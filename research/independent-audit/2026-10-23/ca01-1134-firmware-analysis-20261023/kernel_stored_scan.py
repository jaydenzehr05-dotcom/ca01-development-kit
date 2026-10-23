#!/usr/bin/env python3
"""Bounded stored-block hunt in new Kernel stream; never runs code or flashes.

Validates LEN/NLEN complement, BTYPE=00, and zlib EOF at gzip-shaped
footer. This cannot recover the missing encrypted prefix or verify CRC.
"""
import hashlib,json,struct,sys,zlib
from pathlib import Path
ROOT=Path("/home/starlight/projects/rav4-radio")
BASE=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023"
sys.path.insert(0,str(ROOT/"ca01-development-kit/tools"))
from ca01_experimental_decode import _aligned_zlib_input
f=BASE/"components-1134/03-kernel.bin"
raw=f.read_bytes()
payload=raw[12:]
footer=len(payload)-264
hits=[]; headers=0; attempts=0
for off in range(130000,min(230000,footer-8)):
    l,n=struct.unpack_from("<HH",payload,off)
    if l^n!=0xffff:continue
    headers+=1
    # A stored DEFLATE block header (BFINAL,BTYPE=0) precedes padding
    # to the following byte-aligned LEN/NLEN pair.
    for bytepos in range(max(0,off-2),off):
        for bit in range(8):
            start=bytepos*8+bit
            aligned=((start+3+7)//8)*8
            if aligned!=off*8:continue
            bits=(int.from_bytes(payload[bytepos:bytepos+3],"little")>>bit)&7
            if bits&6:continue
            attempts+=1
            try:
                selected,emitted=_aligned_zlib_input(payload,start,144)
                dec=zlib.decompressobj(-15,zdict=bytes(32768))
                out=dec.decompress(selected,33_554_432)
                if dec.unconsumed_tail:continue
                end=len(payload)-len(dec.unused_data)
                if dec.eof and abs(end-footer)<=2:
                    hits.append(dict(start_byte=bytepos,start_bit=bit,stored_length=l,
                                output_bytes=len(out)-emitted,end_approx_byte=end,
                                trailing_bytes=len(payload)-end,
                                output_sha256_with_zeros=hashlib.sha256(out[emitted:]).hexdigest()))
            except (zlib.error,ValueError):pass
report=dict(input=str(f),sha256=hashlib.sha256(raw).hexdigest(),
            scan_bytes=[130000,230000],valid_len_nlen_headers=headers,
            candidates_tested=attempts,successes=hits,
            limitation="Bounded stored-block candidate scan; initial history unknown and remaining source encrypted.")
(BASE/"kernel-stored-scan.json").write_text(json.dumps(report,indent=2)+"\n")
print("KERNEL STORED",headers,"headers",attempts,"attempts",len(hits),"valid suffixes")
for hit in hits[:16]:print(hit)
