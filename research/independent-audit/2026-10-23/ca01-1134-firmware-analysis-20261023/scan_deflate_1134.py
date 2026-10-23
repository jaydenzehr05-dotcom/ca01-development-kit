#!/usr/bin/env python3
"""Bounded raw-deflate suffix scan of changed CA01 update components.

Starts only at bit-aligned DEFLATE block headers beyond an opaque first 64 KiB.
Require EOF exactly at the independently observed gzip-shaped footer. This
does not recover missing compressed history, decrypt AES, or verify signatures.
"""
import json,sys,hashlib,time,zlib,struct
from pathlib import Path
BASE=Path("/home/starlight/projects/rav4-radio/system-audit/ca01-1134-firmware-analysis-20261023")
INPUT=BASE/"components-1134"
NAMES=["07-gui.bin","06-audio.bin","08-voice-recognition.bin",
       "02-middle-ware.bin","04-device-driver.bin","05-bluetooth.bin","03-kernel.bin"]
MAX_OUTPUT=33_554_432
RANGE_START=64000
RANGE_END=130000
def scan(path):
    raw=path.read_bytes()
    tail_size=struct.unpack_from("<I",raw,8)[0]
    prefix=len(raw)-tail_size
    if not (12<=prefix<=4096): raise RuntimeError("Impossible trailing size")
    payload=raw[prefix:]
    t0=time.monotonic()
    limit=min(RANGE_END,len(payload)-264-65536)
    if limit<=RANGE_START:return {"file":path.name,"error":"too small"}
    footer_at=len(payload)-264
    success=[]
    stats={"headers_tested":0,"first_chunk_plausible":0,"eof_near_footer":0}
    for shift in range(8):
        # Byte-shift so bits from a candidate offset are aligned to bit 0.
        sample=payload[RANGE_START:limit+65536+2]
        if shift:
            sliced=bytes(((sample[i]>>shift)|((sample[i+1]<<(8-shift))&255))
                         for i in range(len(sample)-1))
        else:sliced=sample
        zeros=bytes(32768)
        for off in range(limit-RANGE_START):
            if (sliced[off]&6) not in (2,4): continue
            stats["headers_tested"]+=1
            try:
                decomp=zlib.decompressobj(-15,zdict=zeros)
                out=decomp.decompress(sliced[off:off+65536],MAX_OUTPUT)
                if len(out)<32768 or decomp.unconsumed_tail:continue
                stats["first_chunk_plausible"]+=1
                abs_off=off+RANGE_START
                if decomp.eof:
                    # Unlikely: full short deflate inside initial chunk.
                    end_at=abs_off+len(sliced[off:off+65536])-len(decomp.unused_data)
                else:
                    remaining=payload[abs_off+65536:]
                    if shift:
                        remaining=bytes(((remaining[i]>>shift)|((remaining[i+1]<<(8-shift))&255))
                                        for i in range(len(remaining)-1))
                    next_chunk=decomp.decompress(remaining,MAX_OUTPUT-len(out)+1)
                    out+=next_chunk
                    end_at=abs_off+65536+len(remaining)-len(decomp.unused_data)
                if decomp.eof and abs(end_at-footer_at)<=2:
                    stats["eof_near_footer"]+=1
                    hit=dict(start_byte=abs_off,start_bit=shift,
                             output_bytes=len(out),end_approx_byte=end_at,
                             footer_byte=footer_at,footer_error_bytes=end_at-footer_at,
                             output_sha256_with_zero_dictionary=hashlib.sha256(out).hexdigest())
                    if hit not in success:
                        success.append(hit)
            except (zlib.error,ValueError):pass
    result=dict(input=str(path),sha256=hashlib.sha256(raw).hexdigest(),
        observed_component_prefix=prefix,compressed_length=len(payload),
        unverified_trailer_crc32_hex=f"{struct.unpack_from('<I',payload,footer_at)[0]:08x}",
        unverified_gzip_isize=struct.unpack_from("<I",payload,footer_at+4)[0],
        scan_range=[RANGE_START,limit],stats=stats,candidates=success,
        elapsed_seconds=round(time.monotonic()-t0,3),
        disclaimer="Candidate complete DEFLATE suffix (unknown encrypted prefix and 32 KiB initial LZ history); not original complete gzip or verified TAR")
    (BASE/(path.stem+"-scan.json")).write_text(json.dumps(result,indent=2)+"\n")
    return result
def main():
    selected=sys.argv[1:] or NAMES
    for n in selected:
        p=INPUT/n
        if not p.is_file():raise FileNotFoundError(p)
        record=scan(p)
        print(n,"scanned",record["scan_range"],"hits",len(record["candidates"]),
              "elapsed",record["elapsed_seconds"],"first plausible",record["stats"]["first_chunk_plausible"],flush=True)
        for x in record["candidates"][:12]:
            print("  CANDIDATE",x["start_byte"],x["start_bit"],"output",x["output_bytes"],"eof delta",x["footer_error_bytes"],flush=True)
if __name__=="__main__":main()
