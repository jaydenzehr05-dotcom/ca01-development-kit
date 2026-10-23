from pathlib import Path
import sys,json,subprocess,struct,hashlib
sys.path.insert(0,'/tmp/ca01-firmware-updater-research/tools')
from ca01_experimental_decode import _aligned_zlib_input
records=[]
for label,fn in [('middleware','/tmp/ca01-middleware-research/middleware-post-review-report.json'),('kernel','/tmp/ca01-more-recovery/kernel-earlier-report.json'),('audio','/tmp/ca01-more-recovery/audio-report.json')]:
 r=json.loads(Path(fn).read_text()); original=Path(r['input_path']).read_bytes(); payload=original[r['payload_offset']:][:r['end_byte_ceil']]
 aligned,extra=_aligned_zlib_input(payload,r['start_bit'],144)
 # A synthetic nonfinal stored block supplies only diagnostic history. It is NOT recovered firmware.
 stream=b'\0'+struct.pack('<HH',32768,32767)+bytes(32768)+aligned
 p=subprocess.run(['/home/starlight/projects/rav4-radio/tools/infgen-3.6-1e36c3d/infgen','-sqqr'],input=stream,capture_output=True)
 out=Path('/tmp/ca01-libsecurity-tools')/(label+'-infgen.txt');out.write_bytes(p.stdout)
 records.append(dict(component=label,exit_code=p.returncode,stderr=p.stderr.decode(),expected_total=r['output_size']+32768+extra,
 source_sha256=hashlib.sha256(original).hexdigest(),report=str(out),total_lines=[l for l in p.stdout.decode().splitlines() if 'stats total inout' in l],
 caveat='Artificial 32768-byte zero history and alignment prelude added for disassembly; this does not reconstruct missing history or verify gzip CRC/signature.'))
 print(records[-1])
Path('/tmp/ca01-libsecurity-tools/stream-checks.json').write_text(json.dumps(records,indent=2)+'\n')
