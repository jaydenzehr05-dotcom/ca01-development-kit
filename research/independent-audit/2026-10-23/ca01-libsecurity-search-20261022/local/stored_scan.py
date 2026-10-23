from pathlib import Path
import struct,zlib,json,sys,hashlib
sys.path.insert(0,'/tmp/ca01-firmware-updater-research/tools')
from ca01_experimental_decode import _aligned_zlib_input
root=Path('/home/starlight/projects/rav4-radio/stock-firmware/components');results=[]
for name,prefix,stop in [('02-middle-ware.bin',524,69313),('06-audio.bin',12,65703),('04-device-driver.bin',12,90137),('05-bluetooth.bin',12,101515),('07-gui.bin',12,67615),('08-voice-recognition.bin',12,67954)]:
 raw=(root/name).read_bytes();d=raw[prefix:];hits=[];length_pairs=[]
 for off in range(64000,stop+2):
  length,nlength=struct.unpack_from('<HH',d,off)
  if length^nlength !=65535:continue
  length_pairs.append(off)
  for start in range(off*8-10,off*8-2):
   kind=(int.from_bytes(d[start//8:start//8+2],'little')>>(start%8))&7
   if kind&6:continue
   sd,emitted=_aligned_zlib_input(d,start,144)
   try:
    dec=zlib.decompressobj(-15,zdict=bytes(32768));o=dec.decompress(sd,33554432);end=len(d)-len(dec.unused_data)
    if dec.eof and end==len(d)-264:hits.append({'byte':start//8,'bit':start%8,'size':len(o)-emitted,'end':end,'stored_length':length})
   except zlib.error:pass
 result={'component':name,'source_sha256':hashlib.sha256(raw).hexdigest(),'payload_offset':prefix,'scan_length_offset_range':[64000,stop+2],'complementary_length_pair_offsets':length_pairs,'eof_aligned_hits':hits};results.append(result);print(json.dumps(result),flush=True)
Path('/tmp/ca01-libsecurity-local/stored_scan.json').write_text(json.dumps(results,indent=2))
