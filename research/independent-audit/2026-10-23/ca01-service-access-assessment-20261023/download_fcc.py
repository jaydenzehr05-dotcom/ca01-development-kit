#!/usr/bin/env python3
"""Download primary public FCC exhibits unchanged and verify PDF bytes."""
from pathlib import Path
import urllib.request,hashlib,time
DEST=Path(__file__).resolve().parent/"fcc-docs"
DEST.mkdir(exist_ok=True)
sources=[
 ("BABFT0049B-CPU-boards.pdf","https://fccid.io/BABFT0049B/Internal-Photos/05-2-Internal-Photo-Equipment-FT0049B-1938910.pdf","e379eda2096a5ca8cf3df9c541d853b07757225b974503100cab6ecd32c91ea5"),
 ("BABFT0049B-Bluetooth-ALPS-UGXZE-102A.pdf","https://fccid.io/BABFT0049B/Internal-Photos/05-3-External-Internal-Photo-Bluetooth-FT0049B-1938911.pdf","ecffa7d318cb283e268832dc5dbd1121f35e49e23dcecda3e9399af11a612ea7"),
 ("BABFT0049A-boards.pdf","https://fccid.io/BABFT0049A/Internal-Photos/TempConfidential-05-2-Internal-Photo-FT0049A-Rev01-1938326.pdf",None),
]
for name,url,sha in sources:
    out=DEST/name
    if out.exists():
        blob=out.read_bytes()
        print("EXISTS",name,len(blob),hashlib.sha256(blob).hexdigest())
        continue
    try:
        request=urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0 (Toyota CA01 archival research)"})
        with urllib.request.urlopen(request,timeout=25) as h:
            blob=h.read(4_000_000)
        if not blob.startswith(b"%PDF-"):raise ValueError("Unexpected non-PDF reply")
        actual=hashlib.sha256(blob).hexdigest()
        if sha is not None and actual!=sha:raise ValueError("FCC-published SHA256 mismatch "+actual)
        out.write_bytes(blob)
        print("VERIFIED",name,len(blob),actual)
    except Exception as exc:
        print("NOT_DOWNLOADED",name,type(exc).__name__,str(exc)[:250])
