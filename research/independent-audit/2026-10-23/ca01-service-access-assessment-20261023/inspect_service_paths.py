#!/usr/bin/env python3
"""Static, read-only survey of verified CA01 recovered program strings and C-like Ghidra outputs."""
import json, re, hashlib
from pathlib import Path
A=Path("/home/starlight/projects/rav4-radio/system-audit")
B=Path(__file__).resolve().parent
FILES={
 "REPRO":A/"ca01-local-ai-supervisor-20261023/results/4ec99dbe7ba649cc/ghidra/decomp/decompiled.c",
 "SYSTEM":A/"ca01-critical-decompilation-20261023/system1127/decompiled.c",
 "EXT":A/"ca01-local-ai-supervisor-20261023/results/b95f96ba4f8e8e21/ghidra/decomp/decompiled.c",
 "FLASH_WRITER":A/"ca01-updater-independent-20261022/06-FlashImageWriter",
 "FLASH_CREATER":A/"ca01-updater-independent-20261022/06-FlashImageCreater",
 "REPRO_BIN":A/"ca01-updater-independent-20261022/06-PROC_REPRO",
 "SYSTEM_BIN":A/"ca01-updater-independent-20261022/06-PROC_SYSTEM",
 "EXT_BIN":A/"ca01-updater-independent-20261022/06-PROC_EXT",
 "SOCKET_LIB":A/"ca01-updater-independent-20261022/06-libipas_skt.so",
}
TOKENS={
 "authentication":r"rsa|sig[nature]*|verif|cert|sha.?256|sha.?1|md5|crypt|libsecurity|digest|crc32|hash|pub.?key|auth|hmac",
 "usb":r"usb|/mnt/|/dev/sd|gadget|otg|ehci|ohci|mass.?storage|rndis|cdc.?acm|usb0",
 "bluetooth":r"bluetooth|rfcomm|hci|obex|bluez|bnep|a2dp|sdp|hands.?free|pbap|bt_",
 "storage":r"/dev/mmc|/dev/mtd|/dev/flash|mkfs|mount\(|/opt/ftl|/var/verup",
 "shellaccess":r"dropbear|ssh|telnet|inetd|/dev/tty|uart|serial.?port|/bin/sh|busybox",
}
MATCH={k:re.compile(v,re.I) for k,v in TOKENS.items()}
HDR=re.compile(r"/[*] FUNCTION ([0-9a-fA-F]+)\s+([^\s]+)\s+bytes=([0-9]+) [*]/")
def decomp(path):
    raw=path.read_text(errors="replace");parts=list(HDR.finditer(raw))
    entries=[]
    for i,m in enumerate(parts):
        body=raw[m.start():(parts[i+1].start() if i+1<len(parts) else len(raw))]
        tags={}
        for k,p in MATCH.items():
            hits=list(p.finditer(body))
            if hits:
                examples=[]
                for h in hits[:4]:
                    start=max(0,h.start()-80);end=min(len(body),h.end()+140)
                    examples.append(re.sub(r"\s+"," ",body[start:end])[:240])
                tags[k]={"n":len(hits),"examples":examples}
        if tags: entries.append(dict(address=m.group(1),name=m.group(2),tags=tags))
    return entries
def binstrings(path):
    data=path.read_bytes()
    matches=[]
    for m in re.finditer(rb"[ -~]{5,250}",data):
        s=m.group().decode("ascii","replace");keys=[k for k,p in MATCH.items() if p.search(s)]
        if keys:matches.append(dict(offset=hex(m.start()),text=s[:180],tags=keys))
    return matches
results={}
for name,p in FILES.items():
    if p.is_file():
        arr=decomp(p) if p.suffix==".c" else binstrings(p)
        results[name]={"path":str(p),"sha":hashlib.sha256(p.read_bytes()).hexdigest(),"matches":arr}
        print(name,len(arr))
        if p.suffix==".c":
            relevant=[x for x in arr if "authentication" in x["tags"] or "usb" in x["tags"] or "bluetooth" in x["tags"]]
            relevant.sort(key=lambda x:("authentication" not in x["tags"],"usb" not in x["tags"],-sum(v["n"] for v in x["tags"].values())))
            for q in relevant[:22]:
                print(q["address"],q["name"],[(k,v["n"]) for k,v in q["tags"].items()])
                for k in ("authentication","usb","bluetooth"):
                    if k in q["tags"]:print(" ",k, q["tags"][k]["examples"][0][:210])
        else:
            for q in arr[:12]:print(" ",q["offset"],q["text"][:130],q["tags"])
(B/"access-evidence.json").write_text(json.dumps(results,indent=2)+"\n")
print("SAVED",B/"access-evidence.json")
