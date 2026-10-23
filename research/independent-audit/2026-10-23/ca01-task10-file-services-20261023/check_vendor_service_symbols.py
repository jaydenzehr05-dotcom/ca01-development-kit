#!/usr/bin/env python3
"""Read-only verify recovered ELF service definitions and required SONAME origins."""
import io,json,hashlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

ROOT=Path("/home/starlight/projects/rav4-radio")
manifest=json.loads((ROOT/"system-audit/ca01-updater-independent-20261022/recovery-manifest.json").read_text())
targets={"fs_mpl_Create","rq_fls_Open","rq_tsk_WaitInit","rq_tsk_BlockBegin",
         "rq_tsk_GetBlockObj","rq_tsk_GetTid","fs_mpl_Init","fs_mpl_Delete"}
out=[]
for item in manifest["files"]:
    source=Path(item["local_path"])
    content=source.read_bytes()
    assert hashlib.sha256(content).hexdigest()==item["sha256"]
    if not content.startswith(b"\x7fELF"):continue
    try:
        elf=ELFFile(io.BytesIO(content))
        table=elf.get_section_by_name(".dynsym")
        if table is None: continue
        matches=[]
        for sym in table.iter_symbols():
            if sym.name in targets:
                matches.append(dict(symbol=sym.name,defined=sym["st_shndx"]!="SHN_UNDEF",
                                    virtual=hex(sym["st_value"])))
        if matches:
            out.append(dict(original_path=item["archive_path"],local=str(source),matches=matches))
    except ELFError:
        continue
output=Path(__file__).with_name("vendor-service-availability.json")
output.write_text(json.dumps(dict(scanned=len(manifest["files"]),files=out),indent=2)+"\n")
for row in out:
    print(row["original_path"])
    for item in row["matches"]: print(" ",item["symbol"],"defined",item["defined"],item["virtual"])
print("Done",output)
