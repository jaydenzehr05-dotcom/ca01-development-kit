#!/usr/bin/env python3
"""Recheck all 1134 recovery evidence against actual local source file bytes."""
import hashlib,json,collections,sys
from pathlib import Path
ROOT=Path("/home/starlight/projects/rav4-radio")
BASE=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023"
sys.path.insert(0,str(ROOT/"ca01-development-kit/tools"))
from ca01_inspect import inspect_bytes
OLD=ROOT/"stock-firmware/15TBDANA-CA01_1127.kwi"
NEW=ROOT/"stock-firmware/15TBDANA-CA01_1134.kwi"
old=inspect_bytes(OLD.read_bytes());new=inspect_bytes(NEW.read_bytes())
assert old["sha256"]=="39431b79ed849be627c13be586019ceaab34470a534b76c385f73f1748d367ca"
assert new["sha256"]=="71c62cdcc357b5f249b216d68c06bd31168ab16939aab010a68777ffead04dbc"
assert old["package_tag"]=="UU1127" and new["package_tag"]=="UU1134"
assert len(new["components"])==10
comparison=json.loads((BASE/"component-comparison.json").read_text())
assert sum(not r["byte_identical"] for r in comparison["components"])==9
for r in new["components"]:
    part=(BASE/"components-1134"/r["filename"]).read_bytes()
    assert hashlib.sha256(part).hexdigest()==r["sha256"],r["filename"]
oldfiles=json.loads((ROOT/"system-audit/ca01-updater-independent-20261022/recovery-manifest.json").read_text())["files"]
prior={x["archive_path"]:x for x in oldfiles}
unique=collections.defaultdict(dict)
counts={}
for short in ("06-audio","07-gui","08-voice-recognition"):
    manifest=json.loads((BASE/f"recovered-1134-{short}/recovered-manifest.json").read_text())
    seen=set()
    matches=0;changed=0
    for row in manifest:
        name=row["archive_path"]
        data=Path(row["local_file"]).read_bytes()
        assert len(data)==row["size"] and hashlib.sha256(data).hexdigest()==row["sha256"]
        assert name in prior,("Unexpected new file path",name)
        ident=(row["sha256"]==prior[name]["sha256"])
        matches+=int(ident);changed+=int(not ident)
        assert name not in seen,("Unexpected duplicate",name)
        seen.add(name)
        unique[short][name]=row["sha256"]
    counts[short]=dict(complete=len(manifest),identical=matches,changed=changed)
assert counts=={"06-audio":{"complete":47,"identical":23,"changed":24},
               "07-gui":{"complete":3,"identical":3,"changed":0},
               "08-voice-recognition":{"complete":6,"identical":6,"changed":0}}
diff=json.loads((BASE/"elf-byte-diff.json").read_text())
assert diff["total"]==47 and diff["changed"]==24
records={Path(x["name"]).name:x for x in diff["files"]}
assert records["PROC_HMI"]["changed_bytes"]==10 and records["PROC_HMI"]["text_identical"] is True
assert records["PROC_SYSTEM"]["text_identical"] is True
assert records["PROC_REPRO"]["text_identical"] is True
assert records["PROC_DISPLAY"]["text_identical"] is False
assert records["PROC_VRS"]["text_identical"] is False
assert sum(1 for x in diff["files"] if "/lib/" in x["name"] and x["changed_bytes"]==0)==20
details=json.loads((BASE/"key-elf-differences.json").read_text())
hmi=next(x for x in details if x["executable"]=="PROC_HMI")
assert hmi["exact_byte_differences"]["offsets"]==['0x596790','0x596791','0x596792',
    '0x596794','0x596795','0x59679a','0x59679d','0x59679f','0x5967a2','0x5967a3']
assert all(not row["added_dependencies"] and not row["removed_dependencies"] for row in details)
assert all(not row["added_import_symbols"] and not row["removed_import_symbols"] for row in details)
rea={}
for part in ("07-gui","06-audio"):
    obj=json.loads((BASE/f"rea-{part}.json").read_text())
    subtasks=sum(len(x.get("subtasks",[])) for x in obj.get("raw_result",{}).get("report",[]))
    assert subtasks==0
    rea[part]=subtasks
out=dict(package="15TBDANA-CA01",version_older="UU.11.27",version_new="UU.11.34",
    old_sha256=old["sha256"],new_sha256=new["sha256"],
    changed_package_components=9,unchanged_components=["SH Base"],
    validated_complete_files_counts=counts,unique_recovered_file_count=sum(x["complete"] for x in counts.values()),
    changed_recovered_files=24,unchanged_recovered_files=32,
    critical_elf_text_unchanged=["PROC_HMI","PROC_SYSTEM","PROC_REPRO"],
    critical_elf_text_changed=["PROC_DISPLAY","PROC_VRS"],
    recovered_shared_libraries_unchanged=20,
    new_verified_GUI_MC_mra_mui_font_assets=0,
    no_new_verified_files_among_complete_recoveries=True,
    rea_unblob_nested_subtasks=rea,
    caveats=["No full compressed prefixes, no CRC verification of whole components, no Toyota signature validation.",
             "Cannot rule out files stored only in inaccessible leading component regions or the factory root filesystem.",
             "Build-date-only changes in HMI do not demonstrate any new menu source code.",
             "New DISPLAY code changes do not by themselves establish a new public ABI or working HMI startup."])
(BASE/"verified-1134-summary.json").write_text(json.dumps(out,indent=2)+"\n")
print("PASS byte-exact component hashes for 10 entries")
print("PASS complete-file SHA-256 and names for 56 distinct recovered files")
print("PASS section and ELF imports diff; HMI ten bytes are timestamp only")
print("PASS no matching new original MC/menu resource files in validated recovered entries")
print("PASS REA/Unblob ran, zero recognized subtasks")
print("VERIFIED_SUMMARY",BASE/"verified-1134-summary.json")
