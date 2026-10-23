#!/usr/bin/env python3
"""Read-only storage/filesystem evidence search in recovered CA01 and related OSS.

Recovered binaries are exact known outputs. OSS source archives are nearby
related-source candidates, NOT proven to be built for this exact head unit.
"""
import collections,hashlib,json,re,tarfile
from pathlib import Path
ROOT=Path("/home/starlight/projects/rav4-radio")
RECO=ROOT/"system-audit/ca01-1134-firmware-analysis-20261023/recovered-1134-06-audio/recovered"
OUT=ROOT/"system-audit/ca01-1134-filesystem-tools-20261023"
files={
 "PROC_HMI":RECO/"01116813-PROC_HMI",
 "PROC_DISPLAY":RECO/"01116817-PROC_DISPLAY",
 "PROC_SYSTEM":RECO/"01116815-PROC_SYSTEM",
 "PROC_REPRO":RECO/"01116801-PROC_REPRO",
}
# Resolve sources by basename rather than guessed extraction number.
for key in files:
    found=list(RECO.glob("*-"+key))
    if len(found)!=1:raise RuntimeError(f"Ambiguous recovery for {key}: {found}")
    files[key]=found[0]
patterns=[b"jffs2",b"yaffs",b"ubifs",b"cramfs",b"squashfs",b"mtdparts=",
          b"/proc/mtd",b"/dev/mtd",b"/dev/mmcblk",b"ext3",b"ext4",
          b"fstab",b"/etc/mtab",b"rootfs",b"ubi0",b"nand",b"mount -t",b"/opt/ftl/"]
binary=[]
for name,path in files.items():
    raw=path.read_bytes()
    strings=[(m.start(),m.group().decode("ascii","replace"))
             for m in re.finditer(rb"[ -~]{5,256}",raw)]
    hits=[]
    for off,line in strings:
        if any(p.decode() in line.lower() for p in patterns):
            hits.append({"offset":hex(off),"text":line[:220]})
    binary.append({"name":name,"sha256":hashlib.sha256(raw).hexdigest(),
                   "strings_examined":len(strings),"relevant_hit_count":len(hits),
                   "hits":hits[:160]})
    print("EXE",name,"strings",len(strings),"fs_related",len(hits),flush=True)
    for h in hits[:20]:print(" ",h["offset"],h["text"][:125])
sources=[]
for ar in [ROOT/"vendor-source/20130619_LE2355.tgz",ROOT/"vendor-source/OSS_SOFT_PACK.tgz"]:
    candidates=[]; configurations=[]
    with tarfile.open(ar,"r:gz") as tf:
        for member in tf:
            if not member.isfile():continue
            n=member.name
            low=n.lower()
            if low.endswith(".config") or low.endswith("/config.gz") or low.endswith("/defconfig") or re.search(r"/configs?/[\w.+-]*defconfig$",low):
                candidates.append((n,member))
            elif ("mtdparts" in low or "mtd_partition" in low or "fstab" in low):
                configurations.append({"name":n,"reason":"filesystem/mtd-named source path"})
        matches=[]
        for name,member in candidates[:90]:
            if member.size>2_000_000:continue
            stream=tf.extractfile(member)
            if stream is None:continue
            content=stream.read(2_000_000)
            lines=content.decode("latin1","replace").splitlines()
            capture=[x[:150] for x in lines if any(x.strip().startswith(k) for k in
              ("CONFIG_JFFS2_FS=", "CONFIG_UBIFS_FS=","CONFIG_MTD=",
               "CONFIG_SQUASHFS=", "CONFIG_CRAMFS=","CONFIG_YAFFS_FS=",
               "CONFIG_EXT4_FS=","CONFIG_EXT3_FS=","CONFIG_MMC_BLOCK=",
               "CONFIG_MTD_NAND=","CONFIG_MTD_BLOCK=", "CONFIG_BLK_DEV_INITRD=",
               "CONFIG_NFS_FS=", "CONFIG_FAT_FS="))]
            if capture:matches.append({"name":name,"filesystem_config_lines":capture})
    obj={"archive":ar.name,"config_candidates":len(candidates),
         "filesystem_config_records":matches[:30],
         "fstab_or_mtd_source_paths":configurations[:70],
         "warning":"Related open-source archives may describe other Denso/Fujitsu Ten models or releases, NOT confirmed CA01 production kernel"}
    sources.append(obj)
    print("SOURCE",ar.name,"configs",len(candidates),"actual config matches",len(matches),
          "named fstab/mtd files",len(configurations),flush=True)
    for item in matches[:6]:print(" ",item["name"],item["filesystem_config_lines"][:14])
report={"binary_indicators":binary,"related_source_archive_indicators":sources,
       "conclusion_scope":"Read-only triage; not proof of filesystem format on actual head unit"}
(OUT/"flash-storage-indicators.json").write_text(json.dumps(report,indent=2)+"\n")
