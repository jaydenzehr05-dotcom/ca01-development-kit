#!/usr/bin/env python3
"""Read-only, line-numbered CA01 hardware contract extraction from GPL source tarball.

A symbol or filename in a shared Denso Ten source tree is NOT proof that a
particular production CA01 head unit uses it. No original source is copied
into the generated evidence (only bounded, line-numbered observations).
"""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

TARGETS={
 "boot": [
  "boot/src/board/fujitsuten/rma1_13PF/rma1_13PF.c",
  "boot/src/board/fujitsuten/rma1_13PF/ftensign.c",
  "boot/src/board/fujitsuten/rma1_13PF/Makefile",
 ],
 "board": [
  "kernel/src/arch/arm/mach-shmobile/board-ftenbb.c",
  "kernel/src/include/linux/ftenbb_config.h",
 ],
 "input": [
  "kernel/src/drivers/input/misc/ftenbb_asic_remocon.c",
  "kernel/src/drivers/input/misc/ftenbb_asic_remocon.h",
 ],
 "hardware_diagnostics": [
  "kernel/src/drivers/mfd/ftenbb_asic-core.c",
  "kernel/src/drivers/mfd/ftenbb_asic-proc.c",
  "kernel/src/drivers/misc/ftenbb_asic_adc.c",
  "kernel/src/include/linux/mfd/ftenbb_asic.h",
 ],
 "serial_i2c": [
  "kernel/src/drivers/serial/ftenbb_asic_scifa.c",
  "kernel/src/drivers/i2c/busses/i2c-ftenbb_asic.c",
 ],
 "audio": [
  "kernel/src/sound/soc/ftenbb/ftenbb_asic_fsi.c",
  "kernel/src/sound/soc/ftenbb/fsi-ak7756_lvds.c",
 ],
 "camera": [
  "kernel/src/drivers/media/video/ftenbb_ceu.c",
 ],
 "storage": [
  "kernel/src/drivers/mmc/host/ftenbb_asic_sdhi.c",
 ],
}
REGEX={
 "input_events": re.compile(r"\b(?:input_report_key|input_register_device|input_allocate_device|input_sync|EV_KEY|KEY_[A-Z0-9_]+)\b"),
 "userspace_devices": re.compile(r"\b(?:create_proc_read_entry|proc_mkdir|misc_register|register_chrdev|device_create|register_framebuffer|register_video_device|video_register_device|S_IRUGO)\b"),
 "entrypoints": re.compile(r"\b(?:platform_device|platform_driver|probe\s*\(|remove\s*\(|fb_var_screeninfo|ioctl|IOCTL|_IO[WR]*\s*\()\b"),
 "interfaces": re.compile(r"\b(?:snd_soc|snd_pcm|i2c_transfer|spi_|scifa|i2c_|gpio_|gic_spi|mfd_|rootfs|memblock|root_dev|bootcmd|bootm|secboot|secure|verify|signature|ftensign|watchdog|CAN|can_|video_device|fbdev)\b",re.I),
}
def analyze_tar(archive):
    wanted={path:(group) for group,paths in TARGETS.items() for path in paths}
    results=[]
    with tarfile.open(archive,"r:gz") as tar:
        for member in tar:
            if not member.isfile():continue
            path=member.name.removeprefix("./")
            if path not in wanted:continue
            if member.size>4_000_000:continue
            stream=tar.extractfile(member)
            if stream is None:continue
            data=stream.read()
            hits=[]
            for lineno,line in enumerate(data.decode("utf-8",errors="replace").splitlines(),1):
                kinds=[k for k,pat in REGEX.items() if pat.search(line)]
                if kinds and len(hits)<140:
                    hits.append({"line":lineno,"kinds":kinds,"text":line.strip()[:180]})
            results.append({
                "group":wanted[path], "path":path,"bytes":len(data),
                "sha256":hashlib.sha256(data).hexdigest(),
                "observations":hits,
            })
    found={x["path"] for x in results}
    missing=sorted(set(wanted)-found)
    return {"archive":archive.name,"source_files_analyzed":len(results),
      "sources":sorted(results,key=lambda d:(d["group"],d["path"])),
      "not_found":missing,
      "caveat":"Definitions in the manufacturer source tree do not verify active CA01 production drivers, peripheral wiring, or userspace protocols."}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archive",required=True,type=Path)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    if not args.archive.is_file():ap.error("archive not found")
    report=analyze_tar(args.archive)
    serialized=json.dumps(report,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(serialized)
    else:print(serialized,end="")

if __name__=="__main__":main()
