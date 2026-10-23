#!/usr/bin/env python3
"""Read-only verification that QEMU user mode executes an ARM program in a rootfs.

Does not run recovered Toyota applications; does not touch radio hardware.
"""
import argparse, json, subprocess
from pathlib import Path

def verify(root):
    root=Path(root).resolve()
    qemu=Path("/usr/bin/qemu-arm-static")
    shell=root/"bin/sh"
    interp=(root/"lib/ld-linux-armhf.so.3") if (root/"lib/ld-linux-armhf.so.3").is_symlink() else root/"lib/ld-linux.so.3"
    if not qemu.is_file() or not shell.exists() or not (interp.exists() or interp.is_symlink()):
        raise SystemExit(f"Incomplete rootfs: qemu={qemu.exists()}, shell={shell.exists()}, loader={interp.exists()}")
    cmd=[str(qemu),"-L",str(root),str(shell),"-c","printf 'CA01_ARM_QEMU_OK\\n'; uname -m"]
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
    report={"qemu":str(qemu),"rootfs":str(root),"command":cmd,"returncode":r.returncode,"stdout":r.stdout,"stderr":r.stderr,
            "pass":r.returncode==0 and "CA01_ARM_QEMU_OK" in r.stdout}
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report["pass"] else 1)
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("rootfs")
    a=p.parse_args()
    verify(a.rootfs)
