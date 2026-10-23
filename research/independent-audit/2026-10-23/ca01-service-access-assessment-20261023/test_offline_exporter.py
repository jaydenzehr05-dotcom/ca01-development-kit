#!/usr/bin/env python3
"""Run exporter ONLY against disposable synthetic filesystem. No actual radio."""
import os,sys,hashlib,json,subprocess,shutil,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
src=HERE/"ca01_readonly_exporter.c"
host=HERE/"ca01_readonly_exporter_host"
arm=HERE/"ca01_readonly_exporter_armel_static"
subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-O2",str(src),"-o",str(host)],check=True)
subprocess.run(["arm-linux-gnueabi-gcc","-std=gnu11","-Wall","-Wextra","-O2","-static",str(src),"-o",str(arm)],check=True)
data={}
with tempfile.TemporaryDirectory(prefix="ca01-ex-test-") as temp:
    tmp=Path(temp);root=tmp/"fake-root";dest=tmp/"test-usb";root.mkdir();dest.mkdir()
    files={
      "opt/ftl/gui/MC/CmA.mra":b"synthetic cma archive not factory"+bytes(range(80)),
      "opt/ftl/gui/MC/mui/Opening.mui":b"synthetic opening scene",
      "opt/ftl/gui/font/font.fnt":b"synthetic font",
      "opt/ftl/lib/libipas_fls.so":b"synthetic not functional library",
      "opt/ftl/apl/PROC_HMI":b"synthetic elf placeholder",
      "etc/ipasz.conf":b"synthetic configuration",
    }
    for name,contents in files.items():
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(contents)
    p=root/"opt/ftl/gui/MC/trap.mra"
    p.symlink_to("/etc/passwd")
    dry=subprocess.run([str(host),"--source-root",str(root),"--destination",str(dest)],
             capture_output=True,text=True)
    assert dry.returncode==0,(dry.stdout,dry.stderr)
    assert not list(dest.rglob("*")),"Dry-run unexpectedly wrote data"
    copied=subprocess.run([str(host),"--source-root",str(root),"--destination",str(dest),"--copy"],
             capture_output=True,text=True)
    assert copied.returncode==0,(copied.stdout,copied.stderr)
    for name,contents in files.items():
        assert (dest/name).read_bytes()==contents, f"Wrong content {name}"
    assert not (dest/"opt/ftl/gui/MC/trap.mra").exists(), "Symlink copied"
    assert not (dest/"etc/passwd").exists(), "Symlink traversed"
    repeated=subprocess.run([str(host),"--source-root",str(root),"--destination",str(dest),"--copy"],
             capture_output=True,text=True)
    assert repeated.returncode!=0, "Expected refusal for nonempty destination"
    data=dict(host_compilation=True,
        arm_binary_elf=subprocess.run(["file",str(arm)],capture_output=True,text=True).stdout.strip(),
        arm_sha256=hashlib.sha256(arm.read_bytes()).hexdigest(),
        dry_run_no_writes=True,
        selected_files_copied=len(files),
        expected_files_sha256={x:hashlib.sha256(z).hexdigest() for x,z in files.items()},
        output_matches_input=True,
        ignored_symlink=True,
        refuses_existing_output=True,
        test_only_no_live_radio=True,
        host_stdout=copied.stdout)
    qemu=shutil.which("qemu-arm")
    if qemu:
        target=tmp/"second-usb";target.mkdir()
        run=subprocess.run([qemu,str(arm),"--source-root",str(root),
                "--destination",str(target),"--copy"],capture_output=True,text=True,timeout=25)
        assert run.returncode==0,(run.stdout,run.stderr)
        for name,contents in files.items():assert (target/name).read_bytes()==contents
        data["arm_binary_qemu_test_passed"]=True
    else:
        data["arm_binary_qemu_test_passed"]=False
        data["arm_binary_qemu_test_note"]="qemu-arm missing; byte-level ARM binary and host simulation only"
(HERE/"offline-exporter-test.json").write_text(json.dumps(data,indent=2)+"\n")
print(json.dumps({k:v for k,v in data.items() if k not in ["expected_files_sha256","host_stdout"]},indent=2))
