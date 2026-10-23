#!/usr/bin/env python3
"""Compare loader-only resolution before/after an optional GLES1 SONAME alias.

Uses the existing hash-validated read-only loader sandbox. Does not run the
Toyota HMI application, change the recovery set, or claim graphics compatibility.
"""
import argparse
import json
from pathlib import Path
from ca01_loader_sandbox import stage_verified_elfs, build_trace_command, run_trace

GUEST_ALIAS = "/usr/lib/arm-linux-gnueabi/libGLESv1_CM.so.1"
ALIAS_NAME = "libGLES_CM.so"


def analyze(manifest, rootfs, output):
    manifest, rootfs, output = map(Path, (manifest, rootfs, output))
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    if not (rootfs / GUEST_ALIAS.lstrip("/")).exists():
        raise FileNotFoundError(rootfs / GUEST_ALIAS.lstrip("/"))
    output.mkdir(parents=True)
    vendor = output / "vendor"
    staged = stage_verified_elfs(manifest, vendor)
    if len(staged) < 1:
        raise ValueError("No verified ARM ELFs staged")
    base = run_trace(build_trace_command(rootfs,vendor,"PROC_HMI"), output/"before")
    if not base["inspection_succeeded"]:
        raise RuntimeError("Baseline trace failed: " + repr(base["stderr"]))
    alias = vendor/"opt/ftl/lib"/ALIAS_NAME
    if alias.exists() or alias.is_symlink():
        raise FileExistsError(alias)
    alias.symlink_to(GUEST_ALIAS)
    after = run_trace(build_trace_command(rootfs,vendor,"PROC_HMI"), output/"after")
    if not after["inspection_succeeded"]:
        raise RuntimeError("Aliased trace failed: " + repr(after["stderr"]))
    removed = sorted(set(base["missing_libraries"]) - set(after["missing_libraries"]))
    added = sorted(set(after["missing_libraries"]) - set(base["missing_libraries"]))
    report = {
        "scope":"dynamic-loader dependency tracing ONLY; original Toyota executable never started",
        "sandbox":"Bubblewrap offline, no capabilities, guest rootfs read-only, vendor binaries immutable",
        "alias":{"name":ALIAS_NAME,"guest_symlink_target":GUEST_ALIAS,
                 "external_graphics_library_unmodified":True},
        "baseline":{"missing":base["missing_libraries"],"count":len(base["missing_libraries"])},
        "with_alias":{"missing":after["missing_libraries"],"count":len(after["missing_libraries"])},
        "no_longer_missing":removed,
        "new_missing":added,
        "libGLES_CM_alias_in_resolved_map":ALIAS_NAME in after["resolved_libraries"],
        "application_started":False,
        "not_proof_of_runtime_abi_or_gui":True
    }
    with (output/"comparison.json").open("x", encoding="utf-8") as fp:
        json.dump(report,fp,indent=2);fp.write("\n")
    print(json.dumps(report,indent=2))
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--rootfs",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    analyze(a.manifest,a.rootfs,a.output)
