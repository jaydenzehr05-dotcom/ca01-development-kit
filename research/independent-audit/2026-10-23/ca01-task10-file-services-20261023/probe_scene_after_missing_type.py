#!/usr/bin/env python3
"""Continue original ARM scene initialization through its verified missing-type fallback.

Uses an explicitly *failed* rq_fls_Open('type.txt','r') service and bounded
guest memcpy. Every other file request remains unresolved. Does not infer
original file-service ABI beyond its caller's nonzero=failure branch.
"""
import json,hashlib,struct,sys
from pathlib import Path

ROOT=Path("/home/starlight/projects/rav4-radio")
sys.path.insert(0,str(ROOT/"ca01-development-kit/tools"))
from ca01_scene_boundary import inspect_scene_boundary
from ca01_startup_trace import BoundedArmTrace,HMI_SHA256,SYSC_SHA256
from ca01_group_binding import GROUP_SHA256

HMI=ROOT/"system-audit/ca01-updater-independent-20261022/06-PROC_HMI"
SYSC=ROOT/"system-audit/ca01-updater-independent-20261022/06-libipas_sysc.so"
GROUP=ROOT/"system-audit/ca01-updater-independent-20261022/06-libipas_grp.so"
OUT=Path(__file__).with_name("scene-after-type-fallback.json")

assert hashlib.sha256(HMI.read_bytes()).hexdigest()==HMI_SHA256
assert hashlib.sha256(SYSC.read_bytes()).hexdigest()==SYSC_SHA256
assert hashlib.sha256(GROUP.read_bytes()).hexdigest()==GROUP_SHA256
original_init=BoundedArmTrace.__init__
incidents=[]
def services_init(self,*args,**kwargs):
    original_init(self,*args,**kwargs)
    def guest_string(uc,p):
        return bytes(uc.mem_read(p,128)).split(b"\x00")[0].decode("ascii","replace")
    def open_missing_type(uc,registers):
        path=guest_string(uc,registers[0])
        mode=guest_string(uc,registers[1])
        if path!="type.txt" or mode!="r":
            raise RuntimeError("Unresolved original asset/file request "+repr((path,mode)))
        incident=dict(service="rq_fls_Open",requested=path,mode=mode,
                      outcome="EXPLICIT FAILURE (nonzero caller error branch)",status=1)
        incidents.append(incident)
        return 1
    def memcpy(uc,registers):
        dst,src,n=registers[:3]
        if not 0<n<=4096:raise RuntimeError("memcpy outside bounded fixture size")
        payload=bytes(uc.mem_read(src,n))
        # No host pointer ever crosses the guest boundary.
        uc.mem_read(dst,n)
        uc.mem_write(dst,payload)
        note=dict(service="memcpy",dest=hex(dst),source=hex(src),bytes=n,
                  starts_with_none_literal=payload.startswith(b"(none)\x00"))
        incidents.append(note)
        return dst
    self.services["rq_fls_Open"]=open_missing_type
    self.services["memcpy"]=memcpy

def main():
    BoundedArmTrace.__init__=services_init
    try:
        result=inspect_scene_boundary(HMI,provide_clock=True,provide_semaphores=True,
            system_library=SYSC,group_library=GROUP,instruction_limit=20000)
    finally:
        BoundedArmTrace.__init__=original_init
    scene=result["scene_initialization"]
    calls=scene["service_calls"]
    assert any(c["symbol"]=="rq_fls_Open" and c["result"]==1 for c in calls),scene
    assert any(c["symbol"]=="memcpy" for c in calls),scene
    assert any(note.get("starts_with_none_literal") is True for note in incidents),incidents
    result["type_txt_fallback_experiment"]={
      "synthetic_file_open_result":"1 (nonzero) means file absent; successful file service not supplied",
      "original_arm_type_txt_reader_proceeded":True,
      "read_and_close_not_called_on_failure":not any(
        c["symbol"] in ("rq_fls_Read","rq_fls_Close") for c in calls),
      "original_arm_literal_seen":"(none)",
      "incidents":incidents,
      "note":"This advances bounded original scene initialization only; later service calls remain fail-closed"
    }
    OUT.write_text(json.dumps(result,indent=2)+"\n")
    print("TYPE_TXT_FALLBACK_SCENE_PASS",scene["halt_reason"],
          "original instructions",scene["instructions"],
          "next boundary",scene["boundary"])
    print("PASS",OUT)

if __name__=="__main__":
    main()
