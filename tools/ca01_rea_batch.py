#!/usr/bin/env python3
"""Read-only REA/Unblob extraction sweep of already-carved CA01 update payloads.

Run in isolated workspace, never on the radio. Output folders must be absent.
"""
import argparse,json,os,subprocess
from pathlib import Path
def run(inputs,repo,out):
    if out.exists():raise FileExistsError("output directory already exists")
    out.mkdir(parents=True)
    env=os.environ.copy()
    env["REA_UNBLOB_COMMAND"]=str(repo/".venv/bin/unblob")
    results=[]
    for path in sorted(inputs.glob("*.payload.bin")):
        dest=out/(path.stem+".extracted")
        cmd=[str(repo/"tools/rea_ca01.sh"),"extract-firmware",
             str(path),str(dest),"--format","json"]
        try:
            p=subprocess.run(cmd,text=True,capture_output=True,env=env,timeout=50)
            obj=json.loads(p.stdout)
            report=obj.get("raw_result",{}).get("report",[])
            subtasks=sum(len(t.get("subtasks",[])) for t in report)
            record={"input":path.name,"success":p.returncode==0,
                    "recognized_nested_subtasks":subtasks,
                    "provider":obj.get("provider",{}).get("id"),"error":obj.get("code")}
            (out/(path.stem+".rea.json")).write_text(json.dumps(obj,indent=2)+"\n")
        except (subprocess.TimeoutExpired,ValueError) as exc:
            record={"input":path.name,"success":False,"error":str(exc)}
        results.append(record)
        print(record,flush=True)
    (out/"summary.json").write_text(json.dumps(results,indent=2)+"\n")
    return results
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inputs",required=True,type=Path)
    p.add_argument("--repo",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    args=p.parse_args()
    run(args.inputs,args.repo,args.output)
if __name__=="__main__":main()
