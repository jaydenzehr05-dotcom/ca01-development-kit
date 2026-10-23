import psutil
from pathlib import Path
f=Path(__file__).with_name('supervisor.pid')
pid=int(f.read_text().strip())
p=psutil.Process(pid)
print("PARENT",pid,p.name(),p.cmdline())
for x in p.children(recursive=True):
 try:print("CHILD",x.pid,x.ppid(),x.name(),x.cmdline()[:10])
 except Exception as e:print("CHILD ERR",x.pid,e)
