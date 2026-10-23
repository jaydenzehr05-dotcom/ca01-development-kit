import subprocess,json,hashlib
from pathlib import Path
repo=Path('/home/starlight/projects/rav4-radio/ca01-development-kit')
root=repo.parent/'system-audit/gui-emulation/armel-rootfs'
out=Path('/tmp/ca01-consolidation-20261022/graphics')
cc='/usr/bin/arm-linux-gnueabi-gcc'
exe=out/'arm-graphics-smoke'
cmd=[cc,'-O1','-march=armv7-a','-mfloat-abi=soft','-I',str(root/'usr/include'),'-L',str(root/'usr/lib/arm-linux-gnueabi'),'-Wl,-rpath-link,'+str(root/'usr/lib/arm-linux-gnueabi'),str(repo/'tools/ca01_arm_graphics_smoke.c'),'-lEGL','-lGLESv1_CM','-o',str(exe)]
def run(cmd):
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
 r=dict(command=cmd,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
 assert p.returncode==0,r
 return r
report={'build':run(cmd)}
base=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--cap-drop','ALL','--ro-bind',str(root),'/', '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/opt','--ro-bind',str(exe),'/opt/arm-graphics-smoke','--bind',str(out),'/tmp/out','--setenv','PATH','/usr/bin:/bin','--setenv','LIBGL_ALWAYS_SOFTWARE','1','--setenv','GALLIUM_DRIVER','softpipe','--setenv','EGL_PLATFORM','surfaceless','--setenv','MESA_SHADER_CACHE_DISABLE','true','--chdir','/tmp','/usr/bin/qemu-arm-static','-B','0x100000000','/opt/arm-graphics-smoke']
report['runtime']=run(base)
b=(out/'arm-software-render.ppm').read_bytes();header=b'P6\n800 480\n255\n';assert b.startswith(header);pixels=b[len(header):];assert len(pixels)==800*480*3
for y in range(480):
 left,right=((bytes([0,0,255]),bytes([255,255,255])) if y<240 else (bytes([255,0,0]),bytes([0,255,0])))
 assert pixels[y*2400:(y+1)*2400]==left*400+right*400,y
report['pixel_validation']=dict(width=800,height=480,pixels_checked=384000,all_pixels_match=True,sha256=hashlib.sha256(b).hexdigest(),stock_toyota_gui=False)
# A self-authored guard proves trace semantics independently of Toyota code.
guard_src=out/'trace-guard.c';guard_src.write_text('#include <stdio.h>\n__attribute__((constructor)) static void ctor(void){puts("GUARD_CTOR_EXECUTED");}\nint main(void){puts("GUARD_MAIN_EXECUTED");return 0;}\n')
guard=out/'trace-guard';report['guard_build']=run([cc,'-O1',str(guard_src),'-o',str(guard)])
start=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--cap-drop','ALL','--ro-bind',str(root),'/', '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/opt','--ro-bind',str(guard),'/opt/guard','--chdir','/tmp','/usr/bin/qemu-arm-static','-B','0x100000000']
report['guard_normal']=run(start+['/opt/guard']);report['guard_trace']=run(start+['-E','LD_TRACE_LOADED_OBJECTS=1','/opt/guard'])
assert 'GUARD_CTOR_EXECUTED' in report['guard_normal']['stdout'] and 'GUARD_MAIN_EXECUTED' in report['guard_normal']['stdout']
assert 'GUARD_' not in report['guard_trace']['stdout'] and 'libc.so.6' in report['guard_trace']['stdout']
(out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(report['runtime']['stdout']);print(report['pixel_validation']);print('Self-authored constructor/main guard: trace skips both; ordinary execution calls both.')
