#!/usr/bin/env python3
"""Run selected original ARM HMI graphics functions with real ARMEL Mesa.

This launches a self-authored bounded fixture, never PROC_HMI's entry point.
Configuration/IPC startup and factory menu resources are still unresolved.
"""
from pathlib import Path
import argparse
from collections import Counter
import hashlib
import json
import re
import subprocess

REPO=Path(__file__).resolve().parents[1]
BASE=REPO.parent/'system-audit'
HMI_SHA256='cf7c621b96d0865d7ba5d79a6aa8806e3d2544a827966a27a7c95de56ffa6503'


def validate_capture(data,width,height,rectangle_width,rectangle_height):
    """Independent exact raster check; fixture inputs are NOT menu geometry."""
    header=f'P6\n{width} {height}\n255\n'.encode()
    if not data.startswith(header) or len(data)!=len(header)+width*height*3:
        raise ValueError('Invalid PPM layout')
    pixels=data[len(header):]
    colors=Counter(pixels[i:i+3] for i in range(0,len(pixels),3))
    white=b'\xff\xff\xff';background=bytes((17,34,68))
    expected_white=rectangle_width*rectangle_height
    if colors!=Counter({white:expected_white,background:width*height-expected_white}):
        raise ValueError('Pixels do not match original rectangle/clear commands')
    left=(width-rectangle_width)//2;top=(height-rectangle_height)//2
    for y in range(height):
        row=pixels[y*width*3:(y+1)*width*3]
        expected=(background*left+white*rectangle_width+background*(width-left-rectangle_width)
                  if top<=y<top+rectangle_height else background*width)
        if row!=expected:raise ValueError('Geometry placement differs from independent bounds')
    return dict(sha256=hashlib.sha256(data).hexdigest(),width=width,height=height,
                foreground_pixels=expected_white,background_rgb=[17,34,68],foreground_rgb=[255,255,255],
                original_geometry_function='0x1c4654',fixture_input_rectangle=[rectangle_width,rectangle_height])


def run_original_slice(hmi,output,rootfs,*,width=800,mode='normal'):
    hmi,output,rootfs=map(Path,(hmi,output,rootfs))
    data=hmi.read_bytes()
    if hashlib.sha256(data).hexdigest()!=HMI_SHA256:raise ValueError('Canonical HMI SHA-256 mismatch')
    if width not in (800,480) or mode not in ('normal','alloc-fail','invalid-callback'):
        raise ValueError('Unsupported bounded fixture mode')
    if output.exists() or output.is_symlink():raise FileExistsError(output)
    if output.resolve().is_relative_to(REPO.resolve()):raise ValueError('Generated firmware/runtime files must remain outside Git checkout')
    if not (rootfs/'usr/bin/qemu-arm-static').is_file():raise FileNotFoundError('ARMEL rootfs/qemu missing')
    output.mkdir(parents=True);results=output/'results';results.mkdir()
    staged=output/'verified-hmi.elf';staged.write_bytes(data);staged.chmod(0o444)
    binary=output/'original-render-armel'
    library=rootfs/'usr/lib/arm-linux-gnueabi'
    command=['arm-linux-gnueabi-gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread',
             '-no-pie','-Wl,-Ttext-segment=0x10000000','-rdynamic','-I'+str(REPO/'src'),
             '-I'+str(rootfs/'usr/include'),'-L'+str(library),'-Wl,-rpath-link,'+str(library),
             str(REPO/'src/ca01_gui_compat.c'),str(REPO/'src/ca01_hmi_ipc.c'),
             str(REPO/'tools/display_audit/egl_window_to_pbuffer_bridge_v2.c'),
             str(REPO/'tools/ca01_original_render.c'),'-lEGL','-lGLESv1_CM','-ldl','-o',str(binary)]
    build=subprocess.run(command,capture_output=True,text=True,timeout=60)
    (output/'build.log').write_text(build.stdout+build.stderr)
    if build.returncode:raise RuntimeError('ARM render build failed: '+build.stderr)
    sandbox=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--cap-drop','ALL',
       '--ro-bind',str(rootfs.resolve()),'/','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
       '--ro-bind',str(binary.resolve()),'/tmp/renderer','--ro-bind',str(staged.resolve()),'/tmp/hmi.elf',
       '--dir','/tmp/output','--bind',str(results.resolve()),'/tmp/output',
       '--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/tmp','--setenv','LC_ALL','C',
       '--setenv','XDG_RUNTIME_DIR','/tmp','--setenv','EGL_PLATFORM','surfaceless',
       '--setenv','LIBGL_ALWAYS_SOFTWARE','1','--setenv','GALLIUM_DRIVER','softpipe',
       '--setenv','CA01_EGL_BRIDGE','1','--chdir','/tmp',
       '/usr/bin/qemu-arm-static','-B','0x100000000','/tmp/renderer','/tmp/hmi.elf',str(width),mode]
    completed=subprocess.run(sandbox,capture_output=True,text=True,timeout=35)
    (output/'stdout.log').write_text(completed.stdout);(output/'stderr.log').write_text(completed.stderr)
    log=completed.stdout;captures=[]
    for frame in range(3):
        p=results/f'frame-{frame}.ppm'
        if p.exists():captures.append(validate_capture(p.read_bytes(),width,480,width//2+frame*2,160+frame*2))
    buffers=re.findall(r'BUFFER \d handle=(\d+) token=(\d+) bytes=\d+',log)
    complete=completed.returncode==0 and 'SLICE_COMPLETE' in log
    if complete and len(captures)!=3:raise ValueError('Successful slice omitted required captures')
    from ca01_hmi_startup import ElfImage
    image=ElfImage(data)
    checked_entries={hex(address):hashlib.sha256(image.read(address,32)).hexdigest()
       for address in (0x2bb08,0x2b66c,0x1e092c,0x1c4654,0x1e0640,0x2b9fc,0x1602c)}
    report=dict(unchanged_original_entry_sha256=checked_entries,
       fixture_original_entries=re.findall(r'EVENT ORIGINAL_ENTRY (0x[0-9a-f]+)',log),
       scope='Original ARM graphics slice with fixture-supplied state and modeled services; not full Toyota application startup.',
       hmi_sha256=HMI_SHA256,slice_completed=complete,exit_code=completed.returncode,
       graphics_ready='EVENT GRAPHICS_READY' in log,allocation_failure_observed='injected_allocation_failure' in log,original_gl_draw_calls=log.count('ORIGINAL_GL glDrawArrays'),
       original_gl_clear_calls=log.count('ORIGINAL_GL glClear return='),original_frame_submissions=log.count('VRAM_UPDATE'),
       frames=len(captures),captures=captures,buffer_handles=[int(a) for a,b in buffers],descriptor_tokens=[int(b) for a,b in buffers],
       full_application_started=False,factory_menu_rendered=False,
       original_functions=['0x16094','0x2b66c','0x2bb08','0x2b170','0x1e092c','0x1c4654','0x1e0640','0x2b9fc','0x1602c'],
       substitutions=['Private imports bound to real ARMEL Mesa or explicit display model; other imports terminate',
           'Vehicle-profile selector0x2a548 selects one measured original config record',
           'Graphics-state block, projection, current white color and rectangle dimensions are fixture inputs',
           'Display descriptors use modeled handles and distinct memory tokens, no physical-address claim',
           'Initial system/task/parent startup barriers are outside this bounded rendering slice'],
       error='' if complete else completed.stderr[-2000:])
    if hashlib.sha256(staged.read_bytes()).hexdigest()!=HMI_SHA256 or hashlib.sha256(hmi.read_bytes()).hexdigest()!=HMI_SHA256:raise ValueError('Original bytes changed')
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hmi',type=Path,default=BASE/'ca01-updater-independent-20261022/06-PROC_HMI')
    p.add_argument('--rootfs',type=Path,default=BASE/'gui-emulation/armel-rootfs')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--width',type=int,choices=(800,480),default=800)
    p.add_argument('--mode',choices=('normal','alloc-fail','invalid-callback'),default='normal')
    a=p.parse_args();r=run_original_slice(a.hmi,a.output,a.rootfs,width=a.width,mode=a.mode)
    print(json.dumps(r,indent=2))
    raise SystemExit(0 if r['slice_completed'] else 2)

if __name__=='__main__':main()
