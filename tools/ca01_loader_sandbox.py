#!/usr/bin/env python3
"""Trace dependencies of verified CA01 ARM files in a read-only, offline sandbox.

Only the ARM dynamic loader's LD_TRACE_LOADED_OBJECTS mode is enabled. This
is not a launcher for Toyota applications, flash tools, or a complete radio.
Original recovered files and firmware are never modified. Output must be new.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import signal
import struct
import subprocess

PROGRAMS = ('PROC_HMI', 'PROC_DISPLAY', 'PROC_REPRO')
LIB_PATH = '/opt/ftl/lib:/lib/arm-linux-gnueabi:/usr/lib/arm-linux-gnueabi'



def require_trace_interpreter(data):
    """Reject static/custom-loader ELF files before QEMU can execute their code."""
    phoff = struct.unpack_from('<I', data, 28)[0]
    entsize, count = struct.unpack_from('<HH', data, 42)
    if count == 0:
        raise ValueError('Trace targets require the standard ARMEL interpreter')
    if entsize != 32 or phoff < 52 or phoff + count * entsize > len(data):
        raise ValueError('Invalid ELF program header bounds')
    interpreters = []
    for index in range(count):
        fields = struct.unpack_from('<8I', data, phoff + index * entsize)
        if fields[0] != 3:  # PT_INTERP
            continue
        offset, size = fields[1], fields[4]
        if offset > len(data) or size > len(data) - offset:
            raise ValueError('Invalid ELF interpreter bounds')
        interpreters.append(data[offset:offset + size])
    if interpreters != [b'/lib/ld-linux.so.3\0']:
        raise ValueError('Trace targets require exactly the standard ARMEL interpreter')


def stage_verified_elfs(manifest_path, output):
    """Validate all inputs first, then create byte-identical disposable copies."""
    manifest_path, output = Path(manifest_path).resolve(), Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    records = json.loads(manifest_path.read_text())['files']
    checked, seen = [], set()
    for row in records:
        if not row.get('ELF'):
            continue
        if not row.get('header_checksum_valid') or not row.get('header_and_entire_contents_dictionary_independent'):
            raise ValueError('Only complete, provenance-validated recoveries are accepted')
        source = Path(row['local_path'])
        if source.is_symlink() or not source.resolve().is_relative_to(manifest_path.parent):
            raise ValueError('Source must be an ordinary file inside the manifest directory')
        rel = PurePosixPath(row['archive_path'].removeprefix('./'))
        if rel.is_absolute() or '..' in rel.parts or rel.parts[:2] != ('opt', 'ftl'):
            raise ValueError('Invalid original archive path')
        if str(rel) in seen:
            raise ValueError('Duplicate target path')
        seen.add(str(rel))
        if source.stat().st_size != row['size'] or source.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('Size mismatch or excessive input size')
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('SHA-256 mismatch')
        if len(data) < 52 or data[:6] != b'\x7fELF\x01\x01':
            raise ValueError('Expected ELF32 little-endian bytes')
        kind, machine = struct.unpack_from('<HH', data, 16)
        if machine != 40 or kind not in (2, 3):
            raise ValueError('Expected ARM ET_EXEC or ET_DYN')
        if kind == 2 or (rel.parent == PurePosixPath('opt/ftl/apl') and rel.name in PROGRAMS):
            require_trace_interpreter(data)
        checked.append((row, rel, kind, data))
    if not checked:
        raise ValueError('No validated ARM files in manifest')
    output.mkdir(parents=True)
    staged = []
    for row, rel, kind, data in checked:
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as f:
            f.write(data)
        # QEMU requires an execute bit on its main ELF. Originals stay untouched.
        target.chmod(0o555 if kind == 2 else 0o444)
        staged.append({'guest_path': '/' + str(rel), 'size': len(data),
                       'sha256': row['sha256'], 'elf_type': kind})
    return staged


def build_trace_command(rootfs, vendor, program):
    if program not in PROGRAMS:
        raise ValueError('Only approved dependency-trace targets are supported')
    rootfs, vendor = Path(rootfs).resolve(), Path(vendor).resolve()
    if rootfs == Path('/') or vendor == Path('/'):
        raise ValueError('Never expose the host filesystem root')
    return [
        '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--clearenv', '--cap-drop', 'ALL', '--ro-bind', str(rootfs), '/',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/opt',
        '--ro-bind', str(vendor / 'opt/ftl'), '/opt/ftl', '--setenv', 'PATH',
        '/usr/bin:/bin', '--setenv', 'LC_ALL', 'C', '--chdir', '/tmp',
        '/usr/bin/qemu-arm-static', '-B', '0x100000000',
        '-E', 'LD_TRACE_LOADED_OBJECTS=1', '-E', 'LD_LIBRARY_PATH=' + LIB_PATH,
        '/opt/ftl/apl/' + program,
    ]


def parse_trace(returncode, stdout, stderr):
    missing, resolved = set(), {}
    for line in stdout.splitlines():
        match = re.match(r'^\s*(\S+)\s+=>\s+(not found|/\S+)', line)
        if match:
            name, destination = match.groups()
            if destination == 'not found':
                missing.add(name)
            else:
                resolved[name] = destination
    inspected = returncode == 0 and bool(missing or resolved)
    # Zero exit in trace mode does NOT mean a program can run.
    return {'inspection_succeeded': inspected,
            'all_listed_dependencies_resolved': inspected and not missing and not stderr.strip(),
            'resolved_libraries': dict(sorted(resolved.items())),
            'missing_libraries': sorted(missing), 'application_started': False}


def _limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (15, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))


def run_trace(command, log_prefix):
    """Keep full logs outside the sandbox; bound CPU, output size and wall time."""
    out_path = Path(str(log_prefix) + '.stdout.txt')
    err_path = Path(str(log_prefix) + '.stderr.txt')
    timed_out = False
    with out_path.open('x') as out, err_path.open('x') as err:
        p = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                             start_new_session=True, preexec_fn=_limits)
        try:
            rc = p.wait(timeout=25)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(p.pid, signal.SIGKILL)
            rc = p.wait()
    stdout = out_path.read_text(errors='replace')
    stderr = err_path.read_text(errors='replace')
    return {'returncode': rc, 'timed_out': timed_out, 'command': command,
            **parse_trace(rc, stdout, stderr), 'stdout': stdout, 'stderr': stderr}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path, required=True)
    ap.add_argument('--rootfs', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--program', choices=PROGRAMS, action='append')
    args = ap.parse_args()
    rootfs = args.rootfs.resolve()
    if not (rootfs / 'usr/bin/qemu-arm-static').is_file():
        ap.error('Expected static QEMU inside this rootfs')
    if not (rootfs / 'lib/ld-linux.so.3').exists():
        ap.error('Expected ARMEL dynamic loader')
    if args.output.exists() or args.output.is_symlink():
        ap.error('Output directory must not exist')
    args.output.mkdir(parents=True)
    manifest_hash = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    vendor = args.output / 'vendor'
    staged = stage_verified_elfs(args.manifest, vendor)
    results = []
    for program in args.program or PROGRAMS:
        target = vendor / 'opt/ftl/apl' / program
        if not target.is_file():
            raise ValueError('Requested recovered program absent: ' + program)
        result = run_trace(build_trace_command(rootfs, vendor, program), args.output / program)
        result['program'] = program
        results.append(result)
        print(program, 'inspection:', result['inspection_succeeded'],
              'resolved:', len(result['resolved_libraries']),
              'missing:', len(result['missing_libraries']), flush=True)
    for row in staged:
        data = (vendor / row['guest_path'].lstrip('/')).read_bytes()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('Staged file changed during dependency trace')
    if hashlib.sha256(args.manifest.read_bytes()).hexdigest() != manifest_hash:
        raise ValueError('Recovery manifest changed during analysis')
    report = {'scope': 'Dynamic-loader tracing only; not a GUI or hardware boot',
              'manifest_sha256': manifest_hash, 'verified_elfs': len(staged),
              'staged_files': staged, 'rootfs': str(rootfs), 'runs': results,
              'all_inspections_succeeded': all(x['inspection_succeeded'] for x in results)}
    with (args.output / 'report.json').open('x') as f:
        json.dump(report, f, indent=2)
        f.write('\n')
    raise SystemExit(0 if report['all_inspections_succeeded'] else 1)

if __name__ == '__main__':
    main()
