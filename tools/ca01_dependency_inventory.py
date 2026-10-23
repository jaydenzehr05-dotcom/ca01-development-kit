#!/usr/bin/env python3
"""Hash-verified static ELF inventory; never load or execute recovered binaries.

Requires pyelftools. Candidate providers are name/architecture observations,
not simulated loader resolution: symbol versions, search paths, interposition,
dlopen and device availability are not proven by this report.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
from elftools.elf.elffile import ELFFile


def inspect_record(record):
    path = Path(record['local_path'])
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != record['sha256']:
        raise ValueError(f'SHA-256 mismatch: {path}')
    if len(data) != record['size']:
        raise ValueError(f'Size mismatch: {path}')
    result = {key: record[key] for key in ('archive_path', 'local_path', 'size', 'sha256')}
    result['component'] = record.get('component')
    result['elf'] = None
    result['observed_device_paths'] = [dict(offset=m.start(), text=m.group().decode('ascii'))
        for m in re.finditer(rb'/dev/[A-Za-z0-9_./%+-]+', data)]
    if not data.startswith(b'\x7fELF'):
        return result
    elf = ELFFile(io.BytesIO(data))
    info = dict(bits=elf.elfclass, little_endian=elf.little_endian,
        machine=elf['e_machine'], type=elf['e_type'], entry=hex(elf['e_entry']),
        soname=None, interpreter=None, needed=[], imports=[], exports=[],
        symbol_version_requirements=[])
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_INTERP':
            info['interpreter'] = segment.get_interp_name()
    dynamic = elf.get_section_by_name('.dynamic')
    if dynamic:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED': info['needed'].append(tag.needed)
            elif tag.entry.d_tag == 'DT_SONAME': info['soname'] = tag.soname
    symbols = elf.get_section_by_name('.dynsym')
    if symbols:
        for symbol in symbols.iter_symbols():
            if not symbol.name: continue
            binding = symbol['st_info']['bind']
            if symbol['st_shndx'] == 'SHN_UNDEF':
                info['imports'].append(dict(name=symbol.name, binding=binding,
                    type=symbol['st_info']['type']))
            elif binding in ('STB_GLOBAL','STB_WEAK') and symbol['st_other']['visibility'] in ('STV_DEFAULT','STV_PROTECTED'):
                info['exports'].append(symbol.name)
    version = elf.get_section_by_name('.gnu.version_r')
    if version:
        for need, auxiliaries in version.iter_versions():
            info['symbol_version_requirements'].append(dict(library=need.name,
                versions=sorted(aux.name for aux in auxiliaries)))
    info['imports'].sort(key=lambda s: (s['name'],s['binding']))
    info['exports'] = sorted(set(info['exports']))
    result['elf'] = info
    return result


def compatible(a,b):
    return all(a[k] == b[k] for k in ('machine','bits','little_endian'))


def link_inventory(records):
    """Keep ambiguous candidates and missing weak imports explicit."""
    files = []
    missing = set()
    for record in records:
        row = dict(record)
        info = row['elf']
        if info is not None:
            candidates = [r for r in records if r['elf'] is not None and compatible(info,r['elf'])]
            libs = {name: sorted(set(r['archive_path'] for r in candidates
                if name in (Path(r['archive_path']).name,r['elf'].get('soname')))) for name in info['needed']}
            missing.update(name for name, matches in libs.items() if not matches)
            providers = {s['name']: sorted(set(r['archive_path'] for r in candidates
                if s['name'] in r['elf']['exports'])) for s in info['imports']}
            row.update(library_candidates=libs, symbol_candidates=providers,
                no_observed_provider_strong=sorted({s['name'] for s in info['imports'] if s['binding'] != 'STB_WEAK' and not providers[s['name']]}),
                no_observed_provider_weak=sorted({s['name'] for s in info['imports'] if s['binding'] == 'STB_WEAK' and not providers[s['name']]}))
        files.append(row)
    return dict(scope='Static, hash-verified recovered set only; missing means absent from this set, not absent from the radio.',
        caveat='Library and symbol candidates are name/architecture matches, not runtime resolution. Symbol versions, search order, interposition, dlopen and hardware remain unverified.',
        file_count=len(files), elf_count=sum(r['elf'] is not None for r in files),
        missing_libraries=sorted(missing), files=files)


def write_report(report, path):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(report,stream,indent=2)
        stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest',type=Path,help='JSON with files containing local_path/archive_path/size/sha256')
    parser.add_argument('--output',type=Path,help='New output file; existing files are never overwritten')
    args=parser.parse_args()
    manifest=json.loads(args.manifest.read_text())
    report=link_inventory([inspect_record(r) for r in manifest['files']])
    if args.output: write_report(report,args.output)
    else: print(json.dumps(report,indent=2))

if __name__=='__main__': main()
