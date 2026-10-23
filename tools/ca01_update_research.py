#!/usr/bin/env python3
"""Read-only, confidence-labelled inspection of observed CA01 update components.

Does not install, flash, verify signatures, recover keys, or infer encryption
from entropy. Raw field names deliberately avoid unproven vendor semantics.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import sys
import zlib

from ca01_inspect import FormatError, inspect_bytes


def sha(data):
    return hashlib.sha256(data).hexdigest()


def entropy(data):
    if not data:
        return 0.0
    size = len(data)
    return round(-sum((n / size) * math.log2(n / size) for n in Counter(data).values()), 6)


def probe_zlib(data, wbits=15, max_output=8 * 1024 * 1024):
    """Bounded stream test; EOF plus consumed bytes is evidence, not magic alone."""
    decoder = zlib.decompressobj(wbits)
    try:
        result = decoder.decompress(data, max_output + 1)
    except zlib.error:
        return {'status': 'rejected'}
    if len(result) > max_output or decoder.unconsumed_tail:
        return {'status': 'output_limit', 'max_output': max_output}
    if not decoder.eof:
        return {'status': 'incomplete_stream', 'produced': len(result)}
    return {'status': 'complete_stream', 'consumed': len(data) - len(decoder.unused_data),
            'trailing_bytes': len(decoder.unused_data), 'output_size': len(result),
            'output_sha256': sha(result), 'output_first_16_hex': result[:16].hex(),
            'interpretation': 'Codec accepted a stream; output identity and package linkage still need validation.'}


def analyze_component(data, base_offset=0):
    if len(data) < 12:
        raise FormatError('Component shorter than observed 12-byte common prefix')
    kind, unknown16, flag, trailing = struct.unpack_from('<HHII', data)
    prefix = len(data) - trailing
    if not trailing or not 12 <= prefix <= 4096:
        raise FormatError('Invalid observed trailing-length field')
    payload = data[prefix:]
    record_width = 12 if flag == 0 else 256 if flag == 1 else None
    shape = {'candidate_record_count': kind, 'candidate_record_width': record_width,
             'matches_prefix_size': record_width is not None and prefix == 12 + kind * record_width,
             'confidence': 'strongly_inferred',
             'meaning': 'Size relation fits count and mode-dependent records; actual operation semantics unproven.'}
    descriptors = []
    if flag == 0 and shape['matches_prefix_size']:
        for pos in range(12, prefix, 12):
            descriptors.append({'relative_offset': pos, 'absolute_offset': base_offset + pos,
                'raw_u32_le': list(struct.unpack_from('<III', data, pos)),
                'confidence': 'confirmed_binary', 'meaning': 'Three integers observed; source/length/destination roles are candidates only.'})
    trailer = None
    if flag == 1 and len(payload) >= 264:
        crc, size = struct.unpack_from('<II', payload, len(payload) - 264)
        trailer = {'relative_offset': len(payload) - 264,
            'absolute_offset': base_offset + len(data) - 264,
            'candidate_gzip_crc32': crc, 'candidate_gzip_isize': size,
            'isize_multiple_of_10240': size % 10240 == 0,
            'following_opaque_size': 256, 'following_opaque_sha256': sha(payload[-256:]),
            'confidence': 'strongly_inferred',
            'meaning': 'Gzip-shaped footer before 256 opaque bytes; CRC not verified without complete decoding.'}
    paths = []
    # Only report fixed 256-byte areas that actually contain a plausible path.
    for offset in range(12, prefix - 255, 256):
        region = data[offset:offset + 256]
        leading = 1 if region[0] == 0 else 0
        text_bytes = region[leading:].split(b'\0', 1)[0]
        if text_bytes.startswith((b'./', b'/')) and all(32 <= c <= 126 for c in text_bytes):
            paths.append({'region_relative_offset': offset, 'region_absolute_offset': base_offset + offset,
                'region_size': 256, 'region_sha256': sha(region),
                'leading_marker_hex': region[:leading].hex(), 'text': text_bytes.decode('ascii'),
                'text_absolute_offset': base_offset + offset + leading,
                'confidence': 'confirmed_binary', 'meaning': 'Path bytes observed; operation, ownership and installation semantics unknown.'})
    windows = [{'offset': start, 'absolute_offset': base_offset + prefix + start,
                'size': len(payload[start:start + 4096]),
                'entropy_bits_per_byte': entropy(payload[start:start + 4096])}
               for start in range(0, len(payload), 4096)]
    boundary = None
    if len(payload) > 64000:
        boundary = {'offset': 64000, 'absolute_offset': base_offset + prefix + 64000,
            'preceding_64_hex': payload[63936:64000].hex(), 'following_64_hex': payload[64000:64064].hex(),
            'leading_region_sha256': sha(payload[:64000]), 'remainder_sha256': sha(payload[64000:]),
            'leading_entropy': entropy(payload[:64000]), 'remainder_entropy': entropy(payload[64000:]),
            'confidence': 'confirmed_binary',
            'interpretation': 'Fixed comparison boundary, not an identified decoder or authenticated code entry.'}
    markers = {}
    for name, magic in [('elf', b'\x7fELF'), ('uimage', bytes.fromhex('27051956')),
                        ('gzip', b'\x1f\x8b\x08'), ('xz', b'\xfd7zXZ\0'),
                        ('zip', b'PK\x03\x04'), ('squashfs_le', b'hsqs')]:
        hits = [m.start() for m in re.finditer(re.escape(magic), payload)]
        markers[name] = {'count': len(hits), 'first_32_relative_offsets': hits[:32],
                         'validation': 'unverified_marker_only'}
    return {'size': len(data), 'absolute_offset': base_offset, 'end_offset': base_offset + len(data),
        'sha256': sha(data), 'wrapper': {'common_prefix_hex': data[:12].hex(),
            'raw_u16_at_0': kind, 'raw_u16_at_2': unknown16, 'raw_u32_at_4': flag,
            'trailing_length_u32_at_8': trailing, 'observed_prefix_size': prefix,
            'semantics': 'unknown count/control semantics; trailing length fits this specimen, not a vendor format specification',
            'record_shape': shape, 'raw_descriptors': descriptors,
            'confidence': 'confirmed_binary'},
        'path_regions': paths, 'payload': {'relative_offset': prefix,
            'absolute_offset': base_offset + prefix, 'size': len(payload), 'sha256': sha(payload),
            'gzip_trailer_candidate': trailer, 'first_32_hex': payload[:32].hex(), 'windows': windows, 'boundary_64000': boundary,
            'entropy_limit': 'High entropy does not establish encryption; compressed, transformed and other data can appear similar.',
            'magic_markers': markers,
            'start_stream_probes': {name: probe_zlib(payload, bits) for name, bits in
                                    [('zlib', 15), ('gzip', 31), ('raw_deflate', -15)]}},
        'recovery_status': 'not_decoded'}


def metadata_fields(data, header_size):
    fields = []
    def word(pos, name):
        value = struct.unpack_from('>I', data, pos)[0]
        fields.append({'offset': pos, 'size': 4, 'encoding': 'uint32_be', 'name': name,
                       'value': value, 'raw_hex': data[pos:pos + 4].hex(), 'confidence': 'confirmed_binary'})
        return value
    def string(pos, name):
        length = word(pos, name + '_length')
        end = pos + 4 + length
        fields.append({'offset': pos + 4, 'size': length, 'encoding': 'ascii', 'name': name,
                       'value': data[pos + 4:end].decode('ascii'), 'confidence': 'confirmed_binary'})
        return end
    word(0, 'metadata_size'); word(4, 'file_size')
    pos = string(8, 'model')
    word(pos, 'directory_count_raw'); word(pos + 4, 'directory_offset'); pos += 8
    for name in ['name_key', 'name_value', 'data_key']:
        pos = string(pos, name)
    for name in ['data_count_raw', 'version_raw', 'reserved_raw', 'payload_header_offset', 'data_entry_count_raw']:
        word(pos, name); pos += 4
    pos = string(pos, 'package_tag')
    count = word(pos, 'component_count'); pos += 4
    pointers = [word(pos + i * 4, f'component_{i + 1}_metadata_offset') for i in range(count)]
    end = pos + count * 4
    for i, pointer in enumerate(pointers):
        cursor = pointer
        for name in ['key', 'label', 'update_key']:
            cursor = string(cursor, f'component_{i + 1}_{name}')
        word(cursor, f'component_{i + 1}_update_value_raw')
        end = string(cursor + 4, f'component_{i + 1}_version')
    fields.append({'offset': header_size, 'size': 4, 'encoding': 'bytes', 'name': 'payload_marker_raw',
                   'raw_hex': data[header_size:header_size + 4].hex(), 'confidence': 'confirmed_binary'})
    for i in range(count):
        for j, label in enumerate(['size', 'relative_offset']):
            pos = header_size + 4 + i * 8 + j * 4
            fields.append({'offset': pos, 'size': 4, 'encoding': 'uint32_le',
                'name': f'component_{i + 1}_{label}', 'value': struct.unpack_from('<I', data, pos)[0],
                'confidence': 'confirmed_binary'})
    return {'fields': fields, 'opaque_trailer': {'absolute_offset': end, 'size': header_size - end,
            'sha256': sha(data[end:header_size]), 'meaning': 'Signature role identified in recovered PROC_REPRO FUN_00019f58; cryptographic verification not performed'},
            'semantics_limit': 'Positions, encodings and values confirmed from this binary; vendor behavior for unknown fields not recovered.'}


def analyze_package(data):
    layout = inspect_bytes(data)
    parts = []
    for component in layout['components']:
        offset, size = component['offset'], component['size']
        part = analyze_component(data[offset:offset + size], offset)
        part.update({key: component[key] for key in ['index', 'name', 'version', 'filename']})
        parts.append(part)
    return {'schema': 'ca01-update-research-v1', 'input': {key: layout[key] for key in
            ['model', 'package_tag', 'sha256', 'file_size', 'matches_reviewed_CA01_1127', 'header_size', 'payload_base']},
        'confidence_levels': ['confirmed_source', 'confirmed_binary', 'strongly_inferred', 'unknown'],
        'metadata': metadata_fields(data, layout['header_size']),
        'security_selectors': {'rsa': data[layout['header_size'] + 2], 'aes': data[layout['header_size'] + 3],
            'rsa_offset': layout['header_size'] + 2, 'aes_offset': layout['header_size'] + 3,
            'confidence': 'confirmed_binary',
            'basis': 'Recovered PROC_REPRO FUN_00019f58; selector IDs are not actual key bytes or decoded AES mode.'},
        'components': parts,
        'limitations': ['No signature verification or installation performed.',
            'No component decoder identified by this inspector.',
            'A codec/magic match alone does not establish recovered executables or correct vendor processing.']}


def write_report(report, path):
    with Path(path).open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware', type=Path)
    parser.add_argument('--components', type=Path, help='Optional byte-exact extracted directory to verify')
    parser.add_argument('--output', type=Path, help='New JSON report file; existing files are never overwritten')
    args = parser.parse_args()
    try:
        data = args.firmware.read_bytes()
        report = analyze_package(data)
        if args.components:
            for part in report['components']:
                extracted = (args.components / part['filename']).read_bytes()
                if len(extracted) != part['size'] or sha(extracted) != part['sha256']:
                    raise FormatError('Extracted component differs: ' + part['filename'])
            report['extracted_components_verified'] = True
        if args.output:
            write_report(report, args.output)
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, FormatError) as exc:
        print('Research inspection failed: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
