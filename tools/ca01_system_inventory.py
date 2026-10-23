#!/usr/bin/env python3
"""Read-only inventory of CA01 update components and vendor source archives."""
import argparse
import collections
import hashlib
import json
import math
import tarfile
from pathlib import Path

CATEGORIES = {
    "board": ("board-ftenbb.c", "rma1_13PF", "ftenbb_config.h"),
    "input": ("ftenbb_asic_remocon", "ftenbb_asic_adc"),
    "display": ("sh_mobile_lcdc", "lcdc", "sh_mobile_fb"),
    "audio": ("ftenbb_asic_fsi", "fsi-ak7756", "sound/soc/ftenbb"),
    "camera": ("ftenbb_ceu",),
    "storage": ("ftenbb_asic_sdhi", "ftenbb_asic_mmc", "ftenbb_vuc"),
    "hardware_controller": ("ftenbb_asic-core", "ftenbb_asic_gpio", "ftenbb_asic-intc"),
    "serial_i2c": ("ftenbb_asic_scifa", "i2c-ftenbb_asic"),
    "boot": ("ftensign.c", "u-boot.lds"),
}
CAVEAT = ("File presence does not establish that a driver is enabled in the CA01 "
          "production kernel or that its userspace interface is known.")

def entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values())

def component(path):
    data = path.read_bytes()
    return {
        "name": path.name, "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy_bits_per_byte": round(entropy(data), 4),
        "entropy_64k": [round(entropy(data[i:i + 65536]), 4)
                        for i in range(0, len(data), 65536)],
        "first_16_bytes_hex": data[:16].hex()
    }

def archive(path):
    matches = {key: [] for key in CATEGORIES}
    count = 0
    with tarfile.open(path, mode="r:gz") as t:
        for member in t:
            if not member.isfile():
                continue
            count += 1
            name = member.name
            for key, patterns in CATEGORIES.items():
                if any(pattern.lower() in name.lower() for pattern in patterns):
                    matches[key].append(name)
    return {"archive": path.name, "source_file_entries": count,
            "hardware_candidates": matches}

def build_report(components, archives):
    return {
        "scope": "static, read-only inventory; NOT a boot or compatibility test",
        "caveat": CAVEAT,
        "components": [component(p) for p in sorted(components.glob("*.bin"))],
        "archives": [archive(p) for p in archives],
        "unresolved": [
            "Exact CA01 production kernel configuration",
            "Installed root filesystem and proprietary userspace binaries",
            "Vehicle/audio/camera protocol and active device-node verification",
            "Boot authentication, installation and reliable recovery method"
        ]
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--components", required=True, type=Path)
    p.add_argument("--archive", type=Path, action="append", default=[])
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    if not args.components.is_dir():
        p.error("components directory does not exist")
    for archive_path in args.archive:
        if not archive_path.is_file():
            p.error(f"archive does not exist: {archive_path}")
    report = build_report(args.components, args.archive)
    result = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result)
    else:
        print(result, end="")

if __name__ == "__main__":
    main()
