#!/usr/bin/env python3
"""Validate an *originally ARM-rendered synthetic diagnostic* PPM output.

This is NOT a Toyota factory GUI screenshot. No recovered ELF is launched.
"""
import argparse
import hashlib
import json
from pathlib import Path

WIDTH, HEIGHT = 800, 480
HEADER = b"P6\n800 480\n255\n"
SAMPLES = {
    (200, 120): (0, 0, 255),
    (600, 120): (255, 255, 255),
    (200, 360): (255, 0, 0),
    (600, 360): (0, 255, 0),
}


def validate(data: bytes):
    if not data.startswith(HEADER):
        raise ValueError("Unexpected PPM header or framebuffer dimensions")
    expected_size = len(HEADER) + WIDTH * HEIGHT * 3
    if len(data) != expected_size:
        raise ValueError(f"Expected {expected_size} PPM bytes, received {len(data)}")
    pixels = data[len(HEADER):]
    results = {}
    for (x, y), expected in SAMPLES.items():
        i = 3 * (y * WIDTH + x)
        found = tuple(pixels[i:i + 3])
        if found != expected:
            raise ValueError(f"Pixel {x},{y}: expected {expected}, found {found}")
        results[f"{x},{y}"] = list(found)
    return {"diagnostic_not_toyota_gui": True,
            "frame": {"width": WIDTH, "height": HEIGHT,
                      "source_bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "samples": results},
            "verified_pixel_samples": len(results)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("--report", type=Path)
    p.add_argument("--png", type=Path, help="Optional preview image; needs Pillow")
    args = p.parse_args()
    blob = args.input.read_bytes()
    result = validate(blob)
    if args.report:
        with args.report.open("x", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
            f.write("\n")
    if args.png:
        from PIL import Image
        if args.png.exists():
            raise FileExistsError(args.png)
        Image.frombytes("RGB", (WIDTH, HEIGHT), blob[len(HEADER):]).save(args.png)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
