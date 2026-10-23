#!/usr/bin/env python3
"""Verify 3 actual GLES1 frames and produce PNG previews; synthetic, not Toyota."""
import hashlib
import json
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parent
summary = {"description": "Synthetic ARMEL GLES1 pbuffer test frames, NOT factory Toyota GUI",
           "profiles": []}
for width, height in [(800, 480), (480, 480)]:
    directory = ROOT / "results" / f"{width}x{height}"
    digests = []
    for i in range(3):
        direct = directory / f"direct-{i:02}.ppm"
        bridged = directory / f"bridged-{i:02}.ppm"
        content = direct.read_bytes()
        assert content == bridged.read_bytes(), f"Bridge differs at {width}x{height} frame {i}"
        digest = hashlib.sha256(content).hexdigest()
        digests.append(digest)
        with Image.open(bridged) as im:
            im.load()
            assert im.size == (width, height), f"Wrong size: {im.size}"
            assert im.mode == "RGB", f"Wrong mode: {im.mode}"
            assert im.getpixel((0, 0)) != im.getpixel((width // 2, height // 2)), (
                "No evidence of drawn geometry in image"
            )
            if i == 0:
                im.save(directory / "synthetic-frame00.png", format="PNG")
    assert len(set(digests)) == 3, "All frame hashes should be distinct"
    summary["profiles"].append({
        "width": width, "height": height,
        "pixel_exact_bridge": True,
        "frames_sha256": digests,
        "preview": f"results/{width}x{height}/synthetic-frame00.png"
    })
(ROOT / "results" / "verification.json").write_text(
    json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print("PASS verified frame dimensions, non-flat rendering, distinct frames and bridge parity")
