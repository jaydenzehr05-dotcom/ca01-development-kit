"""Unit tests for independent, synthetic CA01 ARM render-frame validation."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from ca01_gui_pixel_validation import HEADER, HEIGHT, SAMPLES, WIDTH, validate


class Ca01GuiPixelValidationTests(unittest.TestCase):
    def make_frame(self):
        pixels = bytearray(WIDTH * HEIGHT * 3)
        for (x, y), rgb in SAMPLES.items():
            off = 3 * (y * WIDTH + x)
            pixels[off:off + 3] = bytes(rgb)
        return HEADER + bytes(pixels)

    def test_correctly_framed_800x480_rgba_diagnostic(self):
        result = validate(self.make_frame())
        self.assertEqual(result["verified_pixel_samples"], 4)
        self.assertTrue(result["diagnostic_not_toyota_gui"])
        self.assertEqual(result["frame"]["source_bytes"], len(self.make_frame()))

    def test_rejects_truncated_and_wrong_header(self):
        frame = self.make_frame()
        with self.assertRaisesRegex(ValueError, "header"):
            validate(b"not-a-ppm" + frame)
        with self.assertRaisesRegex(ValueError, "Expected"):
            validate(frame[:-3])

    def test_rejects_wrong_pixel(self):
        frame = bytearray(self.make_frame())
        x, y = 200, 120
        frame[len(HEADER) + 3 * (y * WIDTH + x)] = 255
        with self.assertRaisesRegex(ValueError, "Pixel"):
            validate(bytes(frame))


if __name__ == "__main__":
    unittest.main()
