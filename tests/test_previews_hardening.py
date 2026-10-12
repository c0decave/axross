"""Pillow fallback: no Ghostscript-backed formats, bounded decode memory."""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

from core import previews


@unittest.skipIf(Image is None, "Pillow not installed")
class PillowFallbackHardeningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()

    def _write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_eps_is_not_opened(self) -> None:
        path = self._write(
            "x.png", b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\nshowpage\n"
        )
        with mock.patch("subprocess.Popen") as popen, mock.patch("subprocess.run") as run:
            with self.assertRaises(previews.PreviewDecodeFailed):
                previews._decode_with_pillow(path, 64)
        popen.assert_not_called()
        run.assert_not_called()

    def test_decode_memory_is_bounded(self) -> None:
        path = os.path.join(self.dir, "big.png")
        Image.new("1", (12000, 12000)).save(path)  # tiny on disk, 576 MiB as RGBA
        with self.assertRaises(previews.PreviewTooLarge):
            previews._decode_with_pillow(path, 64)

    def test_ordinary_tiff_still_decodes(self) -> None:
        path = os.path.join(self.dir, "ok.tif")
        Image.new("RGB", (40, 30), (200, 10, 10)).save(path)
        data = previews._decode_with_pillow(path, 64)
        self.assertTrue(data.startswith(b"\x89PNG"))

    def test_missing_file(self) -> None:
        with self.assertRaises(previews.PreviewDecodeFailed):
            previews._decode_with_pillow(os.path.join(self.dir, "nope.tif"), 64)


if __name__ == "__main__":
    unittest.main()
