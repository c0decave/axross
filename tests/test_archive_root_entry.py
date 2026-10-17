"""An archive packed from inside its folder extracts.

Measured before: ``tar -C dir -czf x.tgz .`` stores the folder itself as
``./``; tarfile names that member ``.``, and the zip-slip check refused it
as an "empty/root path", so the whole archive was reported unsafe and
nothing was extracted. Only a root DIRECTORY entry is skipped; a file
that claims to be the root, and every escape, are still refused.
"""

from __future__ import annotations

import io
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import archive as A  # noqa: E402


def _tar(path: Path, entries: list[tuple[str, bytes | None]]) -> None:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
            else:
                info.size = len(data)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(data))


class RootEntryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def test_happy_a_tar_packed_from_inside_its_folder_extracts(self) -> None:
        src = self.tmp / "proj"
        (src / "src").mkdir(parents=True)
        (src / "README").write_bytes(b"hi\n")
        (src / "src" / "a.py").write_bytes(b"x\n")
        arc = self.tmp / "proj-dot.tar.gz"
        with tarfile.open(arc, "w:gz") as tf:
            tf.add(src, arcname=".")  # what `tar -C proj -czf x.tgz .` stores
        self.assertIn(".", [m.name for m in tarfile.open(arc).getmembers()])
        self.assertEqual(A.extract(str(arc), str(self.out)), 2)
        self.assertEqual((self.out / "README").read_bytes(), b"hi\n")
        self.assertEqual((self.out / "src" / "a.py").read_bytes(), b"x\n")

    def test_edge_dot_slash_spellings_of_the_root_are_skipped(self) -> None:
        arc = self.tmp / "dots.tar.gz"
        _tar(arc, [("./", None), ("./.", None), ("./f.txt", b"f")])
        self.assertEqual(A.extract(str(arc), str(self.out)), 1)
        self.assertEqual((self.out / "f.txt").read_bytes(), b"f")

    def test_edge_a_zip_with_a_root_folder_entry_extracts(self) -> None:
        arc = self.tmp / "dot.zip"
        with zipfile.ZipFile(arc, "w") as zf:
            zf.writestr("./", b"")
            zf.writestr("./f.txt", b"z")
        self.assertEqual(A.extract(str(arc), str(self.out)), 1)
        self.assertEqual((self.out / "f.txt").read_bytes(), b"z")

    def test_edge_partial_extraction_of_a_dot_rooted_tar(self) -> None:
        arc = self.tmp / "dots.tar.gz"
        _tar(arc, [(".", None), ("./d", None), ("./d/f.txt", b"f"), ("./g.txt", b"g")])
        A.extract_members(str(arc), str(self.out), ["./d"])
        self.assertEqual((self.out / "d" / "f.txt").read_bytes(), b"f")
        self.assertFalse((self.out / "g.txt").exists())

    def test_sad_a_file_entry_named_like_the_root_is_still_refused(self) -> None:
        arc = self.tmp / "dotfile.tar.gz"
        _tar(arc, [(".", b"not a folder")])
        with self.assertRaises(A.UnsafeArchive):
            A.extract(str(arc), str(self.out))

    def test_sad_an_escaping_folder_entry_is_still_refused(self) -> None:
        arc = self.tmp / "up.tar.gz"
        _tar(arc, [("./..", None), ("./f.txt", b"f")])
        with self.assertRaises(A.UnsafeArchive):
            A.extract(str(arc), str(self.out))
        self.assertFalse((self.out / "f.txt").exists())

    def test_sad_an_absolute_root_folder_entry_is_still_refused(self) -> None:
        arc = self.tmp / "abs.tar.gz"
        _tar(arc, [("/", None), ("f.txt", b"f")])
        with self.assertRaises(A.UnsafeArchive):
            A.extract(str(arc), str(self.out))


if __name__ == "__main__":
    unittest.main()
