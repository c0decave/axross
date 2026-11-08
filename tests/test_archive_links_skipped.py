"""Link members of tar and ZIP archives are left out and reported.

Before: one symlink member made a tarball an UnsafeArchive - nothing of
it could be extracted. A ZIP symlink (Info-ZIP ``zip -y``: Unix mode
S_IFLNK, data = the target path) was written as a regular 0755 file that
held the link's target path. Now both are skipped: nothing is written for
them, nothing is followed, and ``ExtractResult.skipped_links`` names them
(the result is still the int count of files written).
"""

from __future__ import annotations

import io
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import archive as A  # noqa: E402


def _tar(path: Path, *, hard: bool = False) -> None:
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("pkg/a.txt")
        info.size = 3
        tf.addfile(info, io.BytesIO(b"abc"))
        link = tarfile.TarInfo("pkg/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../etc/passwd"
        tf.addfile(link)
        if hard:
            h = tarfile.TarInfo("pkg/hard")
            h.type = tarfile.LNKTYPE
            h.linkname = "pkg/a.txt"
            tf.addfile(h)


def _zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("pkg/a.txt", b"abc")
        info = zipfile.ZipInfo("pkg/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, b"a.txt")


def _files(root: Path) -> dict[str, str]:
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = Path(dirpath, f)
            out[str(p.relative_to(root))] = "link" if p.is_symlink() else p.read_text()
    return out


def test_sad_a_tar_symlink_no_longer_refuses_the_whole_archive(tmp_path) -> None:
    """One symlink member refused every member of the tarball."""
    src = tmp_path / "x.tgz"
    _tar(src, hard=True)
    result = A.extract(str(src), str(tmp_path / "out"))
    assert result == 1 and isinstance(result, int)
    assert result.skipped_links == ["pkg/link", "pkg/hard"]
    assert _files(tmp_path / "out") == {"pkg/a.txt": "abc"}


def test_sad_a_zip_symlink_is_not_written_as_a_file(tmp_path) -> None:
    """A ZIP symlink came out as a regular 0755 file holding "a.txt"."""
    src = tmp_path / "z.zip"
    _zip(src)
    result = A.extract(str(src), str(tmp_path / "out"))
    assert result == 1 and result.skipped_links == ["pkg/link"]
    assert _files(tmp_path / "out") == {"pkg/a.txt": "abc"}


def test_edge_a_selected_zip_link_is_left_out_of_a_partial_extract(tmp_path) -> None:
    """extract_members wrote the selected ZIP symlink as a file as well;
    a tar folder selection with a link in it was refused."""
    src = tmp_path / "z.zip"
    _zip(src)
    result = A.extract_members(str(src), str(tmp_path / "out"), ["pkg"])
    assert result == 1 and result.skipped_links == ["pkg/link"]
    assert _files(tmp_path / "out") == {"pkg/a.txt": "abc"}
    tsrc = tmp_path / "x.tgz"
    _tar(tsrc)
    result = A.extract_members(str(tsrc), str(tmp_path / "out2"), ["pkg"])
    assert result == 1 and result.skipped_links == ["pkg/link"]
    assert _files(tmp_path / "out2") == {"pkg/a.txt": "abc"}
