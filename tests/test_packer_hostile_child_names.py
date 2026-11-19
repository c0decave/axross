"""A server-supplied name below a packed folder ("../../.bashrc", "a/b",
a control character, the NUL-marked unusable row of a listing) never
becomes an archive member name - whoever extracts it with a naive tool
would get a file outside the folder. It is left out and named in
``unusable``; the rest is packed."""
from __future__ import annotations

import zipfile

from core import packer as PK
from core.local_fs import LocalFS
from models.file_item import FileItem


class _HostileListing(LocalFS):
    """The folder 'd' lists names a server made up, beside its real file."""

    def __init__(self, folder: str) -> None:
        super().__init__()
        self._folder = folder

    def list_dir(self, path):
        items = super().list_dir(path)
        if path.rstrip("/").endswith("/d"):
            items += [FileItem(name=n, size=1) for n in
                      ("../../.bashrc", "a/b", "bad\x01name", "\x00../x")]
        return items


def test_sad_hostile_child_names_are_left_out(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "real.txt").write_text("real")
    result = PK.pack(_HostileListing(str(tmp_path)), str(tmp_path), ["d"], "out",
                     PK.PackOptions(fmt="zip"))
    with zipfile.ZipFile(result.path) as zf:
        assert sorted(zf.namelist()) == ["d/", "d/real.txt"]
    assert len(result.unusable) == 4 and result.skipped == []
    assert all(s.startswith("d/") for s in result.unusable)
