"""Packing into a folder that cannot be written fails as a PackError.

``pack()`` made its staging folder and, for a local folder, its
temporary archive next to the result before the try that cleans up and
turns errors into ``PackError``. A folder that cannot be written (a
read-only mount, no permission) raised a bare OSError past every caller
that handles PackError (the agent's pack tool), and the staging folder
stayed behind in the temp directory.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import packer as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def test_sad_an_unwritable_folder_is_a_pack_error_and_leaves_no_staging(tmp_path,
                                                                        monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    (work / "f.txt").write_text("hello")
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))

    def refuse(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied", str(work))

    monkeypatch.setattr(P.tempfile, "mkstemp", refuse)
    with pytest.raises(P.PackError):
        P.pack(LocalFS(), str(work), ["f.txt"], "bundle", P.PackOptions("zip"))
    assert list(temp.iterdir()) == []
    assert sorted(p.name for p in work.iterdir()) == ["f.txt"]
