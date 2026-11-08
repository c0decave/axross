"""Google Drive: exists() and copy() do not trust a cached parent id.

The session had listed ``/proj`` (id P_OLD). On the web that folder was
renamed to ``proj-old`` and a new ``/proj`` holding ``report.txt`` took
its name. exists("/proj/report.txt") walked the cached P_OLD and said
False - the no-clobber check of the transfer worker - and open_write(),
which resolves fresh, then overwrote the real report.txt. copy() put its
copy into P_OLD, the folder now called proj-old. Both ask the server now.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("googleapiclient")

from core.gdrive_client import GDriveSession  # noqa: E402
from tests.test_gdrive_duplicate_names import _Drive, _file  # noqa: E402

FOLDER = "application/vnd.google-apps.folder"


@pytest.fixture
def renamed_on_the_web():
    drive = _Drive(
        [
            _file("P_OLD", "proj-old", mime=FOLDER),
            _file("P_NEW", "proj", mime=FOLDER),
            _file("R", "report.txt", parent="P_NEW", mime="text/plain"),
            _file("S", "src.txt", mime="text/plain"),
        ]
    )
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root", "/proj": "P_OLD"}  # listed before the rename
    return s, drive


def test_sad_exists_sees_the_file_in_the_folder_that_has_the_name_now(renamed_on_the_web):
    s, _drive = renamed_on_the_web
    assert s.exists("/proj/report.txt") is True


def test_sad_copy_lands_in_the_folder_that_has_the_name_now(renamed_on_the_web):
    s, drive = renamed_on_the_web
    s.copy("/src.txt", "/proj/src.txt")
    assert [f["parent"] for f in drive.store if f["id"] in drive.created] == ["P_NEW"]
