"""Google Drive: a delete, rename or overwrite acts on the file the
session saw, or on nothing.

stat() and open_read() take the id from the path cache the last listing
filled; remove() asked the server afresh. After "report.pdf" was renamed
on the web and a new file uploaded as "report.pdf", a move read and
size-checked the OLD file (cached id A) and then deleted the NEW one
(fresh id B) with files.delete - which skips the Drive trash: one file
copied, another one gone for good. rename() and open_write() resolved
fresh the same way. Now each refuses (ESTALE) when the fresh id is not
the one the session listed; the fresh id stays cached, so the folder's
next listing and a retry act on what the path names now.
"""

from __future__ import annotations

import errno
import io

import pytest

pytest.importorskip("googleapiclient")

from core import gdrive_client as G  # noqa: E402
from core.gdrive_client import GDriveSession  # noqa: E402
from tests.test_gdrive_duplicate_names import _Drive, _file  # noqa: E402


@pytest.fixture
def renamed_on_the_web(monkeypatch):
    """The session listed /report.pdf as A; on the web, A was renamed
    and B uploaded as report.pdf."""
    drive = _Drive([_file("A", "report-old.pdf"), _file("B", "report.pdf")])
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root", "/report.pdf": "A"}
    monkeypatch.setattr(G, "_download_spooled", lambda req: io.BytesIO(b"x"))
    monkeypatch.setattr(G, "MediaIoBaseUpload", lambda *a, **k: None, raising=False)
    return s, drive


def test_sad_remove_refuses_another_file_than_the_one_listed(renamed_on_the_web):
    s, drive = renamed_on_the_web
    with pytest.raises(OSError) as info:
        s.remove("/report.pdf")
    assert info.value.errno == errno.ESTALE
    assert drive.deleted == []
    assert {f["id"] for f in drive.store} == {"A", "B"}


def test_sad_rename_refuses_another_file_than_the_one_listed(renamed_on_the_web):
    s, drive = renamed_on_the_web
    with pytest.raises(OSError) as info:
        s.rename("/report.pdf", "/moved.pdf")
    assert info.value.errno == errno.ESTALE
    assert drive.updated == []


def test_sad_overwrite_refuses_another_file_than_the_one_listed(renamed_on_the_web):
    s, drive = renamed_on_the_web
    with pytest.raises(OSError) as info:
        s.open_write("/report.pdf")
    assert info.value.errno == errno.ESTALE
    assert drive.updated == [] and drive.created == []


def test_edge_after_the_refusal_the_path_names_the_new_file(renamed_on_the_web):
    s, drive = renamed_on_the_web
    with pytest.raises(OSError):
        s.remove("/report.pdf")
    assert s.stat("/report.pdf").size == 1  # served from the refreshed cache
    assert s._path_cache["/report.pdf"] == "B"
    s.remove("/report.pdf")  # the user saw the refusal; now it is B
    assert drive.deleted == ["B"]


def test_happy_remove_of_the_listed_file_goes_ahead():
    drive = _Drive([_file("A", "report.pdf")])
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root", "/report.pdf": "A"}
    s.remove("/report.pdf")
    assert drive.deleted == ["A"]


def test_happy_remove_of_a_path_never_listed_resolves_fresh():
    drive = _Drive([_file("A", "report.pdf")])
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root"}
    s.remove("/report.pdf")
    assert drive.deleted == ["A"]


def test_edge_overwrite_of_a_listed_file_renamed_away_creates_a_new_one(monkeypatch):
    """Nothing under the name any more: the write creates; the listed
    file (renamed away) is not touched."""
    drive = _Drive([_file("A", "report-old.pdf")])
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root", "/report.pdf": "A"}
    monkeypatch.setattr(G, "MediaIoBaseUpload", lambda *a, **k: None, raising=False)
    with s.open_write("/report.pdf") as fh:
        fh.write(b"new")
    assert drive.updated == []
    assert len(drive.created) == 1
