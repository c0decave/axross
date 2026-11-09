"""Google Drive: Docs, Sheets and Slides are read as their export, and a
request says it knows of shared drives.

Round 5 (repro_gdrive_native_docs.py): a Google-native file has no binary
content - files.get_media answers 403 fileNotDownloadable ("Use Export
with Docs Editors files"). core/gdrive_client.py had no export path and
mapped that 403 to EACCES: every Doc of a folder copy failed with
"Permission denied", which the user can do nothing about. No request
carried supportsAllDrives, so items of shared drives were not answered.

Now a Doc is listed as "<name>.docx" (a Sheet .xlsx, Slides .pptx, a
drawing .pdf), read through files.export_media, and refused for writes;
a native item without an export (a Form) is refused with that reason.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("googleapiclient")

import fake_gdrive  # noqa: E402

DOC = "application/vnd.google-apps.document"
SHEET = "application/vnd.google-apps.spreadsheet"
FORM = "application/vnd.google-apps.form"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@pytest.fixture
def drive():
    d = fake_gdrive.FakeDrive()
    d.items["D1"] = {"id": "D1", "name": "Budget 2026", "mimeType": SHEET, "parents": ["root"],
                     "exports": {XLSX: b"PK-xlsx"}}
    d.items["D2"] = {"id": "D2", "name": "Thesis", "mimeType": DOC, "parents": ["root"]}
    d.items["D3"] = {"id": "D3", "name": "Survey", "mimeType": FORM, "parents": ["root"]}
    d.items["F1"] = {"id": "F1", "name": "notes.txt", "mimeType": "text/plain",
                     "parents": ["root"], "data": b"hello"}
    return d


def test_happy_google_files_are_listed_and_read_as_their_export(drive):
    s = fake_gdrive.make_session(drive)
    listed = {i.name: i for i in s.list_dir("/")}
    assert set(listed) == {"Budget 2026.xlsx", "Thesis.docx", "Survey", "notes.txt"}
    assert listed["Budget 2026.xlsx"].size == 0
    assert listed["Budget 2026.xlsx"].permissions == 0o444
    assert s.open_read("/Budget 2026.xlsx").read() == b"PK-xlsx"
    assert drive.export_calls == [("D1", XLSX)]
    assert s.stat("/Thesis.docx").name == "Thesis.docx"
    # Found by name without the listing in the cache, too.
    s2 = fake_gdrive.make_session(drive)
    assert s2.open_read("/Thesis.docx").read().startswith(b"export of Thesis")
    assert s2.open_read("/notes.txt").read() == b"hello"


def test_sad_a_google_file_is_not_overwritten(drive):
    s = fake_gdrive.make_session(drive)
    s.list_dir("/")
    with pytest.raises(PermissionError) as err:
        s.open_write("/Thesis.docx")
    assert err.value.errno == errno.EPERM
    assert drive.items["D2"]["mimeType"] == DOC
    assert sum(1 for it in drive.items.values() if it["name"].startswith("Thesis")) == 1


def test_sad_an_item_without_an_export_is_no_permission_error(drive):
    s = fake_gdrive.make_session(drive)
    s.list_dir("/")
    with pytest.raises(OSError) as err:
        s.open_read("/Survey")
    assert not isinstance(err.value, PermissionError)
    assert err.value.errno == errno.EOPNOTSUPP
    assert "Form" in str(err.value)


def test_edge_an_export_over_googles_limit_says_so(drive):
    drive.export_limit = 3
    s = fake_gdrive.make_session(drive)
    with pytest.raises(OSError) as err:
        s.open_read("/Budget 2026.xlsx")
    assert err.value.errno == errno.EFBIG
    assert "10 MB" in str(err.value)


def test_edge_a_real_file_beside_a_doc_of_its_name_is_ambiguous(drive):
    drive.items["F2"] = {"id": "F2", "name": "Thesis.docx", "mimeType": "application/x-docx",
                         "parents": ["root"], "data": b"real"}
    drive.items["D4"] = {"id": "D4", "name": "Report.docx", "mimeType": DOC, "parents": ["root"]}
    s = fake_gdrive.make_session(drive)
    names = [i.name for i in s.list_dir("/")]
    assert "Report.docx" in names  # no "Report.docx.docx"
    with pytest.raises(OSError) as err:
        fake_gdrive.make_session(drive).open_read("/Thesis.docx")
    assert "at least 2" in str(err.value)


def test_edge_requests_support_shared_drives(drive):
    s = fake_gdrive.make_session(drive)
    s.list_dir("/")
    s.stat("/notes.txt")
    s.open_read("/notes.txt").read()
    seen = {name: kw for name, kw in drive.kwargs}
    assert seen["list"].get("supportsAllDrives") is True
    assert seen["list"].get("includeItemsFromAllDrives") is True
    assert seen["get"].get("supportsAllDrives") is True
    assert seen["get_media"].get("supportsAllDrives") is True
