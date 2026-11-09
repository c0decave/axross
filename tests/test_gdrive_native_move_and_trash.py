"""Moving a Google Doc out of Drive; removing one; the fake's page tokens.

Round 6 found (repro cloud/gd_export_copy.py): a move of ``Thesis.docx``
(a Google Doc, listed with its export's extension) to a local folder
copied the lossy .docx export and then deleted the original with
``files.delete`` - for good, past Drive's own trash. Now the move is
refused before anything is copied (copy it instead), and removing a
Google-native file or a folder puts it into Drive's trash.

tests/fake_gdrive.py also handed page 3 of a listing the token of page 2
(the client's repeated-token guard then gave up) - fixed in the fake.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("googleapiclient")
import fake_gdrive  # noqa: E402

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

DOC = "application/vnd.google-apps.document"


@pytest.fixture
def drive():
    d = fake_gdrive.FakeDrive()
    d.items["D1"] = {"id": "D1", "name": "Thesis", "mimeType": DOC, "parents": ["root"]}
    d.items["B1"] = {
        "id": "B1", "name": "notes.txt", "mimeType": "text/plain", "parents": ["root"],
        "data": b"plain notes\n",
    }
    return d


def _job(s, src: str, dst: str, *, move: bool) -> TW.TransferJob:
    st = s.stat(src)
    job = TW.TransferJob(
        source_path=src, dest_path=dst, filename=os.path.basename(dst),
        total_bytes=st.size, source_backend=s, dest_backend=LocalFS(),
        use_temp_file=True, move=move,
    )
    TW.TransferWorker()._process_job(job)
    return job


def test_sad_moving_a_google_doc_out_of_drive_is_refused_before_copying(drive, tmp_path):
    s = fake_gdrive.make_session(drive)
    dst = tmp_path / "Thesis.docx"
    job = _job(s, "/Thesis.docx", str(dst), move=True)
    assert job.status == TW.TransferStatus.ERROR  # was DONE, original deleted
    assert "Copy it instead" in job.error_message
    assert not dst.exists()  # refused before the copy
    assert "D1" in drive.items and not drive.items["D1"].get("trashed")
    assert s.exists("/Thesis.docx")


def test_happy_copying_a_google_doc_out_still_works(drive, tmp_path):
    s = fake_gdrive.make_session(drive)
    dst = tmp_path / "Thesis.docx"
    job = _job(s, "/Thesis.docx", str(dst), move=False)
    assert job.status == TW.TransferStatus.DONE, job.error_message
    assert dst.read_bytes().startswith(b"export of Thesis")


def test_happy_moving_a_plain_file_out_still_moves_it(drive, tmp_path):
    s = fake_gdrive.make_session(drive)
    dst = tmp_path / "notes.txt"
    job = _job(s, "/notes.txt", str(dst), move=True)
    assert job.status == TW.TransferStatus.DONE, job.error_message
    assert dst.read_bytes() == b"plain notes\n"
    assert "B1" not in drive.items  # a byte-identical copy exists: deleted


def test_edge_removing_a_google_doc_puts_it_into_drives_trash(drive):
    s = fake_gdrive.make_session(drive)
    s.remove("/Thesis.docx")
    assert drive.items["D1"]["trashed"] is True  # was gone for good (files.delete)
    assert not s.exists("/Thesis.docx")
    assert "Thesis.docx" not in [i.name for i in s.list_dir("/")]


def test_edge_removing_a_folder_puts_it_into_drives_trash(drive):
    drive.items["F1"] = {
        "id": "F1", "name": "docs", "mimeType": fake_gdrive.FOLDER, "parents": ["root"]
    }
    drive.items["D2"] = {"id": "D2", "name": "Plan", "mimeType": DOC, "parents": ["F1"]}
    s = fake_gdrive.make_session(drive)
    s.remove("/docs", recursive=True)
    assert drive.items["F1"]["trashed"] is True
    assert "D2" in drive.items  # inside the trashed folder, restorable with it
    assert not s.exists("/docs")


def test_edge_a_move_inside_drive_is_not_refused(drive):
    s = fake_gdrive.make_session(drive)
    s.refuse_move_out("/Thesis.docx", s)  # a rename: the Doc stays a Doc


def test_edge_the_fake_hands_out_a_new_page_token_per_page():
    d = fake_gdrive.FakeDrive()
    for i in range(5):
        d.items[f"X{i}"] = {"id": f"X{i}", "name": f"f{i}", "mimeType": "text/plain",
                            "parents": ["root"], "data": b""}
    page = d._list("'root' in parents and trashed = false", 2, None)
    tokens, names = [], [f["name"] for f in page["files"]]
    while page.get("nextPageToken"):
        tokens.append(page["nextPageToken"])
        page = d._list("", 2, tokens[-1])
        names += [f["name"] for f in page["files"]]
    assert len(tokens) == len(set(tokens)) == 2  # was ["t0", "t0"]
    assert sorted(names) == [f"f{i}" for i in range(5)]
