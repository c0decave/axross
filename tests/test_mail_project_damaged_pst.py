"""One damaged .pst / .ost costs its broken messages and folders, not the
whole Mail Project import.

Review 4 (features/extensions): a zlib.error while reading a folder of an
.ost (core/pst.py folders()) and an IndexError in a message's table
(message() -> table()) escaped the readers: the import stopped, the
messages after it - and the next files - were never imported, and neither
the import log row nor index.csv was written.

The two files are the review's fuzz finds: the test fixtures with the
bytes the fuzzer changed.
"""

from __future__ import annotations

import gzip
import sqlite3
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import pst as PST  # noqa: E402
from core.mail_project import MailProject  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mail"

#: (fixture, [(offset, new byte)]) - the review's crash 143 (.ost) and 159 (.pst)
DAMAGED = {
    "folder-inflate.ost": ("example-2013.ost", [
        (8616496, 180), (8006956, 197), (4344421, 98), (12494192, 32), (6815880, 168),
        (2374977, 40), (14949110, 194), (13195606, 212), (16663121, 13), (3617457, 236),
        (15508125, 223), (13921489, 242), (5913340, 33), (14758502, 203), (16484290, 69),
        (319132, 118), (6719100, 205), (1361906, 150), (11078051, 198), (15431496, 60)]),
    "message-table.pst": ("dist-list.pst", [
        (213618, 123), (63287, 110), (21769, 192), (96524, 199), (142334, 170), (79117, 185),
        (87774, 114), (184313, 201), (161778, 255), (166982, 96), (85046, 200), (4749, 0),
        (91932, 53), (128908, 232), (131497, 180)]),
}

GOOD = b"From: a@b.example\r\nSubject: fine\r\nMessage-ID: <fine@b.example>\r\n\r\nx\r\n"


def _damaged(tmp_path: Path, name: str) -> Path:
    fixture, patches = DAMAGED[name]
    data = bytearray(gzip.decompress((FIXTURES / f"{fixture}.gz").read_bytes()))
    for offset, value in patches:
        data[offset] = value
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return path


def _logged(project: MailProject) -> int:
    return project._db.execute("select count(*) from imports").fetchone()[0]


@pytest.mark.parametrize("name", sorted(DAMAGED))
def test_happy_a_damaged_file_does_not_end_the_import(tmp_path, name):
    bad = _damaged(tmp_path, name)
    good = tmp_path / "good.eml"
    good.write_bytes(GOOD)
    project = MailProject(tmp_path / "proj")
    try:
        result = project.import_paths([str(bad), str(good)])
        assert result.errors, "the damage is reported"
        assert any(str(bad) in e for e in result.errors)
        assert result.added >= 2                       # the readable messages and good.eml
        subjects = {row["subject"] for row in project.messages(limit=1000)}
        assert "fine" in subjects
        assert _logged(project) == 1
        assert (tmp_path / "proj" / "index.csv").exists()
    finally:
        project.close()


def test_sad_every_message_failing_is_counted_and_logged(tmp_path, monkeypatch):
    def broken(self, *a, **k):
        raise IndexError("index out of range")

    monkeypatch.setattr(PST.PstFile, "table", broken)
    monkeypatch.setattr(PST.PstFile, "message", broken)
    path = tmp_path / "dist-list.pst"
    path.write_bytes(gzip.decompress((FIXTURES / "dist-list.pst.gz").read_bytes()))
    project = MailProject(tmp_path / "proj")
    try:
        result = project.import_paths([str(path)])
        assert result.added == 0 and len(result.errors) >= 1
        assert all("IndexError" in e for e in result.errors)
        assert _logged(project) == 1
        db = sqlite3.connect(str(tmp_path / "proj" / "index.sqlite"))
        try:
            (errors,) = db.execute("select errors from imports").fetchone()
        finally:
            db.close()
        assert "IndexError" in errors
    finally:
        project.close()


def test_edge_a_folder_that_does_not_inflate_is_named_and_skipped(tmp_path, monkeypatch):
    real = PST.PstFile.properties

    def props(self, data_bid, sub_bid=0):
        if any(n.data == data_bid and nid & 0x1F == PST.NID_TYPE_NORMAL_FOLDER
               for nid, n in self.nodes.items()):
            raise zlib.error("Error -3 while decompressing data")
        return real(self, data_bid, sub_bid)

    monkeypatch.setattr(PST.PstFile, "properties", props)
    path = tmp_path / "dist-list.pst"
    path.write_bytes(gzip.decompress((FIXTURES / "dist-list.pst.gz").read_bytes()))
    project = MailProject(tmp_path / "proj")
    try:
        result = project.import_paths([str(path)])
        assert any("folder" in e and "decompressing" in e for e in result.errors)
        assert result.added >= 1              # the messages still come in, without folder names
        assert _logged(project) == 1
    finally:
        project.close()


def test_edge_an_error_outside_the_readers_still_writes_the_log(tmp_path, monkeypatch):
    project = MailProject(tmp_path / "proj")

    def boom(*a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(project, "_import_pst", boom)
    path = tmp_path / "x.pst"
    path.write_bytes(b"!BDN" + b"\0" * 600)
    good = tmp_path / "good.eml"
    good.write_bytes(GOOD)
    try:
        result = project.import_paths([str(path), str(good)])
        assert result.added == 1 and any("RuntimeError" in e for e in result.errors)
        assert _logged(project) == 1 and (tmp_path / "proj" / "index.csv").exists()
    finally:
        project.close()
