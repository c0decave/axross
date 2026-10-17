"""The operation journal keeps the real paths undo acts on.

Before: every journal event went through ``redact`` as a whole, and
``redact_text`` rewrote file names that look like credentials:
"Basic Course" became "Basic <redacted>", "Signature: scan.pdf" became
"Signature=<redacted>". Undo of a trash then restored the file under the
rewritten name, in a folder that did not exist, or next to the original.

Now the path fields (``source``, ``dest`` and ``path`` / ``output`` /
``temp`` in the details) keep their real value - the journal is the
user's own file, mode 0600, and it must name the files it can put back -
except for credentials in a URL-shaped path. Every other field is still
redacted, and the log line about the event stays fully redacted.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import operation_journal as OJ  # noqa: E402
from core import trash  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.undo import apply_undo, pick_undoable, undoable  # noqa: E402


@pytest.fixture
def journal(tmp_path, monkeypatch):
    path = tmp_path / "journal.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(path))
    return path


def _trash_and_undo(path: Path) -> str:
    fs = LocalFS()
    trash.trash(fs, str(path))
    assert not path.exists()
    plan = pick_undoable(undoable(OJ.read_recent(200)), [fs.name])
    return apply_undo(plan, fs)


@pytest.mark.parametrize("name", ["Signature: scan.pdf", "token=abc.txt"])
def test_happy_undo_restores_a_trashed_file_under_its_real_name(journal, tmp_path, name):
    victim = tmp_path / "work" / name
    victim.parent.mkdir()
    victim.write_bytes(b"pdf")
    where = _trash_and_undo(victim)
    assert where == str(victim)
    assert victim.read_bytes() == b"pdf"
    assert sorted(os.listdir(victim.parent)) == [name]


def test_happy_a_folder_that_looks_like_an_auth_header_survives(journal, tmp_path):
    victim = tmp_path / "Basic Course" / "lesson1.txt"
    victim.parent.mkdir()
    victim.write_text("lesson one\n")
    assert _trash_and_undo(victim) == str(victim)
    assert victim.read_text() == "lesson one\n"


def test_sad_credentials_in_a_url_shaped_path_are_still_removed(journal):
    OJ.append_event(
        OJ.JournalEvent(
            operation_id="op1",
            phase="start",
            operation="copy",
            source="s3://user:pass@example/bucket?sig=secret",
            dest="https://u:hunter2@dav.example/x",
        )
    )
    raw = journal.read_text(encoding="utf-8")
    assert "pass@" not in raw and "secret" not in raw and "hunter2" not in raw
    row = json.loads(raw)
    assert row["source"].startswith("s3://<redacted>@example/bucket")


def test_sad_other_fields_are_still_redacted(journal):
    OJ.append_event(
        OJ.JournalEvent(
            operation_id="op1",
            phase="finish",
            operation="copy",
            status="error",
            source="/data/Basic Course",
            error="Authorization: Bearer abc.def",
            details={"token": "t0k3n", "note": "Basic dXNlcjpwYXNz", "path": "/data/Basic Course"},
        )
    )
    row = json.loads(journal.read_text(encoding="utf-8"))
    assert row["source"] == "/data/Basic Course"
    assert row["details"]["path"] == "/data/Basic Course"
    assert "abc.def" not in row["error"]
    assert row["details"]["token"] == "<redacted>"
    assert "dXNlcjpwYXNz" not in row["details"]["note"]


def test_edge_metadata_item_paths_keep_their_names(journal):
    OJ.finish_operation(
        "op2",
        "metadata_remove",
        status="done",
        source="/pics/Signature: a.jpg",
        details={
            "mode": "copy",
            "items": [{"path": "/pics/Signature: a.jpg", "sha256": "ab", "output": "/o/x: y"}],
        },
    )
    row = json.loads(journal.read_text(encoding="utf-8"))
    item = row["details"]["items"][0]
    assert item["path"] == "/pics/Signature: a.jpg"
    assert item["output"] == "/o/x: y"


def test_edge_the_journal_stays_private_and_the_log_line_redacted(journal, caplog):
    import logging

    with caplog.at_level(logging.INFO):
        OJ.append_event(
            OJ.JournalEvent(
                operation_id="op3",
                phase="start",
                operation="delete",
                source="/srv/Basic Course",
            )
        )
    assert journal.stat().st_mode & 0o777 == 0o600
    assert "Basic Course" not in caplog.text
