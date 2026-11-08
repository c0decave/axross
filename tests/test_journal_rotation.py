"""The operation journal rotates instead of growing without bound.

It is appended to for every transfer (three events per file) and was never
shortened: 100 MB after a few benchmark copies, while only its last 4 MB
are ever read (read_recent). Above MAX_JOURNAL_BYTES it becomes
``operations.jsonl.1`` and a new file starts; read_recent reads the
rotated file too when the new one holds fewer events than asked for.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import operation_journal as OJ  # noqa: E402


@pytest.fixture
def small_limit(monkeypatch):
    monkeypatch.setattr(OJ, "MAX_JOURNAL_BYTES", 4096)
    yield
    OJ._FILE.close()


def _event(i: int) -> OJ.JournalEvent:
    return OJ.JournalEvent(operation_id=f"op-{i}", phase="worker_start", operation="copy",
                           source=f"/src/file-{i}", dest=f"/dst/file-{i}")


def test_sad_the_journal_does_not_grow_past_its_limit(tmp_path, small_limit):
    journal = tmp_path / "operations.jsonl"
    for i in range(400):
        OJ.append_event(_event(i), journal_path=journal)
    assert journal.stat().st_size <= 4096 + 1024
    assert (tmp_path / "operations.jsonl.1").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["operations.jsonl", "operations.jsonl.1"]


def test_happy_recent_events_span_the_rotation(tmp_path, small_limit):
    journal = tmp_path / "operations.jsonl"
    for i in range(400):
        OJ.append_event(_event(i), journal_path=journal)
    current = len(journal.read_text("utf-8").splitlines())
    want = current + 5  # more than the new file holds: the rest from .1
    recent = OJ.read_recent(limit=want, journal_path=journal)
    ids = [e["operation_id"] for e in recent]
    assert ids == [f"op-{i}" for i in range(400 - want, 400)]  # in order, nothing lost


def test_edge_a_big_journal_from_before_is_rotated_on_first_write(tmp_path, small_limit):
    journal = tmp_path / "operations.jsonl"
    journal.write_bytes(b'{"operation_id": "old"}\n' * 1000)
    OJ._FILE.close()
    OJ.append_event(_event(1), journal_path=journal)
    assert journal.stat().st_size < 1024
    assert (tmp_path / "operations.jsonl.1").stat().st_size > 4096
    assert oct(journal.stat().st_mode & 0o777) == oct(0o600)


def test_edge_rotation_also_works_when_files_are_opened_per_event(tmp_path, small_limit, monkeypatch):
    monkeypatch.setattr(OJ._JournalFile, "KEEP_OPEN", False)  # the Windows way
    journal = tmp_path / "operations.jsonl"
    for i in range(400):
        OJ.append_event(_event(i), journal_path=journal)
    assert journal.stat().st_size <= 4096 + 1024
    assert os.path.exists(str(journal) + ".1")
