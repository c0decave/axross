"""The Mail Project commits its index in batches and asks DNS once per name.

Review 4 (features/extensions): an import committed SQLite once per
message (2000 messages: 219 s) and asked the same SPF / DKIM / DMARC
records for every message of a domain - with a resolver that does not
answer, ten mails of one domain waited ten times for its timeout.
"""

from __future__ import annotations

import mailbox
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mail_project as CMP  # noqa: E402
from core.mail_project import MailProject  # noqa: E402


class CountingDb:
    """The project's connection, counting commits."""

    def __init__(self, db):
        self._db, self.commits = db, 0

    def commit(self):
        self.commits += 1
        return self._db.commit()

    def __getattr__(self, name):
        return getattr(self._db, name)


def _mbox(path: Path, n: int) -> Path:
    box = mailbox.mbox(str(path))
    for i in range(n):
        box.add(f"From: a{i}@x.example\nTo: b@y.example\nSubject: msg {i}\n\nbody {i}\n".encode())
    box.flush()
    box.close()
    return path


def _rows_on_disk(folder: Path) -> int:
    db = sqlite3.connect(str(folder / "index.sqlite"))
    try:
        return db.execute("select count(*) from messages").fetchone()[0]
    finally:
        db.close()


def test_happy_an_import_commits_in_batches_and_at_its_end(tmp_path, monkeypatch):
    monkeypatch.setattr(CMP, "COMMIT_SECONDS", 3600.0)
    monkeypatch.setattr(CMP, "COMMIT_EVERY", 50)
    project = MailProject(tmp_path / "proj")
    project._db = counting = CountingDb(project._db)
    try:
        result = project.import_paths([str(_mbox(tmp_path / "big.mbox", 120))])
        assert result.added == 120
        assert counting.commits <= 4             # 50, 100, the log row - not 120
        assert _rows_on_disk(tmp_path / "proj") == 120   # all committed at the end
    finally:
        project.close()


def test_sad_a_cancelled_import_still_commits_what_it_added(tmp_path, monkeypatch):
    monkeypatch.setattr(CMP, "COMMIT_SECONDS", 3600.0)
    project = MailProject(tmp_path / "proj")
    seen = []
    try:
        result = project.import_paths([str(_mbox(tmp_path / "big.mbox", 30))],
                                      cancel=lambda: len(seen.append(1) or seen) > 10)
        assert 0 < result.added < 30
        assert _rows_on_disk(tmp_path / "proj") == result.added
        assert (tmp_path / "proj" / "index.csv").exists()
    finally:
        project.close()


def test_edge_a_single_add_outside_an_import_is_committed_at_once(tmp_path):
    project = MailProject(tmp_path / "proj")
    try:
        project.add_bytes(b"From: a@x.example\nSubject: one\n\nx\n", "manual")
        assert _rows_on_disk(tmp_path / "proj") == 1
    finally:
        project.close()


def test_happy_dns_is_asked_once_per_name_in_an_import(tmp_path):
    calls = []

    def unreachable(name, rtype):
        calls.append((name, rtype))
        raise OSError("The DNS operation timed out.")

    src = tmp_path / "src"
    src.mkdir()
    for i in range(10):
        (src / f"{i}.eml").write_bytes(
            ("Received: from mail.sender.example (mail.sender.example [198.51.100.7]) by mx.corp.example;"
             f" Mon, 2 Nov 2026 10:00:0{i} +0000\r\n"
             "DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=s1; h=from; bh=x; b=y\r\n"
             f"From: n@sender.example\r\nTo: me@corp.example\r\nSubject: s{i}\r\n"
             "Return-Path: <b@sender.example>\r\n\r\nbody\r\n").encode())
    project = MailProject(tmp_path / "proj", dns=unreachable)
    try:
        result = project.import_paths([str(src)])
        assert result.added == 10
        assert calls and len(calls) == len(set(calls))       # each (name, type) once
        assert project._dns_cache == {}                      # not kept after the import
    finally:
        project.close()


@pytest.mark.parametrize("answers", [["v=spf1 -all"], []])
def test_edge_a_cached_answer_is_a_copy(tmp_path, answers):
    project = MailProject(tmp_path / "proj")
    try:
        with project._importing():
            lookup = project._dns_lookup(lambda name, rtype: list(answers))
            first = lookup("Example.org.", "TXT")
            first.append("changed")
            assert lookup("example.org", "TXT") == answers
    finally:
        project.close()
