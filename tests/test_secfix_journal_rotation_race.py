"""The operation journal's rotation is safe across processes.

Measured before (pre-release security review): the GUI and an MCP server
append to one journal. Each checks its size and, above the limit, renames
it to ``.1``. Two that both saw it too big both renamed: the second moved
the first one's fresh journal over ``.1`` and the whole rotated history was
gone. The size is now decided again under an ``flock`` of the journal's
folder, so only one rotates.

The journal was also opened through a symlink at its path, and that file
(not the journal) given mode 0600 by path. It is opened with O_NOFOLLOW
now and the mode set on the descriptor.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import operation_journal as OJ  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX journal semantics")


@pytest.fixture
def small_limit(monkeypatch):
    monkeypatch.setattr(OJ, "MAX_JOURNAL_BYTES", 4096)
    yield
    OJ._FILE.close()


def test_sad_a_second_writer_with_a_stale_size_keeps_the_rotated_history(
        tmp_path, small_limit, monkeypatch):
    journal = tmp_path / "operations.jsonl"
    history = b'{"operation_id": "old"}\n' * 1000
    journal.write_bytes(history)
    stale = os.stat(journal)  # what the second process saw before the first rotated

    first = OJ._JournalFile()
    first.write(str(journal), b'{"operation_id": "first"}\n')
    first.close()
    assert (tmp_path / "operations.jsonl.1").read_bytes() == history

    real_stat = os.stat
    handed = []

    def stat(path, *args, **kwargs):
        if os.fspath(path) == str(journal) and not handed:
            handed.append(path)
            return stale
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat)
    second = OJ._JournalFile()
    try:
        second.write(str(journal), b'{"operation_id": "second"}\n')
    finally:
        second.close()
        monkeypatch.setattr(os, "stat", real_stat)
    assert handed  # the stale size was seen
    assert (tmp_path / "operations.jsonl.1").read_bytes() == history
    assert journal.read_bytes() == b'{"operation_id": "first"}\n{"operation_id": "second"}\n'
    # The lock is the folder's: no lock file beside the journal.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["operations.jsonl",
                                                          "operations.jsonl.1"]


def test_sad_a_symlink_at_the_journal_path_is_not_written_through(tmp_path, small_limit):
    target = tmp_path / "bashrc"
    target.write_bytes(b"# mine\n")
    target.chmod(0o644)
    journal = tmp_path / "operations.jsonl"
    journal.symlink_to(target)
    writer = OJ._JournalFile()
    try:
        with pytest.raises(OSError):
            writer.write(str(journal), b'{"operation_id": "x"}\n')
    finally:
        writer.close()
    assert target.read_bytes() == b"# mine\n"
    assert target.stat().st_mode & 0o777 == 0o644


def test_edge_a_widened_mode_is_tightened_on_the_descriptor(tmp_path, small_limit, monkeypatch):
    """Never chmod by path: the path may name another file by then."""
    journal = tmp_path / "operations.jsonl"
    by_path = []
    writer = OJ._JournalFile()
    try:
        writer.write(str(journal), b"a\n")
        journal.chmod(0o644)
        monkeypatch.setattr(os, "chmod", lambda *a, **k: by_path.append(a))
        writer.write(str(journal), b"b\n")
        writer.close()
        writer.write(str(journal), b"c\n")  # opened anew
    finally:
        writer.close()
    assert by_path == []
    assert journal.stat().st_mode & 0o777 == 0o600
    assert journal.read_bytes() == b"a\nb\nc\n"
