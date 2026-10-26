"""Trail (time-lapse snapshots of a folder tree): what a user of
``axross.snapshot_now`` / ``start_trail`` / ``diff_snapshots`` sees.

README highlight 14. Before this file core/trail.py was covered by seven
tests in tests/test_multi_system.py (TrailTests) to 65 % of its branches
(39 of 60, docs/TEST_COVERAGE_MATRIX.md of 2026-10-26): the head hash, the
background runner, unreadable folders and files, the timeline and the
privacy of the database ran in no test.

Bug found while writing it: a folder that lists two entries of one name -
Google Drive allows that, see tests/test_gdrive_duplicate_names.py - made
every snapshot of the folder fail with ``sqlite3.IntegrityError`` (the
``files`` table's key is ``(snapshot_id, path)``), and a background trail
of it recorded nothing at all, only a log line per interval. Each entry is
now recorded; a repeated name gets ``  (duplicate N)`` appended, assigned
in a stable order so an unchanged folder diffs as unchanged.

Second finding: every call opened a database connection and never closed
it (``with sqlite3.connect()`` only ends the transaction), so trail.db
stayed open until the garbage collector ran - a ResourceWarning
"unclosed database" per call on Python 3.13 and later.
"""

from __future__ import annotations

import gc
import json
import os
import sqlite3
import time
import warnings
from contextlib import closing
from datetime import datetime

import pytest

from core import trail
from core.local_fs import LocalFS
from core.ram_fs import RamFsSession
from models.file_item import FileItem


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    path = tmp_path / "cfg" / "trail.db"
    monkeypatch.setattr(trail, "DB_FILE", path)
    yield path
    trail.stop_all_trails()


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "watched"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"alpha")
    (root / "sub" / "b.log").write_bytes(b"bravo bravo")
    return root


def _touch(path, data: bytes, mtime: float) -> None:
    path.write_bytes(data)
    os.utime(path, (mtime, mtime))


# --------------------------------------------------------------- happy path
def test_happy_a_snapshot_records_every_file_with_size_and_a_tree_hash(tree, db):
    snap = trail.snapshot_now(LocalFS(), str(tree), name="w")
    assert (snap.trail_name, snap.file_count, snap.total_bytes) == ("w", 2, 16)
    assert not snap.truncated and len(snap.tree_hash) == 64
    with closing(sqlite3.connect(db)) as conn:
        rows = sorted(
            conn.execute("SELECT path, size FROM files WHERE snapshot_id = ?", (snap.snapshot_id,))
        )
    assert rows == [(str(tree / "a.txt"), 5), (str(tree / "sub" / "b.log"), 11)]


def test_happy_the_diff_names_added_removed_and_modified_files(tree):
    fs = LocalFS()
    first = trail.snapshot_now(fs, str(tree), name="w")
    (tree / "sub" / "b.log").unlink()
    (tree / "new.bin").write_bytes(b"n")
    _touch(tree / "a.txt", b"alpha, changed", time.time() + 5)
    second = trail.snapshot_now(fs, str(tree), name="w")
    diff = trail.diff_snapshots(first.snapshot_id, second.snapshot_id)
    assert diff.added == [str(tree / "new.bin")]
    assert diff.removed == [str(tree / "sub" / "b.log")]
    assert diff.modified == [str(tree / "a.txt")]
    assert diff.summary() == "+1 added, -1 removed, ~1 modified, 0 unchanged"
    assert first.tree_hash != second.tree_hash


def test_happy_an_untouched_tree_diffs_empty_with_the_same_tree_hash(tree):
    fs = LocalFS()
    a = trail.snapshot_now(fs, str(tree), name="w")
    b = trail.snapshot_now(fs, str(tree), name="w")
    diff = trail.diff_snapshots(a.snapshot_id, b.snapshot_id)
    assert diff.is_empty() and diff.unchanged == 2
    assert a.tree_hash == b.tree_hash


def test_happy_head_hash_sees_a_change_that_keeps_size_and_mtime(tree):
    fs = LocalFS()
    target = tree / "a.txt"
    _touch(target, b"AAAAA", 1_700_000_000)
    a = trail.snapshot_now(fs, str(tree), name="h", head_hash=True)
    _touch(target, b"BBBBB", 1_700_000_000)  # same size, same mtime
    b = trail.snapshot_now(fs, str(tree), name="h", head_hash=True)
    assert trail.diff_snapshots(a.snapshot_id, b.snapshot_id).modified == [str(target)]
    # without the head hash the same change is invisible - the documented trade-off
    c = trail.snapshot_now(fs, str(tree), name="plain")
    _touch(target, b"CCCCC", 1_700_000_000)
    d = trail.snapshot_now(fs, str(tree), name="plain")
    assert trail.diff_snapshots(c.snapshot_id, d.snapshot_id).is_empty()


def test_happy_list_trails_and_the_timeline_newest_first(tree):
    fs = LocalFS()
    s1 = trail.snapshot_now(fs, str(tree), name="w")
    s2 = trail.snapshot_now(fs, str(tree), name="w")
    [info] = trail.list_trails()
    assert (info["name"], info["path"], info["backend_label"]) == ("w", str(tree), fs.name)
    assert info["last_snapshot_at"] == pytest.approx(s2.ts)
    assert [s.snapshot_id for s in trail.list_snapshots("w")] == [s2.snapshot_id, s1.snapshot_id]
    lines = trail.render_timeline("w").splitlines()
    assert lines[0] == "trail w:"
    assert f"#{s2.snapshot_id}" in lines[1] and "files=2" in lines[1]


def test_happy_the_default_name_is_backend_and_path(tree):
    fs = LocalFS()
    snap = trail.snapshot_now(fs, str(tree))
    assert snap.trail_name == f"{fs.name}:{tree}"


def test_happy_export_writes_one_json_line_per_snapshot_privately(tree, tmp_path):
    fs = LocalFS()
    trail.snapshot_now(fs, str(tree), name="w")
    trail.snapshot_now(fs, str(tree), name="w")
    out = tmp_path / "export" / "w.jsonl"
    assert trail.export_trail_jsonl("w", out) == 2
    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["file_count"] for r in lines] == [2, 2] and {r["trail_name"] for r in lines} == {"w"}
    assert (out.stat().st_mode & 0o777) == 0o600
    assert [p.name for p in out.parent.iterdir()] == ["w.jsonl"]  # no temp file left


def test_happy_e2e_a_background_trail_on_ramfs_records_a_change(monkeypatch):
    """The scripting API end to end: start_trail on a real RamFS, change a
    file, the next snapshot shows it; stop_trail ends the thread."""
    import core.scripting as axross

    monkeypatch.setattr(trail, "MIN_INTERVAL_S", 0.05)
    ram = RamFsSession("trail-e2e")
    ram.mkdir("/data")
    with ram.open_write("/data/x.txt") as fh:
        fh.write(b"one")
    seen = []
    name = axross.start_trail(ram, "/data", name="ram", interval_s=0.05, on_snapshot=seen.append)
    deadline = time.time() + 10
    while not seen and time.time() < deadline:
        time.sleep(0.01)
    with ram.open_write("/data/y.txt") as fh:
        fh.write(b"two")
    while (not seen or seen[-1].file_count < 2) and time.time() < deadline:
        time.sleep(0.01)
    assert axross.stop_trail(name) is True
    assert seen[0].file_count == 1 and seen[-1].file_count == 2
    diff = axross.diff_snapshots(seen[0].snapshot_id, seen[-1].snapshot_id)
    assert diff.added == ["/data/y.txt"]
    count = len(axross.list_snapshots("ram", limit=1000))
    time.sleep(0.2)
    assert len(axross.list_snapshots("ram", limit=1000)) == count  # stopped means stopped


# ------------------------------------------------------------------ sad path
class _DupBackend:
    """A folder listing two entries of one name, the way a Google Drive
    folder can (tests/test_gdrive_duplicate_names.py)."""

    name = "dup"

    def __init__(self, entries) -> None:
        self.entries = entries

    def join(self, a, b):
        return a.rstrip("/") + "/" + b

    def list_dir(self, path):
        return list(self.entries)


def _item(name, size, day):
    return FileItem(name=name, size=size, modified=datetime(2026, 1, day))


def test_sad_two_entries_of_one_name_are_both_recorded():
    be = _DupBackend([_item("report.pdf", 1, 1), _item("report.pdf", 2, 2), _item("x", 3, 3)])
    snap = trail.snapshot_now(be, "/", name="dup")
    assert (snap.file_count, snap.total_bytes) == (3, 6)
    with closing(sqlite3.connect(trail.DB_FILE)) as conn:
        paths = sorted(p for (p,) in conn.execute("SELECT path FROM files"))
    assert paths == ["/report.pdf", "/report.pdf  (duplicate 2)", "/x"]


def test_sad_duplicates_listed_in_another_order_diff_as_unchanged():
    one, two = _item("report.pdf", 1, 1), _item("report.pdf", 2, 2)
    a = trail.snapshot_now(_DupBackend([one, two]), "/", name="dup")
    b = trail.snapshot_now(_DupBackend([two, one]), "/", name="dup")
    assert trail.diff_snapshots(a.snapshot_id, b.snapshot_id).is_empty()
    assert a.tree_hash == b.tree_hash


def test_sad_a_disambiguated_name_never_collides_with_a_real_one():
    be = _DupBackend([_item("r", 1, 1), _item("r", 2, 2), _item("r  (duplicate 2)", 3, 3)])
    snap = trail.snapshot_now(be, "/", name="dup")
    assert snap.file_count == 3


def test_sad_e2e_a_google_drive_folder_with_a_shared_name_is_snapshotted():
    pytest.importorskip("googleapiclient")
    from core.gdrive_client import GDriveSession
    from tests.test_gdrive_duplicate_names import _Drive, _file

    drive = _Drive([_file("A", "scan.pdf"), _file("B", "scan.pdf"), _file("C", "other.pdf")])
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root"}
    assert sorted(i.name for i in s.list_dir("/")) == ["other.pdf", "scan.pdf", "scan.pdf"]
    snap = trail.snapshot_now(s, "/", name="drive")
    assert snap.file_count == 3


def test_sad_a_background_trail_of_such_a_folder_records_snapshots(monkeypatch):
    monkeypatch.setattr(trail, "MIN_INTERVAL_S", 0.05)
    be = _DupBackend([_item("r", 1, 1), _item("r", 2, 2)])
    seen = []
    trail.start_trail(be, "/", name="bg", interval_s=0.05, on_snapshot=seen.append)
    deadline = time.time() + 10
    while len(seen) < 2 and time.time() < deadline:
        time.sleep(0.01)
    trail.stop_trail("bg")
    assert len(seen) >= 2 and seen[0].file_count == 2


def test_sad_an_unreadable_subfolder_is_skipped_not_fatal(tree):
    class Flaky(LocalFS):
        def list_dir(self, path):
            if path.endswith("sub"):
                raise PermissionError(13, "Permission denied", path)
            return super().list_dir(path)

    snap = trail.snapshot_now(Flaky(), str(tree), name="w")
    assert snap.file_count == 1 and not snap.truncated


def test_sad_a_file_that_cannot_be_read_gets_no_head_hash_but_is_recorded(tree):
    class NoRead(LocalFS):
        def open_read(self, path):
            raise PermissionError(13, "Permission denied", path)

    snap = trail.snapshot_now(NoRead(), str(tree), name="w", head_hash=True)
    assert snap.file_count == 2
    with closing(sqlite3.connect(trail.DB_FILE)) as conn:
        assert {h for (h,) in conn.execute("SELECT sha_prefix FROM files")} == {""}


def test_sad_a_failing_snapshot_does_not_stop_a_background_trail(monkeypatch):
    monkeypatch.setattr(trail, "MIN_INTERVAL_S", 0.05)
    calls = []

    class Sometimes(_DupBackend):
        def list_dir(self, path):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("backend exploded")
            return [_item("ok", 1, 1)]

    seen = []
    trail.start_trail(Sometimes([]), "/", name="flaky", interval_s=0.05, on_snapshot=seen.append)
    deadline = time.time() + 10
    while not seen and time.time() < deadline:
        time.sleep(0.01)
    trail.stop_trail("flaky")
    assert seen and seen[0].file_count == 1


def test_sad_stopping_an_unknown_trail_says_so():
    assert trail.stop_trail("never-started") is False


# --------------------------------------------------------------- edge cases
def test_edge_max_files_truncates_and_says_so(tree):
    snap = trail.snapshot_now(LocalFS(), str(tree), name="w", max_files=1)
    assert snap.file_count == 1 and snap.truncated
    assert "✂" in trail.render_timeline("w")


def test_edge_an_empty_folder_is_a_snapshot_with_no_files(tmp_path):
    (tmp_path / "empty").mkdir()
    snap = trail.snapshot_now(LocalFS(), str(tmp_path / "empty"), name="e")
    assert (snap.file_count, snap.total_bytes, snap.truncated) == (0, 0, False)


def test_edge_an_unknown_trail_has_no_timeline_and_exports_nothing(tmp_path):
    assert trail.list_snapshots("nope") == []
    assert trail.render_timeline("nope") == "trail 'nope': no snapshots."
    out = tmp_path / "nope.jsonl"
    assert trail.export_trail_jsonl("nope", out) == 0 and out.read_text() == ""


def test_edge_the_runner_never_polls_faster_than_the_minimum():
    runner = trail.TrailRunner(LocalFS(), "/", interval_s=0.001)
    assert runner.interval_s == trail.MIN_INTERVAL_S


def test_edge_starting_a_trail_twice_replaces_the_first_runner(monkeypatch, tree):
    monkeypatch.setattr(trail, "MIN_INTERVAL_S", 0.05)
    trail.start_trail(LocalFS(), str(tree), name="twice", interval_s=60)
    first = trail._RUNNERS["twice"]
    trail.start_trail(LocalFS(), str(tree), name="twice", interval_s=60)
    assert trail._RUNNERS["twice"] is not first
    assert first._thread is not None and not first._thread.is_alive()
    assert trail.stop_all_trails() == 1


def test_edge_the_database_is_private(tree, db):
    trail.snapshot_now(LocalFS(), str(tree), name="w")
    assert (db.stat().st_mode & 0o777) == 0o600
    assert (db.parent.stat().st_mode & 0o777) == 0o700


def test_edge_no_database_connection_is_left_open(tree):
    fs = LocalFS()
    gc.collect()  # what earlier tests left behind is not this test's leak
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        a = trail.snapshot_now(fs, str(tree), name="w")
        trail.list_trails()
        trail.list_snapshots("w")
        trail.diff_snapshots(a.snapshot_id, a.snapshot_id)
        gc.collect()
    leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert leaks == [], [str(w.message) for w in leaks]


def test_edge_a_timestamp_that_is_no_date_counts_as_zero():
    assert trail._to_epoch(None) == 0.0
    assert trail._to_epoch("not a number") == 0.0
    assert trail._to_epoch(12.5) == 12.5
