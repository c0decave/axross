"""The polling watcher reads a local folder with scandir + lstat directly
instead of building a full FileItem listing every two seconds.

Measured before (no watchdog installed, so LocalFS panes poll): a pane
showing 20,000 local entries kept the process at ~8 % of a core while idle
(811 ms CPU in 10 s), 128 ms per poll, of which the snapshot needs only
name, size, modification time and the folder bit. The snapshot must be the
one ``_snapshot_of(list_dir())`` gives: every test compares with it.
"""

from __future__ import annotations

import contextlib
import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import watch as W  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _former(backend, path: str):
    """The former PollingWatcher._snapshot."""
    try:
        items = backend.list_dir(path)
    except Exception:  # noqa: BLE001 - as the watcher
        return None
    return W.PollingWatcher._snapshot_of(items)


def _watcher(backend, path) -> W.PollingWatcher:
    return W.PollingWatcher(backend, str(path), lambda *a: None, interval=60)


@pytest.fixture
def tricky(tmp_path):
    root = tmp_path / "f"
    root.mkdir()
    (root / "file.txt").write_text("x" * 10)
    (root / "empty").write_bytes(b"")
    (root / "folder").mkdir()
    (root / ".hidden").write_text("h")
    (root / "日本 ä.txt").write_text("u")
    (root / "link-to-file").symlink_to(root / "file.txt")
    (root / "link-to-folder").symlink_to(root / "folder")
    (root / "dangling").symlink_to(root / "nowhere")
    os.mkfifo(root / "fifo")
    os.utime(root / "file.txt", (1_000_000_000.5, 1_000_000_000.25))
    os.utime(root / "empty", (0, 0))
    return root


def test_happy_the_snapshot_is_the_former_one(tricky):
    fs = LocalFS()
    fast = _watcher(fs, tricky)._snapshot()
    assert fast is not None
    assert fast.entries == _former(fs, str(tricky)).entries
    assert set(fast.entries) == {p.name for p in tricky.iterdir()}


def test_happy_e2e_changes_are_reported_from_the_fast_snapshot(tmp_path):
    (tmp_path / "keep.txt").write_text("k")
    (tmp_path / "gone.txt").write_text("g")
    events, lock = [], threading.Lock()

    def cb(*ev):
        with lock:
            events.append(ev)

    w = W.watch(LocalFS(), str(tmp_path), cb, interval=0.2, force_polling=True)
    try:
        (tmp_path / "new.txt").write_text("n")
        (tmp_path / "keep.txt").write_text("changed size")
        (tmp_path / "gone.txt").unlink()
        assert w.wait_for_tick(2, timeout=10)
    finally:
        w.stop(2.0)
    kinds = {(e[0], Path(e[1]).name) for e in events}
    assert {("created", "new.txt"), ("modified", "keep.txt"), ("deleted", "gone.txt")} <= kinds


def test_sad_a_missing_folder_is_no_snapshot(tmp_path):
    fs = LocalFS()
    assert _watcher(fs, tmp_path / "missing")._snapshot() is None
    assert _former(fs, str(tmp_path / "missing")) is None


def test_sad_a_folder_that_cannot_be_listed_is_logged_like_list_dir(tmp_path, caplog):
    import logging

    fs = LocalFS()
    with caplog.at_level(logging.ERROR, logger="core.local_fs"):
        assert _watcher(fs, tmp_path / "missing")._snapshot() is None
    fast = [(r.name, r.levelno, r.getMessage()) for r in caplog.records]
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="core.local_fs"):
        assert _former(fs, str(tmp_path / "missing")) is None
    former = [(r.name, r.levelno, r.getMessage()) for r in caplog.records]
    assert fast == former and former


def test_sad_a_file_instead_of_a_folder_is_no_snapshot(tmp_path):
    (tmp_path / "plain").write_text("p")
    assert _watcher(LocalFS(), tmp_path / "plain")._snapshot() is None


def test_edge_an_entry_that_cannot_be_statted_is_left_out_like_before(tricky):
    fs = LocalFS()
    real_stat = os.DirEntry.stat

    class Entry:
        """A DirEntry whose lstat of "empty" fails, as a race would."""

        def __init__(self, entry):
            self._e = entry
            self.name = entry.name
            self.path = entry.path

        def stat(self, follow_symlinks=True):
            if self.name == "empty":
                raise PermissionError(13, "denied", self.path)
            return real_stat(self._e, follow_symlinks=follow_symlinks)

        def is_dir(self, follow_symlinks=True):
            return self._e.is_dir(follow_symlinks=follow_symlinks)

    real_scandir = os.scandir

    class Scan:
        def __init__(self, path):
            self._it = real_scandir(path)

        def __enter__(self):
            return (Entry(e) for e in self._it)

        def __exit__(self, *exc):
            self._it.close()

    with mock.patch("os.scandir", Scan):
        fast = _watcher(fs, tricky)._snapshot()
        former = _former(fs, str(tricky))
    assert "empty" not in fast.entries
    assert fast.entries == former.entries


@pytest.mark.parametrize("how", ["class", "instance", "subclass"])
def test_edge_a_changed_listing_is_honoured_not_bypassed(tricky, how):
    """Tests and subclasses that change how LocalFS lists keep being asked."""
    fs = LocalFS()
    calls = []

    def listing(self_or_path, *rest):
        calls.append(1)
        return []

    if how == "class":
        patcher = mock.patch.object(LocalFS, "list_dir", listing)
    elif how == "instance":
        patcher = mock.patch.object(fs, "list_dir", lambda path: listing(path))
    else:
        class Sub(LocalFS):
            def _stat_to_item(self, name, st, full_path=""):
                calls.append(1)
                return super()._stat_to_item(name, st, full_path)

        fs = Sub()
        patcher = contextlib.nullcontext()
    with patcher:
        snap = _watcher(fs, tricky)._snapshot()
    assert calls
    if how != "subclass":
        assert snap.entries == {}


def test_edge_another_backend_is_listed_as_before():
    class Fake:
        def list_dir(self, path):
            from models.file_item import FileItem

            return [FileItem(name="x", size=3)]

    snap = _watcher(Fake(), "/")._snapshot()
    assert set(snap.entries) == {"x"}


def _cost_ms(snapshot, rounds: int = 3) -> float:
    best = 1e9
    for _ in range(rounds):
        start = time.thread_time()
        snapshot()
        best = min(best, (time.thread_time() - start) * 1000)
    return best


@pytest.fixture
def many(tmp_path):
    root = tmp_path / "many"
    root.mkdir()
    for i in range(5000):
        (root / f"f{i:05d}").write_bytes(b"x" * (i % 50))
    return root


def test_perf_happy_a_poll_of_5000_entries_costs_well_under_the_former(many):
    fs = LocalFS()
    w = _watcher(fs, many)
    new = _cost_ms(w._snapshot)
    old = _cost_ms(lambda: _former(fs, str(many)))
    assert new < old * 0.65, (new, old)


def test_perf_sad_the_comparison_catches_a_poll_as_slow_as_before(many):
    """Negative control: the former poll against itself is not cheaper."""
    fs = LocalFS()
    again = _cost_ms(lambda: _former(fs, str(many)))
    old = _cost_ms(lambda: _former(fs, str(many)))
    assert not again < old * 0.65, (again, old)
