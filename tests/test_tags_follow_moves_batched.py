"""Tags follow a large move without rewriting tags.json per file.

2026-10-25 performance round: every finished job of a move called
TagStore.move_path, which scanned every tagged file and wrote the whole
tags.json - moving 1000 tagged files cost 1.5 s of GUI-thread CPU (3000:
12.3 s), and remembering the jobs at the start compared every job with
every tagged path (0.82 s for 2000). The finished jobs are now applied in
one batch per event-loop turn with one write, and the start indexes the
tagged paths once.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import tags as TG  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(TG, "tags_file", lambda: tmp_path / "tags.json")
    TG.reset_cache()
    yield TG.store()
    TG.reset_cache()


def _count_saves(store):
    """Counts the writes of tags.json."""
    return mock.patch.object(type(store), "_write", autospec=True, side_effect=TG.TagStore._write)


# -- the store's batch -----------------------------------------------------------------


def test_happy_a_batch_writes_once_and_ends_like_single_calls(store, tmp_path):
    for i in range(50):
        store.tag("Local", "", f"/src/f{i}.txt", "Important")
    with _count_saves(store) as save:
        with store.batch():
            for i in range(50):
                store.move_path("Local", f"/src/f{i}.txt", f"/dst/f{i}.txt")
    assert save.call_count == 1
    assert all(store.tags_of("Local", f"/dst/f{i}.txt") == ["Important"] for i in range(50))
    assert store.tags_of("Local", "/src/f0.txt") == []
    TG.reset_cache()  # the file holds the same
    assert TG.store().tags_of("Local", "/dst/f49.txt") == ["Important"]


def test_edge_nested_batches_write_once_at_the_outer_end(store):
    store.tag("Local", "", "/a", "Important")
    with _count_saves(store) as save:
        with store.batch():
            with store.batch():
                store.move_path("Local", "/a", "/b")
            assert save.call_count == 0
    assert save.call_count == 1


def test_edge_a_batch_without_a_change_writes_nothing(store):
    with _count_saves(store) as save:
        with store.batch():
            store.move_path("Local", "/nothing", "/else")
    assert save.call_count == 0


def test_sad_an_error_inside_a_batch_still_writes_what_changed(store):
    store.tag("Local", "", "/a", "Important")
    with pytest.raises(RuntimeError):
        with store.batch():
            store.move_path("Local", "/a", "/b")
            raise RuntimeError("boom")
    TG.reset_cache()
    assert TG.store().tags_of("Local", "/b") == ["Important"]


def test_happy_the_tag_index_answers_like_has_tags_under(store):
    for path in ("/x/a.txt", "/x/sub/b.txt", "/y", "C:\\share\\c.txt"):
        store.tag("Local", "", path, "Important")
    index = store.tagged_index("Local")
    for probe in ("/x", "/x/", "/x/a.txt", "/x/sub", "/y", "/y/z", "/z", "/", "C:\\share",
                  "C:\\share\\c.txt", "/x/a"):
        assert index.has_tags_under(probe) == store.has_tags_under("Local", probe), probe


# -- the window ------------------------------------------------------------------------


@pytest.fixture
def win(store, tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    window = MainWindow()
    window._reconnect_timer.stop()
    yield window
    window.close()
    window.deleteLater()


def _move(win, src: Path, dst: Path, names):
    left = win._active_pane
    left.navigate(str(src))
    win._split_pane(Qt.Orientation.Horizontal)
    right = win._active_pane
    right.navigate(str(dst))
    win._set_active_pane(left)
    win._set_target_pane(right)
    win._start_transfer_between(left, right, [str(src / n) for n in names], move=True)
    end = time.time() + 60
    while time.time() < end and (any((src / n).exists() for n in names)
                                 or win._tag_moves or win._tag_folder_moves):
        APP.processEvents()
        time.sleep(0.01)
    for _ in range(10):
        APP.processEvents()
        time.sleep(0.01)
    assert not any((src / n).exists() for n in names), "the move did not finish"


def test_perf_happy_moving_300_tagged_files_writes_tags_json_a_few_times(win, store, tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    names = [f"f{i:03}.txt" for i in range(300)]
    for name in names:
        (src / name).write_text(name)
    store.tag_many("Local", "", [str(src / n) for n in names], "Important")
    with _count_saves(store) as save:
        _move(win, src, dst, names)
    assert all(store.tags_of("Local", str(dst / n)) == ["Important"] for n in names)
    assert store.tags_of("Local", str(src / names[0])) == []
    assert save.call_count <= 30, save.call_count  # was 300: one per finished job


def test_perf_happy_remembering_the_jobs_reads_the_tags_once(win, store, tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    (src / "folder").mkdir(parents=True)
    dst.mkdir()
    names = [f"f{i:03}.txt" for i in range(200)]
    for name in names:
        (src / "folder" / name).write_text(name)
    store.tag("Local", "", str(src / "folder"), "Review later")
    store.tag_many("Local", "", [str(src / "folder" / n) for n in names], "Important")
    with mock.patch.object(type(store), "has_tags_under", autospec=True,
                           side_effect=TG.TagStore.has_tags_under) as probe:
        _move(win, src, dst, ["folder"])
    assert probe.call_count == 0  # one tagged_index() instead of a scan per selected entry
    assert store.tags_of("Local", str(dst / "folder")) == ["Review later"]
    assert all(store.tags_of("Local", str(dst / "folder" / n)) == ["Important"] for n in names)


def test_sad_a_failed_job_in_a_batch_keeps_only_its_own_tag(win, store, tmp_path, monkeypatch):
    from core.transfer_worker import TransferStatus

    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    names = ["a.txt", "b.txt", "c.txt"]
    for name in names:
        (src / name).write_text(name)
    store.tag_many("Local", "", [str(src / n) for n in names], "Important")
    real_get = win._transfer_manager.get_job

    def get_job(job_id):
        job = real_get(job_id)
        if job is not None and job.source_path.endswith("b.txt"):
            job.status = TransferStatus.ERROR
        return job

    monkeypatch.setattr(win._transfer_manager, "get_job", get_job)
    _move(win, src, dst, names)
    assert store.tags_of("Local", str(dst / "a.txt")) == ["Important"]
    assert store.tags_of("Local", str(dst / "c.txt")) == ["Important"]
    assert store.tags_of("Local", str(src / "b.txt")) == ["Important"]  # its tag stayed


# -- jobs that end on a busy event loop ------------------------------------------------
# With watchdog the panes of a move refresh while it runs (inotify), so the event
# loop turns far more often: applied "on the next turn", 300 moved files wrote
# tags.json 38 to 98 times instead of at most 30. The flushes now keep a gap.


def _count_flushes(win, monkeypatch):
    calls = []
    real = win._flush_tag_jobs

    def counting():
        calls.append(time.monotonic())
        real()

    monkeypatch.setattr(win, "_flush_tag_jobs", counting)
    return calls


def _pending(win, count, first=0):
    for i in range(first, first + count):
        win._tag_moves[f"job{i}"] = ("Local", "Local", "", f"/src/f{i}", f"/dst/f{i}")
        win._tags_on_move_finished(f"job{i}")


def test_happy_a_single_ended_job_is_applied_on_the_next_turn(win, monkeypatch):
    flushes = _count_flushes(win, monkeypatch)
    _pending(win, 1)
    APP.processEvents()
    assert len(flushes) == 1
    assert win._tag_job_queue == [] and win._tag_moves == {}


def test_edge_jobs_ending_on_a_busy_loop_share_one_flush(win, monkeypatch):
    flushes = _count_flushes(win, monkeypatch)
    _pending(win, 1)
    APP.processEvents()
    assert len(flushes) == 1
    # Twenty more jobs end, one per event-loop turn, inside the gap.
    for i in range(1, 21):
        _pending(win, 1, first=i)
        APP.processEvents()
    assert len(flushes) == 1
    end = time.monotonic() + 2.0
    while time.monotonic() < end and win._tag_job_queue:
        APP.processEvents()
        time.sleep(0.01)
    assert len(flushes) == 2
    assert flushes[1] - flushes[0] >= win.TAG_FLUSH_GAP_MS / 1000 - 0.02
    assert win._tag_job_queue == [] and win._tag_moves == {}


def test_sad_closing_the_window_applies_what_is_still_queued(win, store):
    store.tag("Local", "", "/src/a.txt", "Important")
    win._tag_moves["late"] = ("Local", "Local", "", "/src/a.txt", "/dst/a.txt")
    win._flush_tag_jobs()  # a flush just ran: the next one would wait the gap
    win._tag_moves["late"] = ("Local", "Local", "", "/src/a.txt", "/dst/a.txt")
    job = mock.Mock(status=None, skipped=False)
    from core.transfer_worker import TransferStatus

    job.status = TransferStatus.DONE
    with mock.patch.object(win._transfer_manager, "get_job", return_value=job):
        win._tags_on_move_finished("late")
        assert win._tag_job_queue  # waiting for the gap
        win.close()
    assert win._tag_job_queue == []
    assert store.tags_of("Local", "/dst/a.txt") == ["Important"]
