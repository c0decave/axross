"""A watched folder that disappears is logged once, not on every poll.

Found in the full suite of 2026-11-08: a pane's PollingWatcher on a folder
that was deleted logged "Cannot list …" as an ERROR on every tick (once a
second, endlessly) - the log of a pane left on a removed USB stick or a
deleted project folder filled with the same line. Now the first failure of
a streak is logged, the watcher keeps polling (a folder made again is
picked up), recovery is one INFO line, and the next streak logs again.
"""

from __future__ import annotations

import logging
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.local_fs import LocalFS  # noqa: E402
from core.watch import PollingWatcher  # noqa: E402


def _errors(caplog, path: Path) -> list:
    return [r for r in caplog.records
            if r.levelno >= logging.ERROR and str(path) in r.getMessage()]


def test_sad_a_deleted_folder_is_logged_once_per_streak(tmp_path, caplog):
    folder = tmp_path / "watched"
    folder.mkdir()
    events = []
    watcher = PollingWatcher(LocalFS(), str(folder), lambda *e: events.append(e), interval=0.2)
    caplog.set_level(logging.INFO)
    watcher.start()
    try:
        shutil.rmtree(folder)
        assert watcher.wait_for_tick(5)
        assert len(_errors(caplog, folder)) == 1

        folder.mkdir()
        (folder / "new.txt").write_text("x")
        assert watcher.wait_for_tick(2)
        assert any("can be listed again" in r.getMessage() for r in caplog.records)

        shutil.rmtree(folder)
        assert watcher.wait_for_tick(3)
        assert len(_errors(caplog, folder)) == 2  # a new streak is logged again
    finally:
        watcher.stop()


def test_happy_a_healthy_folder_logs_nothing(tmp_path, caplog):
    watcher = PollingWatcher(LocalFS(), str(tmp_path), lambda *e: None, interval=0.2)
    caplog.set_level(logging.INFO)
    watcher.start()
    try:
        assert watcher.wait_for_tick(3)
        assert not _errors(caplog, tmp_path)
        assert not any("listed again" in r.getMessage() for r in caplog.records)
    finally:
        watcher.stop()
