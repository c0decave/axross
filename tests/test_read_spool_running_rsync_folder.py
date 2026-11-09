"""The stale-spool sweep leaves an rsync download folder that is in use.

Review round 9: the sweep checked the files INSIDE a spool folder with age
-1 - only the folder's own time counted. A download into it does not touch
the folder's time, so a second axross process deleted another's rsync
download once it had run for over a day. Now every file inside must be
older than the age as well.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from core import read_spool

DAY = 24 * 3600


def _aged(path: Path, days: float = 2) -> Path:
    then = time.time() - days * DAY
    os.utime(path, (then, then), follow_symlinks=False)
    return path


def _folder(tmp_path: Path, name: str, *, inner_days: float) -> Path:
    folder = tmp_path / f".axross-spool-rsync-{name}"
    folder.mkdir()
    (folder / "done.bin").write_bytes(b"done")
    _aged(folder / "done.bin", 3)
    (folder / ".f.bin.Xy12").write_bytes(b"partial")
    if inner_days:
        _aged(folder / ".f.bin.Xy12", inner_days)
    _aged(folder, 2)
    return folder


def test_happy_a_folder_of_old_files_goes(tmp_path):
    folder = _folder(tmp_path, "old", inner_days=2)
    assert read_spool.sweep_stale_spools(str(tmp_path)) == 1
    assert not folder.exists()


def test_sad_a_download_still_being_written_stays(tmp_path):
    folder = _folder(tmp_path, "busy", inner_days=0)  # the file was written just now
    assert read_spool.sweep_stale_spools(str(tmp_path)) == 0
    assert sorted(p.name for p in folder.iterdir()) == [".f.bin.Xy12", "done.bin"]


def test_edge_a_file_just_under_the_age_keeps_the_folder(tmp_path):
    folder = _folder(tmp_path, "edge", inner_days=0)
    now = time.time()
    os.utime(folder / ".f.bin.Xy12", (now - DAY + 60, now - DAY + 60))
    assert read_spool.sweep_stale_spools(str(tmp_path), age=DAY, now=now) == 0
    assert folder.exists()
    os.utime(folder / ".f.bin.Xy12", (now - DAY - 60, now - DAY - 60))
    assert read_spool.sweep_stale_spools(str(tmp_path), age=DAY, now=now) == 1
    assert not folder.exists()
