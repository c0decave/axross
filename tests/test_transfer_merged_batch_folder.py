"""Two source trees of one batch go into one destination folder (two
'photos' folders copied into the same place, the scripting and sync way,
with no conflict plan): the folder the first walk made is no longer "new"
for the second. Its jobs counted the destination as known absent, took no
snapshot, and a failure or Cancel removed the file the first tree's job
had written there - with a move, a file then nowhere."""
from __future__ import annotations

import os

import pytest

from core.local_fs import LocalFS


class _DirectFS(LocalFS):
    """A destination written in place (no temp file and rename)."""

    def rename(self, src, dst):
        return super().rename(src, dst)


@pytest.fixture
def app():
    pytest.importorskip("PyQt6.QtCore")
    from PyQt6.QtCore import QCoreApplication

    global _APP
    _APP = QCoreApplication.instance() or QCoreApplication([])
    return _APP


_APP = None


def test_sad_the_second_tree_is_not_counted_absent(app, tmp_path):
    from core.transfer_manager import TransferManager

    for side in ("a", "b"):
        (tmp_path / side / "photos").mkdir(parents=True)
        (tmp_path / side / "photos" / "x.jpg").write_text(side)
    dest = tmp_path / "dest"
    dest.mkdir()
    queued = []
    manager = TransferManager(max_parallel=1)
    try:
        manager._worker.enqueue = queued.append  # look at what the walks plan only
        manager.transfer_files(LocalFS(), _DirectFS(),
                               [str(tmp_path / "a" / "photos"), str(tmp_path / "b" / "photos")],
                               str(dest))
    finally:
        manager.shutdown()
    jobs = [j for j in queued if j.dest_path == os.path.join(str(dest), "photos", "x.jpg")]
    assert len(jobs) == 2 and not any(j.use_temp_file for j in jobs)
    assert [j.dest_folder_new for j in jobs] == [True, False]
