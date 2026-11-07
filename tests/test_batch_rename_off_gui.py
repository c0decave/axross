"""Batch Rename talks to the server off the GUI thread.

Audit (feedback: no blocked windows): OK ran about five backend calls a
file on the GUI thread - the conflict check, a free temporary name, two
renames, an exists() - so a thousand remote files froze every window for
minutes. The server's part runs on a worker now (ui.off_gui): the
windows keep painting, the dialog counts "Renaming N of M…", and clicks
wait until the batch is through, so it is never left half staged.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


class SlowFS(LocalFS):
    delay = 0.03

    def __init__(self) -> None:
        super().__init__()
        self.threads: set[str] = set()

    def rename(self, src, dst):
        self.threads.add(threading.current_thread().name)
        time.sleep(self.delay)
        return super().rename(src, dst)

    def exists(self, path):
        self.threads.add(threading.current_thread().name)
        time.sleep(self.delay)
        return super().exists(path)


def _dialog(tmp_path, n=12):
    from ui.batch_rename_dialog import BatchRenameDialog

    names = [f"shot{i:02d}.jpg" for i in range(n)]
    for name in names:
        (tmp_path / name).write_text(name)
    fs = SlowFS()
    dlg = BatchRenameDialog(fs, str(tmp_path), [FileItem(name=n) for n in names])
    dlg._find_edit.setText("shot")
    dlg._replace_edit.setText("img")
    return dlg, fs


def test_happy_the_batch_renames_off_the_gui_thread_and_counts(tmp_path):
    dlg, fs = _dialog(tmp_path)
    texts: list[str] = []
    ticks: list[int] = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: (ticks.append(1), texts.append(dlg._status.text())))
    timer.start()
    try:
        dlg._apply()
    finally:
        timer.stop()
    assert sorted(p.name for p in tmp_path.iterdir()) == [f"img{i:02d}.jpg" for i in range(12)]
    assert "MainThread" not in fs.threads
    assert len(ticks) >= 1
    assert any(t.startswith("Renaming ") and t.endswith(" of 12…") for t in texts), texts


def test_sad_a_taken_name_outside_the_set_stops_before_anything_moves(tmp_path):
    dlg, fs = _dialog(tmp_path, n=3)
    (tmp_path / "img01.jpg").write_text("other")
    with mock.patch.object(QMessageBox, "warning") as warning:
        dlg._apply()
    warning.assert_called_once()
    assert "img01.jpg" in warning.call_args.args[2]
    assert (tmp_path / "shot00.jpg").exists() and (tmp_path / "img01.jpg").read_text() == "other"
    assert "MainThread" not in fs.threads
