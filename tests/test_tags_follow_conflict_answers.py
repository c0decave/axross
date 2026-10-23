"""Tags follow a moved folder only where its files really went.

Measured before: a moved folder's own tag followed through
``TagStore.move_path(old, new)``, which re-points every tag below ``old``.
Two answers of the conflict prompt broke that:

* **Skip** a file inside the moved folder: it stays in the source folder
  (which then stays too), but its tag was moved onto the destination's
  file of that name - a different file - and the source file lost it.
* **Rename** the folder (a file of its name at the destination): the
  folder went to ``name (1)``, its tag to ``name`` - the destination's file.

Now a folder whose move the answers left incomplete keeps its tags where
they are (the source folder still exists), and a renamed folder's tag
goes to the name it was given.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import tags as TG  # noqa: E402
from core import transfer_conflicts as TC  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setattr(TG, "tags_file", lambda: tmp_path / "tags.json")
    TG.reset_cache()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    window = MainWindow()
    window._reconnect_timer.stop()
    yield window
    window.close()
    window.deleteLater()
    TG.reset_cache()


def _panes(win, src: Path, dst: Path):
    left = win._active_pane
    left.navigate(str(src))
    win._split_pane(Qt.Orientation.Horizontal)
    right = win._active_pane
    right.navigate(str(dst))
    win._set_active_pane(left)
    win._set_target_pane(right)
    return left, right


def _plan(src: Path, dst: Path, names: list[str], answer: TC.ConflictAction):
    fs = LocalFS()
    scan = TC.scan_conflicts(fs, fs, [str(src / n) for n in names], str(dst))
    plan = TC.ConflictPlan(fs, scan)
    for conflict in scan.conflicts:
        plan.decide(conflict, answer)
    return plan, scan


def _settle(win, done, timeout: float = 30.0) -> None:
    end = time.time() + timeout
    while time.time() < end and not done():
        APP.processEvents()
        time.sleep(0.02)
    assert done(), "the move did not finish"
    end = time.time() + timeout
    while time.time() < end and (win._tag_moves or win._tag_folder_moves):
        APP.processEvents()
        time.sleep(0.02)
    for _ in range(10):
        APP.processEvents()
        time.sleep(0.01)


def test_sad_a_skipped_file_keeps_its_tag_and_the_kept_file_gets_none(win, tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    (src / "folder").mkdir(parents=True)
    (dst / "folder").mkdir(parents=True)
    (src / "folder" / "a.txt").write_text("a")
    (src / "folder" / "keep.txt").write_text("source copy")
    (dst / "folder" / "keep.txt").write_text("destination copy")
    store = TG.store()
    store.tag("Local", "", str(src / "folder"), "Review later")
    store.tag("Local", "", str(src / "folder" / "a.txt"), "Important")
    store.tag("Local", "", str(src / "folder" / "keep.txt"), "Important")
    plan, scan = _plan(src, dst, ["folder"], TC.ConflictAction.SKIP)
    assert [c.name for c in scan.conflicts] == ["keep.txt"]
    left, right = _panes(win, src, dst)
    win._start_transfer_between(left, right, [str(src / "folder")], move=True,
                                conflict_plan=plan)
    _settle(win, lambda: (dst / "folder" / "a.txt").exists()
            and not (src / "folder" / "a.txt").exists())
    assert (src / "folder" / "keep.txt").read_text() == "source copy"
    assert store.tags_of("Local", str(dst / "folder" / "a.txt")) == ["Important"]
    assert store.tags_of("Local", str(src / "folder" / "keep.txt")) == ["Important"]
    assert store.tags_of("Local", str(dst / "folder" / "keep.txt")) == []
    # The source folder is still there (it holds keep.txt), so is its tag.
    assert store.tags_of("Local", str(src / "folder")) == ["Review later"]
    assert store.tags_of("Local", str(dst / "folder")) == []


def test_edge_a_renamed_folder_takes_its_tag_to_the_new_name(win, tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    (src / "photos").mkdir(parents=True)
    dst.mkdir()
    (src / "photos" / "p.jpg").write_text("p")
    (dst / "photos").write_text("a file of the same name")
    store = TG.store()
    store.tag("Local", "", str(src / "photos"), "Review later")
    plan, scan = _plan(src, dst, ["photos"], TC.ConflictAction.RENAME)
    assert scan.conflicts[0].type_mismatch
    left, right = _panes(win, src, dst)
    win._start_transfer_between(left, right, [str(src / "photos")], move=True,
                                conflict_plan=plan)
    renamed = dst / "photos (1)"
    _settle(win, lambda: (renamed / "p.jpg").exists() and not (src / "photos").exists())
    assert store.tags_of("Local", str(renamed)) == ["Review later"]
    assert store.tags_of("Local", str(dst / "photos")) == []


def test_happy_overwrite_answers_still_move_every_tag(win, tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    (src / "folder").mkdir(parents=True)
    (dst / "folder").mkdir(parents=True)
    (src / "folder" / "keep.txt").write_text("new")
    (dst / "folder" / "keep.txt").write_text("old")
    store = TG.store()
    store.tag("Local", "", str(src / "folder"), "Review later")
    store.tag("Local", "", str(src / "folder" / "keep.txt"), "Important")
    plan, _scan = _plan(src, dst, ["folder"], TC.ConflictAction.OVERWRITE)
    left, right = _panes(win, src, dst)
    win._start_transfer_between(left, right, [str(src / "folder")], move=True,
                                conflict_plan=plan)
    _settle(win, lambda: not (src / "folder").exists())
    assert (dst / "folder" / "keep.txt").read_text() == "new"
    assert store.tags_of("Local", str(dst / "folder" / "keep.txt")) == ["Important"]
    assert store.tags_of("Local", str(dst / "folder")) == ["Review later"]


def test_edge_keeps_inside_counts_only_skips_below_the_folder(tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    for root in (src, dst):
        (root / "folder").mkdir(parents=True)
        (root / "folder2").mkdir(parents=True)
        (root / "folder" / "a.txt").write_text("a")
        (root / "folder2" / "b.txt").write_text("b")
    fs = LocalFS()
    scan = TC.scan_conflicts(fs, fs, [str(src / "folder"), str(src / "folder2")], str(dst))
    plan = TC.ConflictPlan(fs, scan)
    by_name = {c.name: c for c in scan.conflicts}
    plan.decide(by_name["a.txt"], TC.ConflictAction.RENAME)
    plan.decide(by_name["b.txt"], TC.ConflictAction.SKIP)
    assert not plan.keeps_inside(str(dst / "folder"))  # a rename still moves the file
    assert plan.keeps_inside(str(dst / "folder2"))
    assert plan.keeps_inside(str(dst))  # nested below
    assert not plan.keeps_inside(str(dst / "folder2" / "b.txt"))  # the entry itself
