"""A folder that fails to list is unknown, never empty; sync never replaces by accident.

Measured before: ``tree_compare.walk`` skipped a folder whose listing
failed (a dropped SFTP channel, a timeout, EACCES) as if it were empty.
Every file under it on the other side then compared as "missing on the
right", ``plan_sync`` turned that into a copy with ``overwrites=False``,
and the main window queued the copy without a conflict plan -- the
transfer engine's IF_EXISTS_OVERWRITE replaced the right side's newer
file that nobody had compared.

Now a listing failure makes that folder and everything under it on the
other side UNKNOWN (a conflict, never an action), and every compare copy
that does not say it overwrites runs with IF_EXISTS_FAIL.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.sync import ConflictPolicy, plan_sync  # noqa: E402
from core.transfer_conflicts import IF_EXISTS_FAIL, ConflictPlan  # noqa: E402
from core.tree_compare import Status, compare_trees, walk  # noqa: E402
from models.file_item import FileItem  # noqa: E402

BASE = datetime(2026, 5, 1, 12, 0, 0)


def _f(name, size=10, *, is_dir=False) -> FileItem:
    return FileItem(name=name, size=size, modified=BASE, is_dir=is_dir)


class _Tree:
    """Backend stub over ``{path: [FileItem]}``; paths in ``broken`` fail."""

    def __init__(self, tree, broken=()):
        self._tree = tree
        self._broken = set(broken)

    @property
    def name(self) -> str:
        return "Stub"

    def join(self, a: str, b: str) -> str:
        return f"{a.rstrip('/')}/{b}"

    def list_dir(self, path: str):
        if path in self._broken:
            raise OSError("Connection reset by peer")
        return self._tree.get(path, [])


def _hasher(backend, path):
    return "same"


LEFT = _Tree({
    "/l": [_f("sub", is_dir=True), _f("subway", is_dir=True), _f("top.txt")],
    "/l/sub": [_f("report.txt"), _f("deep", is_dir=True)],
    "/l/sub/deep": [_f("x.txt")],
    "/l/subway": [_f("ok.txt")],
})


def _right(broken=()):
    return _Tree(
        {
            "/r": [_f("sub", is_dir=True), _f("subway", is_dir=True)],
            "/r/sub": [_f("report.txt", size=99)],
            "/r/subway": [],
        },
        broken=broken,
    )


def _by_rel(entries):
    return {e.rel_path: e for e in entries}


# --------------------------------------------------------------------------
# walk / compare_trees
# --------------------------------------------------------------------------


def test_happy_walk_reports_which_folder_could_not_be_listed():
    unlisted: dict[str, str] = {}
    found = walk(_right(broken={"/r/sub"}), "/r", unlisted=unlisted)
    assert set(found) == {"sub", "subway"}
    assert list(unlisted) == ["sub"]
    assert "Connection reset" in unlisted["sub"]


def test_happy_listable_trees_compare_as_before():
    entries = _by_rel(compare_trees(LEFT, "/l", _right(), "/r", hasher=_hasher))
    assert entries["sub/report.txt"].status == Status.DIFFERS
    assert entries["sub/deep/x.txt"].status == Status.LEFT_ONLY
    assert entries["subway/ok.txt"].status == Status.LEFT_ONLY
    assert entries["sub"].status == Status.SAME


def test_sad_files_under_an_unlisted_folder_are_unknown_not_missing():
    entries = _by_rel(
        compare_trees(LEFT, "/l", _right(broken={"/r/sub"}), "/r", hasher=_hasher)
    )
    for rel in ("sub/report.txt", "sub/deep", "sub/deep/x.txt"):
        assert entries[rel].status == Status.UNKNOWN, rel
        assert "could not be listed" in entries[rel].reason
        assert "right" in entries[rel].reason
    # The folder itself is not "the same" when one side was never read.
    assert entries["sub"].status == Status.UNKNOWN


def test_sad_the_left_side_failing_is_symmetric():
    left = _Tree({"/l": [_f("sub", is_dir=True)]}, broken={"/l/sub"})
    right = _Tree({"/r": [_f("sub", is_dir=True)], "/r/sub": [_f("mine.txt")]})
    entries = _by_rel(compare_trees(left, "/l", right, "/r", hasher=_hasher))
    assert entries["sub/mine.txt"].status == Status.UNKNOWN
    assert "left" in entries["sub/mine.txt"].reason


def test_sad_an_unlisted_folder_never_becomes_a_sync_action():
    entries = compare_trees(LEFT, "/l", _right(broken={"/r/sub"}), "/r", hasher=_hasher)
    for policy in ConflictPolicy:
        plan = plan_sync(entries, policy=policy)
        touched = {a.rel_path for a in plan.actions}
        assert not touched & {"sub", "sub/report.txt", "sub/deep", "sub/deep/x.txt"}, policy
        assert "sub/report.txt" in {c.rel_path for c in plan.conflicts}


def test_edge_a_sibling_sharing_the_name_prefix_is_still_compared():
    entries = _by_rel(
        compare_trees(LEFT, "/l", _right(broken={"/r/sub"}), "/r", hasher=_hasher)
    )
    assert entries["subway/ok.txt"].status == Status.LEFT_ONLY
    assert entries["top.txt"].status == Status.LEFT_ONLY


def test_edge_an_unlisted_folder_facing_a_file_still_differs_by_type():
    left = _Tree({"/l": [_f("x", is_dir=True)]}, broken={"/l/x"})
    right = _Tree({"/r": [_f("x")]})
    entries = _by_rel(compare_trees(left, "/l", right, "/r", hasher=_hasher))
    assert entries["x"].status == Status.DIFFERS
    assert "type" in entries["x"].reason


def test_edge_an_unlisted_folder_on_one_side_only_is_unknown():
    left = _Tree({"/l": [_f("d", is_dir=True)]}, broken={"/l/d"})
    right = _Tree({"/r": []})
    entries = _by_rel(compare_trees(left, "/l", right, "/r", hasher=_hasher))
    assert entries["d"].status == Status.UNKNOWN


def test_edge_an_unlisted_root_leaves_everything_unknown():
    entries = compare_trees(LEFT, "/l", _right(broken={"/r"}), "/r", hasher=_hasher)
    assert entries
    assert {e.status for e in entries} == {Status.UNKNOWN}
    assert plan_sync(entries).actions == []


# --------------------------------------------------------------------------
# The copies the compare window queues
# --------------------------------------------------------------------------


class _Backend:
    name = "fake"

    def parent(self, path: str) -> str:
        return path.rsplit("/", 1)[0] or "/"

    def separator(self) -> str:
        return "/"

    def mkdir(self, path: str) -> None:
        pass


class _Pane:
    def __init__(self, current_path: str) -> None:
        self.backend = _Backend()
        self.current_path = current_path


class _Manager:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], object]] = []

    def transfer_files(self, **kw):
        self.calls.append((list(kw["source_paths"]), kw.get("conflict_plan")))
        return []

    def transfer_files_in_background(self, on_done=None, **kw):
        # The window walks off the GUI thread; the jobs are the same.
        jobs = self.transfer_files(**kw)
        if on_done is not None:
            on_done(jobs)


class _StatusBar:
    def showMessage(self, *a):  # noqa: N802 - Qt name
        pass


def _win():
    from ui.main_window import MainWindow

    class _Win:
        _start_transfer_between = MainWindow._start_transfer_between
        _transfer_direction = staticmethod(MainWindow._transfer_direction)
        _apply_sync = MainWindow._apply_sync
        _copy_compared = MainWindow._copy_compared
        _transfer_compared = MainWindow._transfer_compared

        def __init__(self) -> None:
            self._transfer_target_panes = set()
            self._transfer_manager = _Manager()

        def statusBar(self):  # noqa: N802 - Qt name
            return _StatusBar()

        def _compared_panes_open(self, *panes) -> bool:
            return True

    return _Win()


def _item(rel: str, overwrites: bool) -> dict:
    return {
        "rel_path": rel,
        "kind": "copy",
        "direction": "to_right",
        "overwrites": overwrites,
        "source": f"/l/{rel}",
        "dest": f"/r/{rel}",
    }


def _mode(plan, dest: str) -> str:
    if plan is None:
        return "overwrite"
    resolved = plan.resolve(dest)
    return resolved[1] if resolved is not None else "skip"


def test_happy_a_sync_copy_that_adds_a_file_never_replaces_one():
    win = _win()
    win._apply_sync(_Pane("/l"), _Pane("/r"), [_item("new.txt", overwrites=False)])
    [(paths, plan)] = win._transfer_manager.calls
    assert paths == ["/l/new.txt"]
    assert _mode(plan, "/r/new.txt") == IF_EXISTS_FAIL


def test_happy_a_sync_copy_that_says_it_overwrites_still_overwrites():
    win = _win()
    win._apply_sync(_Pane("/l"), _Pane("/r"), [_item("both.txt", overwrites=True)])
    [(paths, plan)] = win._transfer_manager.calls
    assert paths == ["/l/both.txt"]
    assert _mode(plan, "/r/both.txt") == "overwrite"


def test_edge_a_mixed_plan_in_one_folder_keeps_each_answer():
    win = _win()
    win._apply_sync(
        _Pane("/l"),
        _Pane("/r"),
        [_item("new.txt", overwrites=False), _item("both.txt", overwrites=True)],
    )
    modes = {}
    for paths, plan in win._transfer_manager.calls:
        for p in paths:
            modes[p] = _mode(plan, p.replace("/l/", "/r/"))
    assert modes == {"/l/new.txt": IF_EXISTS_FAIL, "/l/both.txt": "overwrite"}


def test_sad_a_compare_window_copy_never_replaces_a_file():
    win = _win()
    win._copy_compared(_Pane("/l"), _Pane("/r"), "to_right", [("/l/a.txt", "/r/a.txt")])
    [(paths, plan)] = win._transfer_manager.calls
    assert _mode(plan, "/r/a.txt") == IF_EXISTS_FAIL


class NeverReplacePlanTest(unittest.TestCase):
    """The plan the compare copies use, against the real transfer manager."""

    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def test_edge_every_job_including_folder_contents_refuses_to_replace(self) -> None:
        import shutil
        import tempfile

        from core.local_fs import LocalFS
        from core.transfer_manager import TransferManager

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "src" / "dir").mkdir(parents=True)
        (tmp / "dst").mkdir()
        (tmp / "src" / "a.txt").write_text("a")
        (tmp / "src" / "dir" / "b.txt").write_text("b")
        fs = LocalFS()
        mgr = TransferManager()
        self.addCleanup(mgr._thread.wait, 2000)
        self.addCleanup(mgr._thread.quit)
        self.addCleanup(mgr._worker.stop)
        with mock.patch.object(mgr._worker, "enqueue"):
            jobs = mgr.transfer_files(
                fs,
                fs,
                [str(tmp / "src" / "a.txt"), str(tmp / "src" / "dir")],
                str(tmp / "dst"),
                conflict_plan=ConflictPlan.never_replace(fs),
            )
        self.assertEqual(len(jobs), 2)
        self.assertEqual({j.if_exists for j in jobs}, {IF_EXISTS_FAIL})
