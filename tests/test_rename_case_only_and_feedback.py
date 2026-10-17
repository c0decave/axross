"""F2 Rename: a failure is shown, and a case-only rename works where case
does not tell names apart.

Found in review (round 3, files):

* A rename the backend refused (permission denied, a vanished file) was
  only logged; the dialog closed and the file kept its name without a
  word.
* "report.txt" -> "Report.txt" on a case-insensitive file system (APFS,
  NTFS, SMB shares) was refused as "Target already exists": exists()
  finds the file itself. server_side_move had the same guard. Where the
  folder lists no entry spelled exactly like the new name, the "existing"
  target is the source, and the rename goes through a temporary name -
  some servers ignore a rename that changes only the case.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.server_ops import rename_target_taken, server_side_move  # noqa: E402
from models.file_item import FileItem  # noqa: E402


class CaseInsensitiveFS:
    """One flat folder that keeps the spelling but matches names ignoring
    case, like APFS or NTFS. A rename that changes only the case is
    silently ignored, as some SMB/FAT servers do."""

    def __init__(self, *names: str) -> None:
        self.files: dict[str, tuple[str, bytes]] = {}
        for n in names:
            self.files[n.casefold()] = (n, f"data of {n}".encode())
        self.fail_rename_to: str | None = None
        self.renames: list[tuple[str, str]] = []

    # -- path helpers (POSIX-like) ---------------------------------------
    name = "ci"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return "/".join(p.rstrip("/") for p in parts if p) or "/"

    def parent(self, path: str) -> str:
        return path.rsplit("/", 1)[0] or "/"

    def _leaf(self, path: str) -> str:
        return path.rsplit("/", 1)[-1]

    # -- file operations --------------------------------------------------
    def exists(self, path: str) -> bool:
        return self._leaf(path).casefold() in self.files

    def list_dir(self, path: str) -> list[FileItem]:
        return [FileItem(name=n) for n, _ in self.files.values()]

    def rename(self, src: str, dst: str) -> None:
        self.renames.append((src, dst))
        s, d = self._leaf(src), self._leaf(dst)
        if self.fail_rename_to is not None and d == self.fail_rename_to:
            raise PermissionError(13, "Permission denied", dst)
        if s.casefold() not in self.files:
            raise FileNotFoundError(2, "No such file", src)
        if s.casefold() == d.casefold():
            return  # the server ignores a case-only rename
        if d.casefold() in self.files:
            raise FileExistsError(17, "File exists", dst)
        _, data = self.files.pop(s.casefold())
        self.files[d.casefold()] = (d, data)

    def names(self) -> list[str]:
        return sorted(n for n, _ in self.files.values())


# --------------------------------------------------------------------------
# core.server_ops
# --------------------------------------------------------------------------


def test_happy_case_only_rename_on_a_case_insensitive_backend():
    fs = CaseInsensitiveFS("report.txt", "other.txt")
    assert not rename_target_taken(fs, "/d/report.txt", "/d/Report.txt")
    server_side_move(fs, "/d/report.txt", "/d/Report.txt")
    assert fs.names() == ["Report.txt", "other.txt"]
    assert fs.files["report.txt"][1] == b"data of report.txt"
    # Through a temporary name, not a direct (ignored) case-only rename.
    assert len(fs.renames) == 2


def test_happy_case_only_rename_on_a_case_sensitive_local_folder(tmp_path):
    (tmp_path / "report.txt").write_text("x")
    fs = LocalFS()
    server_side_move(fs, str(tmp_path / "report.txt"), str(tmp_path / "Report.txt"))
    assert sorted(os.listdir(tmp_path)) == ["Report.txt"]


def test_sad_case_twin_on_a_case_sensitive_folder_is_a_real_conflict(tmp_path):
    (tmp_path / "report.txt").write_text("lower")
    (tmp_path / "Report.txt").write_text("upper")
    if len(os.listdir(tmp_path)) != 2:
        pytest.skip("this temp folder is case-insensitive")
    fs = LocalFS()
    assert rename_target_taken(fs, str(tmp_path / "report.txt"), str(tmp_path / "Report.txt"))
    with pytest.raises(FileExistsError):
        server_side_move(fs, str(tmp_path / "report.txt"), str(tmp_path / "Report.txt"))
    assert (tmp_path / "report.txt").read_text() == "lower"
    assert (tmp_path / "Report.txt").read_text() == "upper"


def test_sad_other_name_differing_in_case_is_still_taken():
    """OTHER.txt matches other.txt, a different file: refuse."""
    fs = CaseInsensitiveFS("report.txt", "other.txt")
    assert rename_target_taken(fs, "/d/report.txt", "/d/OTHER.txt")
    with pytest.raises(FileExistsError):
        server_side_move(fs, "/d/report.txt", "/d/OTHER.txt")
    assert fs.names() == ["other.txt", "report.txt"]


def test_sad_failed_second_step_puts_the_old_name_back():
    fs = CaseInsensitiveFS("report.txt")
    fs.fail_rename_to = "Report.txt"
    with pytest.raises(PermissionError):
        server_side_move(fs, "/d/report.txt", "/d/Report.txt")
    assert fs.names() == ["report.txt"]


def test_edge_case_only_rename_of_a_long_name_keeps_the_temp_name_short_enough():
    long_name = "a" * 250 + ".txt"
    fs = CaseInsensitiveFS(long_name)
    server_side_move(fs, f"/d/{long_name}", f"/d/{long_name.upper()}")
    assert fs.names() == [long_name.upper()]
    temp = fs.renames[0][1].rsplit("/", 1)[-1]
    assert len(temp.encode()) <= 255


def test_edge_free_name_is_not_taken():
    fs = CaseInsensitiveFS("report.txt")
    assert not rename_target_taken(fs, "/d/report.txt", "/d/final.txt")


# --------------------------------------------------------------------------
# The pane: F2 Rename
# --------------------------------------------------------------------------


class _PaneBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def make_pane(self, backend):
        from ui import column_prefs as CP
        from ui.file_pane import FilePaneWidget

        p = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        pane = FilePaneWidget(backend)
        self.addCleanup(pane.deleteLater)
        pane.navigate(str(self.folder))
        self.app.processEvents()
        return pane

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.folder = self.root / "f"
        self.folder.mkdir()
        (self.folder / "report.txt").write_text("x")

    def select(self, pane, name):
        m = pane._proxy
        row = next(r for r in range(m.rowCount()) if m.data(m.index(r, 0)) == name)
        pane._table.selectRow(row)

    def rename(self, pane, new_name):
        with mock.patch(
            "PyQt6.QtWidgets.QInputDialog.getText", return_value=(new_name, True)
        ), mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            pane._rename_selected()
        return warning


class _CaseInsensitiveLocalFS(LocalFS):
    """LocalFS whose exists() answers like APFS / NTFS."""

    def exists(self, path):
        d, n = os.path.split(path)
        try:
            return any(e.lower() == n.lower() for e in os.listdir(d))
        except OSError:
            return False


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() != 0, "POSIX, not root")
class PaneRenameTest(_PaneBase):
    def test_sad_refused_rename_is_shown(self) -> None:
        pane = self.make_pane(LocalFS())
        self.select(pane, "report.txt")
        os.chmod(self.folder, 0o555)
        self.addCleanup(os.chmod, self.folder, 0o755)
        warning = self.rename(pane, "final.txt")
        warning.assert_called_once()
        self.assertIn("Permission denied", warning.call_args.args[2])
        self.assertEqual(sorted(os.listdir(self.folder)), ["report.txt"])

    def test_happy_case_only_rename_on_a_case_insensitive_backend(self) -> None:
        pane = self.make_pane(_CaseInsensitiveLocalFS())
        self.select(pane, "report.txt")
        warning = self.rename(pane, "Report.txt")
        warning.assert_not_called()
        self.assertEqual(sorted(os.listdir(self.folder)), ["Report.txt"])

    def test_edge_real_conflict_still_says_already_exists(self) -> None:
        (self.folder / "final.txt").write_text("keep")
        pane = self.make_pane(LocalFS())
        self.select(pane, "report.txt")
        warning = self.rename(pane, "final.txt")
        warning.assert_called_once()
        self.assertIn("already exists", warning.call_args.args[2])
        self.assertEqual((self.folder / "final.txt").read_text(), "keep")


# --------------------------------------------------------------------------
# The same guard in Batch Rename
# --------------------------------------------------------------------------


@pytest.fixture()
def qapp():
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _batch(qapp, backend, folder, names, pairs, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from ui.batch_rename_dialog import BatchRenameDialog

    warnings: list[str] = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda _parent, _title, text, *a, **k: warnings.append(text)),
    )
    dlg = BatchRenameDialog(backend, str(folder), [FileItem(name=n) for n in names])
    monkeypatch.setattr(dlg, "_compute_new_names", lambda: list(pairs))
    try:
        dlg._apply()
    finally:
        dlg.deleteLater()
    return warnings


def test_happy_batch_case_only_rename_on_a_case_insensitive_backend(
    qapp, tmp_path, monkeypatch
):
    (tmp_path / "report.txt").write_text("x")
    warnings = _batch(
        qapp, _CaseInsensitiveLocalFS(), tmp_path, ["report.txt"],
        [("report.txt", "Report.txt")], monkeypatch,
    )
    assert warnings == []
    assert sorted(os.listdir(tmp_path)) == ["Report.txt"]


def test_sad_batch_rename_onto_another_file_is_still_refused(qapp, tmp_path, monkeypatch):
    (tmp_path / "report.txt").write_text("x")
    (tmp_path / "other.txt").write_text("keep")
    warnings = _batch(
        qapp, _CaseInsensitiveLocalFS(), tmp_path, ["report.txt"],
        [("report.txt", "OTHER.txt")], monkeypatch,
    )
    assert warnings and "already exists" in warnings[0]
    assert sorted(os.listdir(tmp_path)) == ["other.txt", "report.txt"]
