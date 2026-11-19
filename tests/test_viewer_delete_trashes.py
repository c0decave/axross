"""Del in the image and media viewers moves to the trash, as Del in the pane.

Review: Del in a viewer deleted the shown file permanently on a connection
with a trash, where Del in the pane moves it to the trash; the question
did not say "permanently", and it showed the name escaped twice ("Tom &
Jerry.png" read "Tom &amp; Jerry.png").

Now Del moves to the trash where core.trash.supports_trash(backend), and
asks so; Shift+Del deletes permanently, after a question of its own (and
Del does too where there is no trash). The question shows the name as it
is.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _NoTrashFS(LocalFS):
    supports_trash = False


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(LocalFS, "home", lambda self: str(home))
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    return home


@pytest.fixture
def asked(monkeypatch):
    questions: list[tuple[str, str]] = []

    def question(parent, title, text, *args, **kwargs):
        questions.append((title, _reads(text)))
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", question)
    return questions


def _reads(text: str) -> str:
    """What the user reads in a message box showing *text*."""
    from PyQt6.QtGui import QTextDocument

    if not Qt.mightBeRichText(text):
        return text
    doc = QTextDocument()
    doc.setHtml(text)
    return doc.toPlainText()


def _picture(folder: Path, name: str) -> Path:
    from PyQt6.QtGui import QColor, QImage

    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    img = QImage(16, 16, QImage.Format.Format_RGB32)
    img.fill(QColor("red"))
    assert img.save(str(path), "PNG")
    return path


def test_happy_del_moves_the_shown_file_to_the_trash(tmp_path, home, asked):
    from ui import viewer_file_actions as VFA

    fs = LocalFS()
    pic = _picture(tmp_path / "pics", "Tom & Jerry.png")
    assert VFA.delete_file(None, fs, str(pic), None) is True
    assert not pic.exists()
    entries = T.list_trash(fs)
    assert [e.original_path for e in entries] == [str(pic)]
    (title, text), = asked
    assert "trash" in (title + text).lower() and "permanent" not in text.lower()
    assert "Tom & Jerry.png" in text and "&amp;" not in text


def test_happy_shift_del_deletes_permanently_after_its_own_question(tmp_path, home, asked):
    from ui import viewer_file_actions as VFA

    fs = LocalFS()
    pic = _picture(tmp_path / "pics", "a.png")
    assert VFA.delete_file(None, fs, str(pic), None, permanent=True) is True
    assert not pic.exists()
    assert T.list_trash(fs) == []
    (title, text), = asked
    assert "permanent" in (title + text).lower()


def test_edge_without_a_trash_del_asks_for_a_permanent_delete(tmp_path, home, asked):
    from ui import viewer_file_actions as VFA

    fs = _NoTrashFS()
    pic = _picture(tmp_path / "pics", "a.png")
    assert VFA.delete_file(None, fs, str(pic), None) is True
    assert not pic.exists()
    (title, text), = asked
    assert "permanent" in (title + text).lower()


def _wait(cond, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return cond()


@pytest.mark.parametrize("mods, permanent", [
    (Qt.KeyboardModifier.NoModifier, False),
    (Qt.KeyboardModifier.ShiftModifier, True),
])
def test_happy_image_viewer_del_trashes_and_shift_del_deletes(tmp_path, home, monkeypatch,
                                                              mods, permanent):
    from ui import viewer_file_actions as VFA
    from ui.image_viewer import ImageViewerDialog

    calls = []
    monkeypatch.setattr(VFA, "delete_file",
                        lambda parent, backend, path, pane, *, permanent=False:
                        calls.append(permanent) or False)
    pics = [str(_picture(tmp_path / "pics", n)) for n in ("a.png", "b.png")]
    dlg = ImageViewerDialog(LocalFS(), pics[0], siblings=pics)
    try:
        dlg.show()
        assert _wait(lambda: dlg._original is not None)
        dlg.activateWindow()
        APP.processEvents()
        QTest.keyClick(APP.focusWidget() or dlg, Qt.Key.Key_Delete, mods)
        assert calls == [permanent]
    finally:
        dlg.close()


@pytest.mark.parametrize("mods, permanent", [
    (Qt.KeyboardModifier.NoModifier, False),
    (Qt.KeyboardModifier.ShiftModifier, True),
])
def test_happy_media_viewer_del_trashes_and_shift_del_deletes(tmp_path, home, monkeypatch,
                                                              mods, permanent):
    from ui import media_viewer as MV
    from ui import viewer_file_actions as VFA

    calls = []
    monkeypatch.setattr(VFA, "delete_file",
                        lambda parent, backend, path, pane, *, permanent=False:
                        calls.append(permanent) or False)
    monkeypatch.setattr(MV.MediaViewerDialog, "current_path", lambda self: "/x/a.png")
    _picture(tmp_path / "pics", "a.png")
    window = _media_window(MV, tmp_path / "pics")
    try:
        window.show()
        window.activateWindow()
        APP.processEvents()
        QTest.keyClick(APP.focusWidget() or window, Qt.Key.Key_Delete, mods)
        assert calls == [permanent]
    finally:
        window.close()


def _media_window(MV, folder: Path):
    return MV.MediaViewerDialog(LocalFS(), str(folder), MV.MediaViewOptions())


# -- a share's trash: the same question as the pane's (ui.shared_trash) -------------------


class _ShareFS(LocalFS):
    """A connection whose trash is a folder at the top of a share (SMB, S3 …)."""

    trash_is_private = False


def test_safety_del_on_a_share_says_where_the_trash_is(tmp_path, home, asked, monkeypatch):
    """Review (round 1): Del in a viewer moved the file into the share's
    trash after a plain "Move to the trash?" - the pane's Del says that the
    trash is a folder of the share, readable by whoever may open it, and
    offers Delete Permanently."""
    from ui import shared_trash as ST
    from ui import viewer_file_actions as VFA

    shared = []

    def ask(parent, title, question, folder):
        shared.append((title, question, folder))
        return ST.TRASH

    monkeypatch.setattr(ST, "ask_move_to_shared_trash", ask)
    fs = _ShareFS()
    pic = _picture(tmp_path / "pics", "a.png")
    assert T.shared_trash_folder(fs) is not None
    assert VFA.delete_file(None, fs, str(pic), None) is True
    assert not pic.exists()
    (title, question, folder), = shared
    assert "a.png" in question and folder == T.shared_trash_folder(fs)
    assert asked == [], "the plain question too"
    assert [e.original_path for e in T.list_trash(fs)] == [str(pic)]


def test_safety_on_a_share_delete_permanently_asks_its_own_question(tmp_path, home, asked, monkeypatch):
    from ui import shared_trash as ST
    from ui import viewer_file_actions as VFA

    monkeypatch.setattr(ST, "ask_move_to_shared_trash", lambda *a: ST.DELETE)
    fs = _ShareFS()
    pic = _picture(tmp_path / "pics", "a.png")
    assert VFA.delete_file(None, fs, str(pic), None) is True
    assert not pic.exists()
    assert T.list_trash(fs) == []
    (title, text), = asked
    assert "permanent" in (title + text).lower()


def test_edge_on_a_share_cancel_keeps_the_file(tmp_path, home, asked, monkeypatch):
    from ui import shared_trash as ST
    from ui import viewer_file_actions as VFA

    monkeypatch.setattr(ST, "ask_move_to_shared_trash", lambda *a: None)
    fs = _ShareFS()
    pic = _picture(tmp_path / "pics", "a.png")
    assert VFA.delete_file(None, fs, str(pic), None) is False
    assert pic.exists() and asked == []


def test_edge_a_private_trash_asks_the_plain_question(tmp_path, home, asked, monkeypatch):
    from ui import shared_trash as ST
    from ui import viewer_file_actions as VFA

    monkeypatch.setattr(ST, "ask_move_to_shared_trash",
                        lambda *a: pytest.fail("a private trash is no share's"))
    pic = _picture(tmp_path / "pics", "b.png")
    assert VFA.delete_file(None, LocalFS(), str(pic), None) is True
    assert len(asked) == 1
