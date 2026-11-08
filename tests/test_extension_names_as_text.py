"""The bundled extensions show file, mount, VM and device names as text
(review round 2, the sweep after the Forensic Tools fix).

Qt renders a tooltip - and a label or message box in AutoText - as rich
text when it looks like markup. These places still showed a name that is
not axross's that way, so ``<b>x</b>`` restyled the text and ``<!--`` hid
the rest of it:

* Folder Treemap's tooltip (the file or folder name under the mouse),
* Drives Overview's tooltip on an unreadable drive (the error names the
  mount) and its status line,
* VirtualBox's error boxes (VBoxManage names the file) and the "Attach
  <file> to:" question,
* Backup Repository Info's Unlock error (restic / borg name the
  repository) and its status line,
* the Audio Mixer's message line (an error names the settings file).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, QPointF, Qt, QTimer  # noqa: E402
from PyQt6.QtGui import QMouseEvent  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QLabel,
    QMainWindow,
    QMessageBox,
    QToolTip,
)

from tests.markup_probe import BOLD, markup_leaks, shown  # noqa: E402

APP = QApplication.instance() or QApplication([])
#: A file name (no "/") that, as markup, is a bold "x" and hides what follows.
NAME = "<b>x<!--"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"names_text_{name}",
                                                  ROOT / "resources" / "extensions" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses need it, as the host does
    spec.loader.exec_module(module)
    return module


class Api:
    """What these extensions use of ExtensionAPI; jobs run at once."""

    def __init__(self) -> None:
        self.window = QMainWindow()
        self.actions: dict = {}
        self.handlers: dict = {}
        self.widget = None
        self.notes: list = []

    def add_context_action(self, label, cb, applies_to="any", extensions=(), icon=None):
        self.actions[label] = cb

    def add_dock(self, title, widget, icon=None):
        self.widget = widget

    def on(self, event, callback):
        self.handlers.setdefault(event, []).append(callback)

    def current(self):
        return None

    def notify(self, text):
        self.notes.append(text)

    def run_in_background(self, work, on_done=None, on_error=None):
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 - handed on like the host does
            if on_error is not None:
                on_error(exc)
            return
        if on_done is not None:
            on_done(result)


def _modal_texts(run) -> list[tuple[str, Qt.TextFormat]]:
    """``(text, format)`` of the label of every modal dialog *run()* opens;
    each is closed (rejected) once read."""
    seen: list = []

    def answer():
        box = QApplication.activeModalWidget()
        if box is not None:
            label = (box.findChild(QLabel, "qt_msgbox_label") if isinstance(box, QMessageBox)
                     else box.findChild(QLabel))
            seen.append((label.text(), label.textFormat()))
            box.reject()
        QTimer.singleShot(20, answer)

    QTimer.singleShot(0, answer)
    run()
    APP.processEvents()
    return seen


def _reads(text: str, fmt: Qt.TextFormat) -> str:
    """What the user reads of a label in *fmt* showing *text*."""
    return shown(text, fmt == Qt.TextFormat.RichText
                 or (fmt == Qt.TextFormat.AutoText and Qt.mightBeRichText(text)))


# -- Folder Treemap -------------------------------------------------------------------


def test_sad_the_treemap_tooltip_names_the_file_as_it_is():
    """The tooltip of a box is the entry's name: shown literally."""
    FT = _load("folder_treemap")
    api = Api()
    FT.activate(api)
    view = api.widget
    view.set_entries([(NAME, 4096, False)], True)
    view.resize(300, 200)
    view.show()
    view.grab()  # lays the boxes out
    try:
        event = QMouseEvent(QMouseEvent.Type.MouseMove, QPointF(50, 50), QPointF(50, 50),
                            Qt.MouseButton.NoButton, Qt.MouseButton.NoButton,
                            Qt.KeyboardModifier.NoModifier)
        view.mouseMoveEvent(event)
        tip = QToolTip.text()
        assert tip, "no tooltip was shown"
        assert shown(tip).startswith(NAME + "\n")
    finally:
        QToolTip.hideText()
        view.close()


# -- Drives Overview -------------------------------------------------------------------


def test_sad_an_unreadable_drive_names_its_mount_as_text_in_the_tooltip():
    DO = _load("drives_overview")

    def broken(path):
        raise OSError(f"{path}: host {BOLD} is down")

    drives = DO.measure(DO.parse_proc_mounts("//nas/s /mnt/nas cifs rw 0 0\n"), usage=broken)
    panel = DO.DrivesPanel(refresh=lambda: None, open_folder=lambda path: None)
    panel.set_drives(drives)
    panel.status.setText(f"Cannot list the drives: {BOLD}")
    try:
        leaks, seen = markup_leaks(panel, (BOLD,))
        assert not leaks, leaks
        assert seen >= 2  # the tooltip and the status line read it as text
        assert shown(panel.table.item(0, DO.COL_USE).toolTip()).endswith(f"host {BOLD} is down")
    finally:
        panel.close()


# -- VirtualBox ------------------------------------------------------------------------


def test_sad_a_virtualbox_error_naming_the_file_is_shown_as_it_is(tmp_path, monkeypatch):
    VB = _load("virtualbox")
    vbox = tmp_path / f"{NAME}.vbox"

    def broken(path, exe=None):
        raise VB.VBoxError(f"Machine settings file '{path}' is invalid")

    monkeypatch.setattr(VB, "register", broken)
    api = Api()
    VB.activate(api)
    ctx = SimpleNamespace(paths=[str(vbox)], is_local=True)
    seen = _modal_texts(lambda: api.actions["Register in VirtualBox"](ctx))
    assert len(seen) == 1
    assert _reads(*seen[0]) == f"Machine settings file '{vbox}' is invalid"


def test_edge_attach_names_the_disk_as_text_when_it_asks_for_the_vm(tmp_path, monkeypatch):
    VB = _load("virtualbox")
    disk = tmp_path / f"{NAME}.vdi"
    monkeypatch.setattr(VB, "vboxmanage", lambda: "/usr/bin/VBoxManage")
    monkeypatch.setattr(VB, "run", lambda argv: "")
    monkeypatch.setattr(VB, "parse_vms", lambda text: [("Ubuntu", "8a8e9b3c")])
    api = Api()
    VB.activate(api)
    ctx = SimpleNamespace(paths=[str(disk)], is_local=True)
    seen = _modal_texts(lambda: api.actions["Attach to VirtualBox VM…"](ctx))
    assert len(seen) == 1
    text, fmt = seen[0]
    assert fmt == Qt.TextFormat.PlainText and text == f"Attach {NAME}.vdi to:"


# -- Backup Repository Info ------------------------------------------------------------


def test_sad_a_failed_unlock_names_the_repository_as_text(tmp_path, monkeypatch):
    import tests.test_backup_repos_extension as T

    BR = T.BR
    api = T.SyncApi()
    BR.activate(api)
    repo = T.borg_repo(tmp_path / "repo")
    ctx = SimpleNamespace(backend=T.FS, folder=str(repo), paths=[], items=[], pane=None,
                          is_local=True)
    api.actions[("Backup Repository Info…", "folder")](ctx)
    dialog = api.window._backup_repo_dialog
    try:
        error = BR.RepoError(f"borg: Repository {tmp_path}/{NAME} does not exist.")
        seen = _modal_texts(lambda: dialog.failed(error))
        assert [_reads(*s) for s in seen] == [str(error)]
        assert _reads(dialog.status.text(), dialog.status.textFormat()) == str(error)
    finally:
        dialog.close()


# -- Audio Mixer -----------------------------------------------------------------------


def test_sad_the_mixer_names_the_settings_file_it_cannot_save_as_text(tmp_path):
    MIX = _load("audio_mixer")
    blocker = tmp_path / NAME
    blocker.write_text("a file, not a folder")
    panel = MIX.MixerPanel(settings_path=blocker / "audio.json", device_lister=lambda: [])
    try:
        panel._pending = {"output_volume": 50}
        panel.save_now()
        text = panel.message.text()
        assert NAME in text
        assert _reads(text, panel.message.textFormat()) == text
    finally:
        panel.shutdown()
        panel.close()
