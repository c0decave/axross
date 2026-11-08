"""A pane closed while an extension's job runs does not mark it failed
(review round 2).

Before: Checksum Manifest's Create, Image Batch and Forensic Tools'
Convert to Raw called ``ctx.pane.refresh_after_change()`` in ``on_done``
on the pane the job was started from. Closed meanwhile, the pane was a
deleted Qt object: the refresh raised RuntimeError ("wrapped C/C++ object
... has been deleted") and the host recorded the extension as failed for
work that had been done. Now the three use one helper
(``resources/extensions/_pane.py``) that leaves a deleted pane alone.
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
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QMainWindow, QMessageBox, QWidget  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
FS = LocalFS()


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"pane_closed_{name}",
                                                  ROOT / "resources" / "extensions" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Pane(QWidget):
    """Refreshes like a file pane: through Qt (so a deleted one raises)."""

    def refresh_after_change(self):
        self.update()


class Api:
    """Runs the job at once and, like the host, records what on_done raised."""

    def __init__(self) -> None:
        self.window = QMainWindow()
        self.actions: dict = {}
        self.errors: list = []

    def add_context_action(self, label, cb, applies_to="any", extensions=()):
        self.actions[label] = cb

    def notify(self, text):
        pass

    def run_in_background(self, work, on_done=None, on_error=None):
        result = work()
        try:
            if on_done is not None:
                on_done(result)
        except Exception as exc:  # noqa: BLE001 - the host marks the extension failed
            self.errors.append(exc)


def _closed_pane() -> Pane:
    pane = Pane()
    sip.delete(pane)
    assert sip.isdeleted(pane)
    return pane


def _accept_dialogs() -> None:
    """Answer every modal dialog the action opens with its default (Yes)."""

    def answer():
        box = QApplication.activeModalWidget()
        if isinstance(box, QMessageBox):
            box.button(QMessageBox.StandardButton.Yes).click()
        elif isinstance(box, QDialog):
            box.accept()
        QTimer.singleShot(20, answer)

    QTimer.singleShot(0, answer)


def test_sad_checksum_manifest_with_its_pane_closed(tmp_path):
    CM = _load("checksum_manifest")
    api = Api()
    CM.activate(api)
    (tmp_path / "a.txt").write_bytes(b"a")
    ctx = SimpleNamespace(backend=FS, folder=str(tmp_path), items=[], pane=_closed_pane())
    api.actions["Create SHA256SUMS"](ctx)
    assert (tmp_path / CM.MANIFEST_NAME).exists()
    assert api.errors == []


def test_sad_image_batch_with_its_pane_closed(tmp_path):
    IB = _load("image_batch")
    api = Api()
    IB.activate(api)
    image = QImage(8, 8, QImage.Format.Format_RGB32)
    image.fill(0x336699)
    assert image.save(str(tmp_path / "a.png"))
    ctx = SimpleNamespace(backend=FS, folder=str(tmp_path), pane=_closed_pane(),
                          items=[SimpleNamespace(name="a.png", is_dir=False)])
    _accept_dialogs()
    api.actions["Resize / Convert Images…"](ctx)
    assert os.listdir(tmp_path / IB.OUT_FOLDER)
    assert api.errors == []


def test_sad_forensic_convert_with_its_pane_closed(tmp_path, monkeypatch):
    FT = _load("forensic_tools")
    image = tmp_path / "disk.qcow2"
    image.write_bytes(b"QFI\xfb")
    monkeypatch.setattr(FT, "convert_to_raw", lambda path, target: target)
    api = Api()
    FT.activate(api)
    ctx = SimpleNamespace(backend=FS, folder=str(tmp_path), paths=[str(image)], items=[],
                          pane=_closed_pane(), is_local=True)
    _accept_dialogs()
    api.actions["Convert to Raw Image (qemu-img)…"](ctx)
    assert api.errors == []
