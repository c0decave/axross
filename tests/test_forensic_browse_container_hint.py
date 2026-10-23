"""Browse File System on a container image says how to get at it (wish-list
item 8 follow-up).

Before: Browse File System (Sleuth Kit)… on a qcow2, a VMDK or a dynamic
VDI said "No partition or file system found in this image." - wrong, the
image has partitions, they are just inside a container The Sleuth Kit
cannot read; core.disk_image already knew it (ImageInfo.note: "Convert it
to a raw image…"). Now Browse shows that note, with a Convert to Raw…
button for the formats qemu-img converts.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox, QPushButton  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from tests.test_disk_image import LINUX, SECTOR, gpt_image, put_ext4  # noqa: E402
from tests.test_forensic_tools_extension import FT, qapp  # noqa: E402

QEMU_IMG = shutil.which("qemu-img")
BROWSE = "Browse File System (Sleuth Kit)…"


def _qcow2_header() -> bytes:
    return b"QFI\xfb" + struct.pack(">I", 3) + b"\0" * 16 + struct.pack(">Q", 1 << 30) + b"\0" * 480


def _dynamic_vdi_header() -> bytes:
    head = bytearray(0x200)
    struct.pack_into("<I", head, 0x40, 0xBEDA107F)
    struct.pack_into("<I", head, 0x4C, 1)  # dynamic
    struct.pack_into("<Q", head, 0x170, 1 << 30)
    return bytes(head)


class Api:
    def __init__(self):
        self.window = QMainWindow()
        self.actions = {}
        self.notes = []

    def add_context_action(self, label, cb, applies_to="any", extensions=()):
        self.actions[label] = cb

    def run_in_background(self, work, on_done=None, on_error=None):
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001
            if on_error is None:
                raise
            on_error(exc)
            return
        if on_done is not None:
            on_done(result)

    def notify(self, text):
        self.notes.append(text)


def _browse(path: Path, click: str | None):
    """Browse *path*; the modal hint box is answered by clicking the button
    labelled *click* (None: just read it and close it). Returns the box
    text and the button labels it had."""
    app = qapp()
    api = Api()
    FT.activate(api)
    seen = {}

    def answer():
        box = QApplication.activeModalWidget()
        if not isinstance(box, QMessageBox):
            QTimer.singleShot(20, answer)
            return
        seen["text"] = box.text()
        seen["buttons"] = [b.text() for b in box.findChildren(QPushButton)]
        target = next((b for b in box.findChildren(QPushButton) if b.text() == click), None)
        (target or box.button(QMessageBox.StandardButton.Close)
         or box.findChildren(QPushButton)[0]).click()

    QTimer.singleShot(0, answer)
    ctx = SimpleNamespace(backend=LocalFS(), folder=str(path.parent), paths=[str(path)], items=[],
                          pane=None, is_local=True)
    api.actions[BROWSE](ctx)
    app.processEvents()
    return seen, api


@pytest.mark.skipif(QEMU_IMG is None, reason="qemu-img not installed")
def test_e2e_browse_on_a_qcow2_offers_convert_to_raw_and_converts(tmp_path, monkeypatch):
    image = gpt_image([(LINUX, 2048, 4095, "root")], size=4 * 1024 * 1024)
    put_ext4(image, 2048 * SECTOR, b"inqcow")
    raw = tmp_path / "src.raw"
    raw.write_bytes(bytes(image))
    qcow = tmp_path / "vm.qcow2"
    subprocess.run([QEMU_IMG, "convert", "-f", "raw", "-O", "qcow2", str(raw), str(qcow)],
                   check=True)
    raw.unlink()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    seen, api = _browse(qcow, "Convert to Raw…")
    assert "No partition" not in seen["text"]
    assert "qemu-img convert" in seen["text"] and "qcow2" in seen["text"]
    assert (tmp_path / "vm.raw").read_bytes() == bytes(image)
    assert any("vm.raw" in n for n in api.notes)


def test_happy_a_dynamic_vdi_names_vboxmanage_and_offers_convert(tmp_path):
    vdi = tmp_path / "box.vdi"
    vdi.write_bytes(_dynamic_vdi_header())
    seen, _api = _browse(vdi, None)
    assert "VBoxManage clonemedium" in seen["text"]
    assert "Convert to Raw…" in seen["buttons"]


def test_sad_close_converts_nothing(tmp_path, monkeypatch):
    qcow = tmp_path / "vm.qcow2"
    qcow.write_bytes(_qcow2_header())
    called = []
    monkeypatch.setattr(FT, "convert_to_raw", lambda *a, **k: called.append(a))
    seen, _api = _browse(qcow, None)
    assert "Convert to Raw…" in seen["buttons"] and called == []
    assert not (tmp_path / "vm.raw").exists()


def test_sad_an_e01_gets_its_hint_but_no_qemu_convert(tmp_path):
    e01 = tmp_path / "case.e01"
    e01.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\0" * 600)
    seen, _api = _browse(e01, None)
    assert "ewfexport" in seen["text"]
    assert "Convert to Raw…" not in seen["buttons"]


def test_edge_an_image_with_nothing_in_it_still_says_so(tmp_path):
    blank = tmp_path / "blank.img"
    blank.write_bytes(b"\0" * 1024 * 1024)
    seen, _api = _browse(blank, None)
    assert "No partition or file system found" in seen["text"]
    assert "Convert to Raw…" not in seen["buttons"]
