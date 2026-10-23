"""Disk Image… in the pane menu for an image recognised by its content
(wish-list item 6 gap).

Before, the right-click entry appeared by file name only
(core.disk_image.looks_like_image): an image without a telling name was
reachable only through Identify File Type. Now the menu also offers it
when the content says disk image - without reading remote files on the GUI
thread:

* a local regular file: its first CONTENT_PROBE_BYTES (4 KiB) are read -
  every container header, the GPT header at 512 and the MBR fit; a FIFO or
  device is never opened;
* any pane: what Identify File Type found for the file (same size) counts;
* a remote file Identify has not seen: by name only, nothing is read.
"""

from __future__ import annotations

import os
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import disk_image as DI  # noqa: E402
from tests.test_disk_image import LINUX, SECTOR, gpt_image, put_ext4, put_fat32  # noqa: E402


def _qcow2() -> bytes:
    return b"QFI\xfb" + struct.pack(">I", 3) + b"\0" * 16 + struct.pack(">Q", 1 << 30) + b"\0" * 480


def _gpt_bytes() -> bytes:
    data = gpt_image([(LINUX, 2048, 4095, "root")], size=4 * 1024 * 1024)
    put_ext4(data, 2048 * SECTOR, b"rootfs")
    return bytes(data)


# -- core -------------------------------------------------------------------------------


def test_happy_local_content_says_image_for_gpt_and_qcow2(tmp_path):
    (tmp_path / "blob").write_bytes(_gpt_bytes())
    (tmp_path / "vm-disk").write_bytes(_qcow2())
    assert DI.local_content_says_image(str(tmp_path / "blob"))
    assert DI.local_content_says_image(str(tmp_path / "vm-disk"))


def test_sad_text_missing_and_a_folder_are_no_image(tmp_path):
    (tmp_path / "notes").write_text("just text\n" * 100)
    (tmp_path / "dir").mkdir()
    assert not DI.local_content_says_image(str(tmp_path / "notes"))
    assert not DI.local_content_says_image(str(tmp_path / "missing"))
    assert not DI.local_content_says_image(str(tmp_path / "dir"))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_sad_a_fifo_is_never_opened(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    result = []
    worker = threading.Thread(target=lambda: result.append(DI.local_content_says_image(str(fifo))),
                              daemon=True)
    worker.start()
    worker.join(5)
    if worker.is_alive():  # blocked in open(): free it so the run ends
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
    assert result == [False]


def test_edge_reads_at_most_the_probe_size_and_a_fat_volume_is_no_disk(tmp_path, monkeypatch):
    fat = bytearray(1024 * 1024)
    put_fat32(fat, 0)
    (tmp_path / "fat").write_bytes(bytes(fat))
    (tmp_path / "empty").write_bytes(b"")
    asked = []
    real_read = os.read
    monkeypatch.setattr(DI.os, "read", lambda fd, n: asked.append(n) or real_read(fd, n))
    assert not DI.local_content_says_image(str(tmp_path / "fat"))  # a volume, not a disk
    assert not DI.local_content_says_image(str(tmp_path / "empty"))
    (tmp_path / "big").write_bytes(_gpt_bytes())
    assert DI.local_content_says_image(str(tmp_path / "big"))
    limit = DI.CONTENT_PROBE_BYTES
    assert asked and max(asked) <= limit and sum(asked) <= 3 * limit


@pytest.mark.parametrize("mime, engine, expected", [
    ("application/x-qemu-disk", "disk image", True),
    ("application/x-raw-disk-image", "disk image", True),
    ("application/x-cd-image", "Qt", True),
    ("text/plain", "text heuristic", False),
    ("", "", False),
])
def test_edge_type_says_image(mime, engine, expected):
    assert DI.type_says_image(mime, engine) is expected


# -- the pane menu --------------------------------------------------------------------------

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _select(pane, name):
    table = pane._table
    table.clearSelection()
    for row in range(pane._proxy.rowCount()):
        index = pane._proxy.index(row, 0)
        if index.data() == name:
            table.selectionModel().select(
                index,
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
            return
    raise AssertionError(f"{name} not listed")


def _labels(pane):
    return [a.text().replace("&", "") for a in pane._build_context_menu().actions()]


@pytest.fixture
def local_pane(tmp_path):
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "blob").write_bytes(_gpt_bytes())
    (folder / "notes").write_text("text\n")
    (folder / "sub").mkdir()
    pane = FilePaneWidget(LocalFS())
    pane.show()
    pane.navigate(str(folder))
    assert wait(lambda: pane._proxy.rowCount() >= 3)
    yield pane
    pane.close()
    pane.deleteLater()
    APP.processEvents()


@pytest.fixture
def ram_pane():
    from core.ram_fs import RamFsSession
    from ui.file_pane import FilePaneWidget

    ram = RamFsSession()
    with ram.open_write("/blob") as fh:
        fh.write(_gpt_bytes())
    with ram.open_write("/notes") as fh:
        fh.write(b"text\n")
    pane = FilePaneWidget(ram)
    pane.show()
    pane.navigate("/")
    assert wait(lambda: pane._proxy.rowCount() >= 2)
    yield pane
    pane.close()
    pane.deleteLater()
    APP.processEvents()


def test_e2e_a_local_image_without_a_telling_name_gets_disk_image(local_pane):
    _select(local_pane, "blob")
    menu = local_pane._build_context_menu()
    action = next(a for a in menu.actions() if a.text().replace("&", "") == "Disk Image…")
    assert action.property("axCommand") == "disk-image"
    action.trigger()
    dialogs = [w for w in APP.topLevelWidgets() if type(w).__name__ == "DiskImageDialog"]
    assert dialogs
    dlg = dialogs[-1]
    assert wait(lambda: dlg.info is not None)
    assert dlg.info.scheme == "gpt"
    dlg.close()


def test_sad_text_and_folders_get_no_disk_image(local_pane):
    _select(local_pane, "notes")
    assert "Disk Image…" not in _labels(local_pane)
    _select(local_pane, "sub")
    assert "Disk Image…" not in _labels(local_pane)


def test_sad_a_remote_pane_reads_no_content_for_the_menu(ram_pane, monkeypatch):
    opened = []
    real = ram_pane._backend.open_read
    monkeypatch.setattr(ram_pane._backend, "open_read",
                        lambda path, *a, **k: opened.append(path) or real(path, *a, **k))
    _select(ram_pane, "blob")
    assert "Disk Image…" not in _labels(ram_pane)
    assert opened == []


def test_edge_identify_result_offers_disk_image_on_a_remote_pane(ram_pane):
    _select(ram_pane, "blob")
    dlg = ram_pane.identify_file_type()
    assert wait(lambda: dlg.idle)
    assert "Disk Image…" in _labels(ram_pane)
    dlg.close()
    APP.processEvents()
    assert "Disk Image…" in _labels(ram_pane)  # remembered after the window closed
    _select(ram_pane, "notes")
    assert "Disk Image…" not in _labels(ram_pane)


def test_edge_a_changed_size_forgets_the_identify_result(ram_pane):
    _select(ram_pane, "blob")
    dlg = ram_pane.identify_file_type()
    assert wait(lambda: dlg.idle)
    dlg.close()
    with ram_pane._backend.open_write("/blob") as fh:
        fh.write(b"now text\n")
    ram_pane.refresh()
    assert wait(lambda: any(ram_pane._model.get_item(r).name == "blob"
                            and ram_pane._model.get_item(r).size == 9
                            for r in range(ram_pane._model.rowCount())))
    _select(ram_pane, "blob")
    assert "Disk Image…" not in _labels(ram_pane)


def test_edge_a_new_backend_forgets_identify_results(ram_pane):
    from core.ram_fs import RamFsSession

    _select(ram_pane, "blob")
    dlg = ram_pane.identify_file_type()
    assert wait(lambda: dlg.idle)
    dlg.close()
    other = RamFsSession()
    with other.open_write("/blob") as fh:
        fh.write(_gpt_bytes())
    ram_pane.set_backend(other, "/")
    assert wait(lambda: ram_pane._proxy.rowCount() >= 1)
    _select(ram_pane, "blob")
    assert "Disk Image…" not in _labels(ram_pane)


def test_sad_a_local_fs_subclass_is_not_read_either(tmp_path, monkeypatch):
    """An MTP device is a LocalFS subclass over a FUSE mount that may fetch
    the whole file on open: only a plain LocalFS pane probes content."""
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    class DeviceFS(LocalFS):
        pass

    (tmp_path / "blob").write_bytes(_gpt_bytes())
    probed = []
    monkeypatch.setattr(DI, "local_content_says_image", lambda p, *a: probed.append(p) or True)
    pane = FilePaneWidget(DeviceFS())
    try:
        pane.show()
        pane.navigate(str(tmp_path))
        assert wait(lambda: pane._proxy.rowCount() >= 1)
        _select(pane, "blob")
        assert "Disk Image…" not in _labels(pane) and probed == []
    finally:
        pane.close()
        pane.deleteLater()
        APP.processEvents()
