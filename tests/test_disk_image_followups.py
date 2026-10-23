"""Disk images, the open points of the verification round (item 6):

* Unmount ran on the GUI thread - the window froze while polkit / sudo
  asked (up to 300 s). It runs in the background now.
* Mounts lived only in memory: after a restart axross could neither list
  nor unmount them. They are kept in ``~/.config/axross/mounts.json``; on
  start only those still mounted come back.
* "Disk Image…" was offered by file name only. Identify File Type now
  recognises MBR disks by content too and offers *Disk Image…* for a disk
  image row, whatever the name.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import file_type as FT  # noqa: E402
from core import loop_mount as LM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests.test_disk_image import LINUX, SECTOR, gpt_image, mbr_entry, put_ext4, with_mbr  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "mounts.json"
    monkeypatch.setattr(LM, "mounts_file", lambda: path)
    LM.reset_for_tests()
    yield path
    LM.reset_for_tests()


# -- mounts survive a restart ---------------------------------------------------------


def test_happy_a_mount_is_stored_and_comes_back(store, tmp_path):
    point = str(tmp_path)  # not a mount point - stored, but dropped on reload
    m = LM._remember(LM.Mount("/img/a.img", "/dev/loop3", "/proc", "pkexec", True))
    other = LM._remember(LM.Mount("/img/b.img", "/dev/loop4", point, "udisksctl", False))
    data = json.loads(store.read_text())
    assert [e["mountpoint"] for e in data["mounts"]] == ["/proc", point]
    assert stat.S_IMODE(os.stat(store).st_mode) == 0o600
    LM.reset_for_tests()  # a restart
    assert LM.active_mounts() == [m]  # /proc is mounted, the tmp folder is not
    assert other not in LM.active_mounts()
    LM.forget(m)
    assert json.loads(store.read_text())["mounts"] == []


def test_sad_a_damaged_mounts_file_is_ignored(store):
    store.write_text("{not json")
    LM.reset_for_tests()
    assert LM.active_mounts() == []
    store.write_text(json.dumps({"mounts": [{"image": 3}, "x", {"mountpoint": "/proc"}]}))
    LM.reset_for_tests()
    assert LM.active_mounts() == []  # every entry lacks a field or has a wrong type


def test_edge_an_unknown_method_is_not_trusted(store):
    store.write_text(json.dumps({"mounts": [{"image": "/i", "device": "/dev/loop1",
                                             "mountpoint": "/proc", "method": "rm -rf",
                                             "read_only": True}]}))
    LM.reset_for_tests()
    assert LM.active_mounts() == []


# -- unmount in the background ----------------------------------------------------------


@pytest.fixture
def image(tmp_path):
    data = gpt_image([(LINUX, 2048, 4095, "root")], size=4 * 1024 * 1024)
    put_ext4(data, 2048 * SECTOR, b"rootfs")
    path = tmp_path / "disk.img"
    path.write_bytes(bytes(data))
    return path


def test_happy_unmount_runs_off_the_gui_thread(image, store):
    from ui.disk_image_dialog import DiskImageDialog

    m = LM._remember(LM.Mount(str(image), "/dev/loop9", "/run/media/u/x", "udisksctl", True))
    seen = {}
    release = threading.Event()

    def slow_unmount(mount, password=None, cancelled=None):
        seen["thread"] = threading.current_thread() is threading.main_thread()
        release.wait(5)
        LM.forget(mount)

    dlg = DiskImageDialog(LocalFS(), str(image), unmount=slow_unmount)
    try:
        dlg.mounts.setCurrentRow(0)
        assert dlg.unmount_selected()
        # The window still answers while the unmount waits (polkit, sudo).
        APP.processEvents()
        assert dlg.isEnabled() and not dlg.unmount_button.isEnabled()
        release.set()
        assert wait(lambda: dlg.mounts.count() == 0)
        assert seen["thread"] is False and "Unmounted" in dlg.note.text()
    finally:
        release.set()
        dlg.close()
    assert m not in LM.active_mounts()


def test_sad_a_failed_unmount_is_reported_and_kept(image, store, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from ui.disk_image_dialog import DiskImageDialog

    shown = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    LM._remember(LM.Mount(str(image), "/dev/loop9", "/run/media/u/x", "udisksctl", True))

    def refuse(mount, password=None, cancelled=None):
        raise LM.MountError("target is busy")

    dlg = DiskImageDialog(LocalFS(), str(image), unmount=refuse)
    try:
        dlg.mounts.setCurrentRow(0)
        dlg.unmount_selected()
        assert wait(lambda: shown)
        assert "busy" in shown[0] and dlg.mounts.count() == 1
    finally:
        dlg.close()


# -- Disk Image… from Identify File Type ------------------------------------------------


def mbr_head() -> bytes:
    image = bytearray(1024 * 1024)
    with_mbr(image, [mbr_entry(True, 0x83, 2048, 1024)])
    return bytes(image[:65536])


def test_happy_an_mbr_disk_is_recognised_by_content():
    info = FT.identify_bytes(mbr_head(), name="blob")
    assert "MBR" in info.description and info.mime == "application/x-raw-disk-image"


def test_edge_a_fat_boot_sector_or_hybrid_iso_is_no_mbr_disk():
    from tests.test_disk_image import put_fat32

    fat = bytearray(65536)
    put_fat32(fat, 0)
    assert "MBR" not in FT.identify_bytes(bytes(fat), name="stick").description
    iso = bytearray(mbr_head())
    iso[0x8001:0x8006] = b"CD001"
    assert "MBR" not in FT.identify_bytes(bytes(iso), name="live").description


def test_happy_identify_offers_disk_image_for_an_unnamed_image(tmp_path, monkeypatch):
    from ui import disk_image_dialog as DID
    from ui.file_type_dialog import FileTypeDialog

    blob = tmp_path / "blob"
    data = gpt_image([(LINUX, 2048, 4095, "r")], size=2 * 1024 * 1024)
    blob.write_bytes(bytes(data))
    (tmp_path / "note.txt").write_text("hello")
    opened = []

    class Fake:
        def __init__(self, backend, path, parent=None, **kw):
            opened.append(path)

        def setAttribute(self, *a):
            pass

        def show(self):
            pass

        def start(self):
            pass

    monkeypatch.setattr(DID, "DiskImageDialog", Fake)
    dlg = FileTypeDialog(LocalFS(), [str(blob), str(tmp_path / "note.txt")],
                         use_file_command=False)
    try:
        dlg.start()
        assert wait(lambda: dlg.idle)
        dlg.table.selectRow(1)
        assert not dlg.disk_image_button.isEnabled()
        dlg.table.selectRow(0)
        assert dlg.disk_image_button.isEnabled()
        dlg.disk_image_button.click()
        assert opened == [str(blob)]
    finally:
        dlg.close()
