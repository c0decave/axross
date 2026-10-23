"""Disk Image… in the pane (punch-list item 6): the partition table of an
image, a read-only mount of a volume, writing only after the tick and a
confirmation, the mounted folder in a new pane, and Unmount.

The mount itself is faked (no root here); core.loop_mount's own tests check
the commands."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import loop_mount as LM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests.test_disk_image import LINUX, SECTOR, gpt_image, put_ext4  # noqa: E402

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
def image(tmp_path):
    data = gpt_image([(LINUX, 2048, 4095, "root"), (LINUX, 4096, 6143, "data")], size=4 * 1024 * 1024)
    put_ext4(data, 2048 * SECTOR, b"rootfs")
    put_ext4(data, 4096 * SECTOR, b"datafs")
    path = tmp_path / "disk.img"
    path.write_bytes(bytes(data))
    return path


class FakeMount:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def __call__(self, image, *, offset, size, writable, password=None, cancelled=None):
        self.calls.append((image, offset, size, writable))
        if self.fail:
            raise LM.MountError(self.fail)
        mount = LM.Mount(image, "/dev/loop9", f"/run/media/u/p{len(self.calls)}", "udisksctl",
                         not writable)
        return LM._remember(mount)


@pytest.fixture(autouse=True)
def no_leftover_mounts():
    yield
    for m in LM.active_mounts():
        LM.forget(m)


def make(image, **kw):
    from ui.disk_image_dialog import DiskImageDialog

    opened = []
    dlg = DiskImageDialog(LocalFS(), str(image), open_folder=opened.append, **kw)
    dlg.start()
    assert wait(lambda: dlg.info is not None)
    return dlg, opened


# -- happy ------------------------------------------------------------------------------


def test_happy_the_table_shows_every_partition(image):
    dlg, _ = make(image)
    try:
        assert dlg.table.rowCount() == 2
        assert [dlg.table.item(r, 6).text() for r in range(2)] == ["rootfs", "datafs"]
        assert dlg.table.item(0, 5).text() == "ext4" and dlg.table.item(1, 4).text() == "data"
        assert "GPT" in dlg.summary.text() and "2 partitions" in dlg.summary.text()
        assert dlg.mount_button.isEnabled() and dlg.mount_button.text() == "Mount Read-Only"
    finally:
        dlg.close()


def test_happy_mount_is_read_only_and_opens_a_pane(image):
    fake = FakeMount()
    dlg, opened = make(image, mount=fake)
    try:
        dlg.table.selectRow(1)
        assert dlg.mount_selected()
        assert wait(lambda: opened)
        assert fake.calls == [(str(image), 4096 * SECTOR, 2048 * SECTOR, False)]
        assert opened == ["/run/media/u/p1"]
        assert dlg.mounts.count() == 1 and "[ro, udisksctl]" in dlg.mounts.item(0).text()
    finally:
        dlg.close()


def test_happy_writing_needs_the_tick_and_a_yes(image, monkeypatch):
    fake = FakeMount()
    dlg, opened = make(image, mount=fake)
    asked = []
    monkeypatch.setattr(QMessageBox, "warning",
                        lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Yes)
    try:
        dlg.writable.setChecked(True)
        assert dlg.mount_button.text() == "Mount Read-Write…"
        assert dlg.mount_selected()
        assert wait(lambda: opened)
        assert fake.calls[0][3] is True and "WRITE" in asked[0]
    finally:
        dlg.close()


def test_happy_unmount(image):
    fake = FakeMount()
    unmounted = []
    def unmount(m, password=None, cancelled=None):
        unmounted.append(m)
        LM.forget(m)

    dlg, opened = make(image, mount=fake, unmount=unmount)
    try:
        dlg.mount_selected()
        assert wait(lambda: opened)
        dlg.mounts.setCurrentRow(0)
        assert dlg.unmount_selected()
        # Unmount runs in the background since the verification round.
        assert wait(lambda: unmounted and dlg.mounts.count() == 0)
    finally:
        dlg.close()


def test_happy_context_menu_offers_disk_image_for_an_image(image, monkeypatch):
    from ui.main_window import MainWindow

    home = tempfile.mkdtemp()
    with mock.patch("pathlib.Path.home", return_value=Path(home)):
        win = MainWindow()
    try:
        win._reconnect_timer.stop()
        (image.parent / "notes.txt").write_text("x")
        pane = win._active_pane
        pane.navigate(str(image.parent))
        _select(pane, "disk.img")
        labels = [a.text() for a in pane._build_context_menu().actions()]
        assert "Disk Image…" in labels
        _select(pane, "notes.txt")
        assert "Disk Image…" not in [a.text() for a in pane._build_context_menu().actions()]
        _select(pane, "disk.img")
        dlg = pane.show_disk_image()
        assert wait(lambda: dlg.info is not None)
        assert dlg._open_folder == win.open_local_folder
        before = len(win._panes)
        win.open_local_folder(str(image.parent))
        assert len(win._panes) == before + 1
        assert wait(lambda: win._active_pane.current_path == str(image.parent))
        dlg.close()
    finally:
        win.close()
        win.deleteLater()
        shutil.rmtree(home, ignore_errors=True)


def _select(pane, name):
    from PyQt6.QtCore import QItemSelectionModel

    table = pane._table
    table.clearSelection()
    for row in range(pane._proxy.rowCount()):
        index = pane._proxy.index(row, 0)
        if index.data() == name:
            table.selectionModel().select(
                index, QItemSelectionModel.SelectionFlag.Select
                | QItemSelectionModel.SelectionFlag.Rows)
            return
    raise AssertionError(f"{name} not listed")


# -- sad --------------------------------------------------------------------------------


def test_sad_no_to_writing_mounts_nothing(image, monkeypatch):
    fake = FakeMount()
    dlg, _ = make(image, mount=fake)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.No)
    try:
        dlg.writable.setChecked(True)
        assert not dlg.mount_selected() and fake.calls == []
    finally:
        dlg.close()


def test_sad_a_failed_mount_is_reported(image, monkeypatch):
    shown = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    dlg, opened = make(image, mount=FakeMount(fail="udisksctl: Not authorized"))
    try:
        dlg.mount_selected()
        assert wait(lambda: shown)
        assert "Not authorized" in shown[0] and not opened and dlg.mounts.count() == 0
    finally:
        dlg.close()


def test_sad_sudo_is_still_tried_when_udisksctl_and_pkexec_refuse(image, monkeypatch, tmp_path):
    """The decided chain is udisksctl, then pkexec, then sudo (with
    remembering the sudo password switched off). With all three installed
    and the first two refusing (no polkit agent, an SSH session), the
    password is asked when it comes to sudo - from the worker, through the
    UI thread - and sudo mounts."""
    import functools

    from PyQt6.QtWidgets import QInputDialog

    from core import open_limits as OL
    from core import sudo_password as SP
    from tests.test_loop_mount import Runner

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    SP.set_remember(False)

    every = lambda name: f"/usr/bin/{name}"  # noqa: E731
    monkeypatch.setattr(LM, "_which", every)
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    asked = []
    monkeypatch.setattr(QInputDialog, "getText",
                        lambda *a, **k: (asked.append(a[1]), ("pw", True))[1])
    run = Runner([
        (["udisksctl", "loop-setup"], 1, "", "Error setting up loop device: Not authorized"),
        (["pkexec"], 127, "", "Error executing command as another user: No authentication agent found."),
        (["sudo", "-n", "-v"], 1, "", "a password is required"),
        (["sudo", "-S", "-p", "", "-v"], 0, "", ""),
        (["sudo"], 0, "/dev/loop5\n", ""),
    ])
    mount = functools.partial(LM.mount_partition, runner=run, which=every,
                              mount_root=str(tmp_path / "mounts"))
    dlg, opened = make(image, mount=mount)
    try:
        assert asked == []  # nothing asked before polkit had its turn
        assert dlg.mount_selected()
        assert wait(lambda: opened or warned)
        assert warned == [] and opened
        (m,) = LM.active_mounts()
        assert m.method == "sudo" and m.read_only and asked
        argv, stdin = run.calls[-1]
        assert argv[:4] == ["sudo", "-S", "-p", ""] and stdin == "pw\n"
        assert "pw" not in argv
    finally:
        dlg.close()


def test_sad_closing_the_dialog_releases_a_worker_waiting_for_the_password(image, monkeypatch):
    """The worker asks for the sudo password while the dialog closes: it is
    answered "no password" at once instead of waiting for a reply that
    never comes, and no question opens over the closed dialog."""
    import threading

    from PyQt6.QtWidgets import QInputDialog

    monkeypatch.setattr(QInputDialog, "getText",
                        lambda *a, **k: pytest.fail("asked after the dialog closed"))
    dlg, _ = make(image)
    got = []
    worker = threading.Thread(target=lambda: got.append(dlg._password_from_worker("Mount")))
    worker.start()
    dlg.close()
    worker.join(5)
    APP.processEvents()
    assert not worker.is_alive() and got == [None]


def test_sad_a_remote_image_cannot_be_mounted(image):
    from ui.disk_image_dialog import DiskImageDialog

    with mock.patch("ui.disk_image_dialog._is_local", return_value=False):
        dlg = DiskImageDialog(LocalFS(), str(image))
    dlg.start()
    try:
        assert wait(lambda: dlg.info is not None)
        assert dlg.table.rowCount() == 2  # read through the backend
        assert not dlg.mount_button.isEnabled() and "copy it" in dlg.note.text()
        assert not dlg.mount_selected()
    finally:
        dlg.close()


def test_sad_not_an_image(tmp_path):
    path = tmp_path / "random.img"
    path.write_bytes(os.urandom(64 * 1024).replace(b"\x55\xaa", b"\0\0"))
    dlg, _ = make(path)
    try:
        assert dlg.table.rowCount() == 0 and not dlg.mount_button.isEnabled()
        assert "No disk image" in dlg.note.text()
    finally:
        dlg.close()


# -- edge -------------------------------------------------------------------------------


def test_edge_a_qcow2_explains_how_to_get_at_it(tmp_path):
    path = tmp_path / "vm.qcow2"
    path.write_bytes(b"QFI\xfb\0\0\0\x03" + b"\0" * 1024)
    dlg, _ = make(path)
    try:
        assert "qcow2" in dlg.summary.text() and "qemu-img convert" in dlg.note.text()
        assert not dlg.mount_button.isEnabled()
    finally:
        dlg.close()


def test_edge_the_summary_shows_hostile_names_as_text(tmp_path):
    """The summary is rich text: a file name or a volume label from the
    image's bytes is escaped, never read as markup."""
    from tests.test_disk_image import put_ext4 as ext4

    data = bytearray(2 * 1024 * 1024)
    ext4(data, 0, b"<i>x</i>&y")
    path = tmp_path / "a<b>c.img"
    path.write_bytes(bytes(data))
    dlg, _ = make(path)
    try:
        text = dlg.summary.text()
        assert "a&lt;b&gt;c.img" in text and "&lt;i&gt;x&lt;/i&gt;&amp;y" in text
        assert "<i>" not in text and "a<b>c" not in text
    finally:
        dlg.close()


def test_edge_only_sudo_and_the_question_cancelled_mounts_nothing(image, monkeypatch, tmp_path):
    """With sudo as the only way the password is asked from the worker like
    in the full chain (no question up front: a remembered password or a
    valid sudo ticket needs none); cancelling it mounts nothing."""
    import functools

    from PyQt6.QtWidgets import QInputDialog

    from core import open_limits as OL
    from tests.test_loop_mount import Runner

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    only_sudo = lambda name: "/usr/bin/sudo" if name == "sudo" else None  # noqa: E731
    monkeypatch.setattr(LM, "_which", only_sudo)
    asked = []
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (asked.append(1), ("", False))[1])
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    run = Runner([(["sudo", "-n", "-v"], 1, "", "a password is required")])
    mount = functools.partial(LM.mount_partition, runner=run, which=only_sudo,
                              mount_root=str(tmp_path / "mounts"))
    dlg, opened = make(image, mount=mount)
    try:
        assert asked == [] and dlg.mount_selected()
        assert wait(lambda: warned)
        assert asked == [1] and "no password given" in warned[0]
        assert not opened and LM.active_mounts() == []
    finally:
        dlg.close()


def test_e2e_the_sudo_password_is_asked_once_for_two_mounts(image, monkeypatch, tmp_path):
    """Remembering is on by default: the second mount and the unmount run
    without a question; the password never reaches an argument list."""
    import functools

    from PyQt6.QtWidgets import QInputDialog

    from core import open_limits as OL
    from core import sudo_password as SP
    from tests.test_loop_mount import Runner, fake_system

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    SP.forget()
    only_sudo = lambda name: "/usr/bin/sudo" if name == "sudo" else None  # noqa: E731
    monkeypatch.setattr(LM, "_which", only_sudo)
    asked = []
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (asked.append(1), ("pw", True))[1])
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    no_ticket = (["sudo", "-n", "-v"], 1, "", "a password is required")
    validate = (["sudo", "-S", "-p", "", "-v"], 0, "", "")
    run = Runner([no_ticket, validate, (["sudo", "-S"], 0, "/dev/loop5\n", ""),
                  no_ticket, validate, (["sudo", "-S"], 0, "/dev/loop6\n", ""),
                  no_ticket, validate, (["sudo", "-S"], 0, "", "")])
    mount = functools.partial(LM.mount_partition, runner=run, which=only_sudo,
                              mount_root=str(tmp_path / "mounts"))
    unmount = functools.partial(LM.unmount, runner=run, which=only_sudo)
    dlg, opened = make(image, mount=mount, unmount=unmount)
    try:
        dlg.table.selectRow(0)
        assert dlg.mount_selected() and wait(lambda: len(opened) == 1)
        dlg.table.selectRow(1)
        assert dlg.mount_selected() and wait(lambda: len(opened) == 2)
        assert asked == [1] and warned == []
        first = LM.active_mounts()[0]
        fake_system(tmp_path, monkeypatch, first.device, first.image, first.mountpoint)
        dlg.mounts.setCurrentRow(0)
        assert dlg.unmount_selected() and wait(lambda: dlg.mounts.count() == 1)
        assert asked == [1] and warned == []
        assert all("pw" not in argv for argv in run.raw_calls)
    finally:
        dlg.close()
        SP.forget()


def test_sad_a_wrong_sudo_password_is_asked_again_with_a_note(image, monkeypatch, tmp_path):
    import functools

    from PyQt6.QtWidgets import QInputDialog

    from core import open_limits as OL
    from core import sudo_password as SP
    from tests.test_loop_mount import Runner

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    SP.forget()
    only_sudo = lambda name: "/usr/bin/sudo" if name == "sudo" else None  # noqa: E731
    labels = []
    answers = iter(["wrong", "right"])
    monkeypatch.setattr(QInputDialog, "getText",
                        lambda *a, **k: (labels.append(a[2]), (next(answers), True))[1])
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    run = Runner([(["sudo", "-n", "-v"], 1, "", "a password is required"),
                  (["sudo", "-S", "-p", "", "-v"], 1, "", "1 incorrect password attempt"),
                  (["sudo", "-S", "-p", "", "-v"], 0, "", ""),
                  (["sudo", "-S"], 0, "/dev/loop5\n", "")])
    mount = functools.partial(LM.mount_partition, runner=run, which=only_sudo,
                              mount_root=str(tmp_path / "mounts"))
    dlg, opened = make(image, mount=mount)
    try:
        assert dlg.mount_selected() and wait(lambda: opened or warned)
        assert warned == [] and len(labels) == 2
        assert "Wrong password" not in labels[0] and "Wrong password" in labels[1]
        assert run.calls[-1][1] == "right\n" and SP.remembered() == "right"
    finally:
        dlg.close()
        SP.forget()


# -- bughunt 2026-10-22: a closed dialog runs no further mount method ---------------------


def test_sad_closing_at_the_password_question_runs_no_more_methods(image, monkeypatch, tmp_path):
    """The dialog closes while the worker waits for the sudo password: the
    mount is over. Before, the "no password" answer only failed the sudo
    step and the chain went on to pkexec - a polkit prompt over a closed
    window, and a mount nobody asked for any more."""
    import functools

    from PyQt6.QtWidgets import QInputDialog

    from core import open_limits as OL
    from core import sudo_password as SP
    from tests.test_loop_mount import Runner

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    SP.forget()  # remembering on (the default), nothing remembered
    every = lambda name: f"/usr/bin/{name}"  # noqa: E731
    monkeypatch.setattr(LM, "_which", every)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    holder = {}

    def close_instead_of_answering(*_a, **_k):
        holder["dlg"].close()
        return "", False

    monkeypatch.setattr(QInputDialog, "getText", close_instead_of_answering)
    run = Runner([
        (["udisksctl", "loop-setup"], 1, "", "GDBus.Error:org.freedesktop.UDisks2.Error."
                                              "NotAuthorizedCanObtain: Not authorized"),
        (["sudo", "-n", "-v"], 1, "", "a password is required"),
        (["pkexec"], 0, "/dev/loop7\n", ""),
        (["udisksctl", "loop-setup"], 0, "Mapped file x as /dev/loop8.", ""),
        (["udisksctl", "mount"], 0, "Mounted /dev/loop8 at /run/media/u/x", ""),
    ])
    mount = functools.partial(LM.mount_partition, runner=run, which=every,
                              mount_root=str(tmp_path / "mounts"))
    dlg, opened = make(image, mount=mount)
    holder["dlg"] = dlg
    assert dlg.mount_selected()
    assert wait(lambda: dlg._mount_job._thread is not None
                and not dlg._mount_job._thread.is_alive())
    tools_run = [argv[0] for argv, _stdin in run.calls]
    assert "pkexec" not in tools_run
    assert tools_run.count("udisksctl") == 1  # only the quiet try before the question
    assert LM.active_mounts() == [] and not opened


# -- the Label column fills the table once the partitions arrive -------------------------
#
# Seen in the README screenshot: the dialog opens, the partitions arrive
# later and resizeColumnsToContents() shrank the stretched last column to
# its text; nothing resized the view again, so an empty strip stayed right
# of "Label".


def _shown_then_loaded(image, width):
    from ui.disk_image_dialog import DiskImageDialog

    dlg = DiskImageDialog(LocalFS(), str(image), open_folder=lambda _p: None)
    dlg.resize(width, 560)
    dlg.show()
    APP.processEvents()
    dlg.start()
    assert wait(lambda: dlg.info is not None)
    APP.processEvents()
    return dlg


def _right_gap(dlg):
    header = dlg.table.horizontalHeader()
    last = header.logicalIndex(header.count() - 1)
    end = header.sectionViewportPosition(last) + header.sectionSize(last)
    return dlg.table.viewport().width() - end


def test_happy_the_last_column_reaches_the_right_edge_after_loading(image):
    dlg = _shown_then_loaded(image, 880)
    try:
        assert _right_gap(dlg) <= 1
    finally:
        dlg.close()


def test_sad_a_narrow_dialog_keeps_every_column_at_its_content_width(image):
    dlg = _shown_then_loaded(image, 360)
    try:
        header = dlg.table.horizontalHeader()
        for col in range(header.count() - 1):
            assert header.sectionSize(col) >= dlg.table.sizeHintForColumn(col), col
    finally:
        dlg.close()


def test_edge_widening_after_loading_still_fills_the_table(image):
    dlg = _shown_then_loaded(image, 700)
    try:
        dlg.resize(1100, 560)
        APP.processEvents()
        assert _right_gap(dlg) <= 1
    finally:
        dlg.close()
