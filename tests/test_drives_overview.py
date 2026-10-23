"""The Drives Overview extension (punch-list item 24).

Operator: *„extension, grafische übersicht aller drives mit space, used, also
hübsche diagramme kuchen, balken, tabellen listing von mounted und lokalen
drives (z.b. grafische darstellung von du -sch, es muss jetzt wirklich nicht
du sein, es darf python backend code sein)"*.

A panel: every local and mounted drive in a table (mount point, device,
type, size, used, free, use %), a pie of the selected drive and bars of all
drives. axross does not depend on psutil (core/ram_fs.py), so the mount list
comes from /proc/self/mounts on Linux, the drive letters on Windows, and
psutil or the ``mount`` command on macOS. A drive that does not answer (a
dead network mount) is shown as unknown after a timeout, never blocks.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


def load():
    path = EX.bundled_dir() / "drives_overview.py"
    spec = importlib.util.spec_from_file_location("example_drives_overview", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # as the extension host does (dataclasses need it)
    spec.loader.exec_module(module)
    return module


DO = load()

MOUNTS = """\
/dev/sda3 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0
tmpfs /tmp tmpfs rw 0 0
/dev/sdb /mnt/ext ext4 rw 0 0
/dev/sdb /mnt/ext-bind ext4 rw 0 0
//nas/share /mnt/nas cifs rw 0 0
nas:/export /mnt/nfs nfs4 rw 0 0
git_code /mnt/git_code vboxsf rw 0 0
/dev/sdc1 /run/media/user/USB\\040STICK vfat rw 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw 0 0
"""


def _usage(path):
    return {"/": (100, 60, 40), "/mnt/ext": (1000, 900, 100), "/tmp": (8, 1, 7)}.get(path, (50, 10, 40))


# -- the mount list ----------------------------------------------------------------


class TestParse:
    def test_happy_proc_mounts_with_kinds(self):
        drives = DO.parse_proc_mounts(MOUNTS)
        by_mount = {d.mount: d for d in drives}
        assert by_mount["/"].kind == "local" and by_mount["/"].fstype == "ext4"
        assert by_mount["/mnt/nas"].kind == "network"
        assert by_mount["/mnt/nfs"].kind == "network"
        assert by_mount["/mnt/git_code"].kind == "network"  # VirtualBox shared folder
        assert by_mount["/run/media/user/USB STICK"].kind == "removable"  # \\040 decoded
        assert by_mount["/tmp"].kind == "memory"
        assert by_mount["/proc"].kind == "system"

    def test_edge_a_device_mounted_twice_is_listed_once(self):
        mounts = [d.mount for d in DO.parse_proc_mounts(MOUNTS)]
        assert "/mnt/ext" in mounts and "/mnt/ext-bind" not in mounts

    def test_edge_docker_overlays_are_system(self):
        drives = {d.mount: d for d in DO.parse_proc_mounts(MOUNTS)}
        assert drives["/var/lib/docker/overlay2/abc/merged"].kind == "system"

    def test_sad_garbage_lines_are_skipped(self):
        assert DO.parse_proc_mounts("garbage\n\n/dev/x\n") == []

    def test_happy_macos_mount_output(self):
        text = ("/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n"
                "devfs on /dev (devfs, local, nobrowse)\n"
                "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)\n"
                "//alice@nas._smb._tcp.local/share on /Volumes/share (smbfs, nodev, nosuid, mounted by alice)\n"
                "/dev/disk4s1 on /Volumes/USB Stick (msdos, local, nodev, nosuid, noowners)\n")
        drives = {d.mount: d for d in DO.parse_mount_output(text)}
        assert drives["/"].kind == "local" and drives["/"].fstype == "apfs"
        assert drives["/Volumes/share"].kind == "network"
        assert drives["/Volumes/USB Stick"].kind == "removable"
        assert drives["/dev"].kind == "system"

    def test_happy_windows_letters(self):
        drives = DO.windows_drives(["C:\\", "D:\\", "Z:\\"], lambda root: {"Z:\\": 4, "D:\\": 5}.get(root, 3))
        kinds = {d.mount: d.kind for d in drives}
        assert kinds == {"C:\\": "local", "D:\\": "removable", "Z:\\": "network"}


class TestMeasure:
    def test_happy_usage_and_percent(self):
        drives = DO.measure(DO.parse_proc_mounts(MOUNTS), usage=_usage)
        root = next(d for d in drives if d.mount == "/")
        assert (root.total, root.used, root.free) == (100, 60, 40)
        assert root.percent == pytest.approx(60.0)
        assert root.error == ""

    def test_sad_an_unreadable_drive_says_why(self):
        def usage(path):
            if path == "/mnt/nas":
                raise PermissionError("denied")
            return _usage(path)

        drives = {d.mount: d for d in DO.measure(DO.parse_proc_mounts(MOUNTS), usage=usage)}
        assert drives["/mnt/nas"].total is None and "denied" in drives["/mnt/nas"].error
        assert drives["/"].total == 100

    def test_sad_a_hanging_drive_times_out_without_blocking_the_rest(self):
        release = threading.Event()

        def usage(path):
            if path == "/mnt/nfs":
                release.wait(10)
            return _usage(path)

        t0 = time.monotonic()
        try:
            drives = {d.mount: d for d in DO.measure(DO.parse_proc_mounts(MOUNTS), usage=usage, timeout=0.3)}
        finally:
            release.set()
        assert time.monotonic() - t0 < 2.0
        assert drives["/mnt/nfs"].total is None and "timed out" in drives["/mnt/nfs"].error
        assert drives["/mnt/ext"].total == 1000

    def test_edge_zero_size_is_unknown_not_empty(self):
        drives = DO.measure(DO.parse_proc_mounts("/dev/x /z ext4 rw 0 0\n"), usage=lambda p: (0, 0, 0))
        assert drives[0].total == 0 and drives[0].percent is None


class TestCharts:
    def test_happy_pie_angles_cover_the_circle(self):
        spans = DO.pie_spans([60, 40])
        assert sum(-span for _start, span in spans) == 5760  # Qt: 1/16 degree, clockwise
        assert spans[0] == (90 * 16, -int(round(5760 * 0.6)))

    def test_edge_pie_of_nothing_is_empty(self):
        assert DO.pie_spans([0, 0]) == []

    def test_happy_bars_scale_to_the_largest_drive(self):
        bars = DO.bar_lengths([(100, 60), (1000, 900), (None, None)], width=200)
        assert bars[1] == (200, 180) and bars[0] == (20, 12) and bars[2] == (0, 0)


# -- the panel ---------------------------------------------------------------------


def _panel(drives):
    widget = DO.DrivesPanel(refresh=lambda: None, open_folder=lambda path: None)
    widget.set_drives(drives)
    widget.resize(900, 600)
    widget.show()
    APP.processEvents()
    return widget


def test_happy_table_lists_drives_and_hides_system_ones_by_default():
    drives = DO.measure(DO.parse_proc_mounts(MOUNTS), usage=_usage)
    panel = _panel(drives)
    try:
        mounts = [panel.table.item(r, 0).text() for r in range(panel.table.rowCount())]
        assert "/" in mounts and "/mnt/nas" in mounts and "/proc" not in mounts and "/tmp" not in mounts
        panel.show_system.setChecked(True)
        mounts = [panel.table.item(r, 0).text() for r in range(panel.table.rowCount())]
        assert "/proc" in mounts and "/tmp" in mounts
    finally:
        panel.close()


def test_happy_selecting_a_row_draws_its_pie_and_double_click_opens_it():
    opened = []
    drives = DO.measure(DO.parse_proc_mounts(MOUNTS), usage=_usage)
    panel = DO.DrivesPanel(refresh=lambda: None, open_folder=opened.append)
    panel.set_drives(drives)
    panel.resize(900, 600)
    panel.show()
    try:
        row = next(r for r in range(panel.table.rowCount()) if panel.table.item(r, 0).text() == "/mnt/ext")
        panel.table.selectRow(row)
        APP.processEvents()
        assert panel.pie.drive.mount == "/mnt/ext"
        img = panel.pie.grab().toImage()
        colours = {img.pixelColor(x, y).name() for x in range(0, img.width(), 7) for y in range(0, img.height(), 7)}
        assert DO.USED_COLOUR in colours and DO.FREE_COLOUR in colours
        panel.table.doubleClicked.emit(panel.table.model().index(row, 0))
        assert opened == ["/mnt/ext"]
    finally:
        panel.close()


def test_happy_the_table_sorts_by_size_numerically():
    drives = DO.measure(DO.parse_proc_mounts(MOUNTS), usage=_usage)
    panel = _panel(drives)
    try:
        from PyQt6.QtCore import Qt

        panel.table.sortItems(DO.COL_SIZE, Qt.SortOrder.DescendingOrder)
        assert panel.table.item(0, 0).text() == "/mnt/ext"
    finally:
        panel.close()


def test_sad_unknown_drives_show_the_reason_and_no_bar():
    drives = DO.measure(DO.parse_proc_mounts("//nas/s /mnt/nas cifs rw 0 0\n"),
                        usage=lambda p: (_ for _ in ()).throw(OSError("host is down")))
    panel = _panel(drives)
    try:
        assert "host is down" in panel.table.item(0, DO.COL_USE).text()
        assert panel.bars.lengths()[0] == (0, 0)
    finally:
        panel.close()


def test_e2e_real_drives_of_this_machine():
    drives = DO.measure(DO.list_drives())
    assert any(d.mount in ("/", "C:\\") and d.total for d in drives)


def test_e2e_extension_loads_in_the_window_and_fills_its_panel(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    info = next(e for e in EX.discover() if e.module_name == "drives_overview")
    EX.set_enabled(info.ext_id, True)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        host = win.extension_host
        end = time.time() + 10
        while time.time() < end and host.module(info.ext_id) is None:
            APP.processEvents()
            time.sleep(0.02)
        assert host.error(info.ext_id) == ""
        (dock,) = host.docks(info.ext_id)
        assert dock.windowTitle() == "Drives Overview"
        panel = dock.widget()
        end = time.time() + 10
        while time.time() < end and panel.table.rowCount() == 0:
            APP.processEvents()
            time.sleep(0.02)
        assert panel.table.rowCount() >= 1
        row = next(r for r in range(panel.table.rowCount()) if panel.table.item(r, 0).text() == "/")
        panel.table.doubleClicked.emit(panel.table.model().index(row, 0))
        end = time.time() + 5
        while time.time() < end and win._active_pane.current_path != "/":
            APP.processEvents()
            time.sleep(0.02)
        assert win._active_pane.current_path == "/"
    finally:
        win.close()
        win.deleteLater()
        APP.processEvents()


def test_edge_the_table_starts_sorted_by_mount_ascending():
    drives = DO.measure(DO.parse_proc_mounts(MOUNTS), usage=_usage)
    panel = _panel(drives)
    try:
        mounts = [panel.table.item(r, 0).text() for r in range(panel.table.rowCount())]
        assert mounts == sorted(mounts)
    finally:
        panel.close()
