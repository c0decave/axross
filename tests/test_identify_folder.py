"""Identify Files in This Folder: every file of a folder by its content.

Operator item 6: "sollten wir mit einbauen, dass alle files im dir versucht
werden zu identifizieren und wenn wir z.b. ein festplatten image haben,
partitionen auslesen ...". Before, *Identify File Type…* worked on the
selection only (ui/file_pane.py identify_file_type).

Now the pane's right-click menu (also on empty space) and the Identify File
Type window offer *Identify Files in This Folder…*: the folder's files -
through the backend API, so remote panes work - are identified in the
background with the existing engine (core.file_type; sift's kind as an
extra column for local files when sift is installed). Bounded: at most
FOLDER_MAX_FILES files, DEFAULT_MAX_BYTES per file, IMAGE_NOTE_MAX_BYTES for a
disk image's partition note, Cancel. The table sorts; a disk-image row opens
Disk Image…, any row Properties….
"""

from __future__ import annotations

import io
import os
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import file_type as FT  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from tests.test_disk_image import MiB, mbr_entry, put_ext4, with_mbr  # noqa: E402

APP = QApplication.instance() or QApplication([])

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _wait(predicate, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return predicate()


def _mbr_image(partitions: int = 2) -> bytes:
    image = bytearray(4 * MiB)
    entries = [mbr_entry(i == 0, 0x83, 2048 + i * 2048, 2048) for i in range(partitions)]
    with_mbr(image, entries)
    put_ext4(image, 2048 * 512)
    return bytes(image)


@pytest.fixture()
def folder(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "photo.png").write_bytes(PNG)
    (root / "photo.txt").write_bytes(PNG)  # a PNG under a text name: mismatch
    (root / "notes.md").write_bytes(b"# notes\nplain text\n")
    (root / "laptop.bin").write_bytes(_mbr_image())  # a disk image without a telling name
    (root / ".hidden.txt").write_bytes(b"secret-looking but plain\n")
    (root / "sub").mkdir()
    (root / "sub" / "deep.png").write_bytes(PNG)  # not listed: subfolders are not entered
    return root


# --- core --------------------------------------------------------------------------------


def test_happy_list_folder_gives_the_files_and_counts_the_folders(folder):
    listing = FT.list_folder(LocalFS(), str(folder))
    names = [FT.name_of(p) for p, _item in listing.files]
    assert names == sorted(names, key=str.casefold)
    assert set(names) == {"photo.png", "photo.txt", "notes.md", "laptop.bin", ".hidden.txt"}
    assert (listing.folders, listing.skipped, listing.truncated) == (1, 0, False)
    assert all(not item.is_dir for _p, item in listing.files)


def test_happy_a_disk_image_gets_its_partition_note(folder):
    path = str(folder / "laptop.bin")
    info = FT.identify(LocalFS(), path, use_file_command=False)
    assert FT.is_disk_image(info)
    note = FT.disk_image_note(LocalFS(), path, size=info.size)
    assert "MBR" in note and "2 partitions" in note
    assert not FT.is_disk_image(FT.identify(LocalFS(), str(folder / "notes.md")))


def test_happy_sift_kind_for_a_local_file(folder):
    from core import file_categories as FC

    if not FC.sift_available():
        pytest.skip("sift is not installed")
    assert FC.sift_kind(str(folder / "photo.png")) == "image"
    assert FC.sift_kind(str(folder / "missing.png")) == ""


def test_sad_an_unlistable_folder_raises(tmp_path):
    with pytest.raises(OSError):
        FT.list_folder(LocalFS(), str(tmp_path / "gone"))


def test_sad_hostile_names_from_a_remote_are_skipped_and_counted():
    class Hostile:
        def list_dir(self, path):
            return [FileItem(name="ok.txt", size=1), FileItem(name="../escape", size=1),
                    FileItem(name="a/b", size=1), FileItem(name="..", is_dir=True)]

        def join(self, *parts):
            return "/".join(parts).replace("//", "/")

        def separator(self):
            return "/"

        def normalize(self, path):
            return path

    listing = FT.list_folder(Hostile(), "/srv")
    assert [p for p, _i in listing.files] == ["/srv/ok.txt"]
    assert listing.skipped == 2


def test_sad_a_damaged_disk_image_gives_no_note(tmp_path):
    bad = tmp_path / "bad.img"
    bad.write_bytes(b"\0" * 100)
    assert FT.disk_image_note(LocalFS(), str(bad)) == ""
    assert FT.disk_image_note(LocalFS(), str(tmp_path / "missing.img")) == ""


def test_edge_the_file_cap_truncates(tmp_path):
    for i in range(7):
        (tmp_path / f"f{i}.txt").write_text("x")
    listing = FT.list_folder(LocalFS(), str(tmp_path), max_files=5)
    assert len(listing.files) == 5 and listing.truncated
    assert not FT.list_folder(LocalFS(), str(tmp_path), max_files=7).truncated
    with pytest.raises(ValueError):
        FT.list_folder(LocalFS(), str(tmp_path), max_files=0)


def test_edge_the_disk_image_note_reads_no_more_than_its_budget(tmp_path):
    """An image with 60 logical-looking partitions would probe 60 x 66 KiB."""
    from tests.test_disk_image import gpt_image

    linux = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    image = gpt_image([(linux, 34 + 64 * i, 34 + 64 * i + 63, f"p{i}") for i in range(60)],
                      size=8 * MiB)
    path = tmp_path / "many.img"
    path.write_bytes(bytes(image))
    read = []

    class Counting(LocalFS):
        def open_read(self, p, *a, **kw):
            fh = super().open_read(p, *a, **kw)
            real = fh.read

            def counted(n=-1):
                data = real(n)
                read.append(len(data))
                return data

            fh.read = counted
            return fh

    note = FT.disk_image_note(Counting(), str(path), max_bytes=200_000)
    assert "60 partitions" in note
    assert sum(read) <= 200_000


def test_edge_a_remote_backend_is_read_through_its_api():
    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    ram.mkdir("/box")
    for name, data in {"a.png": PNG, "image.raw": _mbr_image(3)}.items():
        with ram.open_write(f"/box/{name}") as fh:
            fh.write(data)
    listing = FT.list_folder(ram, "/box")
    paths = [p for p, _i in listing.files]
    assert paths == ["/box/a.png", "/box/image.raw"]
    info = FT.identify(ram, "/box/image.raw", use_file_command=False)
    assert FT.is_disk_image(info) and "3 partitions" in FT.disk_image_note(ram, "/box/image.raw")


# --- the window ---------------------------------------------------------------------------


@pytest.fixture()
def pane(folder):
    from ui.file_pane import FilePaneWidget

    widget = FilePaneWidget(LocalFS())
    widget.resize(700, 400)
    widget.show()
    widget.navigate(str(folder))
    APP.processEvents()
    try:
        yield widget
    finally:
        for dlg in list(getattr(widget, "file_type_dialogs", [])):
            dlg.close()
        widget.close()
        widget.deleteLater()
        APP.processEvents()


def _entry(menu, command):
    return next((a for a in menu.actions() if a.property("axCommand") == command), None)


def _row_of(dialog, name: str) -> int:
    for row in range(dialog.table.rowCount()):
        if dialog.table.item(row, 0).text() == name:
            return row
    raise AssertionError(name)


def test_happy_e2e_right_click_on_empty_space_identifies_the_folder(pane, folder, monkeypatch):
    from ui.file_type_dialog import FOLDER_COLUMNS

    pane._table.clearSelection()
    entry = _entry(pane._build_context_menu(), "identify-folder")
    assert entry is not None and entry.text() == "Identify Files in This Folder…"
    entry.trigger()
    assert pane.file_type_dialogs, "no window opened"
    dialog = pane.file_type_dialogs[-1]
    assert _wait(lambda: dialog.idle)
    assert dialog.table.rowCount() == 5  # files only; sub/ is not entered
    col = {name: i for i, name in enumerate(FOLDER_COLUMNS)}
    texts = {dialog.table.item(r, 0).text(): dialog.row_texts(r) for r in range(5)}
    assert texts["photo.txt"][col["Verdict"]] == "mismatch"
    assert texts["photo.png"][col["MIME type"]] == "image/png"
    assert "2 partitions" in texts["laptop.bin"][col["Note"]]
    assert "1 folder" in dialog.status_label.text()
    assert "1 mismatch" in dialog.status_label.text()
    # sorted by a click on a column header, then back
    header = dialog.table.horizontalHeader()
    QTest.mouseClick(header.viewport(), Qt.MouseButton.LeftButton,
                     pos=header.rect().topLeft() + _header_point(header, col["Size"]))
    sizes = [dialog.table.item(r, col["Size"]).data(Qt.ItemDataRole.UserRole) for r in range(5)]
    assert sizes == sorted(sizes) or sizes == sorted(sizes, reverse=True)
    assert max(sizes) == 4 * MiB


def _header_point(header, section):
    from PyQt6.QtCore import QPoint

    return QPoint(header.sectionViewportPosition(section) + 5, header.height() // 2)


def test_happy_e2e_a_disk_image_row_opens_disk_image_and_any_row_properties(
    pane, folder, monkeypatch
):
    import ui.disk_image_dialog as DID
    import ui.properties_dialog as PD

    opened = {}

    class FakeDisk:
        def __init__(self, backend, path, parent=None, open_folder=None):
            opened["disk"] = path

        def setAttribute(self, *_a):
            pass

        def show(self):
            pass

        def start(self):
            opened["started"] = True

    class FakeProps:
        def __init__(self, backend, path, item, parent=None):
            opened["props"] = (path, item.name, item.size)

        def exec(self):
            return 0

    monkeypatch.setattr(DID, "DiskImageDialog", FakeDisk)
    monkeypatch.setattr(PD, "PropertiesDialog", FakeProps)
    dialog = pane.identify_folder()
    assert _wait(lambda: dialog.idle)
    dialog.table.selectRow(_row_of(dialog, "notes.md"))
    assert not dialog.disk_image_button.isEnabled() and dialog.properties_button.isEnabled()
    dialog.table.selectRow(_row_of(dialog, "laptop.bin"))
    assert dialog.disk_image_button.isEnabled()
    dialog.disk_image_button.click()
    assert opened["disk"] == str(folder / "laptop.bin") and opened["started"]
    dialog.properties_button.click()
    assert opened["props"] == (str(folder / "laptop.bin"), "laptop.bin", 4 * MiB)


def test_happy_e2e_the_identify_window_offers_the_whole_folder(pane, folder):
    pane._restore_selection({"photo.png"}, "photo.png")
    single = pane.identify_file_type()
    assert _wait(lambda: single.idle)
    assert single.folder_button.text() == "Identify Files in This Folder…"
    single.folder_button.click()
    whole = pane.file_type_dialogs[-1]
    assert whole is not single and whole.folder == str(folder)
    assert _wait(lambda: whole.idle) and whole.table.rowCount() == 5


def test_happy_e2e_the_sift_column_shows_for_local_files_when_sift_is_there(pane):
    from core import file_categories as FC
    from ui.file_type_dialog import FOLDER_COLUMNS

    dialog = pane.identify_folder()
    assert _wait(lambda: dialog.idle)
    sift_col = FOLDER_COLUMNS.index("sift")
    hidden = dialog.table.isColumnHidden(sift_col)
    assert hidden is (not FC.sift_available())
    if not hidden:
        assert dialog.row_texts(_row_of(dialog, "photo.png"))[sift_col] == "image"


def test_sad_e2e_cancel_stops_a_hanging_remote(tmp_path):
    from ui.file_type_dialog import FolderFileTypeDialog

    release = threading.Event()

    class Hanging:
        def list_dir(self, path):
            return [FileItem(name=f"f{i}.bin", size=10) for i in range(4)]

        def join(self, *parts):
            return "/".join(parts).replace("//", "/")

        def separator(self):
            return "/"

        def normalize(self, path):
            return path

        def stat(self, path):
            return FileItem(name=os.path.basename(path), size=10)

        def open_read(self, path):
            release.wait(30)
            return io.BytesIO(b"x" * 10)

    dialog = FolderFileTypeDialog(Hanging(), "/remote", timeout=20)
    try:
        dialog.show()
        dialog.start()
        assert _wait(lambda: dialog.table.rowCount() == 4)
        dialog.busy.cancel_button.click()
        assert _wait(lambda: dialog.idle, timeout=10)
        assert "cancelled" in dialog.status_label.text()
    finally:
        release.set()
        dialog.close()


def test_sad_e2e_an_unreadable_folder_says_so(tmp_path):
    from ui.file_type_dialog import FolderFileTypeDialog

    dialog = FolderFileTypeDialog(LocalFS(), str(tmp_path / "gone"))
    try:
        dialog.start()
        assert _wait(lambda: dialog.idle)
        assert dialog.table.rowCount() == 0
        assert "failed" in dialog.status_label.text().lower()
    finally:
        dialog.close()


def test_edge_e2e_a_capped_folder_says_how_many_were_left_out(tmp_path):
    from ui.file_type_dialog import FolderFileTypeDialog

    for i in range(6):
        (tmp_path / f"f{i}.txt").write_text("x")
    dialog = FolderFileTypeDialog(LocalFS(), str(tmp_path), max_files=4)
    try:
        dialog.start()
        assert _wait(lambda: dialog.idle)
        assert dialog.table.rowCount() == 4
        assert "first 4" in dialog.status_label.text()
    finally:
        dialog.close()


def test_edge_e2e_a_remote_pane_identifies_through_its_backend():
    from core.ram_fs import RamFsSession
    from ui.file_pane import FilePaneWidget
    from ui.file_type_dialog import FOLDER_COLUMNS

    ram = RamFsSession()
    ram.mkdir("/box")
    with ram.open_write("/box/disk.raw") as fh:
        fh.write(_mbr_image(2))
    with ram.open_write("/box/pic.dat") as fh:
        fh.write(PNG)
    widget = FilePaneWidget(ram)
    try:
        widget.show()
        widget.navigate("/box")
        APP.processEvents()
        dialog = widget.identify_folder()
        assert _wait(lambda: dialog.idle)
        rows = {dialog.table.item(r, 0).text(): dialog.row_texts(r)
                for r in range(dialog.table.rowCount())}
        assert rows["pic.dat"][FOLDER_COLUMNS.index("MIME type")] == "image/png"
        assert "2 partitions" in rows["disk.raw"][FOLDER_COLUMNS.index("Note")]
        assert dialog.table.isColumnHidden(FOLDER_COLUMNS.index("sift"))  # not a local file
        dialog.close()
    finally:
        widget.close()
        widget.deleteLater()
        APP.processEvents()


def test_edge_the_folder_window_has_the_close_corner(tmp_path):
    from PyQt6.QtWidgets import QToolButton

    from ui.file_type_dialog import FolderFileTypeDialog

    dialog = FolderFileTypeDialog(LocalFS(), str(tmp_path))
    try:
        assert len(dialog.findChildren(QToolButton, "axCloseCorner")) == 1
    finally:
        dialog.close()
