"""Forensic tools on disk images: qemu-img, The Sleuth Kit, TestDisk/PhotoRec
and hashing.

Right-click a disk image (``.img .raw .dd .iso .qcow2 .vdi .vmdk .vhd(x) …``):

* **Hash Image** - MD5, SHA-1 and SHA-256 in one pass, on any backend; for
  the case notes.
* **Image Info (qemu-img)** - format, virtual and actual size, backing file,
  encryption, dirty flag (``qemu-img info --output=json``).
* **Convert to Raw Image** - ``qemu-img convert -O raw`` next to the source
  (never over an existing file); the raw image then opens with Disk Image…
  and mounts.
* **Browse File System (Sleuth Kit)…** - every file of a partition, deleted
  ones included (``fls -r -p -o <sector>``), without mounting anything;
  *Extract* writes the selected files' content (``icat``) into a folder.
  On a container (qcow2, VMDK, dynamic VDI, VHD/VHDX, E01) it says how to
  get at the partitions and offers Convert to Raw… where qemu-img can.
* **TestDisk / PhotoRec** - start the interactive tools in a terminal pane
  next to the image (partition recovery, file carving).

The image is only read; the Sleuth Kit and qemu-img calls are argument
lists. Tools that are missing are named with the package that has them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass

from core.subprocess_env import clean_child_env

EXTENSION = {
    "name": "Forensic Tools",
    "version": "1.0",
    "description": "Right-click a disk image: hashes, qemu-img info and convert to raw, "
    "browse and extract files with The Sleuth Kit (deleted ones too), TestDisk and PhotoRec.",
    "author": "axross",
}

CHUNK = 4 * 1024 * 1024
TIMEOUT = 600
MAX_FLS_LINES = 200_000
#: The unit of fls / icat ``-o``: The Sleuth Kit's default sector size.
TSK_SECTOR = 512
PACKAGES = {
    "qemu-img": "qemu-utils / qemu-img",
    "fls": "sleuthkit",
    "icat": "sleuthkit",
    "testdisk": "testdisk",
    "photorec": "testdisk",
}
#: core.disk_image container kinds qemu-img converts to raw (VHD is its "vpc").
QEMU_CONVERTS = ("qcow2", "vdi", "vmdk", "vhd", "vhdx")
_FLS = re.compile(r"^(?P<type>\S)/(?P<meta>\S)\s+(?P<deleted>\*\s+)?(?P<inode>[0-9][0-9-]*)"
                  r"(?P<realloc>\(realloc\))?:\t(?P<path>.*)$")


class ToolError(RuntimeError):
    pass


def suffixes() -> tuple[str, ...]:
    from core.disk_image import IMAGE_SUFFIXES

    return IMAGE_SUFFIXES


def need(tool: str) -> str:
    found = shutil.which(tool)
    if found is None:
        raise ToolError(f"{tool} is not installed (package: {PACKAGES.get(tool, tool)}).")
    return found


def _run(argv: list[str], timeout: int = TIMEOUT) -> str:
    # errors="replace": fls prints ext file names as the raw bytes they are;
    # one that is not UTF-8 failed the whole listing (icat goes by inode).
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL, check=False, env=clean_child_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(str(exc)) from exc
    if proc.returncode != 0:
        lines = [ln for ln in proc.stderr.splitlines() if ln.strip()]
        raise ToolError(lines[-1] if lines else f"{os.path.basename(argv[0])} failed "
                                                 f"(exit {proc.returncode})")
    return proc.stdout


# -- hashing ------------------------------------------------------------------------------


def hash_image(backend, path: str, cancel=lambda: False) -> dict[str, str]:
    """MD5, SHA-1 and SHA-256 of *path* in one read."""
    digests = {"MD5": hashlib.md5(usedforsecurity=False),
               "SHA-1": hashlib.sha1(usedforsecurity=False), "SHA-256": hashlib.sha256()}
    with backend.open_read(path) as fh:
        while not cancel():
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            for d in digests.values():
                d.update(chunk)
    return {name: d.hexdigest() for name, d in digests.items()}


# -- qemu-img -----------------------------------------------------------------------------


def _qemu_info(path: str) -> dict:
    # info opens the image without its backing chain and reads no data.
    data = json.loads(_run([need("qemu-img"), "info", "--output=json", path], 60))
    if not isinstance(data, dict):
        raise ToolError("qemu-img info returned no image description")
    return data


def outside_files(path: str, data: dict) -> list[str]:
    """Files other than the image itself that converting *path* would read,
    from its ``qemu-img info`` *data*: a backing file, a qcow2 external
    data file, VMDK extents outside the image's folder. The image header
    names them, and a hostile image names any readable file
    (``~/.ssh/id_ed25519``); qemu-img convert copies it into the output."""
    found = []
    backing = data.get("full-backing-filename") or data.get("backing-filename")
    if backing:
        found.append(f"backing file {backing}")
    specific = data.get("format-specific")
    specific = specific.get("data") if isinstance(specific, dict) else None
    if isinstance(specific, dict):
        if specific.get("data-file"):
            found.append(f"data file {specific['data-file']}")
        folder = os.path.dirname(os.path.realpath(path))
        for extent in specific.get("extents") or ():
            name = extent.get("filename") if isinstance(extent, dict) else None
            if not isinstance(name, str) or not name:
                continue
            real = os.path.realpath(os.path.join(folder, name))
            if os.path.dirname(real) != folder:
                found.append(f"extent {name} outside the image's folder")
    return found


def image_info(path: str) -> dict:
    data = _qemu_info(path)
    return {
        "Format": data.get("format", "?"),
        "Virtual size": data.get("virtual-size", 0),
        "Actual size": data.get("actual-size", 0),
        "Backing file": data.get("backing-filename") or data.get("full-backing-filename") or "",
        "Encrypted": "yes" if data.get("encrypted") else "no",
        "Dirty": "yes" if data.get("dirty-flag") else "no",
    }


def raw_target(path: str) -> str:
    """Where Convert to Raw writes: ``<stem>.raw`` next to *path*, with a
    number when that exists."""
    folder, name = os.path.split(path)
    stem = name.rsplit(".", 1)[0] if "." in name else name
    target = os.path.join(folder, f"{stem}.raw")
    n = 1
    while os.path.exists(target):
        target = os.path.join(folder, f"{stem}-{n}.raw")
        n += 1
    return target


def convert_to_raw(path: str, target: str | None = None) -> str:
    target = target or raw_target(path)
    if os.path.exists(target):
        raise ToolError(f"{target} exists - not overwritten")
    data = _qemu_info(path)
    outside = outside_files(path, data)
    if outside:
        raise ToolError("Not converted: the image would pull in other files - "
                        + "; ".join(outside) + ".")
    fmt = data.get("format")
    if not isinstance(fmt, str) or not re.fullmatch(r"[a-z0-9_-]+", fmt):
        raise ToolError(f"qemu-img info names no usable format for {path}")
    try:
        # -f: the format checked above; without it convert probes again.
        _run([need("qemu-img"), "convert", "-f", fmt, "-O", "raw", path, target])
    except ToolError:
        if os.path.exists(target):
            os.unlink(target)  # a half-written image is no evidence
        raise
    return target


# -- The Sleuth Kit -----------------------------------------------------------------------


@dataclass(frozen=True)
class Entry:
    path: str
    inode: str
    kind: str
    deleted: bool
    reallocated: bool

    @property
    def is_dir(self) -> bool:
        return self.kind == "d"


def parse_fls(text: str) -> list[Entry]:
    entries = []
    for line in text.splitlines()[:MAX_FLS_LINES]:
        match = _FLS.match(line)
        if not match or match.group("path") in (".", ".."):
            continue
        entries.append(Entry(path=match.group("path"), inode=match.group("inode"),
                             kind=match.group("type"), deleted=bool(match.group("deleted")),
                             reallocated=bool(match.group("realloc"))))
    return entries


def list_files(image: str, sector_offset: int = 0) -> list[Entry]:
    if not isinstance(sector_offset, int) or sector_offset < 0:
        raise ValueError("the sector offset is a whole number >= 0")
    return parse_fls(_run([need("fls"), "-r", "-p", "-o", str(sector_offset), image]))


def safe_name(path: str) -> str:
    """A file name for an extracted entry: its path, flattened."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/")).strip("._") or "unnamed"
    return name[:200]


def _with_inode(name: str, inode: str) -> str:
    """*name* with the entry's inode before its extension: ``a-67.txt``."""
    stem, ext = os.path.splitext(name)
    return f"{stem}-{inode}{ext}"


def extract(image: str, entries: list[Entry], folder: str, sector_offset: int = 0) -> list[str]:
    """``icat`` each regular entry into *folder*; existing files are kept.
    The paths written.

    Entries whose flattened names meet (the deleted versions of one path,
    one per inode) are all extracted: the first under the name, the others
    with their inode added - the same names on every run, so extracting the
    same selection again adds nothing."""
    exe = need("icat")
    written = []
    taken: set[str] = set()  # names given out in this run
    seen: set[tuple] = set()
    for entry in entries:
        if entry.is_dir or not re.fullmatch(r"[0-9][0-9-]*", entry.inode):
            continue
        if (entry.path, entry.inode, entry.deleted) in seen:
            continue  # the same entry twice: one copy
        seen.add((entry.path, entry.inode, entry.deleted))
        name = ("deleted_" if entry.deleted else "") + safe_name(entry.path)
        if name in taken:
            name = _with_inode(name, entry.inode)
        if name in taken:
            continue  # same flattened name and inode (hard links): the same content
        taken.add(name)
        target = os.path.join(folder, name)
        if os.path.exists(target):
            continue
        argv = [exe, "-o", str(sector_offset), image, entry.inode]
        with open(target, "xb") as out:  # a file made meanwhile is not ours: no clean-up
            try:
                proc = subprocess.run(argv, stdout=out, stderr=subprocess.PIPE,
                                      timeout=TIMEOUT, stdin=subprocess.DEVNULL, check=False,
                                      env=clean_child_env())
            except (OSError, subprocess.TimeoutExpired) as exc:
                failure = exc
            else:
                failure = None
        if failure is not None:
            # A half-written file would be "kept" by the next Extract.
            _remove(target)
            raise ToolError(f"icat failed for {entry.path}: {failure}") from failure
        if proc.returncode != 0:
            _remove(target)
            raise ToolError(proc.stderr.decode("utf-8", "replace").strip()
                            or f"icat failed for {entry.path}")
        written.append(target)
    return written


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# -- interface ----------------------------------------------------------------------------


def activate(api):
    from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QDialog,
        QFileDialog,
        QHBoxLayout,
        QInputDialog,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPushButton,
        QTableView,
        QVBoxLayout,
    )

    from core import disk_image as DI

    def local(ctx):
        if not ctx.is_local:
            api.notify("this tool needs the image on this computer")
            return None
        return ctx.paths[0]

    def warn(title):
        return lambda exc: QMessageBox.warning(api.window, title, str(exc))

    def do_hash(ctx):
        path = ctx.paths[0]
        api.notify(f"hashing {os.path.basename(path)}…")

        def done(result):
            text = "\n".join(f"{k}: {v}" for k, v in result.items())
            box = QMessageBox(QMessageBox.Icon.Information, "Hash Image",
                              f"{path}\n\n{text}", parent=api.window)
            copy = box.addButton("Copy", QMessageBox.ButtonRole.ActionRole)
            box.addButton(QMessageBox.StandardButton.Close)
            box.exec()
            if box.clickedButton() is copy:
                QApplication.clipboard().setText(f"{path}\n{text}\n")

        api.run_in_background(lambda: hash_image(ctx.backend, path), on_done=done,
                              on_error=warn("Hash Image"))

    def do_info(ctx):
        path = local(ctx)
        if path is None:
            return

        def done(info):
            lines = [f"{k}: {DI.human_size(v) if isinstance(v, int) else v}"
                     for k, v in info.items()]
            QMessageBox.information(api.window, "Image Info", f"{path}\n\n" + "\n".join(lines))

        api.run_in_background(lambda: image_info(path), on_done=done,
                              on_error=warn("Image Info"))

    def do_convert(ctx):
        path = local(ctx)
        if path is None:
            return
        target = raw_target(path)
        if QMessageBox.question(api.window, "Convert to Raw Image",
                                f"Write a raw copy of\n{path}\nto\n{target}?") \
                != QMessageBox.StandardButton.Yes:
            return
        api.notify(f"converting to {os.path.basename(target)}…")

        def done(written):
            api.notify(f"wrote {written}")
            if ctx.pane is not None:
                ctx.pane.refresh()

        api.run_in_background(lambda: convert_to_raw(path, target), on_done=done,
                              on_error=warn("Convert to Raw Image"))

    class EntryModel(QAbstractTableModel):
        """The fls entries as a table model: 200 000 of them as table items
        took 16 s on the GUI thread, a model answers only what is shown."""

        HEADERS = ("Path", "Inode", "Type", "Deleted")

        def __init__(self, entries, parent=None):
            super().__init__(parent)
            self.entries = entries

        def rowCount(self, parent=QModelIndex()):  # noqa: N802 - Qt
            return 0 if parent.isValid() else len(self.entries)

        def columnCount(self, parent=QModelIndex()):  # noqa: N802 - Qt
            return 0 if parent.isValid() else len(self.HEADERS)

        def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
            if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
                return self.HEADERS[section]
            return None

        def data(self, index, role=Qt.ItemDataRole.DisplayRole):
            if role != Qt.ItemDataRole.DisplayRole or not index.isValid():
                return None
            e = self.entries[index.row()]
            column = index.column()
            if column == 0:
                return e.path
            if column == 1:
                return e.inode
            if column == 2:
                return {"d": "folder", "r": "file", "l": "link"}.get(e.kind, e.kind)
            return ("yes" + (" (reallocated)" if e.reallocated else "")) if e.deleted else ""

    class BrowseDialog(QDialog):
        def __init__(self, image, sector, entries):
            super().__init__(api.window)
            self.image, self.sector, self.entries = image, sector, entries
            self.setWindowTitle("Sleuth Kit - " + os.path.basename(image))
            self.resize(820, 520)
            layout = QVBoxLayout(self)
            deleted = sum(e.deleted for e in entries)
            layout.addWidget(QLabel(f"{len(entries)} entries, {deleted} deleted "
                                    f"(partition at sector {sector})"))
            self.filter = QLineEdit()
            self.filter.setPlaceholderText("Filter paths…")
            self.filter.textChanged.connect(self.apply_filter)
            layout.addWidget(self.filter)
            self.model = EntryModel(entries, self)
            # One pass over the paths per filter text; hiding table rows one
            # by one took 97 s for 200 000 entries.
            self.proxy = QSortFilterProxyModel(self)
            self.proxy.setSourceModel(self.model)
            self.proxy.setFilterKeyColumn(0)
            self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
            self.table = QTableView()
            self.table.setModel(self.proxy)
            self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.verticalHeader().hide()
            self.table.resizeColumnsToContents()
            layout.addWidget(self.table, 1)
            buttons = QHBoxLayout()
            extract_button = QPushButton("Extract…")
            extract_button.clicked.connect(self.extract_selected)
            close = QPushButton("Close")
            close.clicked.connect(self.close)
            buttons.addStretch(1)
            buttons.addWidget(extract_button)
            buttons.addWidget(close)
            layout.addLayout(buttons)
            from ui.close_corner import add_close_corner

            add_close_corner(self)

        def apply_filter(self, text):
            self.proxy.setFilterFixedString(text)

        def visible_entries(self):
            return [self.entries[self.proxy.mapToSource(self.proxy.index(r, 0)).row()]
                    for r in range(self.proxy.rowCount())]

        def selected(self):
            rows = sorted({self.proxy.mapToSource(i).row()
                           for i in self.table.selectionModel().selectedRows()})
            return [self.entries[r] for r in rows]

        def extract_selected(self):
            picked = [e for e in self.selected() if not e.is_dir]
            if not picked:
                return
            folder = QFileDialog.getExistingDirectory(self, "Extract into")
            if not folder:
                return
            image, sector = self.image, self.sector
            api.run_in_background(
                lambda: extract(image, picked, folder, sector),
                on_done=lambda written: api.notify(f"extracted {len(written)} file(s) to {folder}"),
                on_error=warn("Extract"))

    def do_browse(ctx):
        path = local(ctx)
        if path is None:
            return

        def got_layout(info):
            parts = [p for p in info.partitions if p.filesystem not in ("swap", "")
                     or p.number == 0] or info.partitions
            if not parts and info.note:
                container_hint(info)
                return
            if not parts:
                QMessageBox.information(api.window, "Browse File System",
                                        "No partition or file system found in this image.")
                return
            part = parts[0]
            if len(parts) > 1:
                labels = [f"{p.number}: {p.filesystem or p.type_name} {p.label} "
                          f"({DI.human_size(p.size)})" for p in parts]
                choice, ok = QInputDialog.getItem(api.window, "Browse File System", "Partition:",
                                                  labels, editable=False)
                if not ok:
                    return
                part = parts[labels.index(choice)]
            # fls / icat count -o in 512-byte sectors whatever the disk's own
            # sector size (TSK reads a raw image with 512 unless -b names
            # another): a 4Kn disk's LBAs would land an eighth of the way in.
            if part.start % TSK_SECTOR:
                QMessageBox.warning(api.window, "Browse File System",
                                    f"Partition {part.number} does not start on a 512-byte "
                                    "boundary; The Sleuth Kit cannot be pointed at it.")
                return
            sector = part.start // TSK_SECTOR
            api.run_in_background(
                lambda: list_files(path, sector),
                on_done=lambda entries: _show(path, sector, entries),
                on_error=warn("Browse File System"))

        def container_hint(info):
            # A qcow2, VMDK, dynamic VDI, VHD(X) or E01 keeps its partitions
            # inside a container The Sleuth Kit cannot read: say how to get
            # at them (core.disk_image's note) instead of "nothing found".
            box = QMessageBox(QMessageBox.Icon.Information, "Browse File System",
                              f"{os.path.basename(path)}: {info.description}.\n\nThe Sleuth "
                              f"Kit cannot read the partitions inside this container. {info.note}",
                              parent=api.window)
            convert = None
            if info.kind in QEMU_CONVERTS:
                convert = box.addButton("Convert to Raw…", QMessageBox.ButtonRole.ActionRole)
            box.addButton(QMessageBox.StandardButton.Close)
            box.exec()
            if convert is not None and box.clickedButton() is convert:
                do_convert(ctx)

        def _show(path, sector, entries):
            dialog = BrowseDialog(path, sector, entries)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.show()
            api.window._forensic_browse_dialog = dialog

        api.run_in_background(lambda: DI.inspect_path(path), on_done=got_layout,
                              on_error=warn("Browse File System"))

    def terminal(tool):
        def start(ctx):
            path = local(ctx)
            if path is None:
                return
            try:
                exe = need(tool)
            except ToolError as exc:
                QMessageBox.warning(api.window, tool, str(exc))
                return
            opener = getattr(api.window, "open_terminal_command", None)
            if opener is None:
                api.notify("this axross cannot start a terminal command")
                return
            opener([exe, path], cwd=os.path.dirname(path), label=f"{tool}: {os.path.basename(path)}")
        return start

    exts = suffixes()
    api.add_context_action("Hash Image (MD5, SHA-1, SHA-256)", do_hash, applies_to="single_file",
                           extensions=exts)
    api.add_context_action("Image Info (qemu-img)", do_info, applies_to="single_file",
                           extensions=exts)
    api.add_context_action("Convert to Raw Image (qemu-img)…", do_convert,
                           applies_to="single_file", extensions=exts)
    api.add_context_action("Browse File System (Sleuth Kit)…", do_browse,
                           applies_to="single_file", extensions=exts)
    api.add_context_action("Recover Partitions (TestDisk)", terminal("testdisk"),
                           applies_to="single_file", extensions=exts)
    api.add_context_action("Carve Files (PhotoRec)", terminal("photorec"),
                           applies_to="single_file", extensions=exts)
