"""Help > Features… > Packs… (a binary): the units of this release - every
pip extra, bundled extension and feature group - with their size and
whether they are installed; Add and Remove (core.packs: checked against the
release's signed SHA256SUMS before anything is unpacked).

A unit whose wheels are all pure Python is ready to use once added
(core.packs.activate_now): its folders go on sys.path, the backends'
availability is asked again, switched-on bundled extensions that could not
load are loaded, and :attr:`PacksDialog.activated` tells the Features
window to list again. A unit with a native wheel, and a removed unit, take
effect at the next start.
"""

from __future__ import annotations

import threading

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import packs as P
from core.i18n import tr
from core.thread_relay import GuiCall
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon


class PacksDialog(QDialog):
    #: The units just added and already in use (pure Python, no restart).
    activated = pyqtSignal(list)

    def __init__(self, parent=None, *, version: str | None = None, fetch=None, root=None, verify=None,
                 path: list | None = None):
        super().__init__(parent)
        set_window_icon(self, "pack")
        from axross._version import __version__

        self.setWindowTitle(tr("Packs"))
        self.resize(760, 520)
        self.version = version or __version__
        self.fetch, self.root, self.verify = fetch, root, verify
        #: Where activate_now puts the folders (sys.path; a list in the tests).
        self.path = path
        self.release = None
        self.manifest: dict = {}
        self._post = GuiCall(self._loaded)
        self._post_done = GuiCall(self._done)
        self._post_added = GuiCall(self._added)
        layout = QVBoxLayout(self)
        self.status = QLabel(tr("Reading the release of axross {v}…").format(v=self.version))
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([tr("Unit"), tr("Kind"), tr("Download"), tr("Installed")])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.add_button = QPushButton(tr("Add"))
        self.remove_button = QPushButton(tr("Remove"))
        self.add_button.clicked.connect(self.add_selected)
        self.remove_button.clicked.connect(self.remove_selected)
        for b in (self.add_button, self.remove_button):
            b.setEnabled(False)
            row.addWidget(b)
        row.addStretch(1)
        layout.addLayout(row)
        note = QLabel(tr("Packs of pure Python are ready to use once added; packs with native code, "
                         "and removing a pack, take effect at the next start of axross."))
        note.setWordWrap(True)
        layout.addWidget(note)
        add_close_corner(self)
        threading.Thread(target=self._load, daemon=True, name="packs-load").start()

    def _load(self) -> None:
        try:
            release = P.release_for(self.version, fetch=self.fetch)
            manifest, _ = P.signed_manifest(release, self.fetch or P.Fetcher(), verify=self.verify)
            self._post(release, manifest, "")
        except Exception as exc:  # noqa: BLE001 - shown
            self._post(None, {}, f"{type(exc).__name__}: {exc}")

    def _loaded(self, release, manifest, error: str) -> None:
        if error:
            self.status.setText(tr("The packs of this release could not be read: {e}").format(e=error))
            return
        self.release, self.manifest = release, manifest
        self.status.setText(tr("{n} units in the signed release {v}.").format(n=len(manifest["units"]), v=self.version))
        self.refresh()

    def refresh(self) -> None:
        installed = set(P.installed(self.version, self.root))
        sizes = P.unit_sizes(self.manifest)
        units = sorted(self.manifest.get("units", {}).items())
        self.table.setRowCount(len(units))
        for r, (name, u) in enumerate(units):
            for c, text in enumerate((u.get("title") or name, u.get("kind", ""), f"{sizes[name] / 1e6:.1f} MB",
                                      tr("yes") if name in installed else "")):
                item = QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, name)
                self.table.setItem(r, c, item)
        for b in (self.add_button, self.remove_button):
            b.setEnabled(True)

    def _selected(self) -> list[str]:
        rows = {i.row() for i in self.table.selectedItems()}
        return [self.table.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in sorted(rows)]

    def add_selected(self) -> None:
        units = self._selected()
        if not units or self.release is None:
            return
        self.add_button.setEnabled(False)
        self.status.setText(tr("Adding {u}…").format(u=", ".join(units)))

        def work():
            try:
                done = P.install(self.release, units, fetch=self.fetch, root=self.root, verify=self.verify)
                self._post_added(units, len(done))
            except Exception as exc:  # noqa: BLE001
                self._post_done(tr("Not added: {e}").format(e=exc))
        threading.Thread(target=work, daemon=True, name="packs-add").start()

    def _added(self, units: list[str], files: int) -> None:
        """On the GUI thread: use *units* at once when they are pure Python."""
        try:
            _folders, waiting = P.activate_now(self.version, units, self.root, self.path)
        except Exception as exc:  # noqa: BLE001 - shown; the next start activates them
            self._done(tr("Added: {n} files checked and unpacked, but not activated ({e}). "
                          "Restart axross to use them.").format(n=files, e=exc))
            return
        if waiting:
            self._done(tr("Added: {n} files checked and unpacked. {w} contain native code: "
                          "restart axross to use them.").format(n=files, w=", ".join(waiting)))
            return
        _refresh_features()
        self._retry_extensions()
        self._done(tr("Added: {n} files checked and unpacked – ready to use.").format(n=files))
        self.activated.emit(list(units))

    def _retry_extensions(self) -> None:
        """Load the switched-on bundled extensions that could not load - a
        pack just added may be what they missed. A suspended one (it hung)
        and safe mode stay as they are."""
        host = _extension_host(self)
        if host is None:
            return
        from core import extensions as EX

        if EX.safe_mode():
            return
        for ext_id in sorted(EX.enabled_ids() - EX.suspended_ids()):
            if ext_id.startswith("bundled:") and ext_id not in host.loaded_ids() and host.error(ext_id):
                host.retry(ext_id)

    def remove_selected(self) -> None:
        for unit in self._selected():
            P.remove(self.version, unit, self.root)
        self.status.setText(tr("Removed. What is already loaded stays in use until axross is restarted: "
                               "restart axross to finish removing it."))
        self.refresh()

    def _done(self, text: str) -> None:
        self.status.setText(text)
        self.add_button.setEnabled(True)
        self.refresh()


def _refresh_features() -> None:
    """Python finds the new packages, every backend's availability is asked
    again (core.features.refresh_availability, as after a pip install)."""
    from core import features as F

    F.refresh_availability()


def _extension_host(widget):
    """The main window's extension host (ui.extension_host), or None."""
    while widget is not None:
        host = getattr(widget, "extension_host", None)
        if host is not None:
            return host
        widget = widget.parentWidget()
    return None
