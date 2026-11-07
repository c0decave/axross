"""Help > Features… > Packs… (a binary): the units of this release - every
pip extra, bundled extension and feature group - with their size and
whether they are installed; Add and Remove (core.packs: checked against the
release's signed SHA256SUMS before anything is unpacked). Changes take
effect at the next start of axross.
"""

from __future__ import annotations

import threading

from PyQt6.QtCore import Qt
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
    def __init__(self, parent=None, *, version: str | None = None, fetch=None, root=None, verify=None):
        super().__init__(parent)
        set_window_icon(self, "pack")
        from axross._version import __version__

        self.setWindowTitle(tr("Packs"))
        self.resize(760, 520)
        self.version = version or __version__
        self.fetch, self.root, self.verify = fetch, root, verify
        self.release = None
        self.manifest: dict = {}
        self._post = GuiCall(self._loaded)
        self._post_done = GuiCall(self._done)
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
        layout.addWidget(QLabel(tr("Added and removed packs take effect at the next start of axross.")))
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
                self._post_done(tr("Added: {n} files checked and unpacked. Restart axross to use them.").format(n=len(done)))
            except Exception as exc:  # noqa: BLE001
                self._post_done(tr("Not added: {e}").format(e=exc))
        threading.Thread(target=work, daemon=True, name="packs-add").start()

    def remove_selected(self) -> None:
        for unit in self._selected():
            P.remove(self.version, unit, self.root)
        self.status.setText(tr("Removed. Restart axross to finish."))
        self.refresh()

    def _done(self, text: str) -> None:
        self.status.setText(text)
        self.add_button.setEnabled(True)
        self.refresh()
