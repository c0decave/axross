"""Agent Settings > MCP Servers > Add from Catalog…: search the MCP sources,
pick a server, install it into podman (core.mcp_install).

The sources are those switched on in Agent Settings > MCP Sources
(core.mcp_catalog): the built-in catalog, the c0decave MCP Hub, Docker
Hub's ``mcp`` namespace, the MCP Registry, Discover (curated lists,
core.mcp_discover) and the user's catalogs. A search asks them all at once,
off the GUI thread; the results are grouped by category, each with its
source, kind, licence, last update and whether podman has its image.

A Discover entry is "link only" (Open Repository, no install) unless the
MCP Registry or Docker Hub names its repository: then it says
"installable via" that source and installs through it. The check runs in
the background after a search (bounded, cached); *Refresh* reads the lists
and checks again.

Everything a source says is shown as plain text (tooltips escaped). The
install form asks what the server may reach: its network (none by default; an allowlist of
``host:port``; full), its folders (read-only unless ticked writable), the
values of its environment (secret ones are kept in the keyring) and its
arguments. Install pulls or builds in the background with its output
shown and Cancel; the server is then tested (initialize, tools/list) and
switched on if the test passed. :attr:`installed` hands it to the MCP
Servers page; Save there writes it.
"""

from __future__ import annotations

import html
import logging
import queue
import threading

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import mcp_catalog as M
from core import mcp_client as MC
from core import mcp_install as I
from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.column_fit import ColumnFitter

log = logging.getLogger(__name__)
_ENTRY_ROLE = Qt.ItemDataRole.UserRole
NETWORK_LABELS = {
    "none": "None - no network (safest)",
    "allowlist": "Allowlist - only the hosts below (programs that use HTTPS_PROXY)",
    "full": "Full - any host",
}


class McpCatalogDialog(QDialog):
    """Search the sources, install one server at a time."""

    #: (config, secrets {name: value}, token): a server was installed.
    installed = pyqtSignal(object, object, str)

    def __init__(self, parent=None, *, sources: M.CatalogSources | None = None, taken=(),
                 podman: I.Podman | None = None, opener=None, search_now: bool = True,
                 category: str = "", query: str = "") -> None:
        """*category* filters the list from the start (kept even when no
        source names it, so an empty list says so); *query* is searched."""
        super().__init__(parent)
        #: The category asked for (an agent profile's missing one).
        self._wanted_category = category
        self.setWindowTitle(tr("Add MCP Server from Catalog"))
        self.resize(1100, 720)
        self._sources = (sources or M.CatalogSources()).sources(opener=opener)
        self._taken = set(taken)
        self._podman = podman if podman is not None else I.Podman()
        self._index = I.ImageIndex()
        self._results: list[M.SearchResult] = []
        self._entry: M.CatalogEntry | None = None
        self._cancel: threading.Event | None = None
        self._search_cancel: threading.Event | None = None
        self._generation = 0
        self._busy = False
        self._xref_cancel: threading.Event | None = None
        self._xref_running = False
        self._xref_checking: set[str] = set()
        self._refill = QTimer(self)
        self._refill.setSingleShot(True)
        self._refill.setInterval(250)
        self._refill.timeout.connect(self._fill_tree)
        #: Installed here, in order: (config, secrets, token).
        self.installs: list = []

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr("Search MCP servers (name, description, tag)"))
        self.search_edit.returnPressed.connect(self.search)
        self.source_combo = QComboBox()
        self.source_combo.addItem(tr("All sources"), "")
        for source in self._sources:
            self.source_combo.addItem(source.title, source.id)
        self.source_combo.currentIndexChanged.connect(self._fill_tree)
        self.category_combo = QComboBox()
        self.category_combo.addItem(tr("All categories"), "")
        if category:
            self.category_combo.addItem(category, category)
            self.category_combo.setCurrentIndex(1)
        self.category_combo.currentIndexChanged.connect(self._fill_tree)
        self.search_button = QPushButton(tr("Search"))
        self.search_button.clicked.connect(self.search)
        self.refresh_button = QPushButton(tr("Refresh"))
        self.refresh_button.setToolTip(tr("Read the lists and registries again (no cache)"))
        self.refresh_button.clicked.connect(self.refresh)
        top = QHBoxLayout()
        top.addWidget(self.search_edit, 1)
        top.addWidget(self.source_combo)
        top.addWidget(self.category_combo)
        top.addWidget(self.search_button)
        top.addWidget(self.refresh_button)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.podman_label = QLabel()
        self.podman_label.setWordWrap(True)
        self.podman_label.setTextFormat(Qt.TextFormat.PlainText)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([tr("Name"), tr("Source"), tr("Kind"), tr("Licence"),
                                   tr("Updated"), tr("Image")])
        self.tree.setRootIsDecorated(True)
        self._tree_columns = ColumnFitter(self.tree, fill=0)
        self.tree.currentItemChanged.connect(self._show_entry)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText(tr("Choose a server to see what it is and needs."))
        self.open_page_button = QPushButton(tr("Open Repository"))
        self.open_page_button.clicked.connect(self._open_page)
        self.open_page_button.setEnabled(False)

        self.form_box = QGroupBox(tr("Install"))
        form = QFormLayout(self.form_box)
        self.name_edit = QLineEdit()
        form.addRow(tr("Server name"), self.name_edit)
        self.network_combo = QComboBox()
        for key, label in NETWORK_LABELS.items():
            self.network_combo.addItem(tr(label), key)
        self.network_combo.currentIndexChanged.connect(self._update_form)
        form.addRow(tr("Network"), self.network_combo)
        self.hosts_edit = QLineEdit()
        self.hosts_edit.setPlaceholderText("api.example.com:443 other.example:443")
        form.addRow(tr("Allowed hosts"), self.hosts_edit)
        self.mounts_table = QTableWidget(0, 3)
        self.mounts_table.setHorizontalHeaderLabels([tr("In the container"), tr("Folder"),
                                                     tr("Writable")])
        self._mount_columns = ColumnFitter(self.mounts_table, fill=1)
        self.mounts_table.setMaximumHeight(120)
        form.addRow(tr("Folders"), self.mounts_table)
        mount_row = QHBoxLayout()
        self.add_folder_button = QPushButton(tr("Add Folder…"))
        self.add_folder_button.clicked.connect(lambda _c=False: self.add_folder())
        self.remove_folder_button = QPushButton(tr("Remove Folder"))
        self.remove_folder_button.clicked.connect(self.remove_folder)
        mount_row.addWidget(self.add_folder_button)
        mount_row.addWidget(self.remove_folder_button)
        mount_row.addStretch(1)
        form.addRow("", mount_row)
        self.env_table = QTableWidget(0, 2)
        self.env_table.setHorizontalHeaderLabels([tr("Variable"), tr("Value")])
        self._env_columns = ColumnFitter(self.env_table, fill=1)
        self.env_table.setMaximumHeight(120)
        form.addRow(tr("Environment"), self.env_table)
        self.args_edit = QLineEdit()
        form.addRow(tr("Arguments"), self.args_edit)
        self.token_edit = QLineEdit()
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_edit.setPlaceholderText(tr("stored in the keyring"))
        form.addRow(tr("Token"), self.token_edit)
        buttons = QHBoxLayout()
        self.install_button = QPushButton(tr("Install"))
        self.install_button.clicked.connect(self.install)
        self.cancel_button = QPushButton(tr("Cancel Install"))
        self.cancel_button.clicked.connect(self.cancel_install)
        self.cancel_button.setEnabled(False)
        buttons.addWidget(self.install_button)
        buttons.addWidget(self.cancel_button)
        buttons.addStretch(1)
        form.addRow("", buttons)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(2000)
        self.log.setPlaceholderText(tr("What the install does appears here."))

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self.details, 2)
        right_layout.addWidget(self.open_page_button, 0, Qt.AlignmentFlag.AlignLeft)
        right_layout.addWidget(self.form_box)
        right_layout.addWidget(self.log, 1)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.tree)
        splitter.addWidget(right)
        splitter.setSizes([560, 540])

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.status_label)
        layout.addWidget(self.podman_label)
        layout.addWidget(splitter, 1)
        layout.addWidget(close)
        add_close_corner(self)

        # Worker threads never touch Qt: they put (handler, args) here and a
        # timer of the dialog hands them over - a worker that outlives the
        # dialog then writes into a queue nobody reads (an emit on a deleted
        # dialog crashed the process).
        self._inbox: queue.SimpleQueue = queue.SimpleQueue()
        self._poll = QTimer(self)
        self._poll.setInterval(40)
        self._poll.timeout.connect(self._drain)
        self._poll.start()
        if not self._podman.available:
            self.podman_label.setText(tr(
                "podman is not installed: servers that run in a container (images, npm and "
                "pypi packages) cannot be installed. Install rootless podman "
                "(https://podman.io); remote servers work without it."))
        self._show_entry(None)
        if query:
            self.search_edit.setText(query)
        if search_now:
            self.search()

    # -- search -----------------------------------------------------------------------

    def search(self) -> None:
        """Ask every source (in the background); the tree fills when done."""
        if self._search_cancel is not None:
            self._search_cancel.set()
        if self._xref_cancel is not None:
            self._xref_cancel.set()
        cancel = self._search_cancel = threading.Event()
        self._generation += 1
        generation = self._generation
        query = self.search_edit.text().strip()
        self.status_label.setText(tr("Searching {n} sources…").format(n=len(self._sources)))
        sources = list(self._sources)
        podman = self._podman
        inbox = self._inbox

        def run() -> None:
            results = M.search_all(sources, query, cancel=cancel)
            inbox.put(("_take_results", (generation, results)))
            if podman.available:
                try:
                    inbox.put(("_take_index", podman.index()))
                except I.InstallError as exc:
                    inbox.put(("_append_log", tr("podman: {why}").format(why=exc)))

        threading.Thread(target=run, name="mcp-catalog-search", daemon=True).start()

    def refresh(self) -> None:
        """Forget what the sources cached (Discover's lists and checks) and
        search again."""
        for source in self._sources:
            forget = getattr(source, "refresh", None)
            if callable(forget):
                forget()
        self.search()

    def _take_results(self, payload) -> None:
        generation, results = payload
        if generation != self._generation:
            return  # an older search
        self._results = results
        notes = []
        total = 0
        for result in results:
            total += len(result.entries)
            if result.error:
                notes.append(tr("{source}: {why}").format(source=result.title, why=result.error))
            notes.extend(tr("{source}: {why}").format(source=result.title, why=note)
                         for note in result.notes)
            if result.warnings:
                notes.append(tr("{source}: {n} entries skipped ({first})").format(
                    source=result.title, n=len(result.warnings), first=result.warnings[0]))
        self.status_label.setText(
            tr("{n} servers found.").format(n=total) + ("\n" + "\n".join(notes) if notes else ""))
        chosen = self.category_combo.currentData()
        categories = sorted({e.category for r in results for e in r.entries}
                            | ({chosen} if chosen and chosen == self._wanted_category else set()))
        self.category_combo.blockSignals(True)
        self.category_combo.clear()
        self.category_combo.addItem(tr("All categories"), "")
        for category in categories:
            self.category_combo.addItem(category, category)
        self.category_combo.setCurrentIndex(max(0, self.category_combo.findData(chosen)))
        self.category_combo.blockSignals(False)
        self._fill_tree()
        self._start_crossref(generation)

    # -- Discover: the cross-reference --------------------------------------------------

    def _discover(self):
        from core.mcp_discover import DiscoverSource

        return next((s for s in self._sources if isinstance(s, DiscoverSource)), None)

    def _start_crossref(self, generation: int) -> None:
        """Check the unchecked Discover entries in the background."""
        source = self._discover()
        result = next((r for r in self._results if r.source == "discover"), None)
        if source is None or result is None:
            return
        todo = [e for e in result.entries if e.xref == "unchecked"]
        if not todo:
            return
        cancel = self._xref_cancel = threading.Event()
        inbox = self._inbox
        self._xref_running = True
        self._show_xref_state(len(todo))

        def run() -> None:
            done = source.crossref_all(
                todo, cancel=cancel,
                on_entry=lambda entry: inbox.put(("_take_checked", generation, entry)))
            inbox.put(("_crossref_done", generation, done))

        threading.Thread(target=run, name="mcp-discover-crossref", daemon=True).start()

    def _show_xref_state(self, left: int) -> None:
        lines = [line for line in self.status_label.text().split("\n")
                 if not line.startswith(tr("Discover: checking"))]
        if left:
            lines.append(tr("Discover: checking {n} entries against the MCP Registry and "
                            "Docker Hub…").format(n=left))
        self.status_label.setText("\n".join(lines))

    def _take_checked(self, generation: int, entry: M.CatalogEntry) -> None:
        self._xref_checking.discard(entry.id)
        if generation != self._generation:
            return
        for result in self._results:
            if result.source != entry.source:
                continue
            result.entries = [entry if e.id == entry.id else e for e in result.entries]
        if self._entry is not None and self._entry.id == entry.id and not self._busy:
            item = self.tree.currentItem()
            if item is not None:
                item.setData(0, _ENTRY_ROLE, entry)
            self._show_entry(item)
        if not self._refill.isActive():
            self._refill.start()

    def _crossref_done(self, generation: int, _done: int) -> None:
        if generation != self._generation:
            return
        self._xref_running = False
        self._show_xref_state(0)
        self._fill_tree()

    def _check_now(self, entry: M.CatalogEntry) -> None:
        """Check one selected Discover entry the background run has not reached."""
        source = self._discover()
        if source is None or entry.id in self._xref_checking:
            return
        self._xref_checking.add(entry.id)
        generation = self._generation
        inbox = self._inbox

        def run() -> None:
            try:
                checked = source.check(entry)
            except Exception:  # noqa: BLE001 - the entry stays unchecked, shown as such
                log.exception("mcp catalog: checking %s failed", entry.id)
                checked = entry
            inbox.put(("_take_checked", generation, checked))

        threading.Thread(target=run, name="mcp-discover-check", daemon=True).start()

    def _take_index(self, index) -> None:
        self._index = index
        self._fill_tree()

    def entries(self) -> list[M.CatalogEntry]:
        """The entries the filters let through, in the tree's order."""
        source = self.source_combo.currentData()
        category = self.category_combo.currentData()
        out = []
        for result in self._results:
            if source and result.source != source:
                continue
            out.extend(e for e in result.entries if not category or e.category == category)
        return out

    def _image_state(self, entry: M.CatalogEntry) -> str:
        state = self._index.has(entry)
        return {"pinned": tr("pulled"), "other": tr("another version pulled")}.get(state, "")

    def _fill_tree(self, *_args) -> None:
        current = self._entry.id if self._entry is not None else None
        self.tree.blockSignals(True)
        self.tree.clear()
        groups: dict[str, QTreeWidgetItem] = {}
        select = None
        for entry in self.entries():
            group = groups.get(entry.category)
            if group is None:
                group = groups[entry.category] = QTreeWidgetItem([entry.category])
                group.setFlags(group.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                self.tree.addTopLevelItem(group)
            source = next((s.title for s in self._sources if s.id == entry.source), entry.source)
            item = QTreeWidgetItem([entry.title or entry.name, source, self._kind_text(entry),
                                    entry.license, entry.updated, self._image_state(entry)])
            item.setData(0, _ENTRY_ROLE, entry)
            item.setToolTip(0, plain_tooltip(entry.description[:500]))
            group.addChild(item)
            if entry.id == current:
                select = item
        self.tree.expandAll()
        self.tree.blockSignals(False)
        if select is not None:
            self.tree.setCurrentItem(select)

    @staticmethod
    def _kind_text(entry: M.CatalogEntry) -> str:
        if entry.xref == "unchecked":
            return tr("not checked yet")
        if entry.xref == "link":
            return tr("link only")
        if entry.via:
            return tr("installable via {source}").format(source=entry.via)
        return entry.kind if entry.installable else tr("{kind} (not installable)").format(
            kind=entry.kind)

    def select_entry(self, entry_id: str) -> bool:
        """Select the entry *entry_id* in the tree (False: not shown)."""
        for i in range(self.tree.topLevelItemCount()):
            group = self.tree.topLevelItem(i)
            for j in range(group.childCount()):
                item = group.child(j)
                entry = item.data(0, _ENTRY_ROLE)
                if entry is not None and entry.id == entry_id:
                    self.tree.setCurrentItem(item)
                    return True
        return False

    # -- details and the form ---------------------------------------------------------

    def _show_entry(self, item, _previous=None) -> None:
        entry = item.data(0, _ENTRY_ROLE) if item is not None else None
        if self._busy:
            # The form belongs to the install that runs; only the text follows.
            if entry is not None:
                self.details.setPlainText(self._describe(entry))
            return
        self._entry = entry
        self.form_box.setEnabled(entry is not None)
        self.open_page_button.setEnabled(bool(entry and (entry.repository or entry.page)))
        if entry is None:
            self.details.clear()
            self._update_form()
            return
        self.details.setPlainText(self._describe(entry))
        self.name_edit.setText(self._free_name(entry.name))
        self.network_combo.setCurrentIndex(0)  # none: network is an explicit choice
        self.hosts_edit.setText(" ".join(entry.hosts))
        self.mounts_table.setRowCount(0)
        self.env_table.setRowCount(0)
        for spec in entry.env:
            self._add_env_row(spec)
        self.args_edit.setText(" ".join(_quote(a) for a in entry.args))
        self.token_edit.clear()
        self._update_form()
        if entry.xref == "unchecked" and not self._xref_running:
            self._check_now(entry)
        source = next((s for s in self._sources if s.id == entry.source), None)
        if isinstance(source, M.DockerHubSource) and not entry.repository:
            inbox = self._inbox

            def run() -> None:
                inbox.put(("_take_details", source.details(entry)))

            threading.Thread(target=run, name="mcp-catalog-details", daemon=True).start()

    def _take_details(self, entry) -> None:
        if self._entry is not None and self._entry.id == entry.id:
            self._entry = entry
            self.details.setPlainText(self._describe(entry))
            self.open_page_button.setEnabled(bool(entry.repository or entry.page))
            item = self.tree.currentItem()
            if item is not None:
                item.setData(0, _ENTRY_ROLE, entry)
                item.setText(3, entry.license)

    def _describe(self, entry: M.CatalogEntry) -> str:
        lines = [entry.title or entry.name, ""]
        if entry.description:
            lines += [entry.description, ""]
        lines.append(tr("Source: {s}").format(s=entry.source))
        if entry.category:
            lines.append(tr("Category: {c}").format(c=entry.category))
        if entry.listed_in:
            lines.append(tr("Listed in: {lists}").format(lists=entry.listed_in))
        if entry.xref in ("mcpregistry", "dockerhub"):
            lines.append(tr("Installable via {source}").format(source=entry.via))
        if entry.installable:
            lines.append(tr("Runs: {what}").format(what=entry.package_ref))
        if entry.repository:
            lines.append(tr("Repository: {url}").format(url=entry.repository))
        if entry.page:
            lines.append(tr("Page: {url}").format(url=entry.page))
        lines.append(tr("Licence: {l}").format(l=entry.license or tr("not stated")))
        if entry.updated:
            lines.append(tr("Updated: {d}").format(d=entry.updated))
        if entry.tags:
            lines.append(tr("Tags: {t}").format(t=", ".join(entry.tags)))
        needs = {"none": tr("no network"), "full": tr("network (any host)"),
                 "allowlist": tr("network to {hosts}").format(hosts=", ".join(entry.hosts))}
        lines.append(tr("Needs: {what}").format(what=needs.get(entry.network, entry.network)))
        for spec in entry.mounts:
            lines.append(tr("Folder at {target}: {d}{req}").format(
                target=spec.target, d=spec.description,
                req=tr(" (required)") if spec.required else ""))
        for spec in entry.env:
            lines.append(tr("Variable {name}{secret}: {d}").format(
                name=spec.name, secret=tr(" (secret)") if spec.secret else "",
                d=spec.description))
        if entry.maintainer:
            lines += ["", tr("Maintained by {who}, not by axross. axross pins the version and runs "
                             "it in a container; problems with the server itself go to its "
                             "project{at}.").format(
                who=entry.maintainer, at=f" ({entry.repository})" if entry.repository else "")]
        if entry.notes:
            lines += ["", entry.notes]
        if entry.why_not:
            lines += ["", tr("Cannot be installed: {why}").format(why=entry.why_not)]
        state = self._image_state(entry)
        if state:
            lines += ["", tr("Image: {state}").format(state=state)]
        return "\n".join(lines)

    def _free_name(self, name: str) -> str:
        candidate, n = name, 1
        while candidate in self._taken:
            n += 1
            suffix = str(n)
            candidate = f"{name[:32 - len(suffix)]}{suffix}"
        return candidate

    def _add_env_row(self, spec: M.EnvSpec) -> None:
        row = self.env_table.rowCount()
        self.env_table.insertRow(row)
        label = spec.name + (" *" if spec.required else "")
        name_item = QTableWidgetItem(label)
        name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        name_item.setData(_ENTRY_ROLE, spec)
        name_item.setToolTip(spec.description)
        self.env_table.setItem(row, 0, name_item)
        edit = QLineEdit(spec.default)
        if spec.secret:
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.setPlaceholderText(tr("secret - stored in the keyring"))
        self.env_table.setCellWidget(row, 1, edit)

    def env_edit(self, name: str) -> QLineEdit | None:
        for row in range(self.env_table.rowCount()):
            spec = self.env_table.item(row, 0).data(_ENTRY_ROLE)
            if spec.name == name:
                return self.env_table.cellWidget(row, 1)
        return None

    def add_folder(self, path: str | None = None, target: str | None = None,
                   writable: bool = False) -> None:
        entry = self._entry
        if entry is None or not entry.mounts:
            return
        if target is None:
            used = {self.mounts_table.item(r, 0).text()
                    for r in range(self.mounts_table.rowCount())}
            target = next((m.target for m in entry.mounts if m.repeat or m.target not in used),
                          entry.mounts[0].target)
        if not isinstance(path, str):
            path = QFileDialog.getExistingDirectory(self, tr("Folder for {target}").format(
                target=target))
        if not path:
            return
        row = self.mounts_table.rowCount()
        self.mounts_table.insertRow(row)
        target_item = QTableWidgetItem(target)
        target_item.setFlags(target_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.mounts_table.setItem(row, 0, target_item)
        path_item = QTableWidgetItem(path)
        path_item.setFlags(path_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.mounts_table.setItem(row, 1, path_item)
        check = QCheckBox()
        check.setChecked(bool(writable))
        check.setToolTip(tr("Off: the server reads the folder only"))
        self.mounts_table.setCellWidget(row, 2, check)

    def remove_folder(self) -> None:
        row = self.mounts_table.currentRow()
        if row >= 0:
            self.mounts_table.removeRow(row)

    def _update_form(self, *_args) -> None:
        entry = self._entry
        remote = entry is not None and entry.kind == "remote"
        container = entry is not None and entry.kind in ("oci", "npm", "pypi")
        allow = self.network_combo.currentData() == "allowlist"
        self.network_combo.setEnabled(container)
        self.hosts_edit.setEnabled(container and allow)
        has_mounts = bool(entry and entry.mounts)
        for widget in (self.mounts_table, self.add_folder_button, self.remove_folder_button):
            widget.setEnabled(container and has_mounts)
        self.env_table.setEnabled(container)
        self.args_edit.setEnabled(container)
        self.token_edit.setEnabled(remote and bool(entry and entry.bearer))
        can = (entry is not None and entry.installable and not self._busy
               and (remote or self._podman.available))
        self.install_button.setEnabled(bool(can))

    def choice(self) -> I.InstallChoice:
        """What the form says."""
        env, secrets = {}, {}
        for row in range(self.env_table.rowCount()):
            spec = self.env_table.item(row, 0).data(_ENTRY_ROLE)
            value = self.env_table.cellWidget(row, 1).text()
            (secrets if spec.secret else env)[spec.name] = value
        mounts = []
        for row in range(self.mounts_table.rowCount()):
            mounts.append(I.Mount(self.mounts_table.item(row, 1).text(),
                                  self.mounts_table.item(row, 0).text(),
                                  self.mounts_table.cellWidget(row, 2).isChecked()))
        args = _split(self.args_edit.text())
        return I.InstallChoice(
            name=self.name_edit.text().strip(),
            network=self.network_combo.currentData() or "none",
            hosts=tuple(self.hosts_edit.text().split()),
            mounts=tuple(mounts), env={k: v for k, v in env.items() if v},
            secrets={k: v for k, v in secrets.items() if v},
            args=tuple(args), token=self.token_edit.text(),
        )

    # -- install ----------------------------------------------------------------------

    def install(self) -> None:
        entry = self._entry
        if entry is None or self._busy:
            return
        choice = self.choice()
        problems = I.choice_problems(entry, choice, taken=self._taken)
        if problems:
            self._append_log(tr("Not installed: {why}").format(why="; ".join(problems)))
            return
        self._busy = True
        self._cancel = threading.Event()
        cancel = self._cancel
        self.cancel_button.setEnabled(True)
        self.form_box.setEnabled(True)
        self._update_form()
        self._append_log(tr("Installing {name} ({what})…").format(name=choice.name,
                                                                 what=entry.package_ref))
        source = next((s for s in self._sources if s.id == entry.source), None)
        podman = self._podman
        taken = set(self._taken)
        inbox = self._inbox

        def run() -> None:
            try:
                config = I.install(entry, choice, podman=podman, source=source,
                                   on_line=lambda line: inbox.put(("_append_log", line)),
                                   cancel=cancel, taken=taken)
            except I.InstallError as exc:
                inbox.put(("_installed", None, str(exc)))
                return
            except Exception as exc:  # noqa: BLE001 - shown, never a crash of the dialog
                inbox.put(("_installed", None, f"{type(exc).__name__}: {exc}"))
                return
            inbox.put(("_installed", (config, dict(choice.secrets), choice.token), ""))

        threading.Thread(target=run, name="mcp-install", daemon=True).start()

    def cancel_install(self) -> None:
        if self._cancel is not None:
            self._cancel.set()
            self._append_log(tr("Cancelling…"))

    def _installed(self, payload, error: str) -> None:
        self.cancel_button.setEnabled(False)
        self._cancel = None
        if payload is None:
            self._busy = False
            self._update_form()
            self._append_log(tr("Install failed: {why}").format(why=error))
            return
        config, secrets, token = payload
        self._append_log(tr("Installed. Testing {name}…").format(name=config.name))
        inbox = self._inbox

        def run() -> None:
            try:
                client = MC.McpClient(config, token=token, secrets=secrets)
                try:
                    names = [t.remote_name for t in client.tools()]
                finally:
                    client.close()
            except MC.McpClientError as exc:
                inbox.put(("_tested", payload, False, str(exc)))
                return
            inbox.put(("_tested", payload, True, ", ".join(names)))

        threading.Thread(target=run, name="mcp-install-test", daemon=True).start()

    def _tested(self, payload, ok: bool, text: str) -> None:
        config, secrets, token = payload
        self._busy = False
        if ok:
            config.enabled = True
            self._append_log(tr("Test passed - {name} is switched on. Tools: {tools}").format(
                name=config.name, tools=text or tr("none")))
        else:
            self._append_log(tr("Test failed: {why} - {name} is added switched off.").format(
                why=text, name=config.name))
        self._taken.add(config.name)
        self.installs.append(payload)
        self.installed.emit(config, secrets, token)
        self._update_form()
        self.search()  # the image column follows

    def _append_log(self, line: str) -> None:
        self.log.appendPlainText(M.clean_text(line, 2000, lines=True))

    def _open_page(self) -> None:
        entry = self._entry
        url = entry.repository or entry.page if entry is not None else ""
        if url:
            from core.desktop_open import open_url

            open_url(url)

    def busy(self) -> bool:
        return self._busy

    def _drain(self) -> None:
        """Hand what the workers reported to its handler, in the GUI thread."""
        while True:
            try:
                handler, *args = self._inbox.get_nowait()
            except queue.Empty:
                return
            getattr(self, handler)(*args)

    def reject(self) -> None:  # noqa: D102 - Qt override
        if self._cancel is not None:
            self._cancel.set()
        if self._search_cancel is not None:
            self._search_cancel.set()
        if self._xref_cancel is not None:
            self._xref_cancel.set()
        super().reject()


def plain_tooltip(text: str) -> str:
    """*text* as a tooltip that shows it as it is: Qt takes a tooltip that
    looks like markup for rich text, so it is escaped inside ``<qt>``."""
    return f"<qt>{html.escape(text).replace(chr(10), '<br>')}</qt>" if text else ""


def _quote(arg: str) -> str:
    import shlex

    return shlex.quote(arg)


def _split(text: str) -> list[str]:
    import shlex

    try:
        return shlex.split(text)
    except ValueError:
        return text.split()
