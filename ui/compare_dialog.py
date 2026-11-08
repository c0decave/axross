"""Compare the active pane's tree against the target pane's.

The comparison itself lives in :mod:`core.tree_compare`; this is the
window around it. Two decisions here are about not destroying data:

**A copy direction is derived from the row, never from focus.** A file
that exists only on the left implies left-to-right and nothing else. A
file that exists on BOTH sides and differs implies nothing at all —
picking a direction there would be guessing which copy the user
considers authoritative, and guessing wrong overwrites the good side
with the stale one. Those rows require the user to say which way.

**Identical files are hidden by default.** The window exists to show
differences; a tree of several thousand matching files buries the
handful that matter. "All" is one click away.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core.sync import POLICIES, ConflictPolicy, plan_sync, summarize_plan
from core.tree_compare import ComparedEntry, Status, summarize
from ui.close_corner import add_close_corner
from ui.format_utils import human_bytes
from ui.thread_lifetime import detach_running_thread
from ui.icon_provider import set_window_icon
from core.i18n import tr, tr_n

log = logging.getLogger(__name__)

DASH = "—"

#: Filter name -> the statuses it admits. ``None`` means "everything".
FILTERS: dict[str, tuple[str, ...] | None] = {
    "Differences": (Status.LEFT_ONLY, Status.RIGHT_ONLY, Status.DIFFERS, Status.UNKNOWN),
    "All": None,
    "Left only": (Status.LEFT_ONLY,),
    "Right only": (Status.RIGHT_ONLY,),
    "Differs": (Status.DIFFERS,),
    "Unresolved": (Status.UNKNOWN,),
    "Identical": (Status.SAME,),
}

DEFAULT_FILTER = "Differences"

COLUMNS = ("Path", "Status", "Left", "Right", "Reason")

#: What the Status column shows for each status.
STATUS_LABELS = {
    Status.LEFT_ONLY: "only left",
    Status.RIGHT_ONLY: "only right",
    Status.SAME: "identical",
    Status.DIFFERS: "differs",
    Status.UNKNOWN: "unresolved",
}


def copy_direction(entry: ComparedEntry) -> str | None:
    """Which way a copy would obviously go, or ``None``.

    Only a one-sided entry has an unambiguous direction. When both sides
    exist — differing or unresolved — there is no safe default, and the
    caller must ask.
    """
    if entry.status == Status.LEFT_ONLY:
        return "to_right"
    if entry.status == Status.RIGHT_ONLY:
        return "to_left"
    return None


def export_text(entries: list[ComparedEntry]) -> str:
    """Tab-separated report of a comparison, for the clipboard or a file."""
    lines = ["status\tpath\tleft_bytes\tright_bytes\treason"]
    for entry in entries:
        left = entry.left.size if entry.left is not None else ""
        right = entry.right.size if entry.right is not None else ""
        lines.append(f"{entry.status}\t{entry.rel_path}\t{left}\t{right}\t{entry.reason}")
    if len(lines) == 1:
        lines.append("# the two trees match")
    return "\n".join(lines) + "\n"


class _EntriesModel(QAbstractTableModel):
    """The rows the table shows: one per visible entry, each cell's text
    worked out when the view asks for it (the rows on screen). Before, a
    QTableWidgetItem per cell: "All" over 20,000 entries made 100,000 of
    them on the GUI thread (~3 s)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.entries: list[ComparedEntry] = []

    def set_entries(self, entries: list[ComparedEntry]) -> None:
        self.beginResetModel()
        self.entries = list(entries)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.entries)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def cell_text(self, entry: ComparedEntry, col: int) -> str:
        if col == 0:
            return entry.rel_path
        if col == 1:
            return tr(STATUS_LABELS.get(entry.status, entry.status))
        if col == 2:
            return human_bytes(entry.left.size) if entry.left is not None else DASH
        if col == 3:
            return human_bytes(entry.right.size) if entry.right is not None else DASH
        return tr(entry.reason)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        row = index.row()
        if not index.isValid() or not 0 <= row < len(self.entries):
            return None
        entry = self.entries[row]
        if role == Qt.ItemDataRole.DisplayRole:
            return self.cell_text(entry, index.column())
        if role == Qt.ItemDataRole.UserRole:
            return entry.rel_path
        return None

    def headerData(self, section: int, orientation: Qt.Orientation,  # noqa: N802
                   role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole \
                and 0 <= section < len(COLUMNS):
            return tr(COLUMNS[section])
        return None


class _EntriesTable(QTableView):
    """The table of entries; ``rowCount()`` as the former QTableWidget had."""

    def rowCount(self) -> int:  # noqa: N802 - the QTableWidget name
        model = self.model()
        return model.rowCount() if model is not None else 0


class _CompareWorker(QObject):
    """Runs the tree walk + comparison off the GUI thread."""

    done = pyqtSignal(object, str)

    def __init__(self, compare_fn, args) -> None:
        super().__init__()
        self._compare_fn = compare_fn
        self._args = args
        self._cancelled = False

    def cancel(self) -> None:
        """Ask the walk to stop. QThread.quit() ends an event loop but
        cannot interrupt a slot that is already running, and a tree walk
        over a remote backend is unbounded work."""
        self._cancelled = True

    def run(self) -> None:
        try:
            result = self._compare_fn(*self._args, should_continue=lambda: not self._cancelled)
            self.done.emit(list(result), "")
        except Exception as exc:  # noqa: BLE001 — a broken walk must not kill the dialog
            log.debug("tree comparison failed: %s", exc)
            self.done.emit(None, str(exc))


class CompareDialog(QDialog):
    """Side-by-side comparison of two panes' trees."""

    #: (side, absolute path) — the main window navigates and selects.
    reveal_requested = pyqtSignal(str, str)
    #: (direction, [(absolute source, absolute destination)]) — routed to
    #: the transfer machinery.
    copy_requested = pyqtSignal(str, list)
    #: (side, [absolute paths])
    delete_requested = pyqtSignal(str, list)
    #: [{"source", "dest", "direction", "kind", "overwrites"}] — a whole
    #: sync plan, already confirmed by the user.
    sync_requested = pyqtSignal(list)

    def __init__(self, left_pane, right_pane, parent: QWidget | None = None, *, compare_fn=None):
        super().__init__(parent)
        set_window_icon(self, "compare")
        self._left_pane = left_pane
        self._right_pane = right_pane
        self._compare_fn = compare_fn or self._default_compare
        self._entries: list[ComparedEntry] = []
        # Roots of the comparison the rows come from; see refresh().
        self._left_root = self._right_root = ""
        self._pending_roots = ("", "")
        self._error = ""
        self._filter = DEFAULT_FILTER
        self._policy = ConflictPolicy.ASK
        self._thread: QThread | None = None
        self._worker: _CompareWorker | None = None

        self.setWindowTitle(tr("Compare panes"))
        self.resize(900, 520)
        self._build()
        self.refresh()

    # -- construction ----------------------------------------------------

    @staticmethod
    def _default_compare(left_backend, left_root, right_backend, right_root, **kwargs):
        from core.tree_compare import compare_trees

        return compare_trees(left_backend, left_root, right_backend, right_root, **kwargs)

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        add_close_corner(self)
        # F1: the handbook (its contents) - the main window's F1 does not reach this window.
        from ui.handbook import install_help_key

        install_help_key(self)

        top = QHBoxLayout()
        self._filter_box = QComboBox(self)
        for name in FILTERS:
            self._filter_box.addItem(tr(name), name)
        self._filter_box.setCurrentIndex(self._filter_box.findData(DEFAULT_FILTER))
        self._filter_box.currentIndexChanged.connect(
            lambda index: self.set_filter(self._filter_box.itemData(index)))
        top.addWidget(QLabel(tr("Show:"), self))
        top.addWidget(self._filter_box)
        top.addStretch(1)

        top.addWidget(QLabel(tr("On conflict:"), self))
        self._policy_box = QComboBox(self)
        for name in POLICIES:
            self._policy_box.addItem(tr(name), name)
        self._policy_box.currentIndexChanged.connect(
            lambda index: self.set_policy(
                POLICIES.get(self._policy_box.itemData(index), ConflictPolicy.ASK))
        )
        top.addWidget(self._policy_box)

        self._refresh_btn = QPushButton(tr("Re-compare"), self)
        self._refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self._refresh_btn)
        layout.addLayout(top)

        self._table = _EntriesTable(self)
        self._rows = _EntriesModel(self._table)
        self._table.setModel(self._rows)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        from ui.column_fit import ColumnFitter

        # The first column takes the free width; every divider stays draggable.
        self._columns = ColumnFitter(self._table, fill=0)
        self._table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

        actions = QHBoxLayout()
        self._reveal_btn = QPushButton(tr("Reveal in pane"), self)
        self._reveal_btn.clicked.connect(self._reveal_selected)
        actions.addWidget(self._reveal_btn)

        self._copy_btn = QPushButton(tr("Copy to other side"), self)
        self._copy_btn.clicked.connect(self._copy_selected)
        actions.addWidget(self._copy_btn)

        self._delete_btn = QPushButton(tr("Delete…"), self)
        self._delete_btn.clicked.connect(self._delete_selected)
        actions.addWidget(self._delete_btn)

        self._sync_btn = QPushButton(tr("Sync…"), self)
        self._sync_btn.setToolTip(
            tr("Apply the whole comparison in both directions, after showing "
            "you exactly what it would do")
        )
        self._sync_btn.clicked.connect(self._sync)
        actions.addWidget(self._sync_btn)

        self._export_btn = QPushButton(tr("Copy list"), self)
        self._export_btn.setToolTip(tr("Copy the current view to the clipboard"))
        self._export_btn.clicked.connect(self._export)
        actions.addWidget(self._export_btn)

        actions.addStretch(1)
        self._summary = QLabel(self)
        self._summary.setProperty("role", "muted")
        actions.addWidget(self._summary)
        layout.addLayout(actions)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # -- data ------------------------------------------------------------

    def refresh(self) -> None:
        if self._thread is not None:
            return
        self._refresh_btn.setEnabled(False)
        self._summary.setText(tr("comparing…"))

        # The roots of THIS walk become the dialog's roots only when its
        # result replaces the rows: until then the table shows the rows of
        # the previous comparison, and every action resolves them against
        # the roots they were compared under.
        self._pending_roots = (
            getattr(self._left_pane, "current_path", "/"),
            getattr(self._right_pane, "current_path", "/"),
        )
        args = (
            getattr(self._left_pane, "backend", None),
            self._pending_roots[0],
            getattr(self._right_pane, "backend", None),
            self._pending_roots[1],
        )
        self._thread = QThread(self)
        self._worker = _CompareWorker(self._compare_fn, args)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_result)
        self._thread.start()

    def _on_result(self, entries, error: str) -> None:
        self._left_root, self._right_root = self._pending_roots
        self._entries = list(entries) if entries is not None else []
        self._error = error
        self._populate()
        self._refresh_btn.setEnabled(True)
        self._stop_thread(done=True)

    def _populate(self) -> None:
        self._rows.set_entries(self.visible_entries())
        self._summary.setText(self._build_summary())

    def _build_summary(self) -> str:
        if self._error:
            return tr("Comparison failed: {error}").format(error=self._error)
        if not self._entries:
            return tr("The two trees match.")
        counts = summarize(self._entries)
        parts = [
            tr("{n} only left").format(n=counts[Status.LEFT_ONLY]),
            tr("{n} only right").format(n=counts[Status.RIGHT_ONLY]),
            tr("{n} differ").format(n=counts[Status.DIFFERS]),
            tr("{n} identical").format(n=counts[Status.SAME]),
        ]
        if counts[Status.UNKNOWN]:
            parts.append(tr("{n} unresolved").format(n=counts[Status.UNKNOWN]))
        return ", ".join(parts)

    # -- filtering -------------------------------------------------------

    def set_filter(self, name: str) -> None:
        if name not in FILTERS:
            return
        self._filter = name
        if self._filter_box.currentData() != name:
            self._filter_box.setCurrentIndex(self._filter_box.findData(name))
        self._populate()

    def current_filter(self) -> str:
        return self._filter

    def visible_entries(self) -> list[ComparedEntry]:
        allowed = FILTERS[self._filter]
        if allowed is None:
            return list(self._entries)
        return [e for e in self._entries if e.status in allowed]

    def summary_text(self) -> str:
        return self._summary.text()

    # -- selection + actions ---------------------------------------------

    def selected_entries(self) -> list[ComparedEntry]:
        """The entries of the selected rows, top to bottom (rows from the
        selection's ranges: no index per selected cell)."""
        entries = self._rows.entries
        rows = set()
        for selected in self._table.selectionModel().selection():
            rows.update(range(selected.top(), selected.bottom() + 1))
        return [entries[row] for row in sorted(rows) if 0 <= row < len(entries)]

    def absolute_path(self, side: str, rel_path: str) -> str:
        """Resolve a row to a full path on ``side``.

        Uses the root captured when the comparison ran, not the pane's
        current directory — the two diverge as soon as the user browses
        on while the window is open.
        """
        pane = self._left_pane if side == "left" else self._right_pane
        root = self._left_root if side == "left" else self._right_root
        backend = getattr(pane, "backend", None)
        path = root
        for part in rel_path.split("/"):
            path = backend.join(path, part) if backend is not None else f"{path}/{part}"
        return path

    def _on_double_click(self, _index: QModelIndex) -> None:
        self._reveal_selected()

    def _reveal_selected(self) -> None:
        for entry in self.selected_entries():
            side = "left" if entry.left is not None else "right"
            self.reveal_requested.emit(side, self.absolute_path(side, entry.rel_path))

    def _copy_selected(self) -> None:
        entries = self.selected_entries()
        if not entries:
            return
        directed: dict[str, list[tuple[str, str]]] = {"to_left": [], "to_right": []}
        ambiguous: list[str] = []
        for entry in entries:
            direction = copy_direction(entry)
            if direction is None:
                ambiguous.append(entry.rel_path)
                continue
            # to_right means the file lives on the LEFT and travels
            # right, so the source path is the left one. The destination
            # travels along: the receiver must not fall back to whatever
            # folder the target pane shows.
            source_side = "left" if direction == "to_right" else "right"
            dest_side = "right" if direction == "to_right" else "left"
            directed[direction].append(
                (
                    self.absolute_path(source_side, entry.rel_path),
                    self.absolute_path(dest_side, entry.rel_path),
                )
            )

        if ambiguous:
            QMessageBox.information(
                self,
                tr("Direction unclear"),
                tr("These entries exist on both sides, so there is no obvious "
                   "direction to copy them:") + "\n\n"
                + "\n".join(ambiguous[:10])
                + "\n\n" + tr("Open them in a pane and copy the side you want to keep."),
            )
        for direction, paths in directed.items():
            if paths:
                self.copy_requested.emit(direction, paths)

    def _delete_selected(self) -> None:
        entries = self.selected_entries()
        if not entries:
            return
        by_side: dict[str, list[str]] = {"left": [], "right": []}
        for entry in entries:
            # Delete removes the copy that exists; for a two-sided entry
            # the user must disambiguate in a pane.
            if entry.left is not None and entry.right is None:
                by_side["left"].append(self.absolute_path("left", entry.rel_path))
            elif entry.right is not None and entry.left is None:
                by_side["right"].append(self.absolute_path("right", entry.rel_path))

        total = len(by_side["left"]) + len(by_side["right"])
        if total == 0:
            QMessageBox.information(
                self,
                tr("Nothing to delete here"),
                tr("Only entries that exist on one side can be deleted from this "
                "window. For files present on both sides, delete from the pane "
                "holding the copy you want gone."),
            )
            return
        confirm = QMessageBox.question(
            self,
            tr("Delete"),
            tr_n(total, "Delete {n} entry? This cannot be undone.",
                 "Delete {n} entries? This cannot be undone."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        for side, paths in by_side.items():
            if paths:
                self.delete_requested.emit(side, paths)

    # -- sync -------------------------------------------------------------

    def set_policy(self, policy: ConflictPolicy) -> None:
        self._policy = policy

    def sync_plan(self):
        """Plan a sync over the WHOLE comparison.

        Deliberately not the filtered view: the table hides identical
        files by default, and planning off what happens to be on screen
        would quietly sync a subset of what was actually compared.
        """
        return plan_sync(self._entries, policy=self._policy)

    def _sync(self) -> None:
        plan = self.sync_plan()
        if not plan.actions and not plan.conflicts:
            QMessageBox.information(self, tr("Sync"), summarize_plan(plan))
            return

        detail = summarize_plan(plan)
        if plan.conflicts:
            detail += "\n\n" + tr("Left for you to decide:") + "\n" + "\n".join(
                f"  {c.rel_path} — {c.reason}" for c in plan.conflicts[:10]
            )
            if len(plan.conflicts) > 10:
                detail += "\n  " + tr("… and {hidden} more").format(hidden=len(plan.conflicts) - 10)
        if not plan.actions:
            QMessageBox.information(self, tr("Sync"), detail)
            return

        overwrites = sum(1 for a in plan.actions if a.overwrites)
        question = tr("Apply {n} change(s)?").format(n=len(plan.actions)) + f"\n\n{detail}"
        if overwrites:
            question += "\n\n" + tr("This cannot be undone for the replaced files.")
        if QMessageBox.question(
            self,
            tr("Sync"),
            question,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._emit_sync(plan)

    def _emit_sync(self, plan) -> None:
        """Hand the plan over with absolute paths on both ends."""
        items = []
        for action in plan.actions:
            src_side = "left" if action.direction == "to_right" else "right"
            dst_side = "right" if action.direction == "to_right" else "left"
            items.append(
                {
                    "rel_path": action.rel_path,
                    "kind": action.kind,
                    "direction": action.direction,
                    "overwrites": action.overwrites,
                    # "newer wins" decided on the comparison's times: the
                    # copy re-checks them when it runs
                    "newer_only": action.overwrites and self._policy is ConflictPolicy.NEWER_WINS,
                    "source": self.absolute_path(src_side, action.rel_path),
                    "dest": self.absolute_path(dst_side, action.rel_path),
                }
            )
        if items:
            self.sync_requested.emit(items)

    def _export(self) -> None:
        QApplication.clipboard().setText(export_text(self.visible_entries()))
        self._summary.setText(self._build_summary() + "  —  " + tr("copied to clipboard"))

    # -- lifecycle -------------------------------------------------------

    def wait_for_compare(self, timeout_ms: int = 30000) -> None:
        from PyQt6.QtCore import QCoreApplication, QDeadlineTimer, QEventLoop

        deadline = QDeadlineTimer(timeout_ms)
        while self._thread is not None and not deadline.hasExpired():
            # WaitForMoreEvents blocks until something actually happens
            # instead of spinning. A bare processEvents() loop pegs a
            # core for the whole wait, which on a slow remote walk is
            # seconds of a busy CPU doing nothing.
            QCoreApplication.processEvents(
                QEventLoop.ProcessEventsFlag.WaitForMoreEvents, 50
            )

    def _stop_thread(self, *, done: bool = False) -> None:
        """Wind the worker down without dropping a live QThread.

        Clearing the reference while the walk still runs is what
        produces "QThread: Destroyed while thread is still running" and
        an abort — a realistic close-the-window crash on a large remote
        tree.
        """
        if self._thread is None:
            return
        if self._worker is not None:
            self._worker.cancel()
        self._thread.quit()
        if done:
            # The worker's run() has returned (its result is here): the
            # thread only leaves its event loop, at once.
            self._thread.wait(1000)
        # Handed over at once rather than waited for: wait(5000) froze the
        # window for 5 s when Close / Esc came during a slow walk. This
        # dialog is a child of the pane / the window, and destroying it
        # with the thread still running aborts the process; detached (a
        # no-op for a thread that is done) it ends on its own against a
        # cancelled worker, and a late `done` reaches nobody.
        if detach_running_thread(
            self._thread,
            *((self._worker.done,) if self._worker is not None else ()),
            keep=(self._worker,),
        ):
            log.warning("compare: walk still running; left with a cancelled worker")
            self._thread = None
            self._worker = None
            return
        self._thread = None
        self._worker = None

    def reject(self) -> None:  # noqa: D102 - Qt override
        self._stop_thread()
        super().reject()


__all__ = ["FILTERS", "COLUMNS", "CompareDialog", "copy_direction", "export_text"]
