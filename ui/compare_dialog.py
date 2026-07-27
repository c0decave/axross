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

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.sync import POLICIES, ConflictPolicy, plan_sync, summarize_plan
from core.tree_compare import ComparedEntry, Status, summarize
from ui.format_utils import human_bytes

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
    #: (direction, [relative paths]) — routed to the transfer machinery.
    copy_requested = pyqtSignal(str, list)
    #: (side, [absolute paths])
    delete_requested = pyqtSignal(str, list)
    #: [{"source", "dest", "direction", "kind", "overwrites"}] — a whole
    #: sync plan, already confirmed by the user.
    sync_requested = pyqtSignal(list)

    def __init__(self, left_pane, right_pane, parent: QWidget | None = None, *, compare_fn=None):
        super().__init__(parent)
        self._left_pane = left_pane
        self._right_pane = right_pane
        self._compare_fn = compare_fn or self._default_compare
        self._entries: list[ComparedEntry] = []
        self._error = ""
        self._filter = DEFAULT_FILTER
        self._policy = ConflictPolicy.ASK
        self._thread: QThread | None = None
        self._worker: _CompareWorker | None = None

        self.setWindowTitle("Compare panes")
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

        top = QHBoxLayout()
        self._filter_box = QComboBox(self)
        self._filter_box.addItems(list(FILTERS))
        self._filter_box.setCurrentText(DEFAULT_FILTER)
        self._filter_box.currentTextChanged.connect(self.set_filter)
        top.addWidget(QLabel("Show:", self))
        top.addWidget(self._filter_box)
        top.addStretch(1)

        top.addWidget(QLabel("On conflict:", self))
        self._policy_box = QComboBox(self)
        self._policy_box.addItems(list(POLICIES))
        self._policy_box.currentTextChanged.connect(
            lambda name: self.set_policy(POLICIES.get(name, ConflictPolicy.ASK))
        )
        top.addWidget(self._policy_box)

        self._refresh_btn = QPushButton("Re-compare", self)
        self._refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self._refresh_btn)
        layout.addLayout(top)

        self._table = QTableWidget(0, len(COLUMNS), self)
        self._table.setHorizontalHeaderLabels(list(COLUMNS))
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._table.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

        actions = QHBoxLayout()
        self._reveal_btn = QPushButton("Reveal in pane", self)
        self._reveal_btn.clicked.connect(self._reveal_selected)
        actions.addWidget(self._reveal_btn)

        self._copy_btn = QPushButton("Copy to other side", self)
        self._copy_btn.clicked.connect(self._copy_selected)
        actions.addWidget(self._copy_btn)

        self._delete_btn = QPushButton("Delete…", self)
        self._delete_btn.clicked.connect(self._delete_selected)
        actions.addWidget(self._delete_btn)

        self._sync_btn = QPushButton("Sync…", self)
        self._sync_btn.setToolTip(
            "Apply the whole comparison in both directions, after showing "
            "you exactly what it would do"
        )
        self._sync_btn.clicked.connect(self._sync)
        actions.addWidget(self._sync_btn)

        self._export_btn = QPushButton("Copy list", self)
        self._export_btn.setToolTip("Copy the current view to the clipboard")
        self._export_btn.clicked.connect(self._export)
        actions.addWidget(self._export_btn)

        actions.addStretch(1)
        self._summary = QLabel(self)
        self._summary.setStyleSheet("color: #666;")
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
        self._summary.setText("comparing…")

        self._left_root = getattr(self._left_pane, "current_path", "/")
        self._right_root = getattr(self._right_pane, "current_path", "/")
        args = (
            getattr(self._left_pane, "backend", None),
            self._left_root,
            getattr(self._right_pane, "backend", None),
            self._right_root,
        )
        self._thread = QThread(self)
        self._worker = _CompareWorker(self._compare_fn, args)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_result)
        self._thread.start()

    def _on_result(self, entries, error: str) -> None:
        self._entries = list(entries) if entries is not None else []
        self._error = error
        self._populate()
        self._refresh_btn.setEnabled(True)
        self._stop_thread()

    def _populate(self) -> None:
        visible = self.visible_entries()
        self._table.setRowCount(len(visible))
        for row, entry in enumerate(visible):
            cells = (
                entry.rel_path,
                entry.status,
                human_bytes(entry.left.size) if entry.left is not None else DASH,
                human_bytes(entry.right.size) if entry.right is not None else DASH,
                entry.reason,
            )
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, entry.rel_path)
                self._table.setItem(row, col, item)
        self._summary.setText(self._build_summary())

    def _build_summary(self) -> str:
        if self._error:
            return f"Comparison failed: {self._error}"
        if not self._entries:
            return "The two trees match."
        counts = summarize(self._entries)
        parts = [
            f"{counts[Status.LEFT_ONLY]} only left",
            f"{counts[Status.RIGHT_ONLY]} only right",
            f"{counts[Status.DIFFERS]} differ",
            f"{counts[Status.SAME]} identical",
        ]
        if counts[Status.UNKNOWN]:
            parts.append(f"{counts[Status.UNKNOWN]} unresolved")
        return ", ".join(parts)

    # -- filtering -------------------------------------------------------

    def set_filter(self, name: str) -> None:
        if name not in FILTERS:
            return
        self._filter = name
        if self._filter_box.currentText() != name:
            self._filter_box.setCurrentText(name)
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
        by_path = {e.rel_path: e for e in self.visible_entries()}
        rows = {idx.row() for idx in self._table.selectedIndexes()}
        out = []
        for row in sorted(rows):
            item = self._table.item(row, 0)
            if item is None:
                continue
            entry = by_path.get(item.data(Qt.ItemDataRole.UserRole))
            if entry is not None:
                out.append(entry)
        return out

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

    def _on_double_click(self, item: QTableWidgetItem) -> None:
        self._reveal_selected()

    def _reveal_selected(self) -> None:
        for entry in self.selected_entries():
            side = "left" if entry.left is not None else "right"
            self.reveal_requested.emit(side, self.absolute_path(side, entry.rel_path))

    def _copy_selected(self) -> None:
        entries = self.selected_entries()
        if not entries:
            return
        directed: dict[str, list[str]] = {"to_left": [], "to_right": []}
        ambiguous: list[str] = []
        for entry in entries:
            direction = copy_direction(entry)
            if direction is None:
                ambiguous.append(entry.rel_path)
                continue
            # to_right means the file lives on the LEFT and travels
            # right, so the source path is the left one.
            source_side = "left" if direction == "to_right" else "right"
            directed[direction].append(self.absolute_path(source_side, entry.rel_path))

        if ambiguous:
            QMessageBox.information(
                self,
                "Direction unclear",
                "These entries exist on both sides, so there is no obvious "
                "direction to copy them:\n\n"
                + "\n".join(ambiguous[:10])
                + "\n\nOpen them in a pane and copy the side you want to keep.",
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
                "Nothing to delete here",
                "Only entries that exist on one side can be deleted from this "
                "window. For files present on both sides, delete from the pane "
                "holding the copy you want gone.",
            )
            return
        confirm = QMessageBox.question(
            self,
            "Delete",
            f"Delete {total} entr{'y' if total == 1 else 'ies'}? This cannot be undone.",
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
            QMessageBox.information(self, "Sync", summarize_plan(plan))
            return

        detail = summarize_plan(plan)
        if plan.conflicts:
            detail += "\n\nLeft for you to decide:\n" + "\n".join(
                f"  {c.rel_path} — {c.reason}" for c in plan.conflicts[:10]
            )
            if len(plan.conflicts) > 10:
                detail += f"\n  … and {len(plan.conflicts) - 10} more"
        if not plan.actions:
            QMessageBox.information(self, "Sync", detail)
            return

        overwrites = sum(1 for a in plan.actions if a.overwrites)
        question = f"Apply {len(plan.actions)} change(s)?\n\n{detail}"
        if overwrites:
            question += "\n\nThis cannot be undone for the replaced files."
        if QMessageBox.question(
            self,
            "Sync",
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
                    "source": self.absolute_path(src_side, action.rel_path),
                    "dest": self.absolute_path(dst_side, action.rel_path),
                }
            )
        if items:
            self.sync_requested.emit(items)

    def _export(self) -> None:
        QApplication.clipboard().setText(export_text(self.visible_entries()))
        self._summary.setText(f"{self._build_summary()}  —  copied to clipboard")

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

    def _stop_thread(self) -> None:
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
        if not self._thread.wait(5000):
            # A late `done` must not reach a dialog that is on its way
            # out: exec() returns, the last Python reference goes, and
            # the slot would fire on a deleted C++ object.
            if self._worker is not None:
                try:
                    self._worker.done.disconnect()
                except TypeError:  # already disconnected
                    pass
            log.warning("compare: walk still running; left with a cancelled worker")
            return
        self._thread = None
        self._worker = None

    def reject(self) -> None:  # noqa: D102 - Qt override
        self._stop_thread()
        super().reject()


__all__ = ["FILTERS", "COLUMNS", "CompareDialog", "copy_direction", "export_text"]
