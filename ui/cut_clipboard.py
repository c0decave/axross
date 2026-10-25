"""The app-wide pending Cut of file pane entries.

Cut (Ctrl+X or the right-click menu of a file pane) remembers the selected
entries here, with the pane and the connection they came from; nothing is
removed. Paste in any pane - another folder, another connection - asks the
main window to move them (``MainWindow._paste_cut_into``), which goes
through the transfer queue's move: a source is removed only after its own
copy completed and was checked.

A cut that is never pasted removes nothing. It ends when a new Cut replaces
it, when Esc drops it in its pane, when its pane closes or changes
connection (``drop_source``), and once a paste of it was queued (``clear``
with that cut: a paste whose prompt was still open when another Cut came
does not clear the newer one).

The entries of the pending cut are drawn dimmed in their pane
(``names_in``), the way file managers show a cut that waits for a paste.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from PyQt6.QtCore import QObject, pyqtSignal


@dataclass(frozen=True, eq=False)
class PendingCut:
    """Entries cut in *source* (a file pane) on *backend*, all in *folder*."""

    source: object
    backend: object
    folder: str
    paths: tuple[str, ...]

    def names(self) -> frozenset[str]:
        """The entry names of :attr:`paths` (they all are in :attr:`folder`)."""
        try:
            sep = self.backend.separator() or "/"
        except Exception:  # noqa: BLE001 - a backend without separator() is POSIX-like
            sep = "/"
        return frozenset((p.rstrip(sep) or p).rsplit(sep, 1)[-1] for p in self.paths)


class CutClipboard(QObject):
    """Holds at most one :class:`PendingCut`; :attr:`changed` fires when it
    is set, replaced or dropped."""

    changed = pyqtSignal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pending: PendingCut | None = None

    @property
    def pending(self) -> PendingCut | None:
        return self._pending

    def cut(self, source, backend, folder: str, paths: Iterable[str]) -> PendingCut:
        """Remember *paths* (entries of *folder* on *backend*, shown in the
        pane *source*), replacing the pending cut. :class:`ValueError` for
        no paths: the pending cut stays then."""
        chosen = tuple(dict.fromkeys(str(p) for p in paths))
        if not chosen:
            raise ValueError("nothing to cut")
        self._pending = PendingCut(source, backend, folder, chosen)
        self.changed.emit()
        return self._pending

    def clear(self, cut: PendingCut | None = None) -> bool:
        """Drop the pending cut - only if it still is *cut*, when given.
        True when one was dropped."""
        if self._pending is None or (cut is not None and self._pending is not cut):
            return False
        self._pending = None
        self.changed.emit()
        return True

    def drop_source(self, source) -> bool:
        """Drop the pending cut if it came from the pane *source* (the pane
        closes or switches connection). True when one was dropped."""
        if self._pending is None or self._pending.source is not source:
            return False
        return self.clear(self._pending)

    def names_in(self, backend, folder: str) -> frozenset[str]:
        """Names of the pending cut's entries shown in *folder* of *backend*."""
        cut = self._pending
        if cut is None or cut.backend is not backend or cut.folder != folder:
            return frozenset()
        return cut.names()


_CLIPBOARD: CutClipboard | None = None


def cut_clipboard() -> CutClipboard:
    """The application's one :class:`CutClipboard`, made on first use.

    Destroying the QApplication deletes this Python-owned QObject with it;
    a later application (a test process builds several) then gets a new
    one instead of the deleted wrapper - its cut ended with that
    application anyway."""
    global _CLIPBOARD
    from PyQt6 import sip

    if _CLIPBOARD is None or sip.isdeleted(_CLIPBOARD):
        _CLIPBOARD = CutClipboard()
    return _CLIPBOARD
