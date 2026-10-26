"""A panel with a treemap of the current folder: each box is a file or
subfolder, its area the size."""

from __future__ import annotations

import sys

EXTENSION = {
    "name": "Folder Treemap",
    "version": "1.0",
    "description": "A panel that draws the current folder as a treemap - box area is size, "
    "subfolders summed in the background (bounded); double-click a box to open it.",
    "author": "axross",
}

#: Entries walked below one folder before the sums count as "at least".
MAX_ENTRIES = 20000
MAX_DEPTH = 12


def folder_sizes(backend, folder: str, *, max_entries: int = MAX_ENTRIES):
    """``([(name, size, is_dir)], complete)`` for the children of *folder*;
    subfolder sizes are recursive sums. *complete* is False when the walk
    stopped at *max_entries* or met unreadable folders."""
    budget = [max_entries]
    complete = [True]

    def walk(path: str, depth: int) -> int:
        if depth > MAX_DEPTH or budget[0] <= 0:
            complete[0] = False
            return 0
        try:
            items = backend.list_dir(path)
        except OSError:
            complete[0] = False
            return 0
        total = 0
        for item in items:
            if item.name == "..":
                continue
            budget[0] -= 1
            if budget[0] < 0:
                complete[0] = False
                break
            if item.is_dir and not getattr(item, "is_link", False):
                total += walk(backend.join(path, item.name), depth + 1)
            elif not item.is_dir:
                total += max(0, int(item.size or 0))
        return total

    out = []
    for item in backend.list_dir(folder):
        if item.name == "..":
            continue
        if item.is_dir and not getattr(item, "is_link", False):
            out.append((item.name, walk(backend.join(folder, item.name), 1), True))
        elif not item.is_dir:
            out.append((item.name, max(0, int(item.size or 0)), False))
    return out, complete[0]


class _RowSum:
    """The running sum of a row, equal to ``sum(row)`` to the last bit:
    compensated (Neumaier) as the built-in ``sum`` adds floats since Python
    3.12, plainly before."""

    __slots__ = ("hi", "lo")
    compensated = sys.version_info >= (3, 12)

    def __init__(self) -> None:
        self.hi = 0.0
        self.lo = 0.0

    def add(self, x: float) -> None:
        hi = self.hi
        t = hi + x
        if self.compensated:
            if abs(hi) >= abs(x):
                self.lo += (hi - t) + x
            else:
                self.lo += (x - t) + hi
        self.hi = t

    def value(self) -> float:
        return self.hi + self.lo if self.lo else self.hi


def squarify(sizes: list[float], x: float, y: float, w: float, h: float):
    """Rectangles ``(x, y, w, h)`` for *sizes* (sorted large to small),
    filling the box with aspect ratios near 1 (Bruls et al.).

    Linear: the row keeps its sum as it grows, and its worst aspect ratio
    comes from its first (largest) and last (smallest) box - the ratio
    ``max(side² r / s², s² / (side² r))`` is largest at either end."""
    values = [s for s in sizes if s > 0]
    rects: list[tuple[float, float, float, float]] = []
    total = sum(values)
    if not values or w <= 0 or h <= 0:
        return rects
    scaled = [v * w * h / total for v in values]

    def worst(largest: float, smallest: float, s: float, side: float) -> float:
        return max(side * side * largest / (s * s), s * s / (side * side * smallest))

    i = 0
    count = len(scaled)
    while i < count:
        side = min(w, h)
        start = i
        row_sum = _RowSum()
        row_sum.add(scaled[i])
        s = row_sum.value()
        current = worst(scaled[i], scaled[i], s, side)
        i += 1
        while i < count:
            grown = _RowSum()
            grown.hi, grown.lo = row_sum.hi, row_sum.lo
            grown.add(scaled[i])
            grown_s = grown.value()
            candidate = worst(scaled[start], scaled[i], grown_s, side)
            if candidate > current:
                break
            row_sum, s, current = grown, grown_s, candidate
            i += 1
        row = scaled[start:i]
        if w >= h:  # lay the row out as a column on the left
            cw = s / h
            cy = y
            for r in row:
                rects.append((x, cy, cw, r / cw))
                cy += r / cw
            x, w = x + cw, w - cw
        else:  # as a row on the top
            rh = s / w
            cx = x
            for r in row:
                rects.append((cx, y, r / rh, rh))
                cx += r / rh
            y, h = y + rh, h - rh
    return rects


def human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def activate(api):
    from PyQt6.QtCore import QRectF, Qt
    from PyQt6.QtGui import QColor, QPainter
    from PyQt6.QtWidgets import QToolTip, QWidget

    class Treemap(QWidget):
        def __init__(self):
            super().__init__()
            self.entries: list[tuple[str, int, bool]] = []
            self.complete = True
            self.message = "Open a folder to see its treemap."
            self.boxes: list[tuple[QRectF, tuple[str, int, bool]]] = []
            # (entries, width, height) the boxes were laid out for: a repaint
            # of the same folder at the same size reuses them.
            self._laid_out = None
            self._rects: list = []
            self.setMouseTracking(True)
            self.setMinimumSize(200, 160)

        def set_entries(self, entries, complete):
            self.entries = sorted(entries, key=lambda e: -e[1])
            self.complete = complete
            self.message = "" if any(e[1] > 0 for e in entries) else "Nothing with a size here."
            self.update()

        def paintEvent(self, _event):  # noqa: N802
            painter = QPainter(self)
            painter.fillRect(self.rect(), self.palette().base())
            self.boxes = []
            if self.message:
                painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.message)
                return
            shown = [e for e in self.entries if e[1] > 0]
            key = (self.entries, self.width(), self.height())
            if self._laid_out is None or any(a is not b and a != b
                                             for a, b in zip(self._laid_out, key)):
                self._rects = squarify([e[1] for e in shown], 0, 0, self.width(), self.height())
                self._laid_out = key
            rects = self._rects
            for n, ((rx, ry, rw, rh), entry) in enumerate(zip(rects, shown)):
                box = QRectF(rx, ry, rw, rh)
                hue = (n * 47) % 360
                colour = QColor.fromHsv(hue, 90 if entry[2] else 50, 225)
                painter.fillRect(box.adjusted(1, 1, -1, -1), colour)
                if rw > 40 and rh > 16:
                    painter.setPen(QColor("#202020"))
                    label = entry[0] + ("/" if entry[2] else "")
                    painter.drawText(
                        box.adjusted(4, 2, -4, -2),
                        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                        painter.fontMetrics().elidedText(
                            label, Qt.TextElideMode.ElideMiddle, int(rw) - 8
                        ),
                    )
                self.boxes.append((box, entry))
            painter.end()

        def entry_at(self, pos):
            for box, entry in self.boxes:
                if box.contains(pos):
                    return entry
            return None

        def mouseMoveEvent(self, event):  # noqa: N802
            entry = self.entry_at(event.position())
            if entry is not None:
                note = "" if self.complete else " (at least)"
                QToolTip.showText(
                    event.globalPosition().toPoint(), f"{entry[0]}\n{human(entry[1])}{note}", self
                )

        def mouseDoubleClickEvent(self, event):  # noqa: N802
            entry = self.entry_at(event.position())
            ctx = api.current()
            if entry is not None and entry[2] and ctx is not None and ctx.pane is not None:
                ctx.pane.navigate_async(ctx.backend.join(ctx.folder, entry[0]))

    view = Treemap()
    api.add_dock("Folder Treemap", view)
    state = {"folder": None}

    def refresh(ctx):
        state["folder"] = (id(ctx.backend), ctx.folder)
        view.message = "Measuring…"
        view.update()

        def done(result, key=state["folder"]):
            if state["folder"] == key:
                view.set_entries(*result)

        api.run_in_background(
            lambda: folder_sizes(ctx.backend, ctx.folder),
            on_done=done,
            on_error=lambda exc: (
                setattr(view, "message", f"Cannot measure: {exc}") or view.update()
            ),
        )

    api.on("path_changed", refresh)
    api.on("pane_activated", refresh)
    ctx = api.current()
    if ctx is not None:
        refresh(ctx)
