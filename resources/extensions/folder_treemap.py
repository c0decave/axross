"""A panel with a treemap of the current folder: each box is a file or
subfolder, its area the size."""

from __future__ import annotations

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


def squarify(sizes: list[float], x: float, y: float, w: float, h: float):
    """Rectangles ``(x, y, w, h)`` for *sizes* (sorted large to small),
    filling the box with aspect ratios near 1 (Bruls et al.)."""
    values = [s for s in sizes if s > 0]
    rects: list[tuple[float, float, float, float]] = []
    total = sum(values)
    if not values or w <= 0 or h <= 0:
        return rects
    scaled = [v * w * h / total for v in values]

    def worst(row, side):
        s = sum(row)
        return max(max(side * side * r / (s * s), s * s / (side * side * r)) for r in row)

    i = 0
    while i < len(scaled):
        side = min(w, h)
        row = [scaled[i]]
        i += 1
        while i < len(scaled) and worst(row + [scaled[i]], side) <= worst(row, side):
            row.append(scaled[i])
            i += 1
        s = sum(row)
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
            rects = squarify([e[1] for e in shown], 0, 0, self.width(), self.height())
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
