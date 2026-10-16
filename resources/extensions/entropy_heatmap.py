"""Shannon entropy of a file, block by block, as a heat strip."""

from __future__ import annotations

import math

EXTENSION = {
    "name": "Entropy Heatmap",
    "version": "1.0",
    "description": "Right-click a file: its entropy per 4 KiB block as a colour strip - "
    "compressed or encrypted regions glow red, text and padding stay blue.",
    "author": "axross",
}

BLOCK = 4096
MAX_BYTES = 16 * 1024 * 1024


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts if c)


def block_entropies(backend, path: str, *, block: int = BLOCK, limit: int = MAX_BYTES):
    """Entropy of every *block* of the first *limit* bytes, and whether the
    file went on beyond *limit*."""
    values = []
    read = 0
    with backend.open_read(path) as fh:
        while read < limit:
            chunk = fh.read(min(block, limit - read))
            if not chunk:
                break
            read += len(chunk)
            values.append(entropy(chunk))
        more = bool(fh.read(1)) if read >= limit else False
    return values, more


def verdict(values: list[float]) -> str:
    if not values:
        return "empty file"
    high = sum(1 for v in values if v > 7.5) / len(values)
    if high > 0.9:
        return "looks compressed or encrypted throughout"
    if high > 0.2:
        return f"{high:.0%} of the blocks look compressed or encrypted"
    if max(values) < 5.0:
        return "low entropy: text, tables or padding"
    return "mixed content"


def heat_image(values: list[float], width: int = 720, height: int = 60):
    from PyQt6.QtGui import QColor, QImage, QPainter

    image = QImage(max(1, width), height, QImage.Format.Format_RGB32)
    image.fill(QColor("#202020"))
    if not values:
        return image
    painter = QPainter(image)
    try:
        for x in range(image.width()):
            v = values[min(len(values) - 1, x * len(values) // image.width())]
            hue = int(240 - 240 * min(v, 8.0) / 8.0)  # blue (low) .. red (high)
            painter.fillRect(x, 0, 1, height, QColor.fromHsv(hue, 220, 230))
    finally:
        painter.end()
    return image


def activate(api):
    def show(ctx):
        item = next(i for i in ctx.items if not i.is_dir)
        path = ctx.backend.join(ctx.folder, item.name)
        api.notify(f"measuring {item.name}…")

        def done(result):
            from PyQt6.QtCore import Qt
            from PyQt6.QtGui import QPixmap
            from PyQt6.QtWidgets import QDialog, QLabel, QVBoxLayout

            values, more = result
            dialog = QDialog(api.window)
            dialog.setWindowTitle(f"Entropy — {item.name}")
            layout = QVBoxLayout(dialog)
            strip = QLabel()
            strip.setPixmap(QPixmap.fromImage(heat_image(values)))
            layout.addWidget(strip)
            avg = sum(values) / len(values) if values else 0.0
            text = (
                f"{len(values)} blocks of {BLOCK} bytes, average {avg:.2f} bits/byte, "
                f"max {max(values, default=0):.2f}.\n{verdict(values)}."
            )
            if more:
                text += f"\nOnly the first {MAX_BYTES // (1024 * 1024)} MiB were measured."
            layout.addWidget(QLabel(text))
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            dialog.show()

        api.run_in_background(lambda: block_entropies(ctx.backend, path), on_done=done)

    api.add_context_action("Entropy Heatmap…", show, applies_to="single_file")
