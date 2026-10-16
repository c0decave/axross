"""Resize or convert many images at once."""

from __future__ import annotations

import posixpath

EXTENSION = {
    "name": "Image Batch",
    "version": "1.0",
    "description": "Right-click selected images: scale them down to a maximum edge and/or "
    "convert them to PNG, JPEG or WebP, into a 'resized' subfolder - originals untouched.",
    "author": "axross",
}

SUFFIXES = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tif", ".tiff")
FORMATS = {"PNG": ".png", "JPEG": ".jpg", "WebP": ".webp"}
OUT_FOLDER = "resized"
#: Images larger than this are skipped instead of decoded.
MAX_INPUT_BYTES = 64 * 1024 * 1024


def convert(data: bytes, max_edge: int, fmt: str, quality: int = 88) -> bytes:
    """*data* decoded, scaled so its longer edge is at most *max_edge*
    (never up), and encoded as *fmt* (``PNG`` / ``JPEG`` / ``WebP``)."""
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, Qt
    from PyQt6.QtGui import QImage

    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}")
    image = QImage.fromData(data)
    if image.isNull():
        raise ValueError("not an image Qt can read")
    if max_edge > 0 and max(image.width(), image.height()) > max_edge:
        image = image.scaled(
            max_edge,
            max_edge,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
    out = QByteArray()
    buf = QBuffer(out)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buf, fmt.upper(), quality):
        raise ValueError(f"cannot write {fmt}")
    buf.close()
    return bytes(out)


def unique_name(existing: set[str], stem: str, ext: str) -> str:
    name = f"{stem}{ext}"
    n = 2
    while name in existing:
        name = f"{stem} ({n}){ext}"
        n += 1
    existing.add(name)
    return name


def run_batch(backend, folder: str, names: list[str], max_edge: int, fmt: str):
    """Convert *names* from *folder* into ``folder/resized``; returns
    ``(written, skipped)`` lists of names (skipped with the reason)."""
    out_dir = backend.join(folder, OUT_FOLDER)
    if not backend.exists(out_dir):
        backend.mkdir(out_dir)
    existing = {i.name for i in backend.list_dir(out_dir)}
    written, skipped = [], []
    for name in names:
        src = backend.join(folder, name)
        try:
            with backend.open_read(src) as fh:
                data = fh.read(MAX_INPUT_BYTES + 1)
            if len(data) > MAX_INPUT_BYTES:
                raise ValueError("larger than 64 MiB")
            result = convert(data, max_edge, fmt)
        except (OSError, ValueError) as exc:
            skipped.append(f"{name}: {exc}")
            continue
        stem = posixpath.splitext(name)[0]
        target = unique_name(existing, stem, FORMATS[fmt])
        with backend.open_write(backend.join(out_dir, target)) as fh:
            fh.write(result)
        written.append(target)
    return written, skipped


def activate(api):
    def batch(ctx):
        from PyQt6.QtWidgets import QInputDialog

        names = [i.name for i in ctx.items if not i.is_dir and i.name.lower().endswith(SUFFIXES)]
        edge, ok = QInputDialog.getInt(
            api.window, "Image Batch", "Longest edge in pixels (0 = keep size):", 1600, 0, 20000
        )
        if not ok:
            return
        fmt, ok = QInputDialog.getItem(
            api.window, "Image Batch", "Write as:", list(FORMATS), 1, False
        )
        if not ok:
            return
        api.notify(f"converting {len(names)} image(s)…")

        def done(result):
            written, skipped = result
            text = f"{len(written)} written to {OUT_FOLDER}/"
            if skipped:
                text += f", {len(skipped)} skipped ({skipped[0]})"
            api.notify(text)
            if ctx.pane is not None:
                ctx.pane.refresh()

        api.run_in_background(
            lambda: run_batch(ctx.backend, ctx.folder, names, edge, fmt), on_done=done
        )

    api.add_context_action("Resize / Convert Images…", batch, applies_to="files",
                           extensions=SUFFIXES)
