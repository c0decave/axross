"""Modal image viewer — zoom, pan, rotate, next/prev.

Opened from the file pane via F3 / double-click on an allowlisted
image MIME. Decoding routes through :mod:`core.previews` so the
MAX_INPUT_SIZE, MAX_DIMENSION, and allocation-limit guards from
Defense Layer 2 apply to every image the user opens.

The viewer is intentionally local-only: remote images have to be
downloaded first before the MIME allowlist in ``core.previews``
will touch them. That's the same gate as the thumbnail cache —
keeps the image decoders away from attacker-controlled bytes
until the user explicitly triggers ``open_externally`` or
downloads the file.
"""
from __future__ import annotations

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QImage, QKeySequence, QPixmap, QShortcut
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
)

from core import previews as P

log = logging.getLogger("ui.image_viewer")


class ImageViewerDialog(QDialog):
    """Show a single image, with keyboard-driven zoom / pan / rotate.

    Parameters
    ----------
    backend : FileBackend
        Must be local (previews is gated on ``is_local`` so the image
        decoder is never fed attacker-controlled remote bytes).
    path : str
        Absolute local path to the image.
    siblings : list[str] | None
        Other image paths in the same directory, for Prev/Next. If
        None, Prev/Next are disabled.
    """

    def __init__(self, backend, path: str,
                 siblings: list[str] | None = None,
                 parent=None) -> None:
        super().__init__(parent)
        self._backend = backend
        self._siblings = siblings or [path]
        self._idx = self._siblings.index(path) if path in self._siblings else 0
        self._zoom = 1.0
        self._rotation = 0
        self._original: QImage | None = None

        self.setWindowTitle("Image Viewer")
        self.resize(900, 680)
        self._build_ui()
        self._load_current()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        self._label = QLabel("", alignment=Qt.AlignmentFlag.AlignCenter)
        self._label.setBackgroundRole(self._label.backgroundRole())
        self._label.setSizePolicy(
            self._label.sizePolicy().horizontalPolicy(),
            self._label.sizePolicy().verticalPolicy(),
        )
        self._scroll = QScrollArea(self)
        self._scroll.setWidgetResizable(False)
        self._scroll.setWidget(self._label)
        self._scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self._scroll, stretch=1)

        bar = QHBoxLayout()
        prev_btn = QPushButton("◀ Prev")
        prev_btn.clicked.connect(self._prev)
        bar.addWidget(prev_btn)

        next_btn = QPushButton("Next ▶")
        next_btn.clicked.connect(self._next)
        bar.addWidget(next_btn)

        bar.addStretch(1)

        zoom_out = QPushButton("−")
        zoom_out.clicked.connect(lambda: self._zoom_by(0.8))
        bar.addWidget(zoom_out)

        self._zoom_label = QLabel("100%")
        self._zoom_label.setMinimumWidth(60)
        self._zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bar.addWidget(self._zoom_label)

        zoom_in = QPushButton("+")
        zoom_in.clicked.connect(lambda: self._zoom_by(1.25))
        bar.addWidget(zoom_in)

        fit_btn = QPushButton("Fit")
        fit_btn.clicked.connect(self._fit_window)
        bar.addWidget(fit_btn)

        reset_btn = QPushButton("1:1")
        reset_btn.clicked.connect(self._reset_zoom)
        bar.addWidget(reset_btn)

        rot_btn = QPushButton("⟳")
        rot_btn.clicked.connect(self._rotate_cw)
        rot_btn.setToolTip("Rotate 90° clockwise")
        bar.addWidget(rot_btn)

        bar.addStretch(1)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        bar.addWidget(close_btn)

        root.addLayout(bar)

        self._info = QLabel("")
        self._info.setStyleSheet("color: #888;")
        root.addWidget(self._info)

        # Keyboard shortcuts
        for seq, slot in (
            (QKeySequence("Right"), self._next),
            (QKeySequence("Left"), self._prev),
            (QKeySequence("Space"), self._next),
            (QKeySequence("+"),     lambda: self._zoom_by(1.25)),
            (QKeySequence("="),     lambda: self._zoom_by(1.25)),
            (QKeySequence("-"),     lambda: self._zoom_by(0.8)),
            (QKeySequence("0"),     self._reset_zoom),
            (QKeySequence("f"),     self._fit_window),
            (QKeySequence("r"),     self._rotate_cw),
            (QKeySequence("Escape"), self.reject),
        ):
            sh = QShortcut(seq, self)
            sh.activated.connect(slot)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    def _load_current(self) -> None:
        path = self._siblings[self._idx]
        # Decode through core.previews so MAX_INPUT_SIZE / MAX_DIMENSION
        # gates apply. Trick: we want the full-res image, not a
        # thumbnail, so we set edge huge and disable cache.
        try:
            result = P.thumbnail(
                self._backend, path,
                edge=4096, use_cache=False,
            )
        except P.PreviewTooLarge as exc:
            QMessageBox.warning(
                self, "Image Too Large",
                f"Refusing to decode (Defense Layer 2):\n{exc}",
            )
            self.reject()
            return
        except P.PreviewNotAvailable as exc:
            QMessageBox.warning(
                self, "Cannot Preview",
                f"{path}\n\n{exc}",
            )
            self.reject()
            return
        except P.PreviewDecodeFailed as exc:
            QMessageBox.warning(
                self, "Decode Failed",
                f"{path}\n\n{exc}",
            )
            self.reject()
            return
        # previews returns PNG bytes; QImage decodes from those.
        img = QImage.fromData(result.data, "PNG")
        if img.isNull():
            QMessageBox.warning(self, "Decode Failed", "QImage rejected PNG")
            self.reject()
            return
        self._original = img
        self._rotation = 0
        self._zoom = 1.0
        self._render()

    def _render(self) -> None:
        if self._original is None:
            return
        img = self._original
        if self._rotation:
            from PyQt6.QtGui import QTransform
            img = img.transformed(
                QTransform().rotate(self._rotation),
                Qt.TransformationMode.SmoothTransformation,
            )
        target_w = int(img.width() * self._zoom)
        target_h = int(img.height() * self._zoom)
        if target_w > 0 and target_h > 0:
            img = img.scaled(
                target_w, target_h,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        self._label.setPixmap(QPixmap.fromImage(img))
        self._label.resize(img.width(), img.height())
        self._zoom_label.setText(f"{int(self._zoom * 100)}%")
        path = self._siblings[self._idx]
        name = path.rsplit("/", 1)[-1]
        self._info.setText(
            f"{name} — {self._original.width()}×{self._original.height()} "
            f"[{self._idx + 1}/{len(self._siblings)}]"
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _zoom_by(self, factor: float) -> None:
        new_zoom = max(0.05, min(20.0, self._zoom * factor))
        self._zoom = new_zoom
        self._render()

    def _reset_zoom(self) -> None:
        self._zoom = 1.0
        self._render()

    def _fit_window(self) -> None:
        if self._original is None:
            return
        viewport = self._scroll.viewport().size()
        w_ratio = viewport.width() / max(1, self._original.width())
        h_ratio = viewport.height() / max(1, self._original.height())
        self._zoom = max(0.05, min(w_ratio, h_ratio))
        self._render()

    def _rotate_cw(self) -> None:
        self._rotation = (self._rotation + 90) % 360
        self._render()

    def _prev(self) -> None:
        if len(self._siblings) < 2:
            return
        self._idx = (self._idx - 1) % len(self._siblings)
        self._load_current()

    def _next(self) -> None:
        if len(self._siblings) < 2:
            return
        self._idx = (self._idx + 1) % len(self._siblings)
        self._load_current()
