"""Turn one collected media item into pixels, a PDF or a video file.

Called by the media viewer from background threads only; nothing here
touches a widget. Every refusal - too large, password-protected, broken,
blocked by the security mode, a read error - is a :class:`MediaUnavailable`
whose text the viewer shows in place of the item.

Where the bytes come from
-------------------------
* A file on the local file system is read where it is.
* A file on any other backend is copied into a private temp directory with
  :func:`core.file_analysis.copy_bounded` (the analysis dock's bounded copy),
  at most the configured open size limit (*Edit -> Settings... -> Files &
  Panes -> Open Size Limit*); for images also at most
  :data:`core.previews.MAX_INPUT_SIZE`. A file the
  listing shows as larger is not downloaded at all; one that turns out
  larger while copying is cut off and refused. Images and thumbnails drop
  the copy as soon as they are decoded; a PDF or video keeps it until the
  viewer calls :meth:`Prepared.release`.

core.previews keeps its decoders away from remote bytes because a *pane*
would fetch them unasked. Here the user asked to view that folder, so the
copy is decoded - through the same gates and caps as a local file.

How it is decoded
-----------------
* Images and SVG: :func:`core.previews.decode_image` / ``thumbnail`` with
  ``allow_svg=True``.
* PDF: QtPdf (pdfium), page count checked up front so an encrypted or broken
  document is refused before the viewer shows it.
* Video: not decoded here; the viewer's QMediaPlayer streams the file.
  Its thumbnail is one frame taken by an external ffmpeg, for local files
  only (a remote video would have to be downloaded whole for a tile), with
  the same hardened invocation as the metadata cleaner: no shell, only the
  ``file`` protocol, a demuxer allow-list, a timeout and an output bound.
"""

from __future__ import annotations

import os
import stat
import threading
from dataclasses import dataclass

from core import file_analysis as FA
from core import open_limits
from core import previews as P
from core.media_collect import IMAGE, PDF, VIDEO, MediaItem

THUMB_EDGE = P.DEFAULT_THUMBNAIL_EDGE
VIEWER_EDGE = P.VIEWER_MAX_EDGE
#: Longest a remote copy may take before the viewer gives up on it.
COPY_TIMEOUT = 120.0
#: Longest ffmpeg may take for one video thumbnail frame.
VIDEO_FRAME_TIMEOUT = 15.0
#: A PNG frame of at most 2048 px per side stays well below this.
MAX_FRAME_BYTES = 16 * 1024 * 1024


class MediaUnavailable(Exception):
    """The item cannot be shown; ``str()`` is the reason for the user."""


@dataclass
class LocalFile:
    path: str
    copy: FA.BoundedCopy | None = None

    def release(self) -> None:
        if self.copy is not None:
            self.copy.cleanup()
            self.copy = None


@dataclass
class Prepared:
    """A media item ready for the viewer."""

    item: MediaItem
    image: object = None  # QImage for images
    local_path: str = ""  # PDF / video file to open
    page_count: int = 0  # PDF
    file: LocalFile | None = None

    def release(self) -> None:
        if self.file is not None:
            self.file.release()
            self.file = None


def _mb(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MB"


def too_large_text(size: int, limit: int) -> str:
    text = f"too large to show: {_mb(size)}, limit {_mb(limit)}"
    if limit == open_limits.max_open_bytes():  # the user's own setting, not a decoder cap
        text += " (Edit → Settings… → Files & Panes → Open Size Limit)"
    return text


def _require_allowed() -> None:
    from core.security_mode import current_policy

    if not current_policy().allow_auto_preview:
        raise MediaUnavailable(
            f"blocked by the '{current_policy().name}' security mode"
        )


def _image_limit() -> int:
    return min(open_limits.max_open_bytes(), P.MAX_INPUT_SIZE)


def fetch(
    backend,
    item: MediaItem,
    *,
    cancel: threading.Event,
    limit: int | None,
    timeout: float = COPY_TIMEOUT,
) -> LocalFile:
    """A local path holding *item*'s bytes (see the module docstring).

    ``limit`` bounds a local file too when given; ``None`` means a local
    file is used whatever its size (a remote copy always needs a limit)."""
    if FA.is_local_backend(backend):
        try:
            st = os.stat(item.path)
        except OSError as exc:
            raise MediaUnavailable(f"cannot read: {exc.strerror or exc}") from exc
        if not stat.S_ISREG(st.st_mode):
            raise MediaUnavailable("not a regular file")
        if limit is not None and st.st_size > limit:
            raise MediaUnavailable(too_large_text(st.st_size, limit))
        return LocalFile(item.path)
    if limit is None:
        limit = open_limits.max_open_bytes()
    if item.size > limit:
        raise MediaUnavailable(too_large_text(item.size, limit))
    target = FA.Target(
        backend=backend, path=item.path, name=item.name, size=item.size, mtime=item.mtime
    )
    copy = FA.copy_bounded(target, limit, cancel, timeout, prefix="axross-media-")
    if copy.status == "ok":
        return LocalFile(copy.path, copy)
    copy.cleanup()
    if copy.status == "too_large":
        raise MediaUnavailable(too_large_text(copy.total, limit))
    if copy.status == "error":
        raise MediaUnavailable(f"cannot read: {copy.error}")
    if copy.status == "timeout":
        raise MediaUnavailable(f"timed out copying after {timeout:.0f} s")
    raise MediaUnavailable("cancelled")


def _decoder_backend(backend):
    """The backend previews sees: the copy of a remote file is local."""
    if FA.is_local_backend(backend):
        return backend
    from core.local_fs import LocalFS

    return LocalFS()


def _preview_reason(exc: Exception) -> str:
    if isinstance(exc, P.PreviewTooLarge):
        return f"too large to show: {exc}"
    if isinstance(exc, P.PreviewDecodeFailed):
        return f"cannot decode: {exc}"
    return str(exc)


# -- PDF ----------------------------------------------------------------------


def _pdf_error_text(error) -> str:
    from PyQt6.QtPdf import QPdfDocument

    e = QPdfDocument.Error
    return {
        e.IncorrectPassword: "PDF is password-protected",
        e.UnsupportedSecurityScheme: "PDF uses an unsupported encryption",
        e.InvalidFileFormat: "not a valid PDF",
        e.FileNotFound: "PDF file not found",
        e.DataNotYetAvailable: "PDF data not available",
    }.get(error, f"cannot open PDF ({getattr(error, 'name', error)})")


def _open_pdf(path: str):
    try:
        from PyQt6.QtPdf import QPdfDocument
    except ImportError as exc:  # QtPdf needs libatomic from the host
        raise MediaUnavailable(
            f"PDF viewing needs QtPdf, which cannot be loaded here ({exc})"
        ) from exc

    doc = QPdfDocument(None)
    error = doc.load(path)
    if error != QPdfDocument.Error.None_:
        doc.close()
        raise MediaUnavailable(_pdf_error_text(error))
    if doc.pageCount() < 1:
        doc.close()
        raise MediaUnavailable("PDF has no pages")
    return doc


def pdf_page_count(path: str) -> int:
    doc = _open_pdf(path)
    try:
        return doc.pageCount()
    finally:
        doc.close()


def render_pdf_page(path: str, page: int, edge: int):
    """Page *page* of the PDF at *path* as a QImage on white, longer side *edge*."""
    from PyQt6.QtCore import QSize, Qt
    from PyQt6.QtGui import QImage, QPainter

    doc = _open_pdf(path)
    try:
        if not 0 <= page < doc.pageCount():
            raise MediaUnavailable(f"PDF has no page {page + 1}")
        size = doc.pagePointSize(page)
        w, h = max(1.0, size.width()), max(1.0, size.height())
        scale = edge / max(w, h)
        out = QSize(max(1, round(w * scale)), max(1, round(h * scale)))
        rendered = doc.render(page, out)
    finally:
        doc.close()
    if rendered.isNull():
        raise MediaUnavailable("cannot render PDF page")
    # pdfium leaves the page transparent where nothing is drawn.
    image = QImage(rendered.size(), QImage.Format.Format_RGB32)
    image.fill(Qt.GlobalColor.white)
    painter = QPainter(image)
    painter.drawImage(0, 0, rendered)
    painter.end()
    return image


# -- entry points ----------------------------------------------------------------


def thumbnail(backend, item: MediaItem, *, cancel: threading.Event, edge: int = THUMB_EDGE):
    """A QImage whose longer side is about *edge* px."""
    from PyQt6.QtGui import QImage

    _require_allowed()
    if item.kind == IMAGE:
        local = FA.is_local_backend(backend)
        f = fetch(backend, item, cancel=cancel, limit=None if local else _image_limit())
        try:
            result = P.thumbnail(
                _decoder_backend(backend), f.path, edge=edge, use_cache=local, allow_svg=True
            )
        except P.PreviewError as exc:
            raise MediaUnavailable(_preview_reason(exc)) from exc
        except PermissionError as exc:
            raise MediaUnavailable(str(exc)) from exc
        finally:
            f.release()
        image = QImage.fromData(result.data, "PNG")
        if image.isNull():
            raise MediaUnavailable("cannot decode thumbnail")
        return image
    if item.kind == PDF:
        f = fetch(backend, item, cancel=cancel, limit=open_limits.max_open_bytes())
        try:
            return render_pdf_page(f.path, 0, edge)
        finally:
            f.release()
    if item.kind == VIDEO:
        return _video_frame(backend, item, cancel=cancel, edge=edge)
    raise MediaUnavailable("no preview for this file")


def _video_frame(backend, item: MediaItem, *, cancel: threading.Event, edge: int):
    """One frame of a local video, scaled to fit *edge*, as a QImage."""
    from PyQt6.QtGui import QImage

    from core import metadata_formats as MF

    if not FA.is_local_backend(backend):
        raise MediaUnavailable("no preview for videos in a remote folder")
    ffmpeg = MF.ffmpeg_path()
    if not ffmpeg:
        raise MediaUnavailable("video previews need ffmpeg, which is not installed")
    f = fetch(backend, item, cancel=cancel, limit=None)
    edge = max(16, min(int(edge), 2048))
    try:
        # A second in, past a black fade-in; a clip shorter than that has
        # no frame there, so the very first frame is the fallback.
        for offset in ("1", "0"):
            argv = [
                ffmpeg,
                "-hide_banner",
                "-nostdin",
                "-v",
                "error",
                "-protocol_whitelist",
                "file",
                "-format_whitelist",
                MF.FFMPEG_FORMATS,
                "-ss",
                offset,
                "-i",
                MF._ff_input(f.path),
                "-map",
                "0:v:0",
                "-frames:v",
                "1",
                "-vf",
                f"scale={edge}:{edge}:force_original_aspect_ratio=decrease",
                "-f",
                "image2pipe",
                "-c:v",
                "png",
                "pipe:1",
            ]
            try:
                code, out, _err = MF.run_bounded(
                    argv, timeout=VIDEO_FRAME_TIMEOUT, max_output=MAX_FRAME_BYTES, cancel=cancel
                )
            except (MF.FormatError, OSError) as exc:
                raise MediaUnavailable(str(exc)) from exc
            if code == 0 and out:
                image = QImage.fromData(out, "PNG")
                if not image.isNull():
                    return image
    finally:
        f.release()
    raise MediaUnavailable("cannot decode a frame of this video")


def prepare(
    backend, item: MediaItem, *, cancel: threading.Event, max_edge: int = VIEWER_EDGE
) -> Prepared:
    """Everything the viewer needs to show *item* without further I/O."""
    _require_allowed()
    if item.kind == IMAGE:
        local = FA.is_local_backend(backend)
        f = fetch(backend, item, cancel=cancel, limit=None if local else _image_limit())
        try:
            image = P.decode_image(
                _decoder_backend(backend), f.path, max_edge=max_edge, allow_svg=True
            )
        except P.PreviewError as exc:
            raise MediaUnavailable(_preview_reason(exc)) from exc
        except PermissionError as exc:
            raise MediaUnavailable(str(exc)) from exc
        finally:
            f.release()
        return Prepared(item, image=image)
    if item.kind == PDF:
        f = fetch(backend, item, cancel=cancel, limit=open_limits.max_open_bytes())
        try:
            pages = pdf_page_count(f.path)
        except BaseException:
            f.release()
            raise
        return Prepared(item, local_path=f.path, page_count=pages, file=f)
    if item.kind == VIDEO:
        # A local video is streamed by the player, never read whole.
        local = FA.is_local_backend(backend)
        limit = None if local else open_limits.max_open_bytes()
        f = fetch(backend, item, cancel=cancel, limit=limit)
        return Prepared(item, local_path=f.path, file=f)
    raise MediaUnavailable(f"unknown media type {item.kind!r}")


__all__ = [
    "COPY_TIMEOUT",
    "LocalFile",
    "MediaUnavailable",
    "Prepared",
    "THUMB_EDGE",
    "VIEWER_EDGE",
    "fetch",
    "pdf_page_count",
    "prepare",
    "render_pdf_page",
    "thumbnail",
    "too_large_text",
]
