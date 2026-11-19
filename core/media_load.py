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
* PDF: QtPdf (pdfium) in a killable child process (core.pdf_worker), page
  count checked up front so an encrypted or broken document is refused
  before the viewer shows it; the viewer keeps that child for turning pages.
* Video: not decoded here; the viewer's QMediaPlayer streams the file -
  after ffprobe, when installed, opened it in a child first
  (core.media_gate: a file whose probe crashes or hangs is refused).
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
from core import pdf_worker as PW
from core import previews as P
from core.media_collect import IMAGE, PDF, VIDEO, MediaItem

THUMB_EDGE = P.DEFAULT_THUMBNAIL_EDGE
VIEWER_EDGE = P.VIEWER_MAX_EDGE
#: Longer side of a PDF's first page drawn ahead for the viewer.
PDF_FIRST_EDGE = 1600
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
    #: PDF: the drawing child with the document open (core.pdf_worker).
    pdf: object = None
    #: PDF: the first page's size in points (``image`` is that page drawn).
    first_page_points: tuple | None = None

    def release(self) -> None:
        if self.pdf is not None:
            self.pdf.close()
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
    """The user's text for a QPdfDocument.Error (or its name)."""
    return PW.error_text(getattr(error, "name", str(error)))


def qtpdf_install_hint() -> str:
    """Where QtPdf comes from when it is missing, "" if PyQt6 itself should
    have it. From 6.12 on, PyQt6's wheels carry no QtPdf: Riverbank ships it
    as the separate package PyQt6-Pdf. Below 6.12 a missing QtPdf is a host
    library (libatomic), not a package to install."""
    try:
        from PyQt6.QtCore import PYQT_VERSION
    except ImportError:
        return ""
    if PYQT_VERSION < 0x060C00:
        return ""
    return "with PyQt6 6.12 or newer it is the separate package PyQt6-Pdf"


def _require_qtpdf() -> None:
    """QtPdf must load here: the drawing child uses this Python's (its
    module is only imported, no PDF is read in this process)."""
    try:
        from PyQt6.QtPdf import QPdfDocument  # noqa: F401
    except ImportError as exc:  # QtPdf needs libatomic from the host
        hint = qtpdf_install_hint()
        raise MediaUnavailable(
            f"PDF viewing needs QtPdf, which cannot be loaded here ({exc})"
            + (f"; {hint}" if hint else "")
        ) from exc


def open_pdf(path: str) -> PW.PdfRenderer:
    """A drawing child (core.pdf_worker) with the PDF at *path* open; the
    caller closes it."""
    _require_qtpdf()
    renderer = PW.PdfRenderer(PW.RENDER_SECONDS)
    try:
        renderer.open(path)
    except PW.PdfError as exc:
        renderer.close()
        raise MediaUnavailable(str(exc)) from exc
    except BaseException:
        renderer.close()
        raise
    return renderer


def pdf_page_count(path: str) -> int:
    renderer = open_pdf(path)
    try:
        return renderer.page_count
    finally:
        renderer.close()


def _image_of(drawn) -> object:
    from PyQt6.QtGui import QImage

    width, height, stride, data = drawn
    image = QImage(data, width, height, stride, QImage.Format.Format_RGB32).copy()
    if image.isNull():
        raise MediaUnavailable("cannot render PDF page")
    return image


def render_page(renderer: PW.PdfRenderer, page: int, width: int, height: int):
    """Page *page* of an open PDF as a QImage of about *width* x *height*
    px on white (clamped to core.pdf_worker.MAX_PIXELS)."""
    try:
        return _image_of(renderer.render(page, width, height))
    except PW.PdfError as exc:
        raise MediaUnavailable(str(exc)) from exc


def render_page_edge(renderer: PW.PdfRenderer, page: int, edge: int):
    """Page *page* of an open PDF as a QImage, longer side *edge*."""
    try:
        return _image_of(renderer.render_edge(page, edge))
    except PW.PdfError as exc:
        raise MediaUnavailable(str(exc)) from exc


def render_pdf_page(path: str, page: int, edge: int):
    """Page *page* of the PDF at *path* as a QImage on white, longer side
    *edge* - drawn by a pooled child (core.pdf_worker.borrowed)."""
    _require_qtpdf()
    try:
        with PW.borrowed(PW.RENDER_SECONDS) as renderer:
            renderer.open(path)
            if not 0 <= page < renderer.page_count:
                raise MediaUnavailable(f"PDF has no page {page + 1}")
            return _image_of(renderer.render_edge(page, edge))
    except PW.PdfError as exc:
        raise MediaUnavailable(str(exc)) from exc


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
        except P.PreviewIsPdf:
            # A PDF named like a picture: its first page, drawn the way a
            # .pdf is (the picture decoders never draw a PDF).
            return render_pdf_page(f.path, 0, edge)
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
        except P.PreviewIsPdf:
            # A PDF named like a picture: its first page, as a .pdf's is drawn.
            return Prepared(item, image=render_pdf_page(f.path, 0, max_edge))
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
            renderer = open_pdf(f.path)
        except BaseException:
            f.release()
            raise
        entry = Prepared(item, local_path=f.path, page_count=renderer.page_count, file=f,
                         pdf=renderer)
        try:
            # the first page now, so the viewer shows it at once (it draws
            # a sharper one for its window when that one differs much)
            entry.image = render_page_edge(renderer, 0, PDF_FIRST_EDGE)
            entry.first_page_points = renderer.page_size(0)
        except MediaUnavailable as exc:
            entry.image = exc
        except BaseException:
            entry.release()
            raise
        return entry
    if item.kind == VIDEO:
        # A local video is streamed by the player, never read whole.
        local = FA.is_local_backend(backend)
        limit = None if local else open_limits.max_open_bytes()
        f = fetch(backend, item, cancel=cancel, limit=limit)
        # Qt Multimedia's FFmpeg opens the file inside axross: a file that
        # crashes or hangs a probe in a child first is not handed to it.
        from core import media_gate

        try:
            refusal = media_gate.probe_refusal(f.path, cancel=cancel)
        except BaseException:
            f.release()
            raise
        if refusal is not None:
            f.release()
            raise MediaUnavailable(refusal)
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
    "open_pdf",
    "pdf_page_count",
    "prepare",
    "render_page",
    "render_page_edge",
    "render_pdf_page",
    "thumbnail",
    "too_large_text",
]
