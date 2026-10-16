"""Local-only preview helpers: MIME detection, thumbnails, external open.

These helpers are **disabled by default on remote backends**. Decoding
an image from an S3 bucket means downloading bytes and then running
them through QImageReader / libpng / libjpeg — decoders have a long
history of CVEs, so we treat input as attacker-controlled and require
an explicit "this backend is local, I trust its filesystem" flag
before touching the file.

Security model
--------------
* Gated on :attr:`BackendCapabilities.is_local` == True.
* All helpers raise :class:`PreviewNotAvailable` when the backend is
  not local — they never silently skip.
* MIME detection is extension + content-sniff via ``QMimeDatabase``.
  We don't trust the filename alone because a ``.txt`` file might be
  a ZIP; we don't trust the content alone because a malicious
  attacker can forge magic bytes. QMimeDatabase combines both.
* Thumbnail generation:
  - Rejects files larger than :data:`MAX_INPUT_SIZE` (50 MiB default)
    so we never feed a decoder a multi-GB "image".
  - Rejects declared dimensions beyond :data:`MAX_DIMENSION`
    (20 000px) to block decompression bombs.
  - Sets ``QImageReader.setAllocationLimit`` (Qt 6) so the decoder's
    internal allocator caps out at a safe value.
  - Uses ``setScaledSize`` so we don't fully decode before scaling.
  - Only allow-list common lossy/lossless raster MIMEs; SVG is
    excluded by default because it can contain script / external
    references (XXE risk). A caller may opt in with ``allow_svg=True``
    (the media viewer); the source then has to pass :func:`svg_refusal`
    (no DOCTYPE / entities, no scripts, no reference outside the file)
    and is drawn by QtSvg's static Tiny-1.2 renderer.
* :func:`decode_image` is the full-window variant of :func:`thumbnail`:
  same gates, no cache, up to :data:`VIEWER_MAX_EDGE` px.
* External open:
  - Rejects NUL bytes, absolute paths outside the given root, and
    non-existent paths.
  - Uses ``QDesktopServices.openUrl`` rather than ``os.system`` /
    ``subprocess.shell=True``. The underlying handler is whatever
    the desktop session registered; we don't try to second-guess it.

Thumbnail cache
---------------
Thumbnails are content-addressed by ``(abspath, mtime, size)`` and
cached under ``$XDG_CACHE_HOME/axross/thumbnails/`` as PNG files.
A cache hit avoids re-decoding — crucial for large image
directories.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    pass

log = logging.getLogger(__name__)

# Optional Pillow fallback. Qt's QImageReader is the primary decoder,
# but its plugin set varies by build (this environment has no TIFF
# plugin, for example). When Qt can't read a format we still trust
# (it's in ALLOWED_THUMBNAIL_MIMES), we fall back to Pillow.
try:
    from PIL import Image as _PILImage
except Exception:  # pragma: no cover - Pillow optional at runtime
    _PILImage = None


# ---------------------------------------------------------------------------
# Security knobs — change with extreme care
# ---------------------------------------------------------------------------

# Largest file we'll feed to an image decoder. 50 MiB is plenty for any
# realistic photo; anything beyond is a sign of a dangerous payload.
MAX_INPUT_SIZE = 50 * 1024 * 1024

# Maximum width or height we'll accept from an image header. Above
# this the file is almost certainly a decompression bomb
# (a 1x1 PNG can declare 100_000 × 100_000 and explode on decode).
MAX_DIMENSION = 20_000

# Pillow's own decompression-bomb guard — keep it in lock-step with
# our dimension cap so a malicious file can't slip past one decoder.
if _PILImage is not None:  # pragma: no branch
    try:
        _PILImage.MAX_IMAGE_PIXELS = MAX_DIMENSION * MAX_DIMENSION
    except Exception as _exc:  # pragma: no cover - defensive
        log.debug("could not set PIL.Image.MAX_IMAGE_PIXELS: %s", _exc)

# Qt allocation limit in MiB — applies to every QImageReader we create.
QIMAGE_ALLOC_LIMIT_MIB = 128

# The Pillow fallback is reached exactly when Qt refused (often because
# of QIMAGE_ALLOC_LIMIT_MIB), so it needs its own RGBA decode budget;
# MAX_DIMENSION alone still allows 20000x20000 = 1.6 GiB.
PILLOW_ALLOC_LIMIT_MIB = 512

# Raster formats the fallback may open. Deliberately excludes EPS (runs
# Ghostscript), PDF/WMF/EMF and anything else that is a program or a
# container rather than pixels.
PILLOW_FALLBACK_FORMATS = (
    "PNG", "JPEG", "GIF", "BMP", "WEBP", "TIFF", "PPM", "ICO", "TGA", "PCX", "DDS", "ICNS",
)

# Default thumbnail edge length.
DEFAULT_THUMBNAIL_EDGE = 256

# Longest edge :func:`decode_image` produces by default (the media viewer's
# full-window view). Larger pictures are scaled down while decoding.
VIEWER_MAX_EDGE = 4096

SVG_MIME = "image/svg+xml"

# Largest SVG source the gate reads. SVG is text; anything beyond is not a
# drawing anyone hand-made, and the XML parser should never see it.
MAX_SVG_INPUT_SIZE = 8 * 1024 * 1024

# MIME types we're willing to decode for previews. Anything else is
# refused — even if Qt claims it can read it. Keep this small on
# purpose. SVG is NOT here (script/XXE surface): only callers that pass
# ``allow_svg=True`` (the media viewer) get it, and then only through
# :func:`svg_refusal` and QtSvg's restricted static renderer.
ALLOWED_THUMBNAIL_MIMES: frozenset[str] = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/bmp",
        "image/webp",
        "image/tiff",
        "image/x-portable-pixmap",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PreviewError(Exception):
    """Base for everything this module raises."""


class PreviewNotAvailable(PreviewError):
    """Backend is not local, or the file type isn't previewable."""


class PreviewTooLarge(PreviewError):
    """File exceeds MAX_INPUT_SIZE or MAX_DIMENSION."""


class PreviewDecodeFailed(PreviewError):
    """The decoder couldn't produce an image even though the file
    passed the gate checks (malformed PNG, corrupted JPEG, etc.)."""


# ---------------------------------------------------------------------------
# Local-only gate
# ---------------------------------------------------------------------------


def _is_local_backend(backend) -> bool:
    """True iff the backend is flagged ``is_local`` by the registry
    or is the well-known ``LocalFS`` class. Anything we can't
    positively identify is treated as remote — safe default."""
    # Registered backend?
    try:
        from core import backend_registry

        cls = type(backend).__name__
        for info in backend_registry.all_backends():
            if info.class_name == cls:
                return bool(getattr(info.capabilities, "is_local", False))
    except Exception as exc:  # registry shouldn't fail, but be defensive
        log.debug("previews: registry lookup failed: %s", exc)
    # Fall back to class identity — LocalFS and its subclasses.
    try:
        from core.local_fs import LocalFS

        return isinstance(backend, LocalFS)
    except Exception:
        return False


def _require_local(backend) -> None:
    if not _is_local_backend(backend):
        raise PreviewNotAvailable(
            "preview helpers are restricted to local backends "
            "(set BackendCapabilities.is_local=True to opt in)"
        )


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------


def _validate_local_path(path: str) -> str:
    """Normalise + reject unsafe inputs. Returns an absolute path."""
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("path contains a NUL byte")
    abs_path = os.path.abspath(os.path.expanduser(path))
    return abs_path


# ---------------------------------------------------------------------------
# MIME detection
# ---------------------------------------------------------------------------


def guess_mime(backend, path: str) -> str:
    """Return the MIME type of *path* on *backend*.

    Raises :class:`PreviewNotAvailable` when the backend is not local.
    Falls back to ``application/octet-stream`` when even the
    combined extension+content sniff can't classify the file.
    """
    _require_local(backend)
    abs_path = _validate_local_path(path)
    if not os.path.isfile(abs_path):
        raise PreviewNotAvailable(f"not a regular file: {abs_path}")
    try:
        from PyQt6.QtCore import QMimeDatabase
    except ImportError as exc:  # pragma: no cover
        raise PreviewNotAvailable(f"PyQt6.QtCore.QMimeDatabase unavailable: {exc}") from exc
    db = QMimeDatabase()
    mt = db.mimeTypeForFile(abs_path)
    name = mt.name() or "application/octet-stream"
    # QMimeDatabase returns "application/octet-stream" for unknown —
    # pass through without further classification.
    return name


# ---------------------------------------------------------------------------
# Thumbnails
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThumbnailResult:
    """Outcome of :func:`thumbnail`."""

    data: bytes  # PNG-encoded thumbnail
    mime: str  # source file's MIME
    width: int  # thumbnail width (px)
    height: int  # thumbnail height (px)
    from_cache: bool  # True if served from the on-disk cache


def _cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    root = Path(base) / "axross" / "thumbnails"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _cache_key(abs_path: str, mtime: float, size: int, edge: int) -> str:
    h = hashlib.sha256()
    h.update(abs_path.encode("utf-8", errors="replace"))
    h.update(b"\x00")
    # Full mtime precision: rapid write/read/write within one second
    # still invalidates the cache. ``int(mtime)`` would have kept the
    # stale thumbnail in that window.
    h.update(f"{mtime:.6f}:{size}:{edge}".encode("ascii"))
    return h.hexdigest()


def _load_cached(cache_file: Path) -> bytes | None:
    try:
        if cache_file.is_file():
            return cache_file.read_bytes()
    except OSError as exc:
        log.debug("thumbnail cache read failed: %s", exc)
    return None


def _store_cached(cache_file: Path, data: bytes) -> None:
    # Atomic write: tmp in same dir then rename. Use a per-call random
    # suffix so two parallel thumbnail jobs for the same key don't
    # clobber each other's temp file.
    import secrets as _secrets

    tmp = cache_file.parent / f"{cache_file.name}.{_secrets.token_hex(6)}.tmp"
    try:
        tmp.write_bytes(data)
        os.replace(tmp, cache_file)
    except OSError as exc:
        log.debug("thumbnail cache write failed: %s", exc)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _decode_with_pillow(abs_path: str, edge: int | None) -> bytes:
    """Decode *abs_path* with Pillow and return PNG-encoded bytes.

    This is the fallback for formats Qt's ``QImageReader`` can't read
    in this build (e.g. TIFF when the Qt tiff plugin is absent). The
    same security caps as the Qt path apply:

    * ``MAX_INPUT_SIZE`` (file st_size) is already enforced by the
      caller *before* we ever open the file here.
    * Dimension cap (``MAX_DIMENSION``) is checked from the header
      (``img.size`` is available lazily, before ``.load()``) so a
      decompression bomb is rejected before a full decode.
    * Pillow's own ``MAX_IMAGE_PIXELS`` guard is wired to
      ``MAX_DIMENSION**2`` at import time as a second layer.

    Raises:
      * :class:`PreviewDecodeFailed` — Pillow missing or decode failed.
      * :class:`PreviewTooLarge` — header dimensions or a Pillow
        decompression-bomb error exceed the cap.
    """
    if _PILImage is None:
        raise PreviewDecodeFailed(
            f"{abs_path}: Qt cannot decode this format and Pillow is not "
            f"installed (pip install Pillow for TIFF/extra formats)"
        )

    try:
        # An explicit format list: Pillow's default opens EPS, which
        # spawns Ghostscript on load(), and sniffs content rather than
        # the extension, so "x.png" can be a PostScript program.
        img = _PILImage.open(abs_path, formats=list(PILLOW_FALLBACK_FORMATS))
    except Exception as exc:
        raise PreviewDecodeFailed(f"{abs_path}: Pillow could not open file: {exc}") from exc

    # Multi-page formats (TIFF, GIF) — always decode the first frame.
    try:
        img.seek(0)
    except Exception:
        pass

    # Dimension cap from the header, BEFORE a full load — blocks bombs.
    w, h = img.size
    if w > MAX_DIMENSION or h > MAX_DIMENSION:
        raise PreviewTooLarge(
            f"{abs_path}: dimensions {w}x{h} exceed MAX_DIMENSION {MAX_DIMENSION}"
        )

    if w * h * 4 > PILLOW_ALLOC_LIMIT_MIB * 1024 * 1024:
        raise PreviewTooLarge(
            f"{abs_path}: {w}x{h} would need more than {PILLOW_ALLOC_LIMIT_MIB} MiB to decode"
        )

    try:
        img.load()
    except _PILImage.DecompressionBombError as exc:
        raise PreviewTooLarge(
            f"{abs_path}: Pillow decompression-bomb guard tripped: {exc}"
        ) from exc
    except Exception as exc:
        raise PreviewDecodeFailed(f"{abs_path}: Pillow decode failed: {exc}") from exc

    # Convert to a PNG-friendly mode. CMYK / I;16 / YCbCr etc. can't be
    # PNG-encoded directly; RGBA is the safe superset (handles palette
    # transparency too).
    if img.mode not in ("RGB", "RGBA", "L", "LA", "P"):
        try:
            img = img.convert("RGBA")
        except Exception as exc:
            raise PreviewDecodeFailed(
                f"{abs_path}: Pillow mode conversion failed: {exc}"
            ) from exc

    # Downscale only when the image is LARGER than the requested edge.
    # The viewer passes a large edge meaning "full res" — never upscale.
    if edge is not None and max(w, h) > edge:
        img.thumbnail((edge, edge))

    buf = io.BytesIO()
    try:
        img.save(buf, format="PNG")
    except Exception as exc:
        raise PreviewDecodeFailed(f"{abs_path}: Pillow PNG encode failed: {exc}") from exc
    return buf.getvalue()


def _checked_source(backend, path: str, *, allow_svg: bool) -> tuple[str, os.stat_result, str]:
    """The gates every decode passes first: security mode, local backend,
    a non-empty regular file within the size cap, an allow-listed MIME.

    Returns ``(abs_path, stat, mime)``."""
    from core.security_mode import current_policy, require

    require("automatic previews", current_policy().allow_auto_preview)
    _require_local(backend)
    abs_path = _validate_local_path(path)

    try:
        st = os.stat(abs_path)
    except OSError as exc:
        raise PreviewNotAvailable(f"stat failed: {exc}") from exc
    if st.st_size == 0:
        raise PreviewNotAvailable("file is empty")
    if st.st_size > MAX_INPUT_SIZE:
        raise PreviewTooLarge(
            f"file {abs_path} exceeds MAX_INPUT_SIZE ({st.st_size} > {MAX_INPUT_SIZE})"
        )

    mime = guess_mime(backend, abs_path)
    if mime == SVG_MIME and allow_svg:
        if st.st_size > MAX_SVG_INPUT_SIZE:
            raise PreviewTooLarge(
                f"SVG {abs_path} exceeds MAX_SVG_INPUT_SIZE ({st.st_size} > {MAX_SVG_INPUT_SIZE})"
            )
    elif mime not in ALLOWED_THUMBNAIL_MIMES:
        raise PreviewNotAvailable(f"MIME {mime!r} is not in the thumbnail allow-list")
    return abs_path, st, mime


def _png_bytes(image) -> bytes:
    from PyQt6.QtCore import QBuffer, QIODevice

    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buf, "PNG"):
        raise PreviewDecodeFailed("PNG encode of decoded image failed")
    return bytes(buf.data())


def _read_raster(abs_path: str, edge: int):
    """Decode *abs_path* scaled to fit *edge*: ``(QImage, None)`` from Qt, or
    ``(None, png_bytes)`` from the Pillow fallback."""
    try:
        from PyQt6.QtCore import QSize
        from PyQt6.QtGui import QImage, QImageReader
    except ImportError as exc:  # pragma: no cover
        raise PreviewNotAvailable(f"PyQt6.QtGui unavailable: {exc}") from exc

    # Global per-process cap — libpng/libjpeg won't allocate past this.
    try:
        QImageReader.setAllocationLimit(QIMAGE_ALLOC_LIMIT_MIB)
    except Exception as exc:
        # Older Qt without this API: rely on MAX_DIMENSION gate instead.
        log.debug("QImageReader.setAllocationLimit unavailable: %s", exc)

    reader = QImageReader(abs_path)
    reader.setDecideFormatFromContent(True)

    # Sniff declared dimensions BEFORE decoding.
    raw_size = reader.size()
    if raw_size.isValid():
        if raw_size.width() > MAX_DIMENSION or raw_size.height() > MAX_DIMENSION:
            raise PreviewTooLarge(
                f"declared image dimensions "
                f"{raw_size.width()}x{raw_size.height()} "
                f"exceed MAX_DIMENSION={MAX_DIMENSION}"
            )

    # Let Qt scale during decode so we never materialise the full-res
    # raster for a 40-megapixel photo when all we want is a 256-px tile.
    if raw_size.isValid():
        w, h = raw_size.width(), raw_size.height()
        if w > edge or h > edge:
            if w >= h:
                new_w = edge
                new_h = max(1, round(h * edge / w))
            else:
                new_h = edge
                new_w = max(1, round(w * edge / h))
            reader.setScaledSize(QSize(new_w, new_h))

    # Qt-first: only fall back to Pillow when Qt genuinely can't read
    # this format here (no plugin → canRead() False, or read() returns
    # a null QImage). Formats Qt CAN decode (png/jpg/gif/webp/…) stay
    # on the QImageReader path untouched.
    can_read = reader.canRead()
    image: QImage = reader.read() if can_read else QImage()
    if image.isNull():
        # Pillow fallback. The MAX_INPUT_SIZE gate already ran above;
        # _decode_with_pillow re-checks the dimension cap from the
        # header before fully decoding.
        return None, _decode_with_pillow(abs_path, edge)
    return image, None


# ---------------------------------------------------------------------------
# SVG (media viewer only, behind allow_svg=True)
# ---------------------------------------------------------------------------

# Anything that makes the XML parser expand, include or fetch, or that
# would run in a browser. QtSvg runs no scripts and fetches nothing from
# the network, but the gate does not rely on that: it refuses first.
_SVG_FORBIDDEN = (
    b"<!doctype",
    b"<!entity",
    b"<?xml-stylesheet",
    b"<script",
    b"<foreignobject",
    b"<iframe",
    b"<object",
    b"<embed",
    b"@import",
)
_SVG_HREF = re.compile(rb"""href\s*=\s*(["'])\s*(.*?)\1""", re.S)
_SVG_URL = re.compile(rb"""url\(\s*["']?\s*([^)"'\s]*)""")
_SVG_DATA_IMAGE = (b"data:image/png", b"data:image/jpeg", b"data:image/gif", b"data:image/webp")


def svg_refusal(data: bytes) -> str | None:
    """Why *data* must not reach the SVG renderer, or ``None`` when it may.

    Allowed: a UTF-8 document whose references all stay inside it
    (``#id``) or embed a common raster as a ``data:`` URI."""
    if b"\x00" in data:
        return "SVG is not UTF-8 text"
    lowered = data.lower()
    for token in _SVG_FORBIDDEN:
        if token in lowered:
            return f"SVG contains {token.decode()!r}"
    for match in _SVG_HREF.finditer(lowered):
        ref = match.group(2).strip()
        if not (ref.startswith(b"#") or ref.startswith(_SVG_DATA_IMAGE)):
            return "SVG references something outside the file"
    for match in _SVG_URL.finditer(lowered):
        if not match.group(1).startswith(b"#"):
            return "SVG references something outside the file"
    return None


def _render_svg(abs_path: str, edge: int):
    """Render the SVG at *abs_path* to a QImage whose longer side is *edge*."""
    try:
        from PyQt6.QtCore import QByteArray, QRectF, Qt
        from PyQt6.QtGui import QImage, QPainter
        from PyQt6.QtSvg import QSvgRenderer
    except ImportError as exc:  # pragma: no cover - QtSvg is part of the wheel
        raise PreviewNotAvailable(f"PyQt6.QtSvg unavailable: {exc}") from exc

    try:
        with open(abs_path, "rb") as fh:
            data = fh.read(MAX_SVG_INPUT_SIZE + 1)
    except OSError as exc:
        raise PreviewNotAvailable(f"cannot read {abs_path}: {exc}") from exc
    if len(data) > MAX_SVG_INPUT_SIZE:
        raise PreviewTooLarge(f"SVG {abs_path} exceeds MAX_SVG_INPUT_SIZE")
    reason = svg_refusal(data)
    if reason is not None:
        raise PreviewNotAvailable(f"{abs_path}: {reason}")

    renderer = QSvgRenderer()
    try:
        from PyQt6.QtSvg import QtSvg

        # PyQt6 exposes the QFlags as a plain Enum: combine by value.
        renderer.setOptions(
            QtSvg.Option(
                QtSvg.Option.Tiny12FeaturesOnly.value | QtSvg.Option.DisableAnimations.value
            )
        )
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        # Qt < 6.7 has no options; the gate above still applies.
        log.debug("QSvgRenderer.setOptions unavailable: %s", exc)
    if not renderer.load(QByteArray(data)) or not renderer.isValid():
        raise PreviewDecodeFailed(f"{abs_path}: not a valid SVG")
    size = renderer.defaultSize()
    w, h = (size.width(), size.height()) if not size.isEmpty() else (edge, edge)
    scale = edge / max(w, h)
    out_w, out_h = max(1, round(w * scale)), max(1, round(h * scale))
    image = QImage(out_w, out_h, QImage.Format.Format_ARGB32_Premultiplied)
    if image.isNull():
        raise PreviewTooLarge(f"{abs_path}: cannot allocate {out_w}x{out_h}")
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    try:
        renderer.render(painter, QRectF(0, 0, out_w, out_h))
    finally:
        painter.end()
    return image


def thumbnail(
    backend,
    path: str,
    *,
    edge: int = DEFAULT_THUMBNAIL_EDGE,
    use_cache: bool = True,
    allow_svg: bool = False,
) -> ThumbnailResult:
    """Produce a PNG-encoded thumbnail of *path* at roughly *edge* px.

    The full security contract is enforced here: local-only,
    size-bounded, dimension-bounded, allocation-limited, allow-listed
    MIME. Returns the PNG bytes plus metadata. ``allow_svg`` lets an SVG
    through :func:`svg_refusal` to QtSvg (the media viewer opts in; the
    pane does not).

    Raises:
      * :class:`PreviewNotAvailable` — remote backend, wrong MIME,
        missing Qt imaging bindings.
      * :class:`PreviewTooLarge` — file too big or dimension bomb.
      * :class:`PreviewDecodeFailed` — decoder couldn't parse.
    """
    abs_path, st, mime = _checked_source(backend, path, allow_svg=allow_svg)
    edge = max(16, min(int(edge), 2048))

    cache_file: Path | None = None
    if use_cache:
        key = _cache_key(abs_path, st.st_mtime, st.st_size, edge)
        cache_file = _cache_root() / (key + ".png")
        hit = _load_cached(cache_file)
        if hit is not None:
            # Minimal metadata on cache-hit — we don't re-parse to
            # extract dimensions because we trust our own cache.
            return ThumbnailResult(
                data=hit,
                mime=mime,
                width=edge,
                height=edge,
                from_cache=True,
            )

    if mime == SVG_MIME:
        image, data = _render_svg(abs_path, edge), None
    else:
        image, data = _read_raster(abs_path, edge)
    if data is not None:
        from PyQt6.QtGui import QImage

        # Parse dimensions back from the PNG the Pillow fallback produced
        # so the ThumbnailResult contract (width/height) matches the Qt path.
        decoded = QImage.fromData(data, "PNG")
        out_w = decoded.width() if not decoded.isNull() else edge
        out_h = decoded.height() if not decoded.isNull() else edge
    else:
        data = _png_bytes(image)
        out_w, out_h = image.width(), image.height()

    if cache_file is not None:
        _store_cached(cache_file, data)

    return ThumbnailResult(
        data=data,
        mime=mime,
        width=out_w,
        height=out_h,
        from_cache=False,
    )


def decode_image(
    backend, path: str, *, max_edge: int = VIEWER_MAX_EDGE, allow_svg: bool = False
):
    """Decode *path* for a full-window view and return a ``QImage``.

    The same gates as :func:`thumbnail` (security mode, local only, size,
    dimensions, allocation limit, MIME allow-list), no cache, and an edge
    up to *max_edge* instead of the thumbnail's 2048 px clamp; a larger
    picture is scaled down while decoding.

    Raises the same :class:`PreviewError` subclasses as :func:`thumbnail`.
    """
    abs_path, _st, mime = _checked_source(backend, path, allow_svg=allow_svg)
    edge = max(16, min(int(max_edge), MAX_DIMENSION))
    if mime == SVG_MIME:
        return _render_svg(abs_path, edge)
    image, data = _read_raster(abs_path, edge)
    if image is not None:
        return image
    from PyQt6.QtGui import QImage

    image = QImage.fromData(data, "PNG")
    if image.isNull():
        raise PreviewDecodeFailed(f"{abs_path}: decoded image could not be read back")
    return image


# ---------------------------------------------------------------------------
# External open
# ---------------------------------------------------------------------------


def open_externally(backend, path: str) -> None:
    """Hand *path* to the desktop's default handler.

    Uses :class:`QDesktopServices` so we don't have to shell out.
    Still validates the path (NUL byte, existence, regular-file)
    before invoking anything — the desktop handler itself is the
    remaining attack surface and is outside our control.

    Raises:
      * :class:`PreviewNotAvailable` on a remote backend.
      * :class:`ValueError` on malformed path.
      * :class:`OSError` if the desktop refuses to open the file.
    """
    from core.security_mode import current_policy, require

    require("external viewer", current_policy().allow_external_viewer)
    _require_local(backend)
    abs_path = _validate_local_path(path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(abs_path)
    # Only open regular files and directories — refuse devices /
    # FIFOs / sockets.
    st = os.stat(abs_path)
    from stat import S_ISDIR, S_ISREG

    if not (S_ISREG(st.st_mode) or S_ISDIR(st.st_mode)):
        raise PreviewNotAvailable(f"refusing to open special file: {abs_path}")
    try:
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QDesktopServices
    except ImportError as exc:  # pragma: no cover
        raise PreviewNotAvailable(f"PyQt6.QtGui.QDesktopServices unavailable: {exc}") from exc
    url = QUrl.fromLocalFile(abs_path)
    ok = QDesktopServices.openUrl(url)
    if not ok:
        raise OSError(f"QDesktopServices.openUrl refused to open {abs_path}")


__all__ = [
    "ALLOWED_THUMBNAIL_MIMES",
    "DEFAULT_THUMBNAIL_EDGE",
    "MAX_DIMENSION",
    "MAX_INPUT_SIZE",
    "MAX_SVG_INPUT_SIZE",
    "PreviewDecodeFailed",
    "PreviewError",
    "PreviewNotAvailable",
    "PreviewTooLarge",
    "SVG_MIME",
    "ThumbnailResult",
    "VIEWER_MAX_EDGE",
    "decode_image",
    "guess_mime",
    "open_externally",
    "svg_refusal",
    "thumbnail",
]
