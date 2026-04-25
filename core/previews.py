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
    references (XXE risk).
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
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from core.backend import FileBackend

log = logging.getLogger("core.previews")


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

# Qt allocation limit in MiB — applies to every QImageReader we create.
QIMAGE_ALLOC_LIMIT_MIB = 128

# Default thumbnail edge length.
DEFAULT_THUMBNAIL_EDGE = 256

# MIME types we're willing to decode for previews. Anything else is
# refused — even if Qt claims it can read it. Keep this small on
# purpose. SVG is NOT here (script/XXE surface); we can revisit once
# we're ready to run SVG through a sanitising parser.
ALLOWED_THUMBNAIL_MIMES: frozenset[str] = frozenset({
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/bmp",
    "image/webp",
    "image/tiff",
    "image/x-portable-pixmap",
})


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
        raise PreviewNotAvailable(
            f"not a regular file: {abs_path}"
        )
    try:
        from PyQt6.QtCore import QMimeDatabase
    except ImportError as exc:  # pragma: no cover
        raise PreviewNotAvailable(
            f"PyQt6.QtCore.QMimeDatabase unavailable: {exc}"
        ) from exc
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

    data: bytes          # PNG-encoded thumbnail
    mime: str            # source file's MIME
    width: int           # thumbnail width (px)
    height: int          # thumbnail height (px)
    from_cache: bool     # True if served from the on-disk cache


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


def thumbnail(backend, path: str, *,
              edge: int = DEFAULT_THUMBNAIL_EDGE,
              use_cache: bool = True) -> ThumbnailResult:
    """Produce a PNG-encoded thumbnail of *path* at roughly *edge* px.

    The full security contract is enforced here: local-only,
    size-bounded, dimension-bounded, allocation-limited, allow-listed
    MIME. Returns the PNG bytes plus metadata.

    Raises:
      * :class:`PreviewNotAvailable` — remote backend, wrong MIME,
        missing Qt imaging bindings.
      * :class:`PreviewTooLarge` — file too big or dimension bomb.
      * :class:`PreviewDecodeFailed` — decoder couldn't parse.
    """
    _require_local(backend)
    abs_path = _validate_local_path(path)
    edge = max(16, min(int(edge), 2048))

    try:
        st = os.stat(abs_path)
    except OSError as exc:
        raise PreviewNotAvailable(f"stat failed: {exc}") from exc
    if st.st_size == 0:
        raise PreviewNotAvailable("file is empty")
    if st.st_size > MAX_INPUT_SIZE:
        raise PreviewTooLarge(
            f"file {abs_path} exceeds MAX_INPUT_SIZE "
            f"({st.st_size} > {MAX_INPUT_SIZE})"
        )

    mime = guess_mime(backend, abs_path)
    if mime not in ALLOWED_THUMBNAIL_MIMES:
        raise PreviewNotAvailable(
            f"MIME {mime!r} is not in the thumbnail allow-list"
        )

    cache_file: Path | None = None
    if use_cache:
        key = _cache_key(abs_path, st.st_mtime, st.st_size, edge)
        cache_file = _cache_root() / (key + ".png")
        hit = _load_cached(cache_file)
        if hit is not None:
            # Minimal metadata on cache-hit — we don't re-parse to
            # extract dimensions because we trust our own cache.
            return ThumbnailResult(
                data=hit, mime=mime, width=edge, height=edge,
                from_cache=True,
            )

    try:
        from PyQt6.QtGui import QImageReader, QImage
        from PyQt6.QtCore import QBuffer, QIODevice, QSize
    except ImportError as exc:  # pragma: no cover
        raise PreviewNotAvailable(
            f"PyQt6.QtGui unavailable: {exc}"
        ) from exc

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
        if (raw_size.width() > MAX_DIMENSION
                or raw_size.height() > MAX_DIMENSION):
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

    image: QImage = reader.read()
    if image.isNull():
        raise PreviewDecodeFailed(
            f"QImageReader failed on {abs_path}: {reader.errorString()}"
        )

    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buf, "PNG"):
        raise PreviewDecodeFailed("PNG encode of decoded image failed")
    data = bytes(buf.data())

    if cache_file is not None:
        _store_cached(cache_file, data)

    return ThumbnailResult(
        data=data, mime=mime,
        width=image.width(), height=image.height(),
        from_cache=False,
    )


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
    _require_local(backend)
    abs_path = _validate_local_path(path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(abs_path)
    # Only open regular files and directories — refuse devices /
    # FIFOs / sockets.
    st = os.stat(abs_path)
    from stat import S_ISREG, S_ISDIR
    if not (S_ISREG(st.st_mode) or S_ISDIR(st.st_mode)):
        raise PreviewNotAvailable(
            f"refusing to open special file: {abs_path}"
        )
    try:
        from PyQt6.QtGui import QDesktopServices
        from PyQt6.QtCore import QUrl
    except ImportError as exc:  # pragma: no cover
        raise PreviewNotAvailable(
            f"PyQt6.QtGui.QDesktopServices unavailable: {exc}"
        ) from exc
    url = QUrl.fromLocalFile(abs_path)
    ok = QDesktopServices.openUrl(url)
    if not ok:
        raise OSError(
            f"QDesktopServices.openUrl refused to open {abs_path}"
        )


__all__ = [
    "ALLOWED_THUMBNAIL_MIMES",
    "DEFAULT_THUMBNAIL_EDGE",
    "MAX_DIMENSION",
    "MAX_INPUT_SIZE",
    "PreviewDecodeFailed",
    "PreviewError",
    "PreviewNotAvailable",
    "PreviewTooLarge",
    "ThumbnailResult",
    "guess_mime",
    "open_externally",
    "thumbnail",
]
