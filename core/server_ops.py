"""Server-side copy / move helpers with automatic fallback.

Call these from the transfer engine or UI instead of ``backend.copy``
or ``backend.rename`` directly — they prefer the backend's native
operation when available (S3 CopyObject, WebDAV COPY, shell ``cp``,
etc.) and fall back to a read/write stream copy only when the
protocol doesn't offer a native shortcut. The resulting behaviour is
always correct; the difference is bandwidth + latency.
"""
from __future__ import annotations

import logging
import shutil
from typing import TYPE_CHECKING

from core import backend_registry

if TYPE_CHECKING:  # pragma: no cover
    from core.backend import FileBackend

log = logging.getLogger(__name__)


def copy_via_stream(backend, src: str, dst: str) -> None:
    """Fallback copy: read src, write dst. O(bytes) client roundtrip.

    Used when the backend has no native copy. Does NOT do integrity
    verification here — that is the transfer engine's job.
    """
    with backend.open_read(src) as rf, backend.open_write(dst) as wf:
        # shutil.copyfileobj is iteration with a reasonable buffer.
        shutil.copyfileobj(rf, wf)


def server_side_copy(backend, src: str, dst: str) -> None:
    """Copy src to dst on the same backend. Prefers the backend's
    native ``copy()``; falls back to stream copy when the native
    method raises or isn't present.

    We try-then-catch instead of consulting BackendCapabilities
    because test doubles / overlay backends subclass LocalFS etc.
    and the capability registry only knows the canonical class
    names. Try-then-catch is correct for both real and test
    backends.

    Raises :class:`OSError` only when the fallback stream copy also
    fails.
    """
    if hasattr(backend, "copy"):
        try:
            backend.copy(src, dst)
            log.debug("server_side_copy: native path used for %s -> %s",
                      src, dst)
            return
        except (OSError, NotImplementedError) as exc:
            log.debug(
                "server_side_copy: backend.copy raised (%s); "
                "falling back to stream copy",
                exc,
            )
    copy_via_stream(backend, src, dst)


def server_side_move(backend, src: str, dst: str) -> None:
    """Move src to dst on the same backend. Prefers rename() (which is
    already the backend's move primitive for all backends that
    implement it). Falls back to copy-then-delete when rename isn't
    supported (e.g. S3, where rename is internally a CopyObject +
    DeleteObject anyway).
    """
    try:
        backend.rename(src, dst)
        return
    except (OSError, NotImplementedError) as exc:
        log.debug(
            "server_side_move: rename raised (%s); falling back to "
            "copy + delete", exc,
        )
    # Fallback: copy then delete source. If remove fails, the caller
    # has both src and dst — dangerous to hide, so we re-raise with
    # a message that makes the double-copy state explicit.
    server_side_copy(backend, src, dst)
    try:
        backend.remove(src)
    except OSError as exc:
        log.error(
            "server_side_move: copied %s -> %s but remove(src) failed: %s "
            "-- source still present, destination also present",
            src, dst, exc,
        )
        raise OSError(
            f"move partially completed: copy succeeded but remove of "
            f"source {src} failed: {exc}"
        ) from exc
