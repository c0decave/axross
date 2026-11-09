"""Help > Tours > Watch Video: the narrated video of a tour.

The videos (scripts/tour_videos.py makes them, one MP4 per tour and
language) are too big for the wheel and the binaries, about 40 MB
together. They are assets of their own GitHub release (a fixed tag,
``resources/tours/tour_videos.json`` names it), and the manifest shipped
with axross pins each file's size and SHA-256: a video is downloaded on
the first Watch Video, through the update check's https fetch (its host
allow-list, redirect checks, proxy and size limit), checked, and kept in
``$XDG_CACHE_HOME/axross/tour-videos/``. A file that does not match its
pin is never kept or played.

A language without its own video falls back to the English one.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

MANIFEST = Path(__file__).resolve().parent.parent / "resources" / "tours" / "tour_videos.json"
#: A tour video is a few MB; anything much bigger is not one of ours.
MAX_VIDEO_BYTES = 64 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.mp4")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class VideoError(Exception):
    """The video could not be fetched or did not match its pin.

    ``str()`` is the technical text (for the log); :meth:`user_text` is the
    translated sentence for the message box. *kind* is ``"unpublished"``
    (the release or the file answers 404), ``"network"`` (no connection,
    no name resolution, no answer in time), ``"checksum"``, ``"disk"``,
    ``"unsafe"`` (the cache folder is not private to this user) or
    ``"other"``; *cause* is the network error behind a ``"network"`` one."""

    def __init__(self, message: str, *, kind: str = "other", name: str = "",
                 cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.name = name
        self.cause = cause

    def user_text(self) -> str:
        from core.i18n import tr

        if self.kind == "unpublished":
            return tr("This tour video is not published yet.")
        if self.kind == "network":
            # Not core.user_errors' sentence about a host name and DNS
            # (UX review round 6): the user asked for a video, not a host.
            # The technical cause is in the log.
            return tr("The video could not be loaded from GitHub: this computer seems to "
                      "be offline, or GitHub cannot be reached. Try again later.")
        if self.kind == "checksum":
            return tr("The downloaded video does not match the checksum axross expects, so "
                      "it was not kept. Try again later.")
        if self.kind == "unsafe":
            return tr("The video folder {folder} is not private to you (another user owns it, "
                      "others may write to it, or it is a link), so no video is kept there.").format(
                folder=self.name)
        if self.kind == "disk":
            from core.user_errors import describe

            return describe(self.cause or self, self.name)
        return tr("The tour video could not be downloaded ({reason}).").format(reason=str(self))


def _from_update_error(exc: BaseException, name: str) -> VideoError:
    """A VideoError of the right kind for an error of core.self_update.fetch.

    self_update raises its UpdateError ``from None``: the HTTP or network
    error is still its ``__context__``."""
    import urllib.error

    inner = exc.__context__
    if isinstance(inner, urllib.error.HTTPError):
        if inner.code in (404, 410):
            return VideoError(str(exc), kind="unpublished", name=name)
        return VideoError(str(exc), kind="other", name=name)
    if isinstance(inner, urllib.error.URLError):
        reason = inner.reason
        return VideoError(str(exc), kind="network", name=name,
                          cause=reason if isinstance(reason, BaseException) else inner)
    if isinstance(inner, (OSError, TimeoutError)):
        return VideoError(str(exc), kind="network", name=name, cause=inner)
    if " answered HTTP 404" in str(exc) or " answered HTTP 410" in str(exc):
        return VideoError(str(exc), kind="unpublished", name=name)
    return VideoError(str(exc), kind="other", name=name)


@dataclass(frozen=True)
class Video:
    tour_id: str
    language: str
    name: str
    url: str
    size: int
    sha256: str


def _manifest(path: Path | None = None) -> dict:
    try:
        data = json.loads((path or MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        log.info("tour videos: no manifest: %s", exc)
        return {}
    return data if isinstance(data, dict) else {}


def _base(data: dict) -> str:
    from core import self_update

    tag = data.get("tag")
    if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", tag):
        return ""
    return f"{self_update.RELEASES_PREFIX}download/{tag}/"


def video_for(tour_id: str, language: str, *, manifest: Path | None = None) -> Video | None:
    """The video of *tour_id* in *language* (else English), or None."""
    data = _manifest(manifest)
    base = _base(data)
    videos = data.get("videos")
    if not base or not isinstance(videos, dict):
        return None
    for lang in dict.fromkeys((language.split("_")[0].lower(), "en")):
        entry = videos.get(f"{lang}/{tour_id}")
        if not isinstance(entry, dict):
            continue
        name, size, sha = entry.get("file"), entry.get("size"), entry.get("sha256")
        if (isinstance(name, str) and _NAME.fullmatch(name) and isinstance(size, int)
                and not isinstance(size, bool) and 0 < size <= MAX_VIDEO_BYTES
                and isinstance(sha, str) and _SHA256.fullmatch(sha)):
            return Video(tour_id, lang, name, base + name, size, sha)
        log.warning("tour videos: bad manifest entry %s/%s", lang, tour_id)
    return None


def has_videos(*, manifest: Path | None = None) -> bool:
    data = _manifest(manifest)
    return bool(_base(data)) and bool(data.get("videos"))


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    if not base or not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "axross" / "tour-videos"


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached(video: Video) -> Path | None:
    """The cached file of *video* when it is there and matches its pin -
    and its folder is private to this user (self_update.private_dir_problem):
    in a folder others may change, the checked file could be swapped
    before the player reads it."""
    from core import self_update

    if self_update.private_dir_problem(cache_dir(), create=False):
        return None
    path = cache_dir() / video.name
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size != video.size:
            return None
        if _sha256_of(path) != video.sha256:
            log.warning("tour videos: %s does not match its pin; fetched again", path)
            return None
    except OSError:
        return None
    return path


def fetch(video: Video, *, opener=None, progress: Callable[[int, int], None] | None = None,
          cancel: threading.Event | None = None) -> Path:
    """The checked local file of *video*: from the cache, or downloaded.

    Raises :class:`VideoError` (unreachable, too big, wrong checksum) or
    ``core.self_update.Cancelled`` when *cancel* was set."""
    from core import self_update

    found = cached(video)
    if found is not None:
        return found
    folder = cache_dir()
    try:
        folder.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise VideoError(f"Cannot create {folder}: {exc.strerror or exc}", kind="disk",
                         name=str(folder), cause=exc) from exc
    problem = self_update.private_dir_problem(folder)
    if problem:
        raise VideoError(problem, kind="unsafe", name=str(folder))
    digest = hashlib.sha256()
    fd, tmp_name = tempfile.mkstemp(prefix=".part-", suffix=".mp4", dir=folder)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out:
            def sink(chunk: bytes) -> None:
                digest.update(chunk)
                out.write(chunk)
            got = self_update.fetch(video.url, opener=opener or self_update.build_opener(),
                                    max_bytes=video.size, sink=sink, progress=progress,
                                    total=video.size, cancel=cancel)
        if got != video.size or digest.hexdigest() != video.sha256:
            raise VideoError(f"{video.name} does not match the checksum axross expects; "
                             "it was not kept.", kind="checksum", name=video.name)
        target = folder / video.name
        os.replace(tmp, target)
        return target
    except self_update.Cancelled:
        raise
    except self_update.UpdateError as exc:
        raise _from_update_error(exc, video.name) from exc
    except OSError as exc:
        raise VideoError(f"Cannot save {video.name}: {exc.strerror or exc}", kind="disk",
                         name=str(folder / video.name), cause=exc) from exc
    finally:
        tmp.unlink(missing_ok=True)


__all__ = ["MAX_VIDEO_BYTES", "Video", "VideoError", "cache_dir", "cached", "fetch",
           "has_videos", "video_for"]
