"""Bookmark manager — quick access to saved directories."""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# The module-level constants are kept so existing test fixtures that
# do ``BM.BOOKMARKS_FILE = Path("/tmp/x.json")`` to redirect the
# store keep working (BookmarkSchemaTests in test_hardening_regressions
# uses that pattern). Their import-time values are snapshotted in
# ``_DEFAULT_*`` below; the helpers prefer a live re-read from
# ``Path.home()`` ONLY when the public constant still equals its
# snapshot, so a HOME-patch (mock.patch.dict(os.environ, {"HOME":
# ...})) also takes effect — that's what BundledScriptsTests relies
# on.
CONFIG_DIR = Path.home() / ".config" / "axross"
BOOKMARKS_FILE = CONFIG_DIR / "bookmarks.json"
_DEFAULT_CONFIG_DIR = CONFIG_DIR
_DEFAULT_BOOKMARKS_FILE = BOOKMARKS_FILE


def _config_dir() -> Path:
    if CONFIG_DIR != _DEFAULT_CONFIG_DIR:
        return CONFIG_DIR
    return Path.home() / ".config" / "axross"


def _bookmarks_file() -> Path:
    if BOOKMARKS_FILE != _DEFAULT_BOOKMARKS_FILE:
        return BOOKMARKS_FILE
    return _config_dir() / "bookmarks.json"


def _sanitize_icon_name(value: object) -> str:
    """Coerce an icon_name read from JSON into a safe string.

    A hostile bookmarks.json (manually edited or cloud-sync
    compromise) could otherwise plant CR/LF / NUL in what the UI
    renders as a tooltip. Keep the allowlist tight:
    ``[A-Za-z0-9_-]`` only, bounded length, empty fallback.

    Does NOT check that the name exists in the icon provider —
    that decision belongs to the renderer (which substitutes the
    ``unknown`` placeholder for unknown names). Decoupling keeps
    this module free of a UI-layer import.
    """
    import re as _re
    if not isinstance(value, str):
        return "bookmark"
    cleaned = _re.sub(r"[^A-Za-z0-9_-]", "", value)[:64]
    return cleaned or "bookmark"


@dataclass
class Bookmark:
    """A saved directory bookmark.

    ``icon_name`` references an entry in :mod:`ui.icon_provider`'s
    bookmark icon set (``computer``, ``server``, ``code``, ``router``,
    etc.). Unknown names render as the ``unknown`` placeholder so a
    typo or a legacy bookmark entry never crashes the sidebar.
    """
    name: str
    path: str
    backend_name: str = "Local"  # "Local" or "user@host"
    profile_name: str = ""  # connection profile name (empty = local)
    icon_name: str = "bookmark"


class BookmarkManager:
    """Manages saved directory bookmarks."""

    def __init__(self):
        self._bookmarks: list[Bookmark] = []
        self.load()

    def load(self) -> None:
        bf = _bookmarks_file()
        if not bf.exists():
            return
        try:
            data = json.loads(bf.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise TypeError("Bookmarks JSON must be a list")
            self._bookmarks = [
                Bookmark(
                    name=item["name"],
                    path=item["path"],
                    backend_name=item.get("backend_name", "Local"),
                    profile_name=item.get("profile_name", ""),
                    icon_name=_sanitize_icon_name(
                        item.get("icon_name", "bookmark"),
                    ),
                )
                for item in data
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("name"), str)
                    and isinstance(item.get("path"), str)
                    and isinstance(item.get("backend_name", "Local"), str)
                    and isinstance(item.get("profile_name", ""), str)
                )
            ]
            log.info("Loaded %d bookmarks", len(self._bookmarks))
        except (json.JSONDecodeError, OSError, TypeError) as e:
            log.error("Failed to load bookmarks: %s", e)

    def save(self) -> None:
        bf = _bookmarks_file()
        target_dir = bf.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            data = [asdict(b) for b in self._bookmarks]
            try:
                os.chmod(target_dir, 0o700)
            except OSError:
                log.debug("Could not set permissions on %s", target_dir, exc_info=True)
            payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
            # mkstemp creates the file 0o600 from birth — no brief
            # world-readable window like NamedTemporaryFile.
            fd, temp_name = tempfile.mkstemp(
                dir=target_dir, prefix=".bookmarks.", suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    fd = -1
                    tmp.write(payload)
                os.replace(temp_name, bf)
                os.chmod(bf, 0o600)
            except BaseException:
                if fd != -1:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
                raise
        except OSError as e:
            log.error("Failed to save bookmarks: %s", e)

    def add(self, bookmark: Bookmark) -> None:
        # Avoid duplicates
        for existing in self._bookmarks:
            if existing.path == bookmark.path and existing.backend_name == bookmark.backend_name:
                log.debug("Skipping duplicate bookmark for %s on %s", bookmark.path, bookmark.backend_name)
                return
        self._bookmarks.append(bookmark)
        self.save()
        log.info("Added bookmark: %s -> %s", bookmark.name, bookmark.path)

    def remove(self, index: int) -> None:
        if 0 <= index < len(self._bookmarks):
            removed = self._bookmarks.pop(index)
            self.save()
            log.info("Removed bookmark: %s", removed.name)

    def all(self) -> list[Bookmark]:
        return list(self._bookmarks)

    def for_backend(self, backend_name: str) -> list[Bookmark]:
        return [b for b in self._bookmarks if b.backend_name == backend_name]

    def update(self, index: int, bookmark: Bookmark) -> None:
        """Replace the bookmark at *index* with the new one + persist.
        Used by the edit dialog to change name / path / icon in
        place without creating a duplicate entry.
        """
        if not (0 <= index < len(self._bookmarks)):
            raise IndexError(
                f"bookmark index {index} out of range "
                f"(have {len(self._bookmarks)})",
            )
        # Normalise icon_name the same way load() does.
        bookmark.icon_name = _sanitize_icon_name(bookmark.icon_name)
        self._bookmarks[index] = bookmark
        self.save()
        log.info("Updated bookmark #%d: %s → %s", index, bookmark.name,
                 bookmark.path)
