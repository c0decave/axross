"""Tags on files: coloured labels for any file on any backend (item 14).

A file is named as a bookmark names its folder: the backend's display name
("Local", "alice@nas"), the connection profile that reaches it again ("" for
local) and the path. Tags are defined once (name, ``#rrggbb``) and stored
with the files that carry them in ``~/.config/axross/tags.json`` - private,
written atomically. "Important" and "Review later" exist from the start.

The file is hand-editable: a bad definition or entry is skipped, an
unreadable file is moved aside (``tags.json.corrupt-<time>``) and the
defaults are used.
"""

from __future__ import annotations

import bisect
import contextlib
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

MAX_NAME = 40
#: A ceiling on tagged files, so a script cannot grow the file without end.
MAX_ITEMS = 100_000
DEFAULT_TAGS = (("Important", "#d9534f"), ("Review later", "#f0ad4e"))


def tags_file() -> Path:
    return Path.home() / ".config" / "axross" / "tags.json"


def _check_name(name: object) -> str:
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME:
        raise ValueError(f"a tag name is 1 to {MAX_NAME} characters")
    if any(ord(c) < 32 or c == "\x7f" for c in name):
        raise ValueError("a tag name may not hold control characters")
    return name.strip()


def _check_colour(colour: object) -> str:
    if not (isinstance(colour, str) and len(colour) == 7 and colour[0] == "#"
            and all(c in "0123456789abcdefABCDEF" for c in colour[1:])):
        raise ValueError(f"a tag colour is #rrggbb, not {colour!r}")
    return colour.lower()


@dataclass(frozen=True)
class Tag:
    name: str
    colour: str


@dataclass
class TaggedFile:
    backend_name: str
    profile_name: str
    path: str
    tags: list[str] = field(default_factory=list)
    added: float = 0.0


class TaggedIndex:
    """The tagged paths of one backend, sorted: ``has_tags_under`` answers
    as TagStore.has_tags_under does, by a set lookup and one bisect."""

    def __init__(self, paths) -> None:
        self._sorted = sorted(paths)
        self._set = set(self._sorted)

    def has_tags_under(self, path: str) -> bool:
        sep = TagStore._sep(path)
        base = path.rstrip(sep)
        if path in self._set or base in self._set:
            return True
        prefix = base + sep
        at = bisect.bisect_left(self._sorted, prefix)
        return at < len(self._sorted) and self._sorted[at].startswith(prefix)


class TagStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._tags: list[Tag] = [Tag(n, c) for n, c in DEFAULT_TAGS]
        self._items: dict[tuple[str, str], TaggedFile] = {}
        # batch(): nesting depth and whether a write was held back.
        self._batch_depth = 0
        self._batch_dirty = False
        self._load()

    # -- file ------------------------------------------------------------------------------

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            aside = self._path.with_name(f"{self._path.name}.corrupt-{int(time.time())}")
            log.warning("Tags: %s is unreadable (%s); kept as %s, starting from the defaults",
                        self._path, exc, aside.name)
            try:
                os.replace(self._path, aside)
            except OSError:
                pass
            return
        if not isinstance(data, dict):
            return
        tags = []
        for raw in data.get("tags") or []:
            try:
                tags.append(Tag(_check_name(raw["name"]), _check_colour(raw["color"])))
            except (TypeError, KeyError, ValueError):
                log.warning("Tags: a bad tag definition skipped: %r", raw)
        if isinstance(data.get("tags"), list):
            self._tags = tags
        known = {t.name for t in self._tags}
        for raw in data.get("items") or []:
            try:
                backend, path = raw["backend"], raw["path"]
                if not isinstance(backend, str) or not isinstance(path, str) or not path:
                    raise ValueError("backend and path are text")
                names = [n for n in raw.get("tags", []) if isinstance(n, str) and n in known]
                if names:
                    self._items[(backend, path)] = TaggedFile(
                        backend, str(raw.get("profile", "") or ""), path, names,
                        float(raw.get("added", 0) or 0))
            except (TypeError, KeyError, ValueError):
                log.warning("Tags: a bad entry skipped: %r", raw)

    @contextlib.contextmanager
    def batch(self):
        """Changes inside write tags.json once, at the end of the outermost
        batch - also when the block raises (what changed is kept)."""
        with self._lock:
            self._batch_depth += 1
            try:
                yield self
            finally:
                self._batch_depth -= 1
                if self._batch_depth == 0 and self._batch_dirty:
                    self._batch_dirty = False
                    self._write()

    def _save(self) -> None:
        if self._batch_depth:
            self._batch_dirty = True
            return
        self._write()

    def _write(self) -> None:
        payload = {
            "tags": [{"name": t.name, "color": t.colour} for t in self._tags],
            "items": [{"backend": e.backend_name, "profile": e.profile_name, "path": e.path,
                       "tags": e.tags, "added": e.added} for e in self._items.values()],
        }
        # A file name that is not valid UTF-8 comes as lone surrogates
        # ("caf\udce9.txt"), which UTF-8 cannot encode: they are written as
        # their JSON escape and read back as the same name. Everything else
        # stays as it is, so the file stays hand-editable.
        data = json.dumps(payload, indent=1, ensure_ascii=False).encode(
            "utf-8", errors="backslashreplace"
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tags.", dir=str(self._path.parent))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # -- definitions -----------------------------------------------------------------------

    def tags(self) -> list[Tag]:
        with self._lock:
            return list(self._tags)

    def colour(self, name: str) -> str | None:
        return next((t.colour for t in self.tags() if t.name == name), None)

    def _find(self, name: str) -> Tag | None:
        return next((t for t in self._tags if t.name.lower() == name.lower()), None)

    def define(self, name: str, colour: str) -> Tag:
        name, colour = _check_name(name), _check_colour(colour)
        with self._lock:
            if self._find(name) is not None:
                raise ValueError(f"the tag {name!r} exists already")
            tag = Tag(name, colour)
            self._tags.append(tag)
            self._save()
            return tag

    def recolour(self, name: str, colour: str) -> None:
        colour = _check_colour(colour)
        with self._lock:
            self._tags = [Tag(t.name, colour) if t.name == name else t for t in self._tags]
            self._save()

    def rename(self, old: str, new: str) -> None:
        new = _check_name(new)
        with self._lock:
            clash = self._find(new)
            if clash is not None and clash.name != old:
                raise ValueError(f"the tag {new!r} exists already")
            self._tags = [Tag(new, t.colour) if t.name == old else t for t in self._tags]
            for entry in self._items.values():
                entry.tags = [new if n == old else n for n in entry.tags]
            self._save()

    def delete(self, name: str) -> None:
        with self._lock:
            self._tags = [t for t in self._tags if t.name != name]
            for key in list(self._items):
                entry = self._items[key]
                entry.tags = [n for n in entry.tags if n != name]
                if not entry.tags:
                    del self._items[key]
            self._save()

    # -- files -----------------------------------------------------------------------------

    def tags_of(self, backend_name: str, path: str) -> list[str]:
        with self._lock:
            entry = self._items.get((backend_name, path))
            return list(entry.tags) if entry else []

    def tag(self, backend_name: str, profile_name: str, path: str, name: str) -> None:
        self.tag_many(backend_name, profile_name, (path,), name)

    def tag_many(self, backend_name: str, profile_name: str, paths, name: str) -> None:
        """Tag every one of *paths* with *name* and write the file once - the
        effect of :meth:`tag` per path (a selection of thousands rewrote the
        whole file per path). Raises KeyError for an unknown tag (nothing
        changed) and ValueError at :data:`MAX_ITEMS`, after writing the
        paths that fitted."""
        with self._lock:
            if not any(t.name == name for t in self._tags):
                raise KeyError(f"no tag {name!r}")
            changed = False
            try:
                for path in paths:
                    entry = self._items.get((backend_name, path))
                    if entry is None:
                        if len(self._items) >= MAX_ITEMS:
                            raise ValueError(f"more than {MAX_ITEMS} tagged files")
                        entry = TaggedFile(backend_name, profile_name, path, [], time.time())
                        self._items[(backend_name, path)] = entry
                    if profile_name:
                        entry.profile_name = profile_name
                    if name not in entry.tags:
                        entry.tags.append(name)
                        changed = True
            finally:
                if changed:
                    self._save()

    def untag(self, backend_name: str, path: str, name: str) -> None:
        self.untag_many(backend_name, (path,), name)

    def untag_many(self, backend_name: str, paths, name: str) -> None:
        """Take *name* off every one of *paths* and write the file once (not
        at all when none carried it) - the effect of :meth:`untag` per path."""
        with self._lock:
            changed = False
            for path in paths:
                entry = self._items.get((backend_name, path))
                if entry is None or name not in entry.tags:
                    continue
                entry.tags.remove(name)
                if not entry.tags:
                    del self._items[(backend_name, path)]
                changed = True
            if changed:
                self._save()

    def items_with(self, name: str) -> list[TaggedFile]:
        with self._lock:
            return sorted((e for e in self._items.values() if name in e.tags),
                          key=lambda e: (e.backend_name, e.path))

    @staticmethod
    def _sep(path: str) -> str:
        """``\\`` for a Windows path (``\\`` and no ``/``, as in
        ``MainWindow._go_to_tagged_file``); elsewhere ``\\`` is part of a name."""
        return "\\" if "\\" in path and "/" not in path else "/"

    def rename_path(self, backend_name: str, old: str, new: str) -> None:
        """Tags follow a file or folder that was renamed."""
        self.move_path(backend_name, old, new)

    def move_path(self, backend_name: str, old: str, new: str, *, dest_backend: str | None = None,
                  dest_profile: str | None = None) -> None:
        """Tags follow a file or folder - and everything below it - to *new*,
        on *dest_backend* (default: the same) reached through *dest_profile*."""
        sep, new_sep = self._sep(old), self._sep(new)
        base = old.rstrip(sep)
        prefix = base + sep
        target = backend_name if dest_backend is None else dest_backend
        with self._lock:
            moved = False
            for key in list(self._items):
                b, path = key
                if b != backend_name or not (path == old or path.startswith(prefix)):
                    continue
                entry = self._items.pop(key)
                if path in (old, base):
                    entry.path = new
                else:
                    entry.path = new.rstrip(new_sep) + path[len(base):].replace(sep, new_sep)
                entry.backend_name = target
                if dest_profile is not None:
                    entry.profile_name = dest_profile
                existing = self._items.get((target, entry.path))
                if existing is not None:  # the destination had tags of its own
                    entry.tags = existing.tags + [n for n in entry.tags if n not in existing.tags]
                self._items[(target, entry.path)] = entry
                moved = True
            if moved:
                self._save()

    def tagged_index(self, backend_name: str) -> TaggedIndex:
        """A snapshot of *backend_name*'s tagged paths that answers
        has_tags_under() without a scan per question."""
        with self._lock:
            return TaggedIndex(p for b, p in self._items if b == backend_name)

    def has_tags_under(self, backend_name: str, path: str) -> bool:
        """*path* or anything below it carries a tag - a cheap check before
        tracking a move."""
        sep = self._sep(path)
        base = path.rstrip(sep)
        prefix = base + sep
        with self._lock:
            return any(b == backend_name and (p in (path, base) or p.startswith(prefix))
                       for b, p in self._items)


_STORE: TagStore | None = None
_STORE_LOCK = threading.Lock()


def store() -> TagStore:
    """The process-wide tag store (read once)."""
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = TagStore(tags_file())
        return _STORE


def reset_cache() -> None:
    global _STORE
    with _STORE_LOCK:
        _STORE = None
