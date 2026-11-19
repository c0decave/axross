"""Bookmark manager — quick access to saved directories."""

from __future__ import annotations

import dataclasses
import json
import logging
import math
import os
import re
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.secure_storage import keep_unreadable_copy, locked_store_update

log = logging.getLogger(__name__)

# The module-level constants are kept so existing test fixtures that
# do ``BM.BOOKMARKS_FILE = Path("/tmp/x.json")`` to redirect the
# store keep working (tests/test_bookmark_groups.py and
# tests/test_bookmark_dialogs.py use that pattern). Their import-time values are snapshotted in
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


_KEEP = object()


def _set_aside(path: Path, raw: bytes) -> bool:
    """Rename the unreadable store file *path* (holding *raw*) to a unique
    sibling, best effort - only while it still holds *raw*: another
    window's save in the meantime is never renamed away. Returns False
    when the file was replaced since it was read."""
    from core.json_store import set_aside_if_unchanged

    try:
        return set_aside_if_unchanged(path, raw) is not None or not path.exists()
    except OSError as exc:
        log.error("Could not set unreadable %s aside: %s", path, exc)
        return True


def _fsync_dir(folder: Path) -> None:
    """Make a rename in *folder* durable, best effort (not on Windows)."""
    try:
        fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


_HEX_COLOR = re.compile(r"#[0-9a-fA-F]{6}")
# Hostile files could nest groups until the interpreter's recursion limit
# is hit; real trees are a handful of levels deep.
_MAX_DEPTH = 16
_GROUP_ICON_DEFAULT = "folder"


def _sanitize_icon_name(value: object, default: str = "bookmark") -> str:
    """Coerce an icon_name read from JSON into a safe string.

    A hostile bookmarks.json (manually edited or cloud-sync
    compromise) could otherwise plant CR/LF / NUL in what the UI
    renders as a tooltip. Keep the allowlist tight:
    ``[A-Za-z0-9_-]`` only, bounded length, *default* as fallback.

    Does NOT check that the name exists in the icon provider —
    that decision belongs to the renderer (which substitutes the
    ``unknown`` placeholder for unknown names). Decoupling keeps
    this module free of a UI-layer import.
    """
    if not isinstance(value, str):
        return default
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "", value)[:64]
    return cleaned or default


def _sanitize_created(value: object) -> float:
    """A creation time read from JSON: seconds since the epoch, or 0.0
    (undated - a bookmark from before the field existed, or garbage)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    value = float(value)
    return value if math.isfinite(value) and value > 0 else 0.0


#: What a bookmark opens: a folder in a pane, or a terminal on a host.
KIND_FOLDER = "folder"
KIND_TERMINAL = "terminal"
KINDS: tuple[str, ...] = (KIND_FOLDER, KIND_TERMINAL)
#: The profile name of a terminal bookmark for a local shell.
LOCAL_SHELL = "local"

#: The orders :meth:`BookmarkManager.sort_children` knows.
SORT_KEYS: tuple[str, ...] = ("name", "path", "name_path", "age")
#: The sort keys whose reverse order also reverses the groups (by name).
_GROUP_REVERSING_KEYS: frozenset[str] = frozenset({"name", "name_path"})


def _sanitize_color(value: object) -> str:
    """``#rrggbb`` or empty (= the icon's own colour). Anything else is
    dropped: the value ends up inside an SVG source string."""
    if isinstance(value, str) and _HEX_COLOR.fullmatch(value):
        return value.lower()
    return ""


@dataclass
class Bookmark:
    """A saved directory bookmark.

    ``icon_name`` references an entry in :mod:`ui.icon_provider`'s
    bookmark icon set (``computer``, ``server``, ``code``, ``router``,
    etc.). Unknown names render as the ``unknown`` placeholder so a
    typo or a legacy bookmark entry never crashes the sidebar.
    ``color`` is an optional ``#rrggbb`` that recolours the icon so
    related bookmarks are recognisable at a glance.
    ``created`` is when it was added (seconds since the epoch); 0.0 means
    undated - a bookmark saved before the field existed.

    ``kind`` is :data:`KIND_FOLDER` (open *path* in a pane) or
    :data:`KIND_TERMINAL`: open a shell through the connection profile
    *profile_name* (:data:`LOCAL_SHELL` for a local one) and change into
    *path* when it is not empty. A terminal bookmark holds no credential;
    the profile keeps those.

    A terminal bookmark with a *host* needs no profile: it connects over SSH
    to *host*:*port* as *username* (agent, *key_file* or a password asked
    for at the click - see :func:`host_bookmark_profile`). It stores no
    password or passphrase either. ``backend_name`` and ``profile_name``
    are then its address (:func:`host_address`); the profile name is never
    looked up, it is set so that an older axross, which turns a terminal
    bookmark without a profile into a local shell, reports a missing
    profile instead of running the host's commands here. The four host
    fields are written to the file only for such a bookmark.

    A *kind* this version does not know (a newer version's) opens as a
    folder but is kept as it is, and ``extra`` holds the fields of the file
    this version does not know: both are written back verbatim, so an edit
    here does not change what a newer axross made.
    """

    name: str
    path: str
    backend_name: str = "Local"  # "Local" or "user@host"
    profile_name: str = ""  # connection profile name (empty = local)
    icon_name: str = "bookmark"
    color: str = ""
    #: A saved Find Files search (:func:`core.file_search.saved_search_to_dict`).
    #: Non-empty makes this bookmark a Smart Folder: a click runs the search
    #: again, ``path`` is a unique ``search:<id>`` key and ``backend_name``
    #: :data:`SMART_FOLDER_BACKEND`.
    search: dict = field(default_factory=dict)
    created: float = 0.0
    kind: str = KIND_FOLDER
    #: A terminal bookmark on a bare host (no profile): see the class doc.
    host: str = ""
    port: int = 22
    username: str = ""
    key_file: str = ""
    #: Stored fields this version does not know, kept for the next save.
    extra: dict = field(default_factory=dict, repr=False)

    @property
    def is_terminal(self) -> bool:
        return self.kind == KIND_TERMINAL

    @property
    def is_foreign_kind(self) -> bool:
        """A kind a newer version made: opened as a folder, saved as it is."""
        return self.kind not in KINDS

    @property
    def is_host_terminal(self) -> bool:
        """A terminal bookmark that connects to its own host, no profile."""
        return self.kind == KIND_TERMINAL and bool(self.host)

    @property
    def is_smart_folder(self) -> bool:
        return bool(self.search)


#: ``backend_name`` of every Smart Folder.
SMART_FOLDER_BACKEND = "Smart Folder"
#: A stored search larger than this (as JSON) is dropped on load.
MAX_SEARCH_JSON_BYTES = 64 * 1024
#: A Smart Folder search nested deeper than this is damaged: it passed
#: json.loads and the size check, and every save then raised RecursionError.
MAX_SEARCH_DEPTH = 32


def _nesting(value, limit: int) -> int:
    """How deep *value* (parsed JSON) is nested, counted up to *limit* + 1."""
    deepest = 0
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return depth
        deepest = max(deepest, depth)
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        stack.extend((child, depth + 1) for child in children
                     if isinstance(child, (dict, list)))
    return deepest


def new_smart_folder(name: str, search: dict, icon_name: str = "find-index") -> Bookmark:
    """A Smart Folder bookmark for *search* (a saved-search mapping)."""
    return Bookmark(
        name=name,
        path=f"search:{uuid.uuid4().hex[:12]}",
        backend_name=SMART_FOLDER_BACKEND,
        icon_name=icon_name,
        search=dict(search),
    )


#: The fields only a host terminal bookmark writes (see :func:`bookmark_dict`).
HOST_FIELDS: tuple[str, ...] = ("host", "port", "username", "key_file")
DEFAULT_SSH_PORT = 22
#: Marks the connection profile :func:`host_bookmark_profile` builds: it is
#: no saved profile and must never be stored or looked up by name.
_HOST_PROFILE_MARK = "_axross_host_bookmark"
_HOST_CHARS = re.compile(r"[A-Za-z0-9._:%\[\]-]+")


def _has_control(text: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def _sanitize_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        return DEFAULT_SSH_PORT
    return value


def host_address(host: str, port: int, username: str = "") -> str:
    """``user@host:port`` (an IPv6 address in brackets) - the label and the
    ``backend_name`` of a host terminal bookmark."""
    shown = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{username}@{shown}:{port}" if username else f"{shown}:{port}"


def host_bookmark_problem(bookmark: Bookmark) -> str | None:
    """Why the host terminal *bookmark* cannot connect, or ``None``. Checked
    before anything is sent: a name with blanks or control characters, or one
    that starts like a command-line option, is no host."""
    host = bookmark.host
    if _has_control(host) or _has_control(bookmark.username) or _has_control(bookmark.key_file):
        return "The host, user or key file contains control characters."
    if not host or host.startswith("-") or not _HOST_CHARS.fullmatch(host):
        return f"'{host}' is not a host name or IP address."
    if isinstance(bookmark.port, bool) or not isinstance(bookmark.port, int) or not (
        0 < bookmark.port < 65536
    ):
        return f"The port {bookmark.port!r} is not between 1 and 65535."
    if any(c.isspace() or c == "@" for c in bookmark.username):
        return f"'{bookmark.username}' is not a user name."
    return None


def host_bookmark_profile(bookmark: Bookmark, auth_type: str | None = None):
    """The connection profile a click on the host terminal *bookmark* uses:
    SFTP to its host, never saved (``store_password`` off, so no keyring
    read or write), the application's proxy setting. *auth_type* defaults to
    ``key`` with a key file, else ``agent`` when an ssh-agent is running
    (``SSH_AUTH_SOCK``), else ``password``. An empty user is the local one,
    as ``ssh`` does it."""
    import getpass

    from core.profiles import ConnectionProfile

    if auth_type is None:
        if bookmark.key_file:
            auth_type = "key"
        elif os.environ.get("SSH_AUTH_SOCK"):
            auth_type = "agent"
        else:
            auth_type = "password"
    username = bookmark.username
    if not username:
        try:
            username = getpass.getuser()
        except Exception:  # noqa: BLE001 - no passwd entry: leave it empty
            username = ""
    profile = ConnectionProfile(
        name=host_address(bookmark.host, bookmark.port, username),
        protocol="sftp",
        host=bookmark.host.strip("[]"),
        port=bookmark.port,
        username=username,
        auth_type=auth_type,
        key_file=bookmark.key_file,
        store_password=False,
        proxy_mode="default",
    )
    return as_host_profile(profile)


def as_host_profile(profile):
    """Mark *profile* as one :func:`host_bookmark_profile` built (a copy made
    with ``dataclasses.replace`` loses the mark) and return it."""
    setattr(profile, _HOST_PROFILE_MARK, True)
    return profile


def is_host_profile(profile: object) -> bool:
    """True for a profile :func:`host_bookmark_profile` built."""
    return bool(getattr(profile, _HOST_PROFILE_MARK, False))


def bookmark_dict(bookmark: Bookmark) -> dict:
    """*bookmark* as stored: every field, the host fields only for a host
    terminal bookmark, so files of other bookmarks keep their shape, and
    the fields this version does not know (``extra``) as they were read."""
    data = asdict(bookmark)
    extra = data.pop("extra", None) or {}
    if not bookmark.is_host_terminal:
        for name in HOST_FIELDS:
            data.pop(name, None)
    for name, value in extra.items():
        data.setdefault(name, value)
    return data


#: A kind kept as it is when this version does not know it (a newer
#: version's); anything else in ``kind`` is damage.
_FOREIGN_KIND = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}")
#: Fields this version does not know are kept up to this size (as JSON) per
#: entry and this depth per value; deeper ones raised RecursionError at the
#: save (see MAX_SEARCH_DEPTH), larger ones are no bookmark data.
MAX_EXTRA_JSON_BYTES = 64 * 1024
MAX_EXTRA_DEPTH = 32
#: What a stored bookmark's keys mean to this version (the host fields only
#: for a terminal bookmark, see _load_nodes).
_MARK_KEYS = frozenset(
    {"name", "path", "backend_name", "profile_name", "icon_name", "color", "search",
     "created", "kind"}
)
_GROUP_KEYS = frozenset({"type", "name", "icon_name", "color", "expanded", "children"})


def _extra_fields(item: dict, known: frozenset | set, lost: list) -> dict:
    """The fields of the stored *item* outside *known*, kept verbatim; one
    nested too deeply or past the size limit is dropped and noted in *lost*."""
    extra: dict = {}
    total = 0
    for name, value in item.items():
        if name in known:
            continue
        if isinstance(value, (dict, list)) and _nesting(value, MAX_EXTRA_DEPTH) > MAX_EXTRA_DEPTH:
            lost.append(f"field {name!r} nested too deeply")
            continue
        try:
            total += len(name) + len(json.dumps(value))
        except (TypeError, ValueError, RecursionError):
            total = MAX_EXTRA_JSON_BYTES + 1
        if total > MAX_EXTRA_JSON_BYTES:
            lost.append(f"field {name!r} too large")
            continue
        extra[name] = value
    return extra


def _loaded_search(item: dict) -> dict | None:
    """The ``search`` of a stored bookmark: ``{}`` for a plain bookmark, the
    mapping for a Smart Folder, ``None`` when it is damaged (not a mapping,
    or absurdly large) - the entry is then dropped like any malformed one.
    Whether the search itself is valid is checked when it runs."""
    search = item.get("search", {})
    if not isinstance(search, dict):
        log.warning("Dropping bookmark %r: its search is not a mapping", item.get("name"))
        return None
    if search and _nesting(search, MAX_SEARCH_DEPTH) > MAX_SEARCH_DEPTH:
        log.warning("Dropping bookmark %r: its search is nested too deeply", item.get("name"))
        return None
    if search:
        try:
            size = len(json.dumps(search))
        except (TypeError, ValueError):
            size = MAX_SEARCH_JSON_BYTES + 1
        if size > MAX_SEARCH_JSON_BYTES:
            log.warning("Dropping bookmark %r: its search is too large", item.get("name"))
            return None
    return search


@dataclass(eq=False)
class BookmarkGroup:
    """A folder of bookmarks (and further groups) in the sidebar.

    Compared by identity: two groups with the same name are different
    folders, and the manager locates nodes by identity.
    """

    name: str
    icon_name: str = _GROUP_ICON_DEFAULT
    color: str = ""
    expanded: bool = True
    children: list = field(default_factory=list)
    #: Stored fields this version does not know (see Bookmark.extra).
    extra: dict = field(default_factory=dict, repr=False)


Node = Bookmark | BookmarkGroup


def _normalise_kind(bookmark: Bookmark, keep_foreign: bool = False) -> None:
    """The same rules load() applies: a known kind (with *keep_foreign* a
    newer version's kind read from the file stays); a terminal bookmark on
    a host has no profile and its address as backend name; any other
    terminal bookmark without a profile is a local shell."""
    if bookmark.kind not in KINDS and not (
        keep_foreign and isinstance(bookmark.kind, str) and _FOREIGN_KIND.fullmatch(bookmark.kind)
    ):
        bookmark.kind = KIND_FOLDER
    if not isinstance(bookmark.extra, dict):
        bookmark.extra = {}
    for name in ("host", "username", "key_file"):
        if not isinstance(getattr(bookmark, name), str):
            setattr(bookmark, name, "")
    bookmark.port = _sanitize_port(bookmark.port)
    if bookmark.is_host_terminal:
        # Never empty: see the Bookmark doc (an older version's local shell).
        bookmark.backend_name = host_address(bookmark.host, bookmark.port, bookmark.username)
        bookmark.profile_name = bookmark.backend_name
    elif bookmark.kind == KIND_TERMINAL and not bookmark.profile_name:
        bookmark.profile_name = LOCAL_SHELL


def _index_by_identity(nodes: list, node: object) -> int:
    for i, candidate in enumerate(nodes):
        if candidate is node:
            return i
    raise KeyError(node)


class BookmarkManager:
    """Manages saved directory bookmarks, organised as a tree of groups.

    ``all()`` / ``remove(index)`` / ``update(index, ...)`` keep their
    flat, index-based meaning (bookmarks only, in tree order), so
    scripts written against the old flat list keep working.
    """

    def __init__(self):
        self._root: list[Node] = []
        # The tree as this manager last read or wrote the file (dumped
        # form). save() compares the file against it to tell what another
        # writer (a script, a second window) changed in the meantime.
        self._base: list[dict] = []
        #: A failed save raises (after it is reported) - for a script, which
        #: must not be told a change happened that is gone at the next start.
        self.raise_save_errors = False
        self.load()

    # ------------------------------------------------------------------
    # Tree access
    # ------------------------------------------------------------------
    @property
    def _bookmarks(self) -> list[Bookmark]:
        """Flat bookmarks in tree order (read-only view)."""
        return self.all()

    def tree(self) -> list[Node]:
        """Top-level nodes. The nodes are live objects; mutate them only
        through the manager so the change is persisted."""
        return list(self._root)

    def all(self) -> list[Bookmark]:
        out: list[Bookmark] = []

        def walk(nodes: list) -> None:
            for node in nodes:
                if isinstance(node, BookmarkGroup):
                    walk(node.children)
                else:
                    out.append(node)

        walk(self._root)
        return out

    def groups(self) -> list[tuple[int, BookmarkGroup]]:
        """Every group as ``(depth, group)`` in display order."""
        out: list[tuple[int, BookmarkGroup]] = []

        def walk(nodes: list, depth: int) -> None:
            for node in nodes:
                if isinstance(node, BookmarkGroup):
                    out.append((depth, node))
                    walk(node.children, depth + 1)

        walk(self._root, 0)
        return out

    def find(self, path: str, backend_name: str, kind: str = KIND_FOLDER) -> Bookmark | None:
        """The *kind* bookmark for *path* on *backend_name* anywhere in the
        tree (the live node), or ``None``. This is the duplicate rule
        :meth:`add` applies: a folder and a terminal bookmark on the same
        path are two bookmarks."""
        for existing in self.all():
            if (
                existing.path == path
                and existing.backend_name == backend_name
                and existing.kind == kind
            ):
                return existing
        return None

    def for_backend(self, backend_name: str) -> list[Bookmark]:
        return [b for b in self.all() if b.backend_name == backend_name]

    def _siblings(self, parent: BookmarkGroup | None) -> list:
        return self._root if parent is None else parent.children

    def parent_of(self, node: Node) -> BookmarkGroup | None:
        """The group holding *node*, ``None`` for the top level.
        Raises ``KeyError`` when the node is not in the tree."""
        try:
            _index_by_identity(self._root, node)
            return None
        except KeyError:
            pass
        for _depth, group in self.groups():
            try:
                _index_by_identity(group.children, node)
                return group
            except KeyError:
                continue
        raise KeyError(node)

    @staticmethod
    def _contains(group: BookmarkGroup, node: object) -> bool:
        """True when *node* is *group* or lies anywhere below it."""
        if group is node:
            return True
        return any(
            isinstance(child, BookmarkGroup) and BookmarkManager._contains(child, node)
            for child in group.children
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def load(self, _attempts: int = 3) -> None:
        bf = _bookmarks_file()
        if not bf.exists():
            return
        try:
            raw = bf.read_bytes()
        except OSError as e:
            # Not readable now (permissions, an I/O error of a network
            # home): the file stays where it is - set aside, the user lost
            # every bookmark - and a save merges with it once it can be
            # read again, or refuses (_read_disk).
            log.error("Bookmarks cannot be read now, nothing is shown or written: %s", e)
            return
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, list):
                raise TypeError("Bookmarks JSON must be a list")
            root = self._load_nodes(data, 0)
            base = self._dump_nodes(root)
            self._root, self._base = root, base
            log.info("Loaded %d bookmarks", len(self.all()))
        except (ValueError, TypeError, RecursionError) as e:
            # ValueError covers JSONDecodeError and UnicodeDecodeError.
            log.error("Failed to load bookmarks: %s", e)
            # The next save writes the (now empty) tree to this path; move
            # the unreadable file out of the way so it cannot be destroyed.
            if not _set_aside(bf, raw) and _attempts > 1:
                self.load(_attempts - 1)  # another window saved meanwhile

    @classmethod
    def _read_disk(cls, bf: Path) -> tuple[list[dict] | None, bool]:
        """The file's tree in dumped form; ``[]`` when there is no file,
        ``None`` when it is no bookmark file (it is then set aside); an
        OSError when it cannot be read now. The flag tells whether the
        file holds entries that cannot be kept (see _load_nodes)."""
        try:
            raw = bf.read_bytes()
        except FileNotFoundError:
            return [], False
        except OSError as e:
            # Raised: the save must not write this manager's tree over a
            # file it cannot read (save() reports it as a failed save).
            log.error("Failed to re-read bookmarks: %s", e)
            raise
        try:
            # Decoded here, not by read_text(): a file another writer left
            # in another encoding is set aside like one that is no JSON.
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, list):
                raise TypeError("Bookmarks JSON must be a list")
        except (ValueError, TypeError, RecursionError) as e:
            log.error("Failed to re-read bookmarks: %s", e)
            _set_aside(bf, raw)
            return None, False
        lost: list = []
        dumped = cls._dump_nodes(cls._load_nodes(data, 0, lost))
        if lost:
            log.warning("Bookmarks: %d entries or fields cannot be kept (%s)", len(lost),
                        "; ".join(lost[:5]))
        return dumped, bool(lost)

    @staticmethod
    def _flatten(dumped: list[dict]) -> tuple[dict, dict]:
        """Bookmarks of a dumped tree keyed by ``(kind, backend_name, path)`` as
        ``key -> (group path, fields)``, plus its groups as
        ``group path -> fields``. A group path is the tuple of group names."""
        marks: dict[tuple[str, str, str], tuple[tuple[str, ...], dict]] = {}
        groups: dict[tuple[str, ...], dict] = {}

        def walk(nodes: list[dict], gpath: tuple[str, ...]) -> None:
            for item in nodes:
                if item.get("type") == "group":
                    sub = gpath + (item["name"],)
                    groups.setdefault(sub, item)
                    walk(item["children"], sub)
                else:
                    key = (item.get("kind", KIND_FOLDER), item["backend_name"], item["path"])
                    marks.setdefault(key, (gpath, item))

        walk(dumped, ())
        return marks, groups

    def _group_at(self, gpath: tuple[str, ...], fields: dict[tuple[str, ...], dict],
                  orders: dict[tuple[str, ...], list[tuple]] | None = None):
        """The group at name path *gpath*, created (with the attributes in
        *fields*) where it is missing - in the place *orders* (the other
        writer's, see :meth:`_orders`) gives it, else at the end. ``()`` is
        the top level (``None``)."""
        parent: BookmarkGroup | None = None
        for depth in range(len(gpath)):
            name = gpath[depth]
            found = next(
                (
                    n
                    for n in self._siblings(parent)
                    if isinstance(n, BookmarkGroup) and n.name == name
                ),
                None,
            )
            if found is None:
                attrs = fields.get(gpath[: depth + 1], {})
                found = BookmarkGroup(
                    name=name,
                    icon_name=attrs.get("icon_name", _GROUP_ICON_DEFAULT),
                    color=attrs.get("color", ""),
                    expanded=attrs.get("expanded", True),
                    extra=_extra_fields(attrs, _GROUP_KEYS, []),
                )
                if orders is None:
                    self._siblings(parent).append(found)
                else:
                    self._place(parent, found, orders.get(gpath[:depth], []))
            parent = found
        return parent

    def _merge_from_disk(self, bf: Path) -> None:
        """Fold in what another writer changed in the file since this
        manager last read or wrote it - a three-way merge of the file
        (theirs), the tree as last read or written (base) and this tree
        (mine). What this manager did not change takes their version:

        * bookmarks, matched by ``(kind, backend_name, path)``: one they
          added is added, one they removed is removed, one they edited
          takes the edit, one they moved to another group moves there;
        * groups, matched by their name path: one they added is added (in
          its place), one they removed goes once it is empty here, one
          they recoloured takes the colours; a rename is a new group the
          bookmarks moved into, the old one then empty and removed;
        * the order of a group's entries, unless it was changed here.

        What this manager changed wins, and removals made here are never
        undone.

        Returns whether the file holds entries or fields that cannot be
        kept: save() keeps a copy of it before it writes."""
        disk, lossy = self._read_disk(bf)
        if disk is None or disk == self._base:
            return lossy
        mine_dump = self._dump_nodes(self._root)
        base_marks, base_groups = self._flatten(self._base)
        disk_marks, disk_groups = self._flatten(disk)
        mine_marks, mine_groups = self._flatten(mine_dump)
        base_order, disk_order = self._orders(self._base), self._orders(disk)
        mine_order = self._orders(mine_dump)

        for mark in self.all():
            key = (mark.kind, mark.backend_name, mark.path)
            if key not in base_marks:
                continue  # added here
            base_path, base_fields = base_marks[key]
            mine_path = mine_marks[key][0] if key in mine_marks else base_path
            edited = bookmark_dict(mark) != base_fields
            moved = mine_path != base_path
            if key not in disk_marks:
                if not edited and not moved:
                    siblings = self._siblings(self.parent_of(mark))
                    siblings.pop(_index_by_identity(siblings, mark))
                continue
            disk_path, disk_fields = disk_marks[key]
            if not edited and disk_fields != base_fields:
                theirs = self._node_from_dump(disk_fields)
                for spec in dataclasses.fields(Bookmark):
                    setattr(mark, spec.name, getattr(theirs, spec.name))
            if not moved and disk_path != base_path:
                siblings = self._siblings(self.parent_of(mark))
                siblings.pop(_index_by_identity(siblings, mark))
                self._place(self._group_at(disk_path, disk_groups, disk_order), mark,
                            disk_order.get(disk_path, []))

        # Groups they added, each in its place among its siblings.
        for gpath in disk_groups:
            if gpath not in base_groups:
                self._group_at(gpath, disk_groups, disk_order)
        # Group attributes they changed and this manager did not.
        for gpath, fields in disk_groups.items():
            base = base_groups.get(gpath)
            mine = mine_groups.get(gpath)
            if base is None or mine is None or self._group_attrs(mine) != self._group_attrs(base):
                continue
            if self._group_attrs(fields) != self._group_attrs(base):
                group = self._find_group(gpath)
                if group is not None:
                    group.icon_name = fields.get("icon_name", _GROUP_ICON_DEFAULT)
                    group.color = fields.get("color", "")
                    group.expanded = fields.get("expanded", True)
                    group.extra = _extra_fields(fields, _GROUP_KEYS, [])

        known = {(m.kind, m.backend_name, m.path) for m in self.all()}
        for key, (gpath, fields) in disk_marks.items():
            if key in base_marks or key in known:
                continue
            self._place(self._group_at(gpath, disk_groups, disk_order),
                        self._node_from_dump(fields), disk_order.get(gpath, []))
            known.add(key)

        # Groups they removed: gone here too once empty (what is still in
        # one was added or changed here), unless changed here. Deepest first.
        for gpath in sorted(base_groups, key=len, reverse=True):
            if gpath in disk_groups or gpath not in mine_groups:
                continue
            if self._group_attrs(mine_groups[gpath]) != self._group_attrs(base_groups[gpath]):
                continue
            group = self._find_group(gpath)
            if group is not None and not group.children:
                siblings = self._siblings(self._find_group(gpath[:-1]) if gpath[:-1] else None)
                siblings.pop(_index_by_identity(siblings, group))

        # The order they gave a group's entries, where it was not changed here.
        for gpath, order in disk_order.items():
            if mine_order.get(gpath) != base_order.get(gpath):
                continue
            if gpath and self._find_group(gpath) is None:
                continue
            rank = {ident: i for i, ident in enumerate(order)}
            siblings = self._siblings(self._find_group(gpath) if gpath else None)
            siblings.sort(key=lambda node: rank.get(self._identity(node), len(rank)))
        return lossy

    @staticmethod
    def _group_attrs(fields: dict) -> tuple:
        extra = {k: v for k, v in fields.items() if k not in _GROUP_KEYS}
        return (fields.get("icon_name"), fields.get("color"), fields.get("expanded", True),
                json.dumps(extra, sort_keys=True))

    @staticmethod
    def _identity(node) -> tuple:
        """A node as the merge tells it apart from its siblings."""
        if isinstance(node, dict):
            if node.get("type") == "group":
                return ("group", node.get("name"))
            return ("mark", node.get("kind", KIND_FOLDER), node.get("backend_name"),
                    node.get("path"))
        if isinstance(node, BookmarkGroup):
            return ("group", node.name)
        return ("mark", node.kind, node.backend_name, node.path)

    @classmethod
    def _orders(cls, dumped: list[dict]) -> dict[tuple[str, ...], list[tuple]]:
        """``group path -> the identities of its entries, in order`` of a
        dumped tree; ``()`` is the top level."""
        orders: dict[tuple[str, ...], list[tuple]] = {}

        def walk(nodes: list[dict], gpath: tuple[str, ...]) -> None:
            if gpath in orders:
                return  # a second group of that name: the first one counts
            orders[gpath] = [cls._identity(item) for item in nodes]
            for item in nodes:
                if item.get("type") == "group":
                    walk(item["children"], gpath + (item["name"],))

        walk(dumped, ())
        return orders

    def _find_group(self, gpath: tuple[str, ...]) -> BookmarkGroup | None:
        parent: BookmarkGroup | None = None
        for name in gpath:
            parent = next(
                (n for n in self._siblings(parent) if isinstance(n, BookmarkGroup) and n.name == name),
                None,
            )
            if parent is None:
                return None
        return parent

    def _place(self, parent: BookmarkGroup | None, node, order: list[tuple]) -> None:
        """Put *node* into *parent* where *order* (the other writer's) has
        it: after the nearest entry before it that is here too."""
        siblings = self._siblings(parent)
        ident = self._identity(node)
        if ident not in order:
            siblings.append(node)
            return
        present = {self._identity(n): i for i, n in enumerate(siblings)}
        for before in reversed(order[: order.index(ident)]):
            if before in present:
                siblings.insert(present[before] + 1, node)
                return
        siblings.insert(0, node)

    @classmethod
    def _load_nodes(cls, data: list, depth: int, lost: list | None = None) -> list[Node]:
        """The nodes of the stored list *data* at *depth*. What cannot be
        taken in (an entry that is no mapping or is damaged, a group nested
        deeper than _MAX_DEPTH, a field too deep or too large) is left out
        and noted in *lost*: save() then keeps a copy of the file first."""
        if lost is None:
            lost = []
        nodes: list[Node] = []
        for item in data:
            if not isinstance(item, dict):
                lost.append("an entry that is no mapping")
                continue
            if item.get("type") == "group":
                name = item.get("name")
                children = item.get("children", [])
                if not isinstance(name, str):
                    lost.append("a group without a name")
                    continue
                if depth >= _MAX_DEPTH:
                    lost.append(f"group {name!r} nested too deeply")
                    continue
                if not isinstance(children, list):
                    lost.append(f"the entries of group {name!r}")
                    children = []
                nodes.append(
                    BookmarkGroup(
                        name=name,
                        icon_name=_sanitize_icon_name(item.get("icon_name"), _GROUP_ICON_DEFAULT),
                        color=_sanitize_color(item.get("color")),
                        expanded=item.get("expanded", True) is not False,
                        children=cls._load_nodes(children, depth + 1, lost),
                        extra=_extra_fields(item, _GROUP_KEYS, lost),
                    )
                )
                continue
            search = _loaded_search(item)
            if not (
                search is not None
                and isinstance(item.get("name"), str)
                and isinstance(item.get("path"), str)
                and isinstance(item.get("backend_name", "Local"), str)
                and isinstance(item.get("profile_name", ""), str)
            ):
                lost.append(f"bookmark {item.get('name')!r}")
                continue
            # An unknown kind (a newer version's) opens as a folder and is
            # saved as it is: never dropped, never turned into a folder.
            kind = item.get("kind", KIND_FOLDER)
            if kind not in KINDS and not (isinstance(kind, str) and _FOREIGN_KIND.fullmatch(kind)):
                lost.append(f"the kind of bookmark {item['name']!r}")
                kind = KIND_FOLDER
            known = _MARK_KEYS | set(HOST_FIELDS) if kind == KIND_TERMINAL else _MARK_KEYS
            bookmark = Bookmark(
                name=item["name"],
                path=item["path"],
                backend_name=item.get("backend_name", "Local"),
                profile_name=item.get("profile_name", ""),
                icon_name=_sanitize_icon_name(item.get("icon_name", "bookmark")),
                color=_sanitize_color(item.get("color")),
                search=search,
                created=_sanitize_created(item.get("created")),
                kind=kind,
                extra=_extra_fields(item, known, lost),
            )
            if kind == KIND_TERMINAL:
                # Damaged host fields fall back to defaults; without a
                # usable host the bookmark stays what it was before.
                bookmark.host = item.get("host", "")
                bookmark.port = item.get("port", DEFAULT_SSH_PORT)
                bookmark.username = item.get("username", "")
                bookmark.key_file = item.get("key_file", "")
            _normalise_kind(bookmark, keep_foreign=True)
            nodes.append(bookmark)
        return nodes

    @classmethod
    def _dump_nodes(cls, nodes: list) -> list[dict]:
        out: list[dict] = []
        for node in nodes:
            if isinstance(node, BookmarkGroup):
                entry = {
                    "type": "group",
                    "name": node.name,
                    "icon_name": node.icon_name,
                    "color": node.color,
                    "expanded": node.expanded,
                    "children": cls._dump_nodes(node.children),
                }
                for name, value in (node.extra or {}).items():
                    entry.setdefault(name, value)
                out.append(entry)
            else:
                out.append(bookmark_dict(node))
        return out

    @classmethod
    def _node_from_dump(cls, fields: dict):
        """The node a dumped entry stands for (the load rules applied)."""
        return cls._load_nodes([fields], 0)[0]

    def save(self) -> None:
        """Write the tree, first merging what another writer changed in the
        file meanwhile (see :meth:`_merge_from_disk`), under a file lock."""
        bf = _bookmarks_file()
        target_dir = bf.parent
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            with locked_store_update(bf):
                if self._merge_from_disk(bf) and not keep_unreadable_copy(bf):
                    # What this version cannot keep would be gone with the
                    # write: no copy, no write.
                    raise OSError(
                        f"{bf} holds entries this version cannot keep and no copy of it "
                        "could be made"
                    )
                self._write(bf)
        except OSError as e:
            from core.json_store import report_save_failure

            report_save_failure("bookmarks", e)
            if self.raise_save_errors:
                raise

    def _write(self, bf: Path) -> None:
        target_dir = bf.parent
        data = self._dump_nodes(self._root)
        try:
            os.chmod(target_dir, 0o700)
        except OSError:
            log.debug("Could not set permissions on %s", target_dir, exc_info=True)
        payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        # mkstemp creates the file 0o600 from birth — no brief
        # world-readable window like NamedTemporaryFile.
        fd, temp_name = tempfile.mkstemp(
            dir=target_dir,
            prefix=".bookmarks.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace") as tmp:
                fd = -1
                tmp.write(payload)
                # On disk before the rename: a crash or power cut right
                # after it otherwise leaves an empty bookmarks.json.
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(temp_name, bf)
            os.chmod(bf, 0o600)
            _fsync_dir(target_dir)
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
        self._base = data

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    def add(
        self,
        bookmark: Bookmark,
        group: BookmarkGroup | None = None,
        index: int | None = None,
    ) -> bool:
        """Add *bookmark* to *group* (``None`` = top level) at *index*
        (clamped; ``None`` appends). Returns ``False`` without changing
        anything when the same path on the same backend is already
        bookmarked anywhere in the tree (see :meth:`find`)."""
        _normalise_kind(bookmark)
        if self.find(bookmark.path, bookmark.backend_name, bookmark.kind) is not None:
            log.debug(
                "Skipping duplicate bookmark for %s on %s", bookmark.path, bookmark.backend_name
            )
            return False
        bookmark.icon_name = _sanitize_icon_name(bookmark.icon_name)
        bookmark.color = _sanitize_color(bookmark.color)
        bookmark.created = _sanitize_created(bookmark.created) or time.time()
        siblings = self._siblings(group)
        if index is None:
            siblings.append(bookmark)
        else:
            siblings.insert(max(0, min(index, len(siblings))), bookmark)
        self.save()
        log.info("Added bookmark: %s -> %s", bookmark.name, bookmark.path)
        return True

    def remove(self, index: int) -> None:
        """Remove the bookmark at flat *index* (see :meth:`all`)."""
        flat = self.all()
        if 0 <= index < len(flat):
            self.remove_node(flat[index])

    def remove_node(self, node: Bookmark) -> None:
        """Remove a bookmark by identity."""
        parent = self.parent_of(node)
        siblings = self._siblings(parent)
        siblings.pop(_index_by_identity(siblings, node))
        self.save()
        log.info("Removed bookmark: %s", getattr(node, "name", "?"))

    def update(self, index: int, bookmark: Bookmark) -> None:
        """Replace the bookmark at flat *index* with the new one + persist.
        Used by the edit dialog to change name / path / icon in
        place without creating a duplicate entry.
        """
        flat = self.all()
        if not (0 <= index < len(flat)):
            raise IndexError(
                f"bookmark index {index} out of range (have {len(flat)})",
            )
        self.update_bookmark(flat[index], bookmark)
        log.info("Updated bookmark #%d: %s → %s", index, bookmark.name, bookmark.path)

    def update_bookmark(
        self, old: Bookmark, new: Bookmark, *, group: BookmarkGroup | None | object = _KEEP
    ) -> None:
        """Replace *old* by *new* in place (same position). With
        ``group=`` the bookmark also moves to the end of that group
        (``None`` = top level)."""
        parent = self.parent_of(old)
        # Normalise the same way load() does.
        new.icon_name = _sanitize_icon_name(new.icon_name)
        new.color = _sanitize_color(new.color)
        # A newer version's kind stays through an edit that keeps it.
        _normalise_kind(new, keep_foreign=new.kind == old.kind)
        # An edit is not a new bookmark: it keeps its age.
        new.created = _sanitize_created(new.created) or old.created
        siblings = self._siblings(parent)
        siblings[_index_by_identity(siblings, old)] = new
        if group is not _KEEP and group is not parent:
            siblings.pop(_index_by_identity(siblings, new))
            self._siblings(group).append(new)
        self.save()

    def _levels_below(self, parent: BookmarkGroup | None) -> int:
        """How many group levels are above an entry of *parent* (0 for the
        top level)."""
        levels = 0
        while parent is not None:
            levels += 1
            parent = self.parent_of(parent)
        return levels

    @staticmethod
    def _group_height(node) -> int:
        """The group levels *node* brings along: 0 for a bookmark."""
        if not isinstance(node, BookmarkGroup):
            return 0
        return 1 + max((BookmarkManager._group_height(c) for c in node.children), default=0)

    def _check_nesting(self, parent: BookmarkGroup | None, nodes) -> None:
        """ValueError when *nodes* in *parent* would nest groups deeper
        than load() takes (_MAX_DEPTH): the next start dropped them, with
        every bookmark inside."""
        base = self._levels_below(parent)
        if any(base + self._group_height(node) > _MAX_DEPTH for node in nodes):
            raise ValueError(f"bookmark groups nest {_MAX_DEPTH} levels deep at most")

    def add_group(
        self,
        name: str,
        icon_name: str = _GROUP_ICON_DEFAULT,
        color: str = "",
        parent: BookmarkGroup | None = None,
    ) -> BookmarkGroup:
        """A new group in *parent*; ValueError past _MAX_DEPTH levels."""
        if self._levels_below(parent) + 1 > _MAX_DEPTH:
            raise ValueError(f"bookmark groups nest {_MAX_DEPTH} levels deep at most")
        group = BookmarkGroup(
            name=name,
            icon_name=_sanitize_icon_name(icon_name, _GROUP_ICON_DEFAULT),
            color=_sanitize_color(color),
        )
        self._siblings(parent).append(group)
        self.save()
        return group

    def update_group(
        self,
        group: BookmarkGroup,
        *,
        name: str | None = None,
        icon_name: str | None = None,
        color: str | None = None,
    ) -> None:
        self.parent_of(group)  # KeyError when the group is not in the tree
        if name is not None:
            group.name = name
        if icon_name is not None:
            group.icon_name = _sanitize_icon_name(icon_name, _GROUP_ICON_DEFAULT)
        if color is not None:
            group.color = _sanitize_color(color)
        self.save()

    def set_expanded(self, group: BookmarkGroup, expanded: bool) -> None:
        if group.expanded == bool(expanded):
            return
        group.expanded = bool(expanded)
        self.save()

    def remove_group(self, group: BookmarkGroup) -> None:
        """Delete the group only: its children take its place in the
        parent, in order. Nothing inside is lost."""
        parent = self.parent_of(group)
        siblings = self._siblings(parent)
        pos = _index_by_identity(siblings, group)
        siblings[pos : pos + 1] = group.children
        group.children = []
        self.save()

    def move(self, node: Node, parent: BookmarkGroup | None, index: int | None = None) -> None:
        """Move *node* into *parent* (``None`` = top level) at *index*.

        *index* counts positions in the destination list as it is BEFORE
        the move (what a drop indicator shows); moving within one list
        past the node's own slot is compensated. ``None`` appends.
        Raises ``ValueError`` when a group would land inside itself."""
        old_parent = self.parent_of(node)  # KeyError for unknown nodes
        if isinstance(node, BookmarkGroup) and parent is not None and self._contains(node, parent):
            raise ValueError("a group cannot be moved into itself or its descendants")
        self._check_nesting(parent, [node])
        old_siblings = self._siblings(old_parent)
        old_pos = _index_by_identity(old_siblings, node)
        old_siblings.pop(old_pos)
        dest = self._siblings(parent)
        if index is None:
            index = len(dest)
        elif old_parent is parent and old_pos < index:
            index -= 1
        dest.insert(max(0, min(index, len(dest))), node)
        self.save()

    def _outermost(self, nodes: list) -> list:
        """*nodes* in tree order, without duplicates and without any node
        that lies inside another one of them (it moves or goes with its
        group). Raises ``KeyError`` for a node that is not in the tree."""
        for node in nodes:
            self.parent_of(node)  # KeyError for unknown nodes
        order: list = []

        def walk(siblings: list) -> None:
            for node in siblings:
                order.append(node)
                if isinstance(node, BookmarkGroup):
                    walk(node.children)

        walk(self._root)
        chosen = [n for n in order if any(n is m for m in nodes)]
        groups = [g for g in chosen if isinstance(g, BookmarkGroup)]
        return [n for n in chosen if not any(g is not n and self._holds(g, n) for g in groups)]

    @staticmethod
    def _holds(group: BookmarkGroup, node: object) -> bool:
        """True when *node* (bookmark or group) lies anywhere below *group*."""
        return any(
            child is node
            or (isinstance(child, BookmarkGroup) and BookmarkManager._holds(child, node))
            for child in group.children
        )

    def move_nodes(
        self, nodes: list, parent: BookmarkGroup | None, index: int | None = None
    ) -> bool:
        """Move several nodes into *parent* (``None`` = top level) at *index*,
        in tree order, with one save. *index* means what it means for
        :meth:`move`. A node inside another moved group goes with that group.
        All or nothing: ``KeyError`` for an unknown node, ``ValueError`` when
        a group would land inside itself. Returns whether anything moved."""
        moving = self._outermost(nodes)
        if parent is not None:
            self.parent_of(parent)
        for node in moving:
            if isinstance(node, BookmarkGroup) and parent is not None and self._contains(
                node, parent
            ):
                raise ValueError("a group cannot be moved into itself or its descendants")
        self._check_nesting(parent, moving)
        if not moving:
            return False
        dest = self._siblings(parent)
        if index is None:
            index = len(dest)
        # Entries taken out of the destination list in front of the drop
        # position shift it, as move() compensates for one node.
        index -= sum(1 for pos, n in enumerate(dest) if pos < index and any(n is m for m in moving))
        for node in moving:
            siblings = self._siblings(self.parent_of(node))
            siblings.pop(_index_by_identity(siblings, node))
        index = max(0, min(index, len(dest)))
        dest[index:index] = moving
        self.save()
        return True

    def remove_nodes(self, nodes: list) -> int:
        """Delete several nodes with one save: bookmarks are removed, groups
        are dissolved like :meth:`remove_group` (their children move up).
        Returns how many of *nodes* were deleted."""
        unique: list = []
        for node in nodes:
            self.parent_of(node)  # KeyError before anything changes
            if not any(node is u for u in unique):
                unique.append(node)
        nodes = unique
        done = 0
        # Bookmarks first, then groups: a dissolved group's children move up
        # in its place, so a selected child is still found where it went.
        for node in sorted(nodes, key=lambda n: isinstance(n, BookmarkGroup)):
            siblings = self._siblings(self.parent_of(node))
            pos = _index_by_identity(siblings, node)
            if isinstance(node, BookmarkGroup):
                siblings[pos : pos + 1] = node.children
                node.children = []
            else:
                siblings.pop(pos)
            done += 1
        if done:
            self.save()
            log.info("Removed %d bookmark entries", done)
        return done

    def sort_children(
        self, group: BookmarkGroup | None, key: str, reverse: bool = False
    ) -> bool:
        """Sort the direct entries of *group* (``None`` = top level) and
        store that order. *key* is one of :data:`SORT_KEYS`: ``name``,
        ``path`` (then backend), ``name_path`` (name, then path) or ``age``
        (creation time). Groups always come first, ordered by name: A-Z for
        the path and age keys (a group has neither), while the name keys
        reverse them too, so Name (Reverse) is Z-A for everything named.
        Undated bookmarks (``created`` 0) always come last. Ties keep their
        order. Returns whether the order changed (only then is it saved)."""
        if key not in SORT_KEYS:
            raise ValueError(f"unknown sort key {key!r}; one of {', '.join(SORT_KEYS)}")
        if group is not None:
            self.parent_of(group)  # KeyError when the group is not in the tree
        siblings = self._siblings(group)

        def fold(text: str) -> tuple[str, str]:
            return (text.casefold(), text)

        keys = {
            "name": lambda b: fold(b.name),
            "path": lambda b: (fold(b.path), fold(b.backend_name)),
            # The path decides between names that differ only in case.
            "name_path": lambda b: (b.name.casefold(), fold(b.path), b.name),
            "age": lambda b: b.created,
        }
        groups = sorted(
            (n for n in siblings if isinstance(n, BookmarkGroup)),
            key=lambda g: fold(g.name),
            reverse=reverse and key in _GROUP_REVERSING_KEYS,
        )
        marks = [n for n in siblings if not isinstance(n, BookmarkGroup)]
        if key == "age":
            undated = [b for b in marks if not b.created]
            marks = [b for b in marks if b.created]
        else:
            undated = []
        marks = sorted(marks, key=keys[key], reverse=reverse) + undated
        ordered = groups + marks
        if all(a is b for a, b in zip(ordered, siblings, strict=True)):
            return False
        siblings[:] = ordered
        self.save()
        return True

    def move_by(self, node: Node, delta: int) -> bool:
        """Shift *node* by *delta* places inside its parent (clamped).
        Returns whether anything moved."""
        parent = self.parent_of(node)
        siblings = self._siblings(parent)
        pos = _index_by_identity(siblings, node)
        target = max(0, min(pos + delta, len(siblings) - 1))
        if target == pos:
            return False
        siblings.insert(target, siblings.pop(pos))
        self.save()
        return True

    def move_to_top(self, node: Node) -> bool:
        parent = self.parent_of(node)
        siblings = self._siblings(parent)
        return self.move_by(node, -_index_by_identity(siblings, node))
