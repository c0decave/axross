"""Gopher (RFC 1436) read-only backend.

Treats a Gopher hole as a filesystem. Type-1 directories map to
directories; type-0 text, type-9 binary, type-g/I images, type-h
HTML, type-M mailbox/MIME, type-4 BinHex, type-5 DOS, type-6
uuencoded all map to files. Type-i (info) lines are display-only
and dropped from the listing. Type-7 (search) is currently treated
as a directory placeholder — listing it returns the prompt as a
single info entry; future versions can wire a search-query dialog.

Pure stdlib: no extra deps. Optional TLS via ``use_tls`` for
gophers:// servers.

Why a Gopher backend in axross? Gopher holes still host
documentation, retrocomputing artefacts, and a surprising amount
of niche file collections. The protocol is tiny, well documented,
and a great example of "every backend is just a FileBackend"
working out cleanly.
"""
from __future__ import annotations

import io
import logging
import posixpath
import socket
import ssl
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

# Read cap per file (16 MiB). Gopher servers can dump arbitrary
# binaries; refusing >16 MiB protects the UI from a stray ISO
# without rejecting realistic content.
MAX_FILE_BYTES = 16 * 1024 * 1024

# Per-listing cap: refuse to allocate beyond this from one PROPFIND-
# equivalent dir read. 8 MiB of Gopher menu text would already be
# unreasonable.
MAX_DIR_BYTES = 8 * 1024 * 1024

# Receive timeout per socket. Gopher servers are usually quick;
# 30s gives slow / re-routed servers room without locking the UI.
DEFAULT_TIMEOUT = 30.0

# Maximum nesting depth of a Gopher path. The selector → menu chain
# costs one TCP round-trip per directory; capping keeps a hostile menu
# from steering us into thousands of cascading fetches.
MAX_PATH_DEPTH = 32

# Cap on the per-session menu cache. Without it, a long browsing
# session against a server that emits unique selectors per click
# would grow self._dir_cache unboundedly.
DIR_CACHE_LIMIT = 256


# Item types defined by RFC 1436 + common extensions. Any not
# listed here are treated as opaque files.
_DIR_TYPES = frozenset({"1"})
_INFO_TYPES = frozenset({"i", "3"})  # 'i' info line, '3' error
_FILE_TYPES = frozenset({
    "0",  # plain text
    "4",  # BinHex
    "5",  # DOS binary
    "6",  # uuencoded
    "7",  # search index — we expose as a "file" placeholder for now
    "9",  # binary
    "M",  # MIME
    "I",  # image
    "g",  # GIF
    "h",  # HTML
    "s",  # sound
    ";",  # video (extension)
    "d",  # document (extension)
    "p",  # PDF (extension)
})

# File-extension hint by item type, used when the selector lacks one.
_TYPE_EXT = {
    "0": ".txt",
    "h": ".html",
    "I": ".img",
    "g": ".gif",
    "5": ".bin",
    "9": ".bin",
    "4": ".hqx",
    "6": ".uue",
    "M": ".eml",
    "s": ".au",
    ";": ".mp4",
    "d": ".doc",
    "p": ".pdf",
}


class GopherProtocolError(OSError):
    """Raised on malformed responses, oversized payloads, or
    connection failure."""


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _open_socket(
    host: str, port: int, use_tls: bool, proxy_config,
    timeout: float = DEFAULT_TIMEOUT,
) -> socket.socket:
    """Open a TCP socket to ``host:port``, optionally via a SOCKS/HTTP
    proxy, and TLS-wrap it when ``use_tls`` is set.
    """
    if proxy_config is not None and getattr(proxy_config, "enabled", False):
        from core.proxy import create_proxy_socket
        sock = create_proxy_socket(proxy_config, host, port, timeout=timeout)
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.settimeout(timeout)
    return sock


def _send_selector(sock: socket.socket, selector: str) -> None:
    """Send the selector + CRLF as required by RFC 1436. Selectors
    must not themselves contain CR/LF/TAB; any such byte is rejected
    so a hostile path can't smuggle a second request."""
    if "\r" in selector or "\n" in selector or "\t" in selector:
        raise GopherProtocolError(
            f"selector contains CR/LF/TAB which is not RFC1436-legal: {selector!r}"
        )
    sock.sendall(selector.encode("utf-8") + b"\r\n")


def _recv_all(sock: socket.socket, max_bytes: int) -> bytes:
    """Read until EOF or ``max_bytes`` worth, whichever comes first.
    Raises if the server keeps sending past the cap."""
    chunks: list[bytes] = []
    received = 0
    while True:
        try:
            chunk = sock.recv(64 * 1024)
        except socket.timeout as exc:
            raise GopherProtocolError(f"recv timeout after {received} bytes") from exc
        if not chunk:
            break
        received += len(chunk)
        if received > max_bytes:
            raise GopherProtocolError(
                f"response exceeds {max_bytes} byte cap (received {received})",
            )
        chunks.append(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Menu parsing
# ---------------------------------------------------------------------------

def _parse_menu(raw: bytes) -> list[dict]:
    """Parse a Gopher menu blob into a list of entry dicts.

    Each line is ``<type><display>\\t<selector>\\t<host>\\t<port>\\r\\n``.
    Lines that don't match are dropped (with a debug log). The menu
    is terminated by a ``.`` on its own line; lines after it are
    ignored."""
    text = raw.decode("utf-8", errors="replace")
    entries: list[dict] = []
    for line in text.splitlines():
        if line == ".":
            break
        if not line:
            continue
        # First char is the item type; the rest splits by TAB.
        item_type = line[0]
        rest = line[1:]
        parts = rest.split("\t")
        if len(parts) < 4:
            log.debug("dropping malformed gopher line: %r", line)
            continue
        display, selector, host, port = parts[0], parts[1], parts[2], parts[3]
        try:
            port_int = int(port)
        except ValueError:
            port_int = 70
        entries.append({
            "type": item_type,
            "display": display,
            "selector": selector,
            "host": host,
            "port": port_int,
        })
    return entries


def _entry_to_filename(entry: dict) -> str:
    """Build a readable filename for a Gopher entry. The display
    string is the user-visible label; we keep it but sanitise it for
    filesystem-style paths and tack on a hint extension when the
    type is known."""
    display = entry["display"].strip() or posixpath.basename(entry["selector"]) or entry["type"]
    # Replace path-hostile chars.
    safe = display.replace("/", "_").replace("\\", "_")
    safe = safe.replace("\x00", "").strip()
    if not safe:
        safe = entry["selector"] or entry["type"]
    if entry["type"] in _DIR_TYPES:
        return safe
    # File: append a type-hint extension only when the display name
    # has none of its own (so disk.iso stays disk.iso, not disk.iso.bin).
    ext = _TYPE_EXT.get(entry["type"], "")
    has_ext = "." in posixpath.basename(safe)
    if ext and not has_ext:
        safe = safe + ext
    return safe


def _disambiguate(entries: list[dict]) -> dict[int, str]:
    """Resolve filename collisions by suffixing duplicates with
    ``-N`` (1-based, second-occurrence onwards). Returns a mapping
    of entry-index → final filename so callers can hand each
    Gopher entry a unique on-screen name even when the menu has
    two ``report`` entries (one type 0, one type h, both rendered
    as ``report.html`` etc.)."""
    seen: dict[str, int] = {}
    out: dict[int, str] = {}
    for idx, entry in enumerate(entries):
        if entry["type"] in _INFO_TYPES:
            continue
        base = _entry_to_filename(entry)
        count = seen.get(base, 0)
        if count == 0:
            out[idx] = base
        else:
            # Insert -N before the extension if there is one.
            stem, dot, ext = base.rpartition(".")
            if dot:
                out[idx] = f"{stem}-{count}.{ext}"
            else:
                out[idx] = f"{base}-{count}"
        seen[base] = count + 1
    return out


# ---------------------------------------------------------------------------
# Public session
# ---------------------------------------------------------------------------

class GopherSession:
    """Read-only Gopher backend implementing the FileBackend protocol.

    Path semantics:

    * ``"/"`` → root selector (empty string).
    * ``"/foo/bar"`` → selector ``/foo/bar`` (most servers expect this
      shape; some prefer no leading slash — we send it as-is, leaving
      that to the server's tolerance).
    """

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str,
        port: int = 70,
        username: str = "",
        password: str = "",
        use_tls: bool = False,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        self._host = host
        self._port = int(port)
        self._use_tls = bool(use_tls)
        # username / password are accepted for profile compatibility
        # but Gopher has no auth — we ignore them.
        from core.proxy import ProxyConfig
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )
        # Per-session cache: parent-dir-path → list of menu entries.
        # Lets stat/open_read look up an item's type without re-listing.
        self._dir_cache: dict[str, list[dict]] = {}

        # Cheap probe: list the root so __init__ raises early on a
        # dead host or wrong-port misconfig.
        try:
            self._fetch_menu("")
        except Exception as exc:
            raise OSError(
                f"Cannot connect to gopher{'s' if use_tls else ''}://{host}:{port}/: {exc}",
            ) from exc

        log.info(
            "Gopher%s connected: %s:%d",
            "S" if self._use_tls else "", self._host, self._port,
        )

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        scheme = "gophers" if self._use_tls else "gopher"
        return f"{scheme}://{self._host}:{self._port}"

    @property
    def connected(self) -> bool:
        # Stateless — every operation opens a fresh socket.
        return True

    def close(self) -> None:
        self._dir_cache.clear()

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        # Strip first, then drop empties — otherwise a single ``"/"``
        # part survives the truthy check, gets stripped to ``""``, and
        # injects a stray leading slash into the joined result
        # (``join("/", "x")`` → ``"//x"``).
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path) or "/"

    @staticmethod
    def _path_to_selector(path: str) -> str:
        """Translate an axross path to a Gopher selector. The root
        ``"/"`` becomes the empty selector; everything else is
        returned verbatim (with the leading slash). RFC1436 places
        no formal restriction on selector contents beyond banning
        CR/LF/TAB; we relay the path as-is."""
        if path in ("", "/"):
            return ""
        return path

    # ------------------------------------------------------------------
    # Wire ops (cached menu fetch)
    # ------------------------------------------------------------------

    def _fetch_menu(self, selector: str) -> list[dict]:
        sock = _open_socket(self._host, self._port, self._use_tls, self._proxy)
        try:
            _send_selector(sock, selector)
            blob = _recv_all(sock, MAX_DIR_BYTES)
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
        return _parse_menu(blob)

    def _fetch_file(self, selector: str) -> bytes:
        sock = _open_socket(self._host, self._port, self._use_tls, self._proxy)
        try:
            _send_selector(sock, selector)
            return _recv_all(sock, MAX_FILE_BYTES)
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

    def _menu_for_path(self, path: str) -> list[dict]:
        """Resolve ``path`` to a Gopher selector via the parent
        directory's cached listing, then fetch the menu. Falls back
        to using the path verbatim as a selector when the parent is
        unknown (e.g. the user pasted a deep selector without
        clicking through). Root always maps to the empty selector.
        """
        path = self.normalize(path)
        # Refuse pathological depths: each level costs one TCP round-trip
        # (and one Python recursion via _entry_for_path), so a hostile
        # menu can otherwise steer us into thousands of fetches.
        if path.count("/") > MAX_PATH_DEPTH:
            raise OSError(
                f"Gopher path nesting exceeds {MAX_PATH_DEPTH} levels: {path!r}"
            )
        cached = self._dir_cache.get(path)
        if cached is not None:
            return cached
        if path == "/":
            selector = ""
        else:
            parent_entry = self._entry_for_path(path)
            if parent_entry is not None and parent_entry["selector"]:
                selector = parent_entry["selector"]
            else:
                selector = self._path_to_selector(path)
        entries = self._fetch_menu(selector)
        # LRU-trim so a long browsing session against a hostile / huge
        # server doesn't grow the cache without bound.
        if len(self._dir_cache) >= DIR_CACHE_LIMIT:
            try:
                oldest = next(iter(self._dir_cache))
                self._dir_cache.pop(oldest, None)
            except StopIteration:
                pass
        self._dir_cache[path] = entries
        return entries

    def _entry_for_path(self, path: str) -> dict | None:
        """Look up the parent-dir's listing and find the entry whose
        rendered filename matches ``path``'s last component. Honours
        disambiguation suffixes (``foo-1``, ``foo-2``) so a leaf name
        we exposed via list_dir always resolves back to the same
        underlying menu entry."""
        path = self.normalize(path)
        if path == "/":
            return {
                "type": "1", "display": "/", "selector": "",
                "host": self._host, "port": self._port,
            }
        parent = self.parent(path)
        leaf = posixpath.basename(path)
        menu = self._menu_for_path(parent)
        names = _disambiguate(menu)
        for idx, entry in enumerate(menu):
            if idx in names and names[idx] == leaf:
                return entry
        return None

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        try:
            menu = self._menu_for_path(path)
        except GopherProtocolError as exc:
            raise OSError(f"Gopher list({path}): {exc}") from exc
        # Disambiguate before iteration so two entries that sanitise to
        # the same filename get -1, -2, … suffixes instead of silently
        # shadowing one another.
        names = _disambiguate(menu)
        items: list[FileItem] = []
        for idx, entry in enumerate(menu):
            if idx not in names:
                continue
            is_dir = entry["type"] in _DIR_TYPES
            items.append(FileItem(
                name=names[idx],
                is_dir=is_dir,
                is_link=False,
                size=0,  # Gopher menus don't carry sizes
                modified=datetime.fromtimestamp(0),
                permissions=0o555 if is_dir else 0o444,
            ))
        return items

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o555,
            )
        entry = self._entry_for_path(path)
        if entry is None:
            raise OSError(f"Gopher stat({path}): not found in parent menu")
        is_dir = entry["type"] in _DIR_TYPES
        return FileItem(
            name=posixpath.basename(path),
            is_dir=is_dir, is_link=False, size=0,
            modified=datetime.fromtimestamp(0),
            permissions=0o555 if is_dir else 0o444,
        )

    def is_dir(self, path: str) -> bool:
        path = self.normalize(path)
        if path == "/":
            return True
        entry = self._entry_for_path(path)
        return bool(entry and entry["type"] in _DIR_TYPES)

    def exists(self, path: str) -> bool:
        path = self.normalize(path)
        if path == "/":
            return True
        return self._entry_for_path(path) is not None

    def open_read(self, path: str, mode: str = "rb") -> IO[bytes]:
        path = self.normalize(path)
        entry = self._entry_for_path(path)
        if entry is None:
            # Fallback: try fetching the path verbatim — some servers
            # let clients address files without listing the parent.
            selector = self._path_to_selector(path)
        else:
            if entry["type"] in _DIR_TYPES:
                raise OSError(f"Gopher: {path} is a directory")
            selector = entry["selector"] or self._path_to_selector(path)
        try:
            blob = self._fetch_file(selector)
        except GopherProtocolError as exc:
            raise OSError(f"Gopher read({path}): {exc}") from exc
        return io.BytesIO(blob)

    def readlink(self, path: str) -> str:
        raise OSError("Gopher does not expose symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("Gopher has no version history")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return ""

    # ------------------------------------------------------------------
    # Gopher-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    # Map of every type byte we recognise + its human-readable label.
    # Lifted from RFC 1436 + the de-facto Gopher+ extensions.
    _TYPE_LABELS = {
        "0": "text-file",
        "1": "menu",
        "2": "ccso-nameserver",
        "3": "error",
        "4": "binhex-file",
        "5": "dos-binary",
        "6": "uuencoded-file",
        "7": "search-index",
        "8": "telnet-session",
        "9": "binary-file",
        "+": "redundant-server",
        "T": "tn3270-session",
        "g": "gif-image",
        "I": "image",
        "M": "mime-message",
        "h": "html-file",
        "s": "audio",
        ";": "video",
        "d": "document",
        "p": "pdf",
    }

    def selector_type(self, path: str) -> dict:
        """Look up the Gopher item-type byte for ``path`` and return
        a dict ``{"type": "0", "label": "text-file", "selector": "/x"}``.

        Returns ``{"type": "?", "label": "unknown", ...}`` for menu
        entries the parent listing didn't expose. The lookup uses the
        cached parent-menu rendering so it doesn't re-fetch.
        """
        entry = self._entry_for_path(path)
        if not entry:
            raise FileNotFoundError(f"Gopher: no entry at {path!r}")
        t = entry.get("type") or "?"
        return {
            "type": t,
            "label": self._TYPE_LABELS.get(t, "unknown"),
            "selector": entry.get("selector") or "",
            "display": entry.get("display") or "",
        }

    def recursive_fetch(self, path: str = "/", *,
                        max_files: int = 1000,
                        max_depth: int = 10,
                        on_visit=None) -> dict[str, bytes]:
        """Walk a Gopher menu tree starting at ``path`` and return
        ``{path: body_bytes}`` for every leaf item up to ``max_files``
        / ``max_depth``.

        ``on_visit`` is an optional ``callable(path, type) -> None``
        invoked for each entry as we descend — useful for progress UIs.

        Skips item-types that aren't directly fetchable over Gopher
        wire (8 = telnet, 7 = search-index, T = tn3270). Errors on a
        single fetch are logged but don't abort the walk; the dict
        will simply be missing that path.
        """
        out: dict[str, bytes] = {}
        skipped = {"7", "8", "T", "+"}
        seen: set[str] = set()

        def _walk(p: str, depth: int) -> None:
            if depth > max_depth or len(out) >= max_files:
                return
            if p in seen:
                return
            seen.add(p)
            try:
                entries = self._menu_for_path(p)
            except Exception as exc:  # noqa: BLE001
                log.debug("Gopher recursive_fetch: skip %s: %s", p, exc)
                return
            for e in entries:
                if len(out) >= max_files:
                    return
                t = e.get("type") or ""
                child_path = self.join(p, e.get("display") or e.get("selector") or "")
                if on_visit is not None:
                    try:
                        on_visit(child_path, t)
                    except Exception:  # noqa: BLE001
                        pass
                if t == "1":
                    _walk(child_path, depth + 1)
                    continue
                if t in skipped:
                    continue
                # Leaf — fetch via the existing single-file helper.
                try:
                    body = self._fetch_file(e.get("selector") or "")
                except Exception as exc:  # noqa: BLE001
                    log.debug(
                        "Gopher recursive_fetch: fetch %s failed: %s",
                        child_path, exc,
                    )
                    continue
                out[child_path] = body

        _walk(path, 0)
        return out

    # ------------------------------------------------------------------
    # FileBackend — write surface (refused; Gopher is read-only)
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        raise OSError("Gopher is read-only — no PUT primitive in the protocol.")

    def mkdir(self, path: str) -> None:
        raise OSError("Gopher is read-only — mkdir not supported.")

    def remove(self, path: str, recursive: bool = False) -> None:
        raise OSError("Gopher is read-only — delete not supported.")

    def rename(self, src: str, dst: str) -> None:
        raise OSError("Gopher is read-only — rename not supported.")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("Gopher carries no POSIX permissions.")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("Gopher has no server-side copy primitive.")
