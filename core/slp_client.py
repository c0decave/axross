"""SLP (Service Location Protocol) read-only FileBackend.

Maps an SLPv2 daemon's service registry onto a filesystem view::

    /                                  — list of service types
    /<service-type>/                   — one entry per registered URL
    /<service-type>/<encoded-url>.attrs — text file: attribute list

Use case: security audits / network inventory. Listing the SLP types
exposed by an ESXi host or printer fleet has historically uncovered
unintended services (vCenter SDK, WBEM, IPP). SLP is read-only here
by design: see CVE-2023-29552 — the amplification vulnerability
needs ``SrvReg`` (registration) packets, which this backend simply
does not implement.

Hard refusals:

* No multicast / broadcast queries — :mod:`core.slp_lib` rejects
  multicast targets at the socket layer.
* No ``SrvReg``: there is no code path that crafts a registration
  packet, so the amplification pattern is structurally impossible.
* Read-only FileBackend surface: every write entry point raises.
"""
from __future__ import annotations

import io
import logging
import posixpath
import re
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

_FILENAME_BAD = re.compile(r'[/\\:*?"<>|\x00-\x1f]')


def _safe_name(text: str) -> str:
    cleaned = _FILENAME_BAD.sub("_", text).strip(". ")
    if not cleaned:
        cleaned = "service"
    return cleaned[:120]


def _parse_slp_attrs(text: str) -> dict[str, str]:
    """Parse an SLP AttrReply payload — the wire format is a comma-
    separated list of ``(name=value)`` pairs (RFC 2608 §10). Bare
    names without ``=`` (``"(some-flag)"``) map to ``""``. Repeated
    names: last wins.

    Robust to whitespace inside parens and to escaped commas
    (``\\,`` per RFC 2608 §5).
    """
    if not text:
        return {}
    out: dict[str, str] = {}
    # Split on commas that are NOT preceded by a backslash (un-escaped).
    pairs: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            cur.append(text[i + 1])
            i += 2
            continue
        if c == ",":
            pairs.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        pairs.append("".join(cur).strip())
    for p in pairs:
        if not p:
            continue
        if p.startswith("(") and p.endswith(")"):
            inner = p[1:-1].strip()
        else:
            inner = p
        if "=" in inner:
            name, _, val = inner.partition("=")
            out[name.strip()] = val.strip()
        else:
            out[inner] = ""
    return out


class SlpSession:
    """Read-only SLPv2 backend implementing the FileBackend protocol."""

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str,
        port: int = 427,
        scope: str = "DEFAULT",
        use_tcp: bool = False,
        timeout: float = 5.0,
        **_ignored,
    ):
        self._host = host
        self._port = int(port)
        self._scope = scope.encode("utf-8")
        self._use_tcp = bool(use_tcp)
        self._timeout = float(timeout)
        # Per-session caches: service_types kept after the first
        # SrvTypeReq; URLs per type kept until the lifetime expires.
        self._types_cache: list[str] | None = None
        self._urls_cache: dict[str, list[tuple[str, int]]] = {}
        # Probe: actually query the host so __init__ fails fast on a
        # dead daemon.
        try:
            self._fetch_types()
        except Exception as exc:
            raise OSError(f"SLP probe to {host}:{self._port}: {exc}") from exc
        log.info("SLP session ready: %s:%d (scope=%s, %d types)",
                 host, self._port, scope, len(self._types_cache or []))

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"SLP: {self._host}:{self._port}"

    @property
    def connected(self) -> bool:
        return True

    def close(self) -> None:
        self._types_cache = None
        self._urls_cache.clear()

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

    # ------------------------------------------------------------------
    # SLP queries
    # ------------------------------------------------------------------

    def _query(self, packet: bytes) -> bytes:
        from core.slp_lib import query_tcp, query_udp
        fn = query_tcp if self._use_tcp else query_udp
        return fn(self._host, packet, port=self._port, timeout=self._timeout)

    def _fetch_types(self) -> list[str]:
        from core.slp_lib import build_srv_type_req, parse_srv_type_reply
        if self._types_cache is not None:
            return self._types_cache
        blob = self._query(build_srv_type_req(self._scope))
        types = parse_srv_type_reply(blob)
        self._types_cache = types
        return types

    def _fetch_urls(self, svc_type: str) -> list[tuple[str, int]]:
        from core.slp_lib import build_srv_req, parse_srv_reply
        cached = self._urls_cache.get(svc_type)
        if cached is not None:
            return cached
        blob = self._query(build_srv_req(svc_type.encode("utf-8"), self._scope))
        urls = parse_srv_reply(blob)
        self._urls_cache[svc_type] = urls
        return urls

    def _fetch_attrs(self, url: str) -> str:
        from core.slp_lib import build_attr_req, parse_attr_reply
        blob = self._query(build_attr_req(url.encode("utf-8"), self._scope))
        return parse_attr_reply(blob)

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        if path == "/":
            items = []
            for svc_type in self._fetch_types():
                items.append(FileItem(
                    name=_safe_name(svc_type), is_dir=True, is_link=False,
                    size=0, modified=datetime.fromtimestamp(0),
                    permissions=0o555,
                ))
            return items
        # /<service-type>
        parts = path.strip("/").split("/")
        if len(parts) != 1:
            raise OSError(f"SLP list({path}): nesting beyond /<type> is not supported")
        svc_type = self._lookup_type(parts[0])
        items = []
        for url, lifetime in self._fetch_urls(svc_type):
            items.append(FileItem(
                name=_safe_name(url) + ".attrs",
                is_dir=False, is_link=False,
                size=0, modified=datetime.fromtimestamp(0),
                permissions=0o444,
            ))
        return items

    def _lookup_type(self, safe_name: str) -> str:
        """Translate a sanitised filename back to the original SLP
        service-type string."""
        for t in self._fetch_types():
            if _safe_name(t) == safe_name:
                return t
        raise OSError(f"SLP: unknown service type {safe_name!r}")

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o555,
            )
        parts = path.strip("/").split("/")
        if len(parts) == 1:
            return FileItem(
                name=parts[0], is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o555,
            )
        return FileItem(
            name=posixpath.basename(path), is_dir=False, is_link=False,
            size=0, modified=datetime.fromtimestamp(0), permissions=0o444,
        )

    def is_dir(self, path: str) -> bool:
        path = self.normalize(path)
        return path == "/" or "/" not in path.strip("/")

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def open_read(self, path: str) -> IO[bytes]:
        path = self.normalize(path)
        parts = path.strip("/").split("/")
        if len(parts) != 2 or not parts[1].endswith(".attrs"):
            raise OSError(f"SLP read({path}): expected /<type>/<url>.attrs")
        svc_type = self._lookup_type(parts[0])
        leaf = parts[1][:-len(".attrs")]
        for url, _lifetime in self._fetch_urls(svc_type):
            if _safe_name(url) == leaf:
                attrs = self._fetch_attrs(url)
                return io.BytesIO(attrs.encode("utf-8"))
        raise OSError(f"SLP: no URL matching {path!r}")

    def readlink(self, path: str) -> str:
        raise OSError("SLP has no symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("SLP has no version history")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return ""

    # ------------------------------------------------------------------
    # SLP-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def services_browse(self) -> list[dict]:
        """One-shot full inventory of every service the directory agent
        publishes. Returns a list of dicts ``{type, urls, attributes}``
        — one entry per service-type, with every URL of that type and
        the per-URL attributes flattened.

        This is the CLI ``slptool findsrvtypes`` + ``findsrvs`` +
        ``findattrs`` round-trip in one call. Useful for "what's on
        this network?" inventory scripts.

        Result rows preserve the order that the directory agent
        returned them — typically newest-first.
        """
        out: list[dict] = []
        for svc_type in self._fetch_types():
            urls_with_lifetime = self._fetch_urls(svc_type)
            for url, _lifetime in urls_with_lifetime:
                attrs_text = ""
                try:
                    attrs_text = self._fetch_attrs(url)
                except Exception as exc:  # noqa: BLE001
                    log.debug("SLP attrs fetch failed for %s: %s", url, exc)
                out.append({
                    "type": svc_type,
                    "url": url,
                    "attributes": _parse_slp_attrs(attrs_text),
                })
        return out

    def attributes_get(self, url: str) -> dict[str, str]:
        """Fetch the per-URL attribute list and parse the
        ``(name=value)`` pairs into a dict. ``url`` must be a string
        that ``services_browse`` already returned (or one the caller
        knows the directory agent recognises)."""
        text = self._fetch_attrs(url)
        return _parse_slp_attrs(text)

    # ------------------------------------------------------------------
    # FileBackend — write surface (refused)
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        raise OSError(
            "SLP backend is read-only. Writes would map to SrvReg, "
            "which axross deliberately does not implement "
            "(CVE-2023-29552 amplification mitigation).",
        )

    def mkdir(self, path: str) -> None:
        raise OSError("SLP backend is read-only — mkdir not supported")

    def remove(self, path: str, recursive: bool = False) -> None:
        raise OSError("SLP backend is read-only — remove not supported")

    def rename(self, src: str, dst: str) -> None:
        raise OSError("SLP backend is read-only — rename not supported")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("SLP carries no POSIX permissions")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("SLP backend is read-only — copy not supported")
