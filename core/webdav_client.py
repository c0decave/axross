"""WebDAV backend implementing the FileBackend protocol.

Pure ``requests`` + ``defusedxml`` implementation — no third-party
WebDAV SDK. WebDAV is HTTP + a small XML vocabulary; the dependency
that used to live here (``webdavclient3``) added ~2k LOC for what
amounts to PROPFIND, GET, PUT, DELETE, MKCOL, MOVE, COPY. This
module is a focused re-implementation against RFC 4918 (WebDAV) and
RFC 4331 (quota).

The public surface is :class:`WebDavSession`. Internally it talks to
:class:`_WebDavClient` which owns the ``requests.Session`` and the
XML parsing.

Requires: ``pip install axross[webdav]`` — ``requests`` +
``defusedxml``. ``defusedxml`` is **mandatory** because every
PROPFIND response we parse comes from an external server (a trust
boundary), so we refuse to fall back to the stdlib parser.
"""
from __future__ import annotations

import io
import logging
import posixpath
import tempfile
from datetime import datetime
from typing import IO, Any
from urllib.parse import quote, unquote, urlsplit

from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except ImportError:
    _xml_fromstring = None  # type: ignore[assignment]


# WebDAV uses the "DAV:" XML namespace; Nextcloud / ownCloud expose
# extra properties under "http://owncloud.org/ns".
_DAV_NS = "DAV:"
_OC_NS = "http://owncloud.org/ns"
_NSMAP = {"d": _DAV_NS, "oc": _OC_NS}

# Hard cap on a single PROPFIND response. WebDAV servers can return
# arbitrarily-large multistatus blobs (think: a 100 000-entry directory).
# Refusing past this prevents a runaway / hostile server from OOMing
# the UI before the parser can complete.
MAX_PROPFIND_BYTES = 64 * 1024 * 1024


class WebDavRequestError(OSError):
    """Raised when a WebDAV HTTP request returns an error status."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def _build_requests_proxies(
    proxy_type: str, host: str, port: int,
    username: str = "", password: str = "",
) -> dict[str, str]:
    """Backwards-compat thin wrapper around :func:`core.proxy.build_requests_proxies`.

    Kept so external code that imports this private symbol from the
    webdav_client module keeps working.
    """
    from core.proxy import build_requests_proxies
    return build_requests_proxies(proxy_type, host, port, username, password)


def _redact_proxy_url(url: str) -> str:
    """Strip userinfo for logging (``scheme://user:pw@host:port`` →
    ``scheme://host:port``)."""
    if "://" not in url or "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    _creds, _, hostpart = rest.rpartition("@")
    return f"{scheme}://<REDACTED>@{hostpart}"


def _parse_http_date(text: str) -> datetime:
    """Parse a Last-Modified / DAV:getlastmodified value. Returns
    epoch on parse failure so list_dir keeps working."""
    if not text:
        return datetime.fromtimestamp(0)
    for fmt in (
        "%a, %d %b %Y %H:%M:%S %Z",
        "%a, %d %b %Y %H:%M:%S GMT",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return datetime.fromtimestamp(0)


# ---------------------------------------------------------------------------
# Internal WebDAV client — does the HTTP and XML
# ---------------------------------------------------------------------------

class _WebDavClient:
    """Minimal WebDAV client over ``requests``.

    Supports the methods axross actually uses: PROPFIND (Depth 0/1),
    GET, PUT, DELETE, MKCOL, MOVE, COPY. Everything else raises.
    """

    PROPFIND_BODY = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
        b'<d:prop>'
        b'<d:displayname/>'
        b'<d:getcontentlength/>'
        b'<d:getlastmodified/>'
        b'<d:resourcetype/>'
        b'<d:getcontenttype/>'
        b'<d:getetag/>'
        b'<oc:checksums/>'
        b'</d:prop>'
        b'</d:propfind>'
    )

    QUOTA_BODY = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<d:propfind xmlns:d="DAV:">'
        b'<d:prop>'
        b'<d:quota-available-bytes/>'
        b'<d:quota-used-bytes/>'
        b'</d:prop>'
        b'</d:propfind>'
    )

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        proxies: dict[str, str] | None = None,
        timeout: float = 30.0,
    ):
        if requests is None:
            raise ImportError(
                "WebDAV support requires the 'requests' package. "
                "Install with: pip install axross[webdav]"
            )
        self._base = url.rstrip("/")
        parts = urlsplit(self._base)
        # Server-relative prefix (e.g. /remote.php/dav/files/alice for
        # Nextcloud). Used to strip from PROPFIND <href> entries so
        # callers see paths in the same shape they passed in.
        self._url_path = parts.path or ""
        self._auth = (username, password) if username else None
        self._timeout = timeout
        self.session = requests.Session()
        if proxies:
            self.session.proxies = dict(proxies)
        # Override default User-Agent so traffic doesn't shout
        # "python-requests/X.Y.Z". See docs/OPSEC.md #4.
        from core.client_identity import HTTP_USER_AGENT
        self.session.headers["User-Agent"] = HTTP_USER_AGENT

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _full_url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        # Quote path segments but preserve '/' so the URL stays well
        # formed. WebDAV servers expect URL-encoded high-bit chars.
        return self._base + quote(path, safe="/")

    def _strip_prefix(self, href: str) -> str:
        """Convert a <D:href> back to the client-side path the user
        passed in. ``href`` may be absolute (``http://host/dav/x``)
        or root-relative (``/dav/x``)."""
        href_path = urlsplit(href).path or href
        href_path = unquote(href_path)
        if self._url_path and href_path.startswith(self._url_path):
            href_path = href_path[len(self._url_path):]
        return href_path or "/"

    # ------------------------------------------------------------------
    # Request plumbing
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> "requests.Response":
        url = self._full_url(path)
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("auth", self._auth)
        return self.session.request(method, url, **kwargs)

    @staticmethod
    def _check_status(resp: "requests.Response", *, allowed: tuple[int, ...]) -> None:
        if resp.status_code in allowed:
            return
        if resp.status_code == 404:
            raise FileNotFoundError(f"WebDAV 404: {resp.request.method} {resp.request.url}")
        raise WebDavRequestError(
            f"WebDAV {resp.request.method} {resp.request.url}: HTTP {resp.status_code}",
            resp.status_code,
        )

    # ------------------------------------------------------------------
    # PROPFIND parsing
    # ------------------------------------------------------------------

    def _propfind(self, path: str, depth: str, body: bytes = PROPFIND_BODY) -> list[dict]:
        if _xml_fromstring is None:
            raise ImportError(
                "defusedxml is required to talk to WebDAV servers safely. "
                "Install with: pip install axross[webdav]"
            )
        # ``with`` closes the response (and returns its socket to the
        # pool) on every exit path — including the cap-exceeded raise
        # below. Without it, the connection-pool would be left holding
        # an unread half-response and subsequent requests on the same
        # session can read stale body bytes.
        with self._request(
            "PROPFIND", path,
            data=body,
            headers={
                "Content-Type": "application/xml; charset=utf-8",
                "Depth": depth,
            },
            stream=True,
        ) as resp:
            self._check_status(resp, allowed=(207, 200))
            # Stream the response so we can enforce a hard cap before
            # buffering the whole body (RAM-DoS protection on hostile /
            # huge servers).
            chunks: list[bytes] = []
            received = 0
            for chunk in resp.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                received += len(chunk)
                if received > MAX_PROPFIND_BYTES:
                    raise WebDavRequestError(
                        f"PROPFIND response exceeds {MAX_PROPFIND_BYTES} byte cap "
                        f"({received} bytes received)",
                        status=507,
                    )
                chunks.append(chunk)
        return self._parse_propfind(b"".join(chunks))

    def _parse_propfind(self, payload: bytes) -> list[dict]:
        root = _xml_fromstring(payload)
        results: list[dict] = []
        for resp_el in root.findall("d:response", _NSMAP):
            href_el = resp_el.find("d:href", _NSMAP)
            if href_el is None or not (href_el.text or "").strip():
                continue
            href_path = self._strip_prefix(href_el.text.strip())
            # First propstat with HTTP/1.1 200 OK is the live one;
            # 404s for missing properties get reported on a separate
            # propstat we can ignore.
            prop = None
            for ps in resp_el.findall("d:propstat", _NSMAP):
                status = (ps.findtext("d:status", default="", namespaces=_NSMAP) or "").upper()
                if " 200 " in status:
                    prop = ps.find("d:prop", _NSMAP)
                    break
            if prop is None:
                continue

            def _txt(tag: str) -> str:
                return (prop.findtext(tag, default="", namespaces=_NSMAP) or "").strip()

            displayname = _txt("d:displayname")
            size_text = _txt("d:getcontentlength")
            try:
                size = int(size_text)
            except ValueError:
                size = 0
            modified_text = _txt("d:getlastmodified")
            ctype = _txt("d:getcontenttype")
            etag = _txt("d:getetag").strip('"')

            rtype = prop.find("d:resourcetype", _NSMAP)
            is_dir = bool(rtype is not None and rtype.find("d:collection", _NSMAP) is not None)
            # Apache mod_dav doesn't always set resourcetype/collection;
            # fall back to content-type or trailing slash.
            if not is_dir:
                ctype_low = ctype.lower()
                if ctype_low == "httpd/unix-directory" or ctype_low.endswith("/directory"):
                    is_dir = True
                elif href_path.endswith("/") and not size:
                    is_dir = True

            # Nextcloud-style oc:checksums:
            # <oc:checksums><oc:checksum>SHA1:...</oc:checksum></oc:checksums>
            oc_checksums: list[str] = []
            oc_root = prop.find("oc:checksums", _NSMAP)
            if oc_root is not None:
                for c in oc_root.findall("oc:checksum", _NSMAP):
                    if c.text:
                        oc_checksums.append(c.text.strip())

            name = displayname or posixpath.basename(href_path.rstrip("/")) or ""
            results.append({
                "path": href_path,
                "name": name,
                "size": size,
                "modified": modified_text,
                "isdir": is_dir,
                "content_type": ctype,
                "etag": etag,
                "oc_checksums": oc_checksums,
            })
        return results

    # ------------------------------------------------------------------
    # Public WebDAV operations
    # ------------------------------------------------------------------

    def info(self, path: str) -> dict:
        results = self._propfind(path, depth="0")
        if not results:
            raise FileNotFoundError(f"WebDAV PROPFIND empty for {path}")
        # PROPFIND Depth: 0 returns the resource itself; pick the
        # entry whose path matches (some servers also include children).
        # Both sides go through the SAME rstrip — root then compares as
        # ``"" == ""``. Falling back to ``"/"`` for the LHS only would
        # mismatch Apache mod_dav's ``<href>/</href>`` (which our
        # _strip_prefix rstrips to ``""``) and would mis-fail the
        # is_dir('/') case.
        target = path.rstrip("/")
        for r in results:
            if r["path"].rstrip("/") == target:
                return r
        # No matching entry. A misbehaving server returning only an
        # unrelated child would have us silently misreport — fail loudly
        # instead so callers see the disagreement.
        raise FileNotFoundError(
            f"WebDAV PROPFIND returned no entry for {path!r} "
            f"(got {len(results)} unrelated entries)"
        )

    def list(self, path: str) -> list[dict]:
        results = self._propfind(path, depth="1")
        target = path.rstrip("/")
        return [r for r in results if r["path"].rstrip("/") != target]

    def is_dir(self, path: str) -> bool:
        try:
            return bool(self.info(path)["isdir"])
        except FileNotFoundError:
            return False

    def check(self, path: str) -> bool:
        try:
            self.info(path)
            return True
        except (FileNotFoundError, WebDavRequestError):
            return False

    def download_to(self, fileobj: IO[bytes], path: str) -> None:
        with self._request("GET", path, stream=True) as resp:
            self._check_status(resp, allowed=(200,))
            for chunk in resp.iter_content(chunk_size=64 * 1024):
                if chunk:
                    fileobj.write(chunk)

    def upload_from(self, fileobj: IO[bytes], path: str) -> None:
        # Stream the body — requests handles chunked transfer.
        resp = self._request("PUT", path, data=fileobj)
        self._check_status(resp, allowed=(200, 201, 204))

    def mkdir(self, path: str) -> None:
        resp = self._request("MKCOL", path)
        # 405 = already exists; treat as no-op so callers can be
        # idempotent (matches webdavclient3 historical behaviour).
        if resp.status_code == 405:
            return
        self._check_status(resp, allowed=(200, 201))

    def delete(self, path: str) -> None:
        resp = self._request("DELETE", path)
        self._check_status(resp, allowed=(200, 204, 404))

    def move(self, src: str, dst: str) -> None:
        dst_url = self._full_url(dst)
        resp = self._request(
            "MOVE", src,
            headers={"Destination": dst_url, "Overwrite": "T"},
        )
        self._check_status(resp, allowed=(200, 201, 204))

    def copy(self, src: str, dst: str) -> None:
        dst_url = self._full_url(dst)
        resp = self._request(
            "COPY", src,
            headers={"Destination": dst_url, "Overwrite": "T"},
        )
        self._check_status(resp, allowed=(200, 201, 204))

    def quota(self, path: str = "/") -> tuple[int, int, int]:
        """RFC 4331 quota-available-bytes / quota-used-bytes via
        PROPFIND. Returns ``(total, used, available)`` or ``(0,0,0)``
        if the server doesn't expose quota properties.

        The defusedxml import is repeated here (rather than relying on
        the module-level cache) so a runtime-broken install or a
        sandboxed test that hides defusedxml triggers the fail-closed
        path with a warning, rather than the cached module-level
        binding.
        """
        try:
            from defusedxml.ElementTree import fromstring as _local_fromstring
        except ImportError:
            log.warning(
                "defusedxml is required for disk_usage() on WebDAV "
                "(install via `pip install defusedxml`). Skipping "
                "quota query."
            )
            return (0, 0, 0)
        try:
            resp = self._request(
                "PROPFIND", path,
                data=self.QUOTA_BODY,
                headers={
                    "Content-Type": "application/xml; charset=utf-8",
                    "Depth": "0",
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("WebDAV quota PROPFIND failed: %s", exc)
            return (0, 0, 0)
        if resp.status_code not in (207, 200):
            return (0, 0, 0)
        tree = _local_fromstring(resp.content)
        avail_el = tree.find(".//{DAV:}quota-available-bytes")
        used_el = tree.find(".//{DAV:}quota-used-bytes")
        if avail_el is None or used_el is None:
            return (0, 0, 0)
        try:
            available = int(avail_el.text or "0")
            used = int(used_el.text or "0")
        except ValueError:
            return (0, 0, 0)
        return (used + available, used, available)


# ---------------------------------------------------------------------------
# Spooled writer — keeps the same API so transfer_worker doesn't care
# ---------------------------------------------------------------------------

class _SpooledWriter:
    """Write to a temp file, then upload via PUT on close."""

    def __init__(self, client: _WebDavClient, remote_path: str):
        self._client = client
        self._remote_path = remote_path
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)

    def write(self, data: bytes) -> int:
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        self._buf.seek(0)
        self._client.upload_from(self._buf, self._remote_path)
        self._buf.close()

    def discard(self) -> None:
        """Drop buffered bytes without uploading (transfer-cancel path)."""
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# Public session
# ---------------------------------------------------------------------------

class WebDavSession:
    """WebDAV backend implementing the FileBackend protocol.

    Compatible with Nextcloud, ownCloud, Apache mod_dav, IIS WebDAV,
    and any RFC 4918-compliant server. Auth is HTTP Basic via the
    URL's path prefix.
    """

    def __init__(
        self,
        url: str,
        username: str = "",
        password: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if requests is None:
            raise ImportError(
                "WebDAV support requires the 'requests' package. "
                "Install with: pip install axross[webdav]"
            )
        if _xml_fromstring is None:
            raise ImportError(
                "WebDAV support requires 'defusedxml' (we refuse to parse "
                "remote XML with the stdlib parser). "
                "Install with: pip install axross[webdav]"
            )

        self._url = url.rstrip("/")
        self._username = username
        self._password = password
        self._proxy = _build_requests_proxies(
            proxy_type, proxy_host, proxy_port,
            proxy_username, proxy_password,
        )
        self._client = _WebDavClient(
            self._url, username, password, proxies=self._proxy,
        )
        if self._proxy:
            log.info(
                "WebDAV via proxy: %s",
                {k: _redact_proxy_url(v) for k, v in self._proxy.items()},
            )

        # Connection probe — PROPFIND Depth 0 on the root tells us the
        # auth + base URL line up before the first user-driven op.
        try:
            self._client.info("/")
        except FileNotFoundError:
            # Some servers refuse PROPFIND on "/" (returning 404)
            # but still serve the actual mount path. That's fine —
            # connection is alive, we'll find out on the first list.
            pass
        except Exception as e:
            raise OSError(f"Cannot connect to WebDAV server: {e}") from e

        log.info("WebDAV connected: %s@%s", username, self._url)

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"{self._username}@{self._url} (WebDAV)"

    @property
    def connected(self) -> bool:
        try:
            self._client.info("/")
            return True
        except FileNotFoundError:
            return True
        except Exception:
            return False

    def close(self) -> None:
        try:
            self._client.session.close()
        except Exception:  # noqa: BLE001
            pass

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self._norm(path)
        try:
            entries = self._client.list(path)
        except FileNotFoundError as e:
            raise OSError(f"Cannot list {path}: {e}") from e
        except WebDavRequestError as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        items: list[FileItem] = []
        for entry in entries:
            name = entry["name"]
            if not name:
                continue
            items.append(FileItem(
                name=name,
                size=int(entry["size"]),
                modified=_parse_http_date(entry["modified"]),
                is_dir=bool(entry["isdir"]),
            ))
        return items

    def stat(self, path: str) -> FileItem:
        path = self._norm(path)
        try:
            info = self._client.info(path)
        except FileNotFoundError as e:
            raise OSError(f"Cannot stat {path}: {e}") from e
        except WebDavRequestError as e:
            raise OSError(f"Cannot stat {path}: {e}") from e
        name = posixpath.basename(path.rstrip("/")) or path
        return FileItem(
            name=name,
            size=int(info["size"]),
            modified=_parse_http_date(info["modified"]),
            is_dir=bool(info["isdir"]),
        )

    def is_dir(self, path: str) -> bool:
        return self._client.is_dir(self._norm(path))

    def exists(self, path: str) -> bool:
        return self._client.check(self._norm(path))

    def open_read(self, path: str) -> IO[bytes]:
        buf = io.BytesIO()
        try:
            self._client.download_to(buf, self._norm(path))
        except FileNotFoundError as e:
            raise OSError(f"Cannot read {path}: {e}") from e
        except WebDavRequestError as e:
            raise OSError(f"Cannot read {path}: {e}") from e
        buf.seek(0)
        return buf

    # ------------------------------------------------------------------
    # FileBackend — write surface
    # ------------------------------------------------------------------

    def mkdir(self, path: str) -> None:
        try:
            self._client.mkdir(self._norm(path))
        except WebDavRequestError as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        # WebDAV DELETE on a collection removes the tree by default —
        # there's no "non-recursive" knob in the spec, so the
        # ``recursive`` flag is ignored (matches webdavclient3 behaviour).
        try:
            self._client.delete(self._norm(path))
        except WebDavRequestError as e:
            raise OSError(f"Cannot remove {path}: {e}") from e

    def rename(self, src: str, dst: str) -> None:
        try:
            self._client.move(self._norm(src), self._norm(dst))
        except WebDavRequestError as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            # WebDAV has no append — download, concat, re-upload.
            try:
                with self.open_read(path) as f:
                    existing = f.read()
            except OSError:
                existing = b""
            writer = _SpooledWriter(self._client, self._norm(path))
            writer.write(existing)
            return writer
        return _SpooledWriter(self._client, self._norm(path))

    def copy(self, src: str, dst: str) -> None:
        """WebDAV COPY method — server-side, no client bytes."""
        try:
            self._client.copy(self._norm(src), self._norm(dst))
        except WebDavRequestError as exc:
            raise OSError(f"WebDAV copy {src} -> {dst} failed: {exc}") from exc

    # ------------------------------------------------------------------
    # FileBackend — metadata + path helpers
    # ------------------------------------------------------------------

    def normalize(self, path: str) -> str:
        return posixpath.normpath(path) or "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("WebDAV does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("WebDAV does not support symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return a content fingerprint.

        Nextcloud/ownCloud expose ``oc:checksums`` whose entries look
        like ``SHA1:abcd...``. If one matches the requested algorithm
        we return it. Otherwise fall back to ``DAV:getetag`` — strong
        etags on mod_dav are inode-based and change with content, so
        they work as a fingerprint even if not technically a hash.
        """
        try:
            info = self._client.info(self._norm(path))
        except FileNotFoundError as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        except WebDavRequestError as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc

        for entry in info.get("oc_checksums", []):
            if ":" not in entry:
                continue
            algo, _, hexpart = entry.partition(":")
            if algo.lower() == algorithm.lower():
                return f"{algorithm}:{hexpart.lower()}"

        etag = info.get("etag", "")
        if etag:
            return f"etag:{etag}"
        return ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        try:
            return self._client.quota(self._norm(path) or "/")
        except Exception as e:  # noqa: BLE001 — quota is best-effort
            log.debug("WebDAV disk_usage query failed: %s", e)
            return (0, 0, 0)

    @staticmethod
    def _norm(path: str) -> str:
        """Ensure path has leading slash and no trailing slash (except root)."""
        if not path.startswith("/"):
            path = "/" + path
        return path
