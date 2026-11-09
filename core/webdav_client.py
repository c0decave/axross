"""WebDAV backend implementing the FileBackend protocol.

Pure ``requests`` + ``defusedxml`` implementation — no third-party
WebDAV SDK. WebDAV is HTTP + a small XML vocabulary; the dependency
that used to live here (``webdavclient3``) added ~2k LOC for what
amounts to PROPFIND, GET, PUT, DELETE, MKCOL, MOVE, COPY. This
module is a focused re-implementation against RFC 4918 (WebDAV) and
RFC 4331 (quota).

The public surface is :class:`WebDavSession`. Internally it talks to
:class:`_WebDavClient` which owns the ``requests.Session`` of every
thread and the XML parsing.

Requires: ``pip install axross[webdav]`` — ``requests`` +
``defusedxml``. ``defusedxml`` is **mandatory** because every
PROPFIND response we parse comes from an external server (a trust
boundary), so we refuse to fall back to the stdlib parser.
"""

from __future__ import annotations

import errno
import logging
import posixpath
import threading
import weakref
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import IO, Any
from urllib.parse import quote, unquote, urlsplit

from core import transfer_hooks
from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.path_policy import refuse_folder_path
from core.read_spool import new_spool
from core.redaction import redact_url
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
#: The quota answer is one small multistatus (Depth: 0).
MAX_QUOTA_BYTES = 1024 * 1024


# C0 characters XML 1.0 cannot carry (TAB, LF and CR it can).
_XML_UNSAFE = frozenset(chr(c) for c in range(0x20)) - {"\t", "\n", "\r"}


def _refuse_unlistable_name(path: str) -> None:
    """OSError (EINVAL) for a name a PROPFIND answer cannot carry: the
    multistatus is XML 1.0, where U+0001 and the other C0 controls are
    not allowed even as character references. The server stored such a
    file, and every listing of its folder then failed to parse."""
    bad = sorted({c for c in path if c in _XML_UNSAFE})
    if bad:
        points = ",".join(f"U+{ord(c):04X}" for c in bad)
        raise OSError(
            errno.EINVAL,
            f"WebDAV cannot list a name with control characters ({points}): {path!r}",
        )


#: "Not processed, try again later" (RFC 6585 4, RFC 9110 15.6.4).
_RETRY_STATUSES = frozenset({429, 503})
#: Requests that may be sent twice: nothing changes, or the second one
#: leaves what the first left (PUT of the same body, DELETE, MKCOL).
_RETRY_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PROPFIND", "PUT", "DELETE", "MKCOL"})
#: MOVE / COPY run a second time after an unseen success answer
#: differently (412 under "Overwrite: F", 404 for the moved source): only
#: 429 - a rate limit, which turns the request away before it runs - is
#: taken as "nothing happened". A 503 may come from a gateway that gave
#: up on a server still working on it.
_RETRY_ON_429_ONLY = frozenset({"MOVE", "COPY"})


def _may_retry(method: str, status) -> bool:
    method = method.upper()
    if method in _RETRY_ON_429_ONLY:
        return status == 429
    return method in _RETRY_METHODS and status in _RETRY_STATUSES


def _body_rewinder(data):
    """A function that puts *data* back to where the first send started,
    or None when it cannot be sent again (a stream without seek / tell)."""
    if data is None or isinstance(data, (bytes, bytearray, memoryview, str, dict)):
        return lambda: None
    seek, tell = getattr(data, "seek", None), getattr(data, "tell", None)
    if seek is None or tell is None:
        return None
    try:
        if hasattr(data, "seekable") and not data.seekable():
            return None
        start = tell()
    except (OSError, ValueError):
        return None
    return lambda: seek(start)


class WebDavRequestError(OSError):
    """Raised when a WebDAV HTTP request returns an error status."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def _build_requests_proxies(
    proxy_type: str,
    host: str,
    port: int,
    username: str = "",
    password: str = "",
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
    return redact_url(url)


def _parse_xml(fromstring, payload: bytes):
    """Parse a PROPFIND answer; anything unusable is a WebDavRequestError.

    defusedxml raises ParseError (a SyntaxError) for malformed XML, its
    EntitiesForbidden / DTDForbidden (ValueError subclasses) for XXE and
    entity expansion, and expat a LookupError for an unknown encoding.
    None of them is an OSError, which is what every caller handles.
    """
    try:
        return fromstring(payload)
    except (SyntaxError, ValueError, LookupError) as exc:
        raise WebDavRequestError(
            f"WebDAV PROPFIND answer is not usable XML: {type(exc).__name__}: {exc}"
        ) from exc


def _parse_http_date(text: str) -> datetime:
    """Parse a Last-Modified / DAV:getlastmodified value. Returns
    epoch on parse failure so list_dir keeps working."""
    if not text:
        return datetime.fromtimestamp(0)
    # RFC 1123 dates are GMT by definition (RFC 9110 5.6.7). Not strptime's
    # %a / %b: those follow LC_TIME, which Qt sets from the user's locale -
    # under de_DE every date would fail and read as 1970.
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        parsed = None
    if parsed is not None:
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    for fmt, utc in (
        ("%Y-%m-%dT%H:%M:%S%z", False),
        ("%Y-%m-%dT%H:%M:%S", False),
    ):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc) if utc else parsed
    return datetime.fromtimestamp(0)


# ---------------------------------------------------------------------------
# One requests.Session per thread
# ---------------------------------------------------------------------------


def _close_quietly(session) -> None:
    try:
        session.close()
    except Exception:  # noqa: BLE001 - nothing left to report it to
        pass


class _ThreadSession:
    """The requests.Session of one thread. ``closer`` closes it once:
    when the thread ends (its threading.local entry, the only strong
    reference, goes away) or when the client closes every session."""

    __slots__ = ("session", "generation", "closer", "__weakref__")

    def __init__(self, session, generation: int) -> None:
        self.session = session
        self.generation = generation
        self.closer = weakref.finalize(self, _close_quietly, session)


class _ThreadSessions:
    """requests never promised that a Session is thread safe
    (psf/requests#2766: the cookie jar, the adapters), and a WebDavSession
    is used by transfer workers, listing threads and the GUI thread at
    once. Each thread gets a Session of its own from ``factory`` and keeps
    it for its later calls; :meth:`close_all` closes every one, and a
    thread that calls again afterwards gets a new one."""

    def __init__(self) -> None:
        self._local = threading.local()
        self._lock = threading.Lock()
        self._open: weakref.WeakSet[_ThreadSession] = weakref.WeakSet()
        self._generation = 0

    def get(self, factory):
        holder = getattr(self._local, "holder", None)
        if holder is not None and holder.generation == self._generation:
            return holder.session
        session = factory()
        with self._lock:
            holder = _ThreadSession(session, self._generation)
            self._open.add(holder)
        self._local.holder = holder  # replaces (and so closes) a stale one
        return session

    def close_all(self) -> None:
        with self._lock:
            holders = list(self._open)
            self._open = weakref.WeakSet()
            self._generation += 1
        for holder in holders:
            holder.closer()


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
        b"<d:prop>"
        b"<d:displayname/>"
        b"<d:getcontentlength/>"
        b"<d:getlastmodified/>"
        b"<d:resourcetype/>"
        b"<d:getcontenttype/>"
        b"<d:getetag/>"
        b"<oc:checksums/>"
        b"</d:prop>"
        b"</d:propfind>"
    )

    QUOTA_BODY = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<d:propfind xmlns:d="DAV:">'
        b"<d:prop>"
        b"<d:quota-available-bytes/>"
        b"<d:quota-used-bytes/>"
        b"</d:prop>"
        b"</d:propfind>"
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
        # callers see paths in the same shape they passed in. Kept
        # decoded: hrefs are unquoted before the comparison, and a base
        # such as .../files/John%20Doe would otherwise never match.
        self._url_path = unquote(parts.path or "")
        self._auth = (username, password) if username else None
        self._timeout = timeout
        self._proxies = dict(proxies) if proxies else None
        # The constructing thread's Session now: a proxy that cannot be
        # locked in fails here, not on the first request.
        self.session  # noqa: B018 - built for its side effect

    @property
    def session(self) -> "requests.Session":
        """The calling thread's Session (see :class:`_ThreadSessions`)."""
        sessions = self.__dict__.get("_thread_sessions")
        if sessions is None:
            sessions = self.__dict__.setdefault("_thread_sessions", _ThreadSessions())
        return sessions.get(self._new_session)

    def _new_session(self) -> "requests.Session":
        """A Session built as every one of this client is: locked to the
        profile proxy (never the environment's), with the axross
        User-Agent. Auth and timeout go with each request (``_request``)."""
        from core.client_identity import HTTP_USER_AGENT
        from core.proxy import lock_requests_session_to_profile_proxy

        session = requests.Session()
        try:
            lock_requests_session_to_profile_proxy(session, getattr(self, "_proxies", None))
        except BaseException:
            session.close()
            raise
        # Override default User-Agent so traffic doesn't shout
        # "python-requests/X.Y.Z". See docs/OPSEC.md #4.
        session.headers["User-Agent"] = HTTP_USER_AGENT
        return session

    def close(self) -> None:
        """Close every thread's Session."""
        sessions = self.__dict__.get("_thread_sessions")
        if sessions is not None:
            sessions.close_all()

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
            href_path = href_path[len(self._url_path) :]
        return href_path or "/"

    # ------------------------------------------------------------------
    # Request plumbing
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> "requests.Response":
        """One request, sent again (at most cloud_http.ATTEMPTS times in
        all, after cloud_http's pause / the server's Retry-After) while the
        server answers 429 or 503 - "not processed, try later": Nextcloud's
        brute-force and rate limits, a server in maintenance mode, a busy
        proxy. Only requests that may be sent twice (_may_retry), and only
        with a body that can be sent again from its start."""
        from core import cloud_http

        url = self._full_url(path)
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("auth", self._auth)
        rewind = _body_rewinder(kwargs.get("data"))
        attempt = 1
        while True:
            resp = self.session.request(method, url, **kwargs)
            status = getattr(resp, "status_code", None)
            if (
                attempt >= cloud_http.ATTEMPTS
                or rewind is None
                or not _may_retry(method, status)
            ):
                return resp
            headers = getattr(resp, "headers", None) or {}
            retry_after = cloud_http.retry_after_seconds(headers.get("Retry-After"))
            close = getattr(resp, "close", None)
            if close is not None:
                close()
            log.info(
                "WebDAV %s %s: HTTP %s, trying again (%d of %d)",
                method, redact_url(url), status, attempt + 1, cloud_http.ATTEMPTS,
            )
            cloud_http.pause(attempt, retry_after)
            rewind()
            attempt += 1

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
            "PROPFIND",
            path,
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
        root = _parse_xml(_xml_fromstring, payload)
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

            # The name is the href's last segment - the resource's address.
            # DAV:displayname is presentation text: it may differ from the
            # segment (Nextcloud), repeat a sibling's name or hold "/" and
            # "..", and every later call addresses the entry by its name.
            name = posixpath.basename(href_path.rstrip("/")) or ""
            results.append(
                {
                    "path": href_path,
                    "name": name,
                    "size": size,
                    "modified": modified_text,
                    "isdir": is_dir,
                    "content_type": ctype,
                    "etag": etag,
                    "oc_checksums": oc_checksums,
                }
            )
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
            f"WebDAV PROPFIND returned no entry for {path!r} (got {len(results)} unrelated entries)"
        )

    def list(self, path: str) -> list[dict]:
        results = self._propfind(path, depth="1")
        target = path.rstrip("/")
        if any(r["path"].rstrip("/") == target and not r["isdir"] for r in results):
            # Depth 1 on a FILE answers the file alone: that was listed as
            # an empty folder.
            raise NotADirectoryError(errno.ENOTDIR, f"{path} is not a folder", path)
        return [r for r in results if r["path"].rstrip("/") != target]

    def is_dir(self, path: str) -> bool:
        try:
            return bool(self.info(path)["isdir"])
        except FileNotFoundError:
            return False

    def check(self, path: str) -> bool:
        """False only when the server says the resource is not there (404,
        410). Any other failure (403, 429, 5xx, a broken answer) is an
        OSError: "absent" is the go-ahead of if_exists="fail" / "newer" and
        of an overwrite, and would replace the file the user chose to keep."""
        try:
            self.info(path)
            return True
        except FileNotFoundError:
            return False
        except WebDavRequestError as exc:
            if exc.status in (404, 410):
                return False
            raise

    def download_stream(self, path: str) -> "requests.Response":
        """The GET response of *path*, its body not read yet (the caller
        closes it): a folder is IsADirectoryError, a missing file
        FileNotFoundError."""
        resp = self._request("GET", path, stream=True)
        try:
            self._check_status(resp, allowed=(200,))
            if resp.headers.get("Content-Type", "").lower().startswith("text/html"):
                # GET on a collection answers its HTML index (Apache, nginx,
                # sabre/dav, axross' own server): that page was "read" as the
                # folder's content. Only an HTML answer pays the PROPFIND.
                try:
                    is_collection = bool(self.info(path)["isdir"])
                except (FileNotFoundError, WebDavRequestError):
                    is_collection = False
                if is_collection:
                    raise IsADirectoryError(errno.EISDIR, f"{path} is a folder", path)
        except BaseException:
            resp.close()
            raise
        return resp

    def download_to(self, fileobj: IO[bytes], path: str) -> None:
        with self.download_stream(path) as resp:
            for chunk in resp.iter_content(chunk_size=64 * 1024):
                if chunk:
                    fileobj.write(chunk)

    def upload_from(self, fileobj: IO[bytes], path: str) -> None:
        # Stream the body — requests handles chunked transfer.
        resp = self._request("PUT", path, data=fileobj)
        self._check_status(resp, allowed=(200, 201, 204))

    def mkdir(self, path: str) -> None:
        resp = self._request("MKCOL", path)
        if resp.status_code == 405:
            # 405: something is there (RFC 4918 9.3.1). A folder is the
            # idempotent no-op mkdir always was; a FILE of that name was
            # taken for "folder exists" too and the caller wrote into a
            # folder that was never made.
            self._refuse_taken_by_a_file(path, resp)
            return
        if resp.status_code == 409:
            # 409: the parent is missing - or is a file.
            parent = posixpath.dirname(path.rstrip("/")) or "/"
            try:
                parent_is_dir = bool(self.info(parent)["isdir"])
            except FileNotFoundError:
                raise FileNotFoundError(
                    errno.ENOENT, f"Cannot create {path}: the parent folder is missing", path
                ) from None
            if not parent_is_dir:
                raise NotADirectoryError(
                    errno.ENOTDIR, f"Cannot create {path}: {parent} is a file", path
                )
        self._check_status(resp, allowed=(200, 201))

    def _refuse_taken_by_a_file(self, path: str, resp) -> None:
        try:
            isdir = bool(self.info(path)["isdir"])
        except FileNotFoundError:
            # 405 for a name that is not there: MKCOL is not allowed here.
            self._check_status(resp, allowed=(200, 201))
            return
        if not isdir:
            raise FileExistsError(
                errno.EEXIST, f"Cannot create the folder {path}: a file has that name", path
            )

    def delete(self, path: str) -> None:
        resp = self._request("DELETE", path)
        if resp.status_code in (404, 410):
            # Counted as success: removing a typo said "removed".
            raise FileNotFoundError(errno.ENOENT, f"Cannot remove {path}: not found", path)
        self._check_status(resp, allowed=(200, 204))

    def move(self, src: str, dst: str, *, overwrite: bool = False) -> None:
        self._move_or_copy("MOVE", src, dst, overwrite)

    def copy(self, src: str, dst: str, *, overwrite: bool = False) -> None:
        self._move_or_copy("COPY", src, dst, overwrite)

    def _move_or_copy(self, method: str, src: str, dst: str, overwrite: bool) -> None:
        """MOVE / COPY with ``Overwrite: F`` unless *overwrite*. With T the
        server DELETES an existing destination first (RFC 4918 9.8.4,
        9.9.3), a whole folder included. A taken destination under F is
        412: FileExistsError."""
        resp = self._request(
            method,
            src,
            headers={"Destination": self._full_url(dst), "Overwrite": "T" if overwrite else "F"},
        )
        if resp.status_code == 412 and not overwrite:
            raise FileExistsError(
                errno.EEXIST, f"WebDAV {method}: the destination exists", dst
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
            # Streamed and capped: the pane asks on every navigation, and a
            # hostile server could otherwise send an endless body.
            with self._request(
                "PROPFIND",
                path,
                data=self.QUOTA_BODY,
                headers={
                    "Content-Type": "application/xml; charset=utf-8",
                    "Depth": "0",
                },
                stream=True,
            ) as resp:
                if resp.status_code not in (207, 200):
                    return (0, 0, 0)
                chunks: list[bytes] = []
                received = 0
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    received += len(chunk)
                    if received > MAX_QUOTA_BYTES:
                        log.debug("WebDAV quota answer exceeds %d bytes", MAX_QUOTA_BYTES)
                        return (0, 0, 0)
                    chunks.append(chunk)
        except Exception as exc:  # noqa: BLE001
            log.debug("WebDAV quota PROPFIND failed: %s", exc)
            return (0, 0, 0)
        try:
            tree = _parse_xml(_local_fromstring, b"".join(chunks))
        except WebDavRequestError as exc:
            log.debug("WebDAV quota answer unusable: %s", exc)
            return (0, 0, 0)
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


#: Guards WebDavSession._written_paths (transfer workers write in parallel).
_WRITTEN_LOCK = threading.Lock()


class _SpooledWriter:
    """Write to a temp file, then upload via PUT on close."""

    def __init__(self, client: _WebDavClient, remote_path: str, on_put=None):
        self._client = client
        self._remote_path = remote_path
        self._buf = new_spool(max_size=8 * 1024 * 1024)
        self._closed = False
        #: Called with the remote path once the PUT went through.
        self._on_put = on_put
        # The running transfer's Cancel and progress (core.transfer_hooks):
        # the PUT happens in close(), after the copy loop.
        self._hooks = transfer_hooks.current()
        if self._hooks is not None:
            self._hooks.expect_upload()

    def write(self, data: bytes) -> int:
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        hooks = self._hooks
        try:
            size = self._buf.seek(0, 2)
            self._buf.seek(0)
            if hooks is None:
                self._client.upload_from(self._buf, self._remote_path)
            else:
                # The body is read through ReadProgress: every block the
                # PUT sends checks Cancel and counts as sent. A cancelled
                # PUT may leave a partial file on servers that write in
                # place: a plain InterruptedError, the engine rolls back.
                hooks.check()
                body = transfer_hooks.ReadProgress(self._buf, hooks, size)
                try:
                    with transfer_hooks.bound(hooks):
                        self._client.upload_from(body, self._remote_path)
                except Exception as exc:
                    if hooks.cancelled():
                        # requests wraps the InterruptedError a body read
                        # raised into a ConnectionError.
                        raise InterruptedError(transfer_hooks.CANCELLED) from exc
                    raise
                hooks.sent(size, size, check=False)
        finally:
            self._buf.close()
        if self._on_put is not None:
            self._on_put(self._remote_path)

    def discard(self) -> None:
        """Drop buffered bytes without uploading (transfer-cancel path)."""
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


# ---------------------------------------------------------------------------
# Public session
# ---------------------------------------------------------------------------


class WebDavSession(SessionLifecycle):
    """WebDAV backend implementing the FileBackend protocol.

    Compatible with Nextcloud, ownCloud, Apache mod_dav, IIS WebDAV,
    and any RFC 4918-compliant server. Auth is HTTP Basic via the
    URL's path prefix.
    """

    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

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
        self._display_url = redact_url(self._url)
        self._username = username
        self._password = password
        self._proxy = _build_requests_proxies(
            proxy_type,
            proxy_host,
            proxy_port,
            proxy_username,
            proxy_password,
        )
        self._client = _WebDavClient(
            self._url,
            username,
            password,
            proxies=self._proxy,
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

        log.info("WebDAV connected: %s@%s", username, self._display_url)

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"{self._username}@{self._display_url} (WebDAV)"

    @property
    def connected(self) -> bool:
        try:
            self._client.info("/")
            return True
        except FileNotFoundError:
            return True
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("WebDAV liveness check failed: %s", exc)
            return False

    def close(self) -> None:
        log.info("WebDAV disconnecting: %s", self._display_url)
        try:
            self._client.close()
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
            raise FileNotFoundError(errno.ENOENT, f"Cannot list {path}: {e}", path) from e
        except WebDavRequestError as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        items: list[FileItem] = []
        for entry in entries:
            name = entry["name"]
            if not name or name in (".", ".."):
                continue
            items.append(
                FileItem(
                    name=name,
                    size=int(entry["size"]),
                    modified=_parse_http_date(entry["modified"]),
                    is_dir=bool(entry["isdir"]),
                )
            )
        return items

    def stat(self, path: str) -> FileItem:
        folder_only = path.endswith("/") and bool(path.strip("/"))
        path = self._norm(path)
        try:
            info = self._client.info(path)
        except FileNotFoundError as e:
            raise FileNotFoundError(errno.ENOENT, f"Cannot stat {path}: {e}", path) from e
        except WebDavRequestError as e:
            raise OSError(f"Cannot stat {path}: {e}") from e
        if folder_only and not info["isdir"]:
            # The slash is normalized away: "g/" answered with the file g.
            raise NotADirectoryError(errno.ENOTDIR, f"Cannot stat {path}/: not a folder", path)
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
        from core.read_spool import (
            StreamedBody,
            ensure_stream_room,
            new_read_spool,
            streaming_wanted,
        )

        if streaming_wanted() and isinstance(self._client, _WebDavClient):
            # The transfer engine reads front to back: the body as it
            # arrives, no spool beside the local copy (twice the room).
            try:
                resp = self._client.download_stream(self._norm(path))
            except FileNotFoundError as e:
                raise FileNotFoundError(errno.ENOENT, f"Cannot read {path}: {e}", path) from e
            except WebDavRequestError as e:
                raise OSError(f"Cannot read {path}: {e}") from e
            try:
                ensure_stream_room(int(resp.headers.get("Content-Length")))
            except (AttributeError, TypeError, ValueError):
                pass
            except BaseException:
                resp.close()
                raise
            return StreamedBody(resp.iter_content(chunk_size=64 * 1024),
                                what=f"Cannot read {path}", close=resp.close)
        # Spooled, not a BytesIO: the whole file used to sit in RAM.
        buf = new_read_spool()
        # In a running transfer every block checks Cancel and counts as
        # received (the whole download happens here, before the copy loop).
        hooks = transfer_hooks.current()
        sink = buf if hooks is None else transfer_hooks.WriteProgress(buf, hooks)
        try:
            self._client.download_to(sink, self._norm(path))
        except FileNotFoundError as e:
            buf.close()
            raise FileNotFoundError(errno.ENOENT, f"Cannot read {path}: {e}", path) from e
        except WebDavRequestError as e:
            buf.close()
            raise OSError(f"Cannot read {path}: {e}") from e
        except BaseException:
            buf.close()
            raise
        buf.seek(0)
        return buf

    # ------------------------------------------------------------------
    # FileBackend — write surface
    # ------------------------------------------------------------------

    def mkdir(self, path: str) -> None:
        _refuse_unlistable_name(path)
        try:
            self._client.mkdir(self._norm(path))
        except WebDavRequestError as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        # WebDAV DELETE on a collection always removes the whole tree
        # (RFC 4918 9.6.1: Depth infinity is the only depth), so a
        # non-recursive remove has to refuse a collection with members
        # itself, the way rmdir does.
        target = self._norm(path)
        try:
            if not recursive and self._client.is_dir(target) and self._client.list(target):
                raise OSError(errno.ENOTEMPTY, f"Directory not empty: {path}", path)
            self._client.delete(target)
        except WebDavRequestError as e:
            raise OSError(f"Cannot remove {path}: {e}") from e

    def rename(self, src: str, dst: str) -> None:
        _refuse_unlistable_name(dst)
        # The path is normalized before the MOVE: a file renamed to "x/"
        # became a FILE x. A folder may be named so.
        refuse_folder_path(dst, "rename to",
                           source_is_file=lambda: self.exists(src) and not self.is_dir(src))
        try:
            self._guarded_move_or_copy(self._client.move, src, dst, "rename")
        except WebDavRequestError as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    def _guarded_move_or_copy(self, call, src: str, dst: str, what: str) -> None:
        """*call* (the client's move or copy) without letting the server
        delete a folder to make room. A taken destination is replaced only
        when both ends are files - what rename and copy do on every other
        backend; a folder at either end is refused and nothing changes."""
        src, dst = self._norm(src), self._norm(dst)
        try:
            call(src, dst)
            return
        except FileExistsError:
            pass
        if self.is_dir(dst):
            raise IsADirectoryError(
                errno.EISDIR, f"Cannot {what} {src} -> {dst}: the destination is a folder", dst
            )
        if self.is_dir(src):
            raise FileExistsError(
                errno.EEXIST, f"Cannot {what} the folder {src} over the file {dst}", dst
            )
        call(src, dst, overwrite=True)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if path.endswith("/") and path.strip("/"):
            # PUT "x/" made a FILE "x" on servers that drop the slash.
            raise IsADirectoryError(
                errno.EISDIR, f"Cannot write {path}: a path ending in '/' names a folder", path
            )
        _refuse_unlistable_name(path)
        if append:
            # WebDAV has no append — download, concat, re-upload.
            cap = self._MAX_APPEND_EXISTING_SIZE
            existing = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="WebDAV",
                logger=log,
            )
            if len(existing) > cap:
                raise OSError(
                    f"WebDAV append: existing file exceeds {cap // (1024 * 1024)} MiB cap"
                )
            writer = _SpooledWriter(self._client, self._norm(path), self._note_put)
            writer.write(existing)
            return writer
        return _SpooledWriter(self._client, self._norm(path), self._note_put)

    def copy(self, src: str, dst: str) -> None:
        """WebDAV COPY method — server-side, no client bytes."""
        _refuse_unlistable_name(dst)
        try:
            self._guarded_move_or_copy(self._client.copy, src, dst, "copy")
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
        raise OSError(f"{type(self).__name__} does not expose file version history")

    # -- what checksum() of a file this session wrote answers ---------------
    #: Paths this session PUT and has not been asked the checksum of yet.
    _WRITTEN_KEPT = 256
    #: Once written files proved to come back without the hash, still ask
    #: for every this-many-th one: a server that hashes later (or only some
    #: uploads) is noticed again.
    RECHECK_WRITTEN_EVERY = 50
    _written_paths: dict | None = None
    #: algorithm -> True once a written file came back with it, False while
    #: every one asked came back without it.
    _written_hash: dict | None = None
    _written_skips = 0

    def _note_put(self, remote_path: str) -> None:
        with _WRITTEN_LOCK:
            written = self._written_paths
            if written is None:
                written = self._written_paths = {}
            written[remote_path] = None
            while len(written) > self._WRITTEN_KEPT:
                written.pop(next(iter(written)), None)

    def checksum_kinds(self, path: str = "", *, written: bool = False) -> frozenset[str] | None:
        """What :meth:`checksum` (default algorithm) can answer for *path*.

        Unknown (None) except for a file this session has just *written*
        when the files it wrote before came back without a SHA-256: the
        server keeps no hash of an upload (only Nextcloud and ownCloud
        report ``oc:checksums``, and those only what an uploader sent, or
        their own SHA1 / MD5 / Adler-32), so the answer is the ETag - a
        storage fingerprint the transfer engine never compares. It then
        skips the PROPFIND. Every RECHECK_WRITTEN_EVERY-th file is still
        asked."""
        if not written or (self._written_hash or {}).get("sha256") is not False:
            return None
        self._written_skips += 1
        if self._written_skips % self.RECHECK_WRITTEN_EVERY == 0:
            return None
        return frozenset({"etag"})

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return a content fingerprint.

        Nextcloud/ownCloud expose ``oc:checksums`` whose entries look
        like ``SHA1:abcd...``. If one matches the requested algorithm
        we return it. Otherwise fall back to ``DAV:getetag`` — strong
        etags on mod_dav are inode-based and change with content, so
        they work as a fingerprint even if not technically a hash.
        """
        norm = self._norm(path)
        try:
            info = self._client.info(norm)
        except FileNotFoundError as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        except WebDavRequestError as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc

        found = ""
        # Nextcloud / ownCloud put every checksum of a file into ONE
        # <oc:checksum>, separated by blanks ("SHA1:.. MD5:.. ADLER32:..").
        tokens = [token for entry in info.get("oc_checksums", []) for token in entry.split()]
        for token in tokens:
            algo, sep, hexpart = token.partition(":")
            if sep and hexpart and algo.lower() == algorithm.lower():
                found = f"{algorithm}:{hexpart.lower()}"
                break
        with _WRITTEN_LOCK:
            written = self._written_paths
            was_written = written is not None and written.pop(norm, False) is None
        if was_written:
            # A file this session wrote: what the server keeps of uploads.
            hashes = self._written_hash
            if hashes is None:
                hashes = self._written_hash = {}
            key = algorithm.lower()
            hashes[key] = bool(found) or hashes.get(key) is True
        if found:
            return found

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
