"""Reverse-serve — expose an axross backend as a server endpoint.

The leverage idea: every tool that already speaks S3 (terraform,
aws-cli, restic, rclone, …) or WebDAV (browsers, gnome-files,
cadaver, davfs2, …) suddenly has access to *any* protocol axross
speaks — because axross stands in front, accepting their requests and
forwarding them to whatever backend you opened (SFTP, SMB, IMAP,
RamFS, Postgres-FS, …).

Two server flavours in this module, sharing a single ``http.server``-
based skeleton:

* :class:`ReverseS3Server` — minimum-viable S3 API: ListBucket,
  GetObject, PutObject, DeleteObject, HeadBucket, HeadObject.
  Path-style addressing only (``/bucket/key`` — no virtual host
  parsing). Sufficient for ``aws s3 cp`` / ``aws s3 ls`` / restic /
  rclone with ``provider = Other``.
* :class:`ReverseWebDAVServer` — minimum-viable WebDAV: GET, PUT,
  PROPFIND (depth 0/1), MKCOL, MOVE, COPY, DELETE, OPTIONS, HEAD,
  LOCK/UNLOCK as no-ops. Compatible with cadaver, davfs2, gnome-files
  and macOS Finder for read+write.

Common behaviour:

* **localhost binding by default.** Listening on ``0.0.0.0`` requires
  an explicit ``bind="0.0.0.0"`` argument so a stray reverse-server
  never accidentally exposes your remote SFTP to the LAN.
* **A token on every bind.** Pass ``auth_token=…`` or let a loopback
  server generate one (``server.auth_token``): every other local user of
  the host could otherwise reach the exposed backend through the port.
  Clients send ``Authorization: Bearer <token>`` (curl), Basic auth with
  the token as the password (davfs2, Finder, gnome-files, cadaver - a
  WebDAV refusal asks for it), or the token as the AWS access key id
  (aws-cli, restic, rclone, boto3; the signature itself is not checked).
  ``auth_token=None`` turns auth off, on loopback only; binding to a
  non-loopback address without a token is refused.
* **Read-only mode.** ``read_only=True`` rejects every mutating
  verb with 403.
* **Path policy.** Every incoming key is normalised; ``..``
  segments are rejected.

The servers run in their own ``ThreadingHTTPServer`` thread; the
caller stops them with ``server.shutdown()``. Multiple reverse-servers
can run side-by-side on different ports.

This is **not** a full S3 / WebDAV implementation. Anything beyond
the verb table above returns 501 Not Implemented. That's fine for
the swiss-army-knife use case ("let restic back up to my SFTP via
S3 API"); operators who need full conformance should run a real
gateway.

SFTP-server reverse-mode is an obvious next step (paramiko
``ServerInterface``); it is **not** in this first cut. The
``register_server_factory`` plug-point exists so a future
``ReverseSFTPServer`` slots in alongside the HTTP variants.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import logging
import ntpath
import posixpath
import re
import secrets
import socket
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import quote, unquote, urlparse

from security.reverse_s3_limits import enforce_listing_caps, validate_truncation_flag

log = logging.getLogger(__name__)


DEFAULT_BIND = "127.0.0.1"
DEFAULT_S3_PORT = 9000
DEFAULT_WEBDAV_PORT = 8080
MAX_BODY_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB hard cap per request
PUT_CHUNK = 1 * 1024 * 1024
HEAD_BANNER = "axross-reverse/1"
REQUEST_TIMEOUT_S = 30.0
MIN_WALK_DIR_VISITS = 128
MAX_WALK_DIR_VISITS = 50_000
MAX_WALK_PATH_CHARS = 8_192
#: Most keys one ListBucket request walks. S3 lists keys sorted and
#: pages by "after this key", so every page needs the whole key set
#: below the prefix; a bucket above this answers with an error instead
#: of a page that would skip keys.
MAX_LIST_WALK_KEYS = 250_000
#: S3's ETag of an empty object (MD5 of no bytes), for a folder marker.
_EMPTY_ETAG = '"d41d8cd98f00b204e9800998ecf8427e"'


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------


#: A segment that starts with a drive (``C:``): ntpath.join drops
#: everything before it, so it would replace the served root.
_DRIVE_SEGMENT = re.compile(r"^[A-Za-z]:")


def _split_segments(raw: str) -> list[str]:
    """Decoded "/"-segments of *raw* without empty and "." ones; ``..``
    is a PermissionError."""
    decoded = unquote(raw or "")
    parts = []
    for seg in decoded.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            raise PermissionError(f".. segment in path: {raw!r}")
        parts.append(seg)
    return parts


def _normalize_key(raw: str) -> str:
    """Decode + normalise an HTTP path/key into a backend-friendly path.

    Rejects path-traversal segments so a hostile client can't escape
    the rooted backend - also in Windows path semantics, where LocalFS
    joins with ntpath: a backslash is a separator there (``..%5C..``
    climbs out) and a drive (``C:``) replaces the root.
    """
    parts = _split_segments(raw)
    for seg in parts:
        if "\\" in seg:
            raise PermissionError(f"backslash in path segment: {raw!r}")
        if _DRIVE_SEGMENT.match(seg):
            raise PermissionError(f"drive in path segment: {raw!r}")
    return "/" + "/".join(parts)


def _normalize_root_path(raw: str) -> str:
    """Normalize an operator-supplied backend root path.

    The caller is trusted, but accepting ``..`` here would undermine
    the promise that client-supplied paths stay rooted below this path.
    Backslashes and a drive are the operator's own (a Windows root).
    """
    return "/" + "/".join(_split_segments(raw or "/"))


def _is_local_bind(bind: str) -> bool:
    host = (bind or "").strip().lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _loopback_authority(value: str) -> bool:
    """True when a ``Host`` / ``Origin`` authority is a literal loopback
    name (``127.0.0.1``, ``[::1]``, ``localhost``, with or without port)."""
    host = (value or "").strip()
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return bool(host) and _is_local_bind(host)


def _backend_join(backend, *parts: str) -> str:
    if hasattr(backend, "join"):
        return backend.join(*parts)
    cleaned = [p.strip("/") for p in parts if p]
    return "/" + "/".join(cleaned)


def _backend_parent(backend, path: str) -> str:
    if hasattr(backend, "parent"):
        return backend.parent(path)
    return _path_flavour(backend).dirname(path)


def _path_flavour(backend):
    """ntpath for a backend with backslash paths (LocalFS on Windows,
    WinRM), else posixpath."""
    try:
        sep = backend.separator() if hasattr(backend, "separator") else "/"
    except Exception:  # noqa: BLE001 - a separator() that fails says nothing
        sep = "/"
    return ntpath if sep == "\\" else posixpath


def _rooted_join(backend, root: str, *parts: str) -> str:
    """Join client-derived *parts* below *root*, refusing a result that
    leaves it in the backend's own path flavour (second layer behind the
    segment checks of :func:`_normalize_key`)."""
    full = _backend_join(backend, root, *parts)
    flavour = _path_flavour(backend)
    base = flavour.normcase(flavour.normpath(root or flavour.sep))
    target = flavour.normcase(flavour.normpath(full))
    if flavour is ntpath:
        inside_root = target == base or target.startswith(base.rstrip("\\/") + "\\")
    else:
        inside_root = target == base or target.startswith(base.rstrip("/") + "/")
    if not inside_root:
        raise PermissionError(f"path leaves the served root: {full!r}")
    return full


def _mkdir_best_effort(backend, path: str) -> None:
    try:
        backend.mkdir(path, parents=True, exist_ok=True)
        return
    except TypeError:
        pass
    except (OSError, FileExistsError):
        return
    try:
        backend.mkdir(path)
    except (OSError, FileExistsError):
        pass


def _is_absent(backend, path: str, exc: OSError) -> bool:
    """Whether *exc*, raised by a stat or a listing of *path*, means the
    path is not there. A client takes 404 / NoSuchKey / an empty listing
    for "gone" (rclone sync, ``aws s3 sync --delete``) and deletes its
    copy, so a timeout or a refusal must never read as one. Backends whose
    stat raises a plain OSError for a missing path (RamFS) are asked
    exists(), which says False only for "not found"."""
    if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        return True
    if isinstance(exc, PermissionError):
        return False
    exists = getattr(backend, "exists", None)
    if not callable(exists):
        return False
    try:
        return not exists(path)
    except Exception as probe_exc:  # noqa: BLE001 - unknown is not gone
        log.debug("reverse-serve: exists(%s) failed: %s", path, probe_exc)
        return False


def _stat_entry(backend, path: str):
    """``backend.stat(path)``, or None when the path is not there. Any
    other failure is raised (see :func:`_is_absent`)."""
    try:
        return backend.stat(path)
    except OSError as exc:
        if _is_absent(backend, path, exc):
            return None
        raise


def _list_entries(backend, path: str) -> list | None:
    """``backend.list_dir(path)``, or None when the folder is not there.
    Any other failure is raised: an unlistable folder is no empty one."""
    try:
        return backend.list_dir(path)
    except OSError as exc:
        if _is_absent(backend, path, exc):
            return None
        raise


def _entry_size(item) -> int:
    return int(getattr(item, "size", 0) or 0)


def _entry_mtime(item) -> float:
    raw = getattr(item, "modified", None)
    if raw is None:
        return time.time()
    if hasattr(raw, "timestamp"):
        try:
            return float(raw.timestamp())
        except (OSError, OverflowError, ValueError):
            return time.time()
    try:
        return float(raw)
    except (TypeError, ValueError):
        return time.time()


def _http_date(epoch: float) -> str:
    return formatdate(epoch, usegmt=True)


def _iso_date(epoch: float) -> str:
    """ISO-8601 with milliseconds — the format S3 LIST returns."""
    t = time.gmtime(epoch)
    return time.strftime("%Y-%m-%dT%H:%M:%S", t) + ".000Z"


def _build_webdav_lock_xml(token: str) -> bytes:
    return (
        "<?xml version='1.0'?>"
        "<D:prop xmlns:D='DAV:'><D:lockdiscovery><D:activelock>"
        "<D:locktype><D:write/></D:locktype>"
        "<D:lockscope><D:exclusive/></D:lockscope>"
        "<D:depth>infinity</D:depth>"
        "<D:owner><D:href>axross</D:href></D:owner>"
        "<D:timeout>Second-3600</D:timeout>"
        f"<D:locktoken><D:href>{token}</D:href></D:locktoken>"
        "</D:activelock></D:lockdiscovery></D:prop>"
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Auth + common request handler base
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    backend: Any
    bind: str = DEFAULT_BIND
    port: int = 0
    read_only: bool = False
    # "" -> a loopback server generates one; None -> no auth (loopback only)
    auth_token: str | None = ""
    root_path: str = "/"  # everything is rooted here on the backend


class _BaseHandler(BaseHTTPRequestHandler):
    """Common handler — auth, error-shape, logging."""

    server_version = HEAD_BANNER
    sys_version = ""  # don't leak Python version

    # Subclasses populate these:
    config: ServerConfig

    # Suppress default access logging — we use the structured logger.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        log.debug("%s - - %s", self.address_string(), format % args)

    def setup(self) -> None:
        super().setup()
        try:
            self.connection.settimeout(REQUEST_TIMEOUT_S)
        except OSError as exc:
            log.debug("reverse-server: cannot set socket timeout: %s", exc)

    def parse_request(self) -> bool:
        """Refuse DNS rebinding on loopback binds before any verb runs.

        A loopback server may run without a token (``auth_token=None``),
        and then the only thing keeping a web page away from the backend is
        that it cannot forge ``Host``: after a rebind the page's own
        hostname arrives there (and in ``Origin``).
        Non-loopback binds require the bearer token instead and are served
        under whatever name clients use.
        """
        if not super().parse_request():
            return False
        if not _is_local_bind(self.config.bind):
            return True
        host = self.headers.get("Host")
        origin = self.headers.get("Origin")
        refused = ""
        if host is not None and not _loopback_authority(host):
            refused = "Host header is not a loopback name"
        elif origin is not None and not _loopback_authority(urlparse(origin).netloc):
            refused = "cross-origin request refused"
        if refused:
            log.warning("reverse-server: %s (Host=%r Origin=%r)", refused, host, origin)
            self.close_connection = True
            self._send_simple(403, refused.encode("utf-8"))
            return False
        return True

    # --------------------------------- helpers ---------------------------

    def _is_authed(self) -> bool:
        """The token as ``Bearer <token>``, as the password of Basic auth
        (any user name) - what WebDAV clients can send - or as the access
        key id of an AWS signature (V4 ``Credential=<token>/...`` or V2
        ``AWS <token>:...``): S3 SDKs (aws-cli, restic) sign every request
        and own the header. The signature itself is not checked; the key
        id travels in clear like a Bearer token."""
        token = self.config.auth_token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        scheme, _, value = header.partition(" ")
        presented = ""
        if scheme.lower() == "bearer":
            presented = value.strip()
        elif scheme == "AWS4-HMAC-SHA256":
            for part in value.split(","):
                name, _, credential = part.strip().partition("=")
                if name == "Credential":
                    presented = credential.split("/", 1)[0]
        elif scheme == "AWS":
            presented = value.strip().rpartition(":")[0]
        elif scheme.lower() == "basic":
            try:
                decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return False
            _user, colon, presented = decoded.partition(":")
            if not colon:
                return False
        return bool(presented) and hmac.compare_digest(
            presented.encode("utf-8"), token.encode("utf-8")
        )

    def _send_simple(
        self, code: int, body: bytes = b"", *, content_type: str = "text/plain"
    ) -> None:
        self.send_response(code)
        if code == 401:
            # WebDAV clients ask for credentials only when told the scheme.
            self.send_header("WWW-Authenticate", 'Basic realm="axross", charset="UTF-8"')
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", HEAD_BANNER)
        self.send_header("Date", _http_date(time.time()))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_failure(self, what: str, exc: OSError) -> None:
        """A stat or listing that failed: 403 for a refusal, 500 else -
        never 404, which a client takes for "gone"."""
        log.warning("reverse-%s %s failed: %s", self._flavour_name(), what, exc)
        code = 403 if isinstance(exc, PermissionError) else 500
        self._send_simple(code, str(exc).encode("utf-8"))

    def _flavour_name(self) -> str:
        return "s3" if isinstance(self, _S3Handler) else "dav"

    def _read_body(self) -> bytes:
        length = self._content_length(default=0)
        if length <= 0:
            return b""
        if length > MAX_BODY_BYTES:
            raise ValueError(f"Content-Length {length} exceeds cap {MAX_BODY_BYTES}")
        return self.rfile.read(length)

    def _content_length(self, *, default: int | None = None) -> int:
        raw = self.headers.get("Content-Length")
        if raw in (None, ""):
            if default is None:
                raise ValueError("missing Content-Length")
            return default
        try:
            length = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid Content-Length {raw!r}") from exc
        if length < 0:
            raise ValueError("negative Content-Length")
        if length > MAX_BODY_BYTES:
            raise ValueError(f"Content-Length {length} exceeds cap {MAX_BODY_BYTES}")
        return length

    def _stream_body_to(self, write_handle, length: int) -> int:
        """Copy ``length`` bytes from the request body to ``write_handle``.

        Streamed in ``PUT_CHUNK`` chunks so a multi-GiB upload doesn't
        materialise in memory.
        """
        body = _RequestBody(self.rfile, length)
        moved = 0
        while chunk := body.read(PUT_CHUNK):
            written = write_handle.write(chunk)
            if written is not None and int(written) != len(chunk):
                raise OSError(f"short backend write: wrote {written} of {len(chunk)} bytes")
            moved += len(chunk)
        return moved

    def _store_body(self, path: str, length: int) -> None:
        """Store the request body at ``path``; a failed PUT keeps the old object.

        Raises :class:`ValueError` when the client did not deliver the
        body it announced and :class:`OSError` when the backend refused
        it or failed to commit it.
        """
        from core.server_ops import _discard_or_close_writer, _supports_temp_destination

        backend = self.config.backend
        if _supports_temp_destination(backend):
            # The body lands in a sibling temp file and replaces the old
            # object (keeping its mode) only once every byte arrived. A
            # direct open_write here truncated the old file on LocalFS
            # before the first byte was read.
            from core.atomic_io import atomic_write_stream

            atomic_write_stream(
                backend, path, _RequestBody(self.rfile, length), chunk_size=PUT_CHUNK
            )
            return
        handle = backend.open_write(path)
        completed = False
        try:
            self._stream_body_to(handle, length)
            completed = True
        finally:
            # Buffered writers commit at close: an incomplete body is
            # discarded, not committed, and a failed commit propagates.
            _discard_or_close_writer(handle, completed=completed)


class _RequestBody:
    """``read(size)`` over exactly ``length`` request-body bytes.

    A body that ends early, or a socket that fails while reading it,
    raises :class:`ValueError`: either way the client did not deliver
    what it announced, and nothing of it may be committed.
    """

    def __init__(self, rfile, length: int) -> None:
        if length < 0:
            raise ValueError("missing Content-Length")
        if length > MAX_BODY_BYTES:
            raise ValueError(f"Content-Length {length} exceeds cap {MAX_BODY_BYTES}")
        self._rfile = rfile
        self._length = length
        self._received = 0

    def read(self, size: int = -1) -> bytes:
        left = self._length - self._received
        if left <= 0:
            return b""
        want = min(left, PUT_CHUNK if size is None or size < 0 else size)
        try:
            chunk = self._rfile.read(want)
        except OSError as exc:
            raise ValueError(
                f"request body unreadable after {self._received} of {self._length} bytes: {exc}"
            ) from exc
        if not chunk:
            raise ValueError(
                f"short request body: received {self._received} of {self._length} bytes"
            )
        self._received += len(chunk)
        return chunk


# ---------------------------------------------------------------------------
# Reverse-S3
# ---------------------------------------------------------------------------


class _S3Handler(_BaseHandler):
    config: ServerConfig

    # ------- routing ---------------------------------------------------

    def do_GET(self) -> None:
        if not self._is_authed():
            self._s3_error(403, "AccessDenied", "missing or bad bearer token")
            return
        try:
            bucket, key = self._parse_path()
        except (ValueError, PermissionError) as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        if not bucket:
            self._handle_list_buckets()
            return
        if key == "":
            self._handle_list_bucket(bucket)
            return
        self._handle_get_object(bucket, key)

    def do_HEAD(self) -> None:
        if not self._is_authed():
            self._s3_error(403, "AccessDenied", "missing or bad bearer token")
            return
        try:
            bucket, key = self._parse_path()
        except (ValueError, PermissionError) as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        if not bucket:
            self._send_simple(200)
            return
        if key == "":
            self._handle_head_bucket(bucket)
            return
        self._handle_head_object(bucket, key)

    def do_PUT(self) -> None:
        if not self._is_authed():
            self._s3_error(403, "AccessDenied", "missing or bad bearer token")
            return
        if self.config.read_only:
            self._s3_error(403, "AccessDenied", "read-only reverse-server")
            return
        try:
            bucket, key = self._parse_path()
        except (ValueError, PermissionError) as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        if not bucket or not key:
            self._s3_error(400, "InvalidArgument", "PUT requires bucket and key")
            return
        if urlparse(self.path).path.endswith("/"):
            # "dir/" is a folder marker (console "Create folder", rclone
            # directory markers); _parse_path dropped the slash.
            self._handle_put_folder(bucket, key)
            return
        self._handle_put_object(bucket, key)

    def do_DELETE(self) -> None:
        if not self._is_authed():
            self._s3_error(403, "AccessDenied", "missing or bad bearer token")
            return
        if self.config.read_only:
            self._s3_error(403, "AccessDenied", "read-only reverse-server")
            return
        try:
            bucket, key = self._parse_path()
        except (ValueError, PermissionError) as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        if not bucket or not key:
            self._s3_error(400, "InvalidArgument", "DELETE requires key")
            return
        self._handle_delete_object(bucket, key)

    # ------- helpers ---------------------------------------------------

    def _parse_path(self) -> tuple[str, str]:
        """Path-style: ``/bucket/key…``. Empty bucket = list buckets.

        Rejects ``..`` segments anywhere in the URL — those would let a
        client escape the rooted bucket.
        """
        parsed = urlparse(self.path)
        path = _normalize_key(parsed.path or "/")
        path = path[1:]
        if not path:
            return ("", "")
        if "/" not in path:
            bucket, key = path, ""
        else:
            bucket, _, key = path.partition("/")
        # Second layer: the joined path must stay below the root.
        _rooted_join(self.config.backend, self.config.root_path, bucket, key)
        return (bucket, key)

    def _backend_path_for(self, bucket: str, key: str) -> str:
        """Rooted backend path. The reverse-server treats the *first
        URL segment* as the bucket name; we map it to a top-level
        directory under ``config.root_path``."""
        return _rooted_join(self.config.backend, self.config.root_path, bucket, key)

    def _s3_failure(self, what: str, exc: OSError) -> None:
        """A stat or listing that failed: AccessDenied for a refusal,
        InternalError else - never NoSuchKey / NoSuchBucket."""
        log.warning("reverse-s3 %s failed: %s", what, exc)
        if isinstance(exc, PermissionError):
            self._s3_error(403, "AccessDenied", str(exc))
        else:
            self._s3_error(500, "InternalError", str(exc))

    def _s3_error(self, code: int, s3_code: str, message: str) -> None:
        body_xml = (
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<Error>"
            f"<Code>{s3_code}</Code>"
            f"<Message>{_xml_escape(message)}</Message>"
            "</Error>"
        ).encode("utf-8")
        self._send_simple(code, body_xml, content_type="application/xml")

    # ------- handlers --------------------------------------------------

    def _handle_list_buckets(self) -> None:
        """Top-level: list all top-level dirs under root as "buckets"."""
        try:
            entries = self.config.backend.list_dir(self.config.root_path)
        except OSError as exc:
            self._s3_error(500, "InternalError", str(exc))
            return
        when = _iso_date(time.time())
        buckets_xml = "".join(
            f"<Bucket><Name>{_xml_escape(item.name)}</Name>"
            f"<CreationDate>{when}</CreationDate></Bucket>"
            for item in entries
            if getattr(item, "is_dir", False)
        )
        body = (
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<ListAllMyBucketsResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
            "<Owner><ID>axross</ID><DisplayName>axross</DisplayName></Owner>"
            f"<Buckets>{buckets_xml}</Buckets>"
            "</ListAllMyBucketsResult>"
        ).encode("utf-8")
        self._send_simple(200, body, content_type="application/xml")

    def _handle_list_bucket(self, bucket: str) -> None:
        """ListObjects (v1) and ListObjectsV2 (``list-type=2``): keys in
        S3 order, paged by marker / start-after / continuation-token,
        grouped into CommonPrefixes by a delimiter."""
        v2 = self._query_param("list-type") == "2"
        prefix = self._query_param("prefix") or ""
        delimiter = self._query_param("delimiter") or ""
        try:
            max_keys = int(self._query_param("max-keys") or "1000")
        except ValueError:
            self._s3_error(400, "InvalidArgument", "max-keys must be an integer")
            return
        max_keys = max(1, min(max_keys, 5000))
        token = self._query_param("continuation-token") if v2 else ""
        start_after = self._query_param("start-after") if v2 else ""
        if not v2:
            after = self._query_param("marker")
        elif token:
            try:
                after = _decode_continuation_token(token)
            except ValueError:
                self._s3_error(400, "InvalidArgument", "the continuation token is not valid")
                return
        else:
            after = start_after
        bucket_root = _rooted_join(self.config.backend, self.config.root_path, bucket)
        try:
            root_item = _stat_entry(self.config.backend, bucket_root)
        except OSError as exc:
            self._s3_failure(f"list {bucket}", exc)
            return
        if root_item is None or not getattr(root_item, "is_dir", False):
            self._s3_error(404, "NoSuchBucket", "bucket not found")
            return
        try:
            entries, walk_truncated = _walk_keys(
                self.config.backend, bucket_root, prefix, MAX_LIST_WALK_KEYS
            )
        except OSError as exc:
            # A folder that could not be listed: its keys would be missing
            # from a listing that says it is complete.
            self._s3_failure(f"list {bucket}", exc)
            return
        if walk_truncated:
            # Pages are cut from the sorted whole: a walk that stopped
            # early would make "after this key" skip keys it never saw.
            self._s3_error(
                500,
                "InternalError",
                "the listing exceeds the reverse-server walk limits; list a narrower prefix",
            )
            return
        entries.sort(key=lambda entry: entry[0])
        contents, prefixes, page_truncated, last = _list_page(
            entries, prefix, delimiter, after, max_keys
        )
        # Defense-in-depth: re-enforce listing-size caps at
        # the HTTP boundary so a regression in _walk_keys cannot blow
        # the response body up.
        contents, defense_truncated = enforce_listing_caps(contents)
        contents_xml = "".join(
            f"<Contents>"
            f"<Key>{_xml_escape(rel)}</Key>"
            f"<LastModified>{_iso_date(item['mtime'])}</LastModified>"
            f"<Size>{item['size']}</Size>"
            f"<StorageClass>STANDARD</StorageClass>"
            f"</Contents>"
            for rel, item in contents
        )
        prefixes_xml = "".join(
            f"<CommonPrefixes><Prefix>{_xml_escape(cp)}</Prefix></CommonPrefixes>"
            for cp in prefixes
        )
        # Defense-in-depth: consolidate the truncation signals through a
        # single boundary helper so a regression that drops one signal
        # cannot re-introduce the IsTruncated=false lie when keys remain.
        truncated = validate_truncation_flag(
            entry_count=len(contents) + len(prefixes),
            max_keys=max_keys,
            claimed_truncated=page_truncated or defense_truncated,
            walk_truncated=walk_truncated,
        )
        if v2:
            paging = f"<KeyCount>{len(contents) + len(prefixes)}</KeyCount>"
            if token:
                paging += f"<ContinuationToken>{_xml_escape(token)}</ContinuationToken>"
            if start_after:
                paging += f"<StartAfter>{_xml_escape(start_after)}</StartAfter>"
            if truncated and last:
                paging += (
                    "<NextContinuationToken>"
                    f"{_encode_continuation_token(last)}"
                    "</NextContinuationToken>"
                )
        else:
            paging = f"<Marker>{_xml_escape(after)}</Marker>"
            if truncated and last:
                paging += f"<NextMarker>{_xml_escape(last)}</NextMarker>"
        if delimiter:
            paging += f"<Delimiter>{_xml_escape(delimiter)}</Delimiter>"
        body = (
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
            f"<Name>{_xml_escape(bucket)}</Name>"
            f"<Prefix>{_xml_escape(prefix)}</Prefix>"
            f"<MaxKeys>{max_keys}</MaxKeys>"
            f"{paging}"
            f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
            f"{contents_xml}"
            f"{prefixes_xml}"
            "</ListBucketResult>"
        ).encode("utf-8")
        self._send_simple(200, body, content_type="application/xml")

    def _handle_head_bucket(self, bucket: str) -> None:
        bucket_root = _rooted_join(self.config.backend, self.config.root_path, bucket)
        try:
            item = _stat_entry(self.config.backend, bucket_root)
        except OSError as exc:
            self._s3_failure(f"HEAD {bucket}", exc)
            return
        if item is None or not getattr(item, "is_dir", False):
            self._s3_error(404, "NoSuchBucket", "bucket not found")
            return
        self._send_simple(200)

    def _handle_get_object(self, bucket: str, key: str) -> None:
        path = self._backend_path_for(bucket, key)
        try:
            item = _stat_entry(self.config.backend, path)
        except OSError as exc:
            self._s3_failure(f"GET {path}", exc)
            return
        if item is None:
            self._s3_error(404, "NoSuchKey", "key not found")
            return
        if getattr(item, "is_dir", False):
            self._s3_error(404, "NoSuchKey", "key is a directory")
            return
        size = _entry_size(item)
        try:
            handle = self.config.backend.open_read(path)
        except OSError as exc:
            self._s3_error(500, "InternalError", str(exc))
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Last-Modified", _http_date(_entry_mtime(item)))
            self.send_header("Server", HEAD_BANNER)
            self.end_headers()
            while True:
                chunk = handle.read(PUT_CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
        finally:
            try:
                handle.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("reverse-s3 close: %s", exc)

    def _handle_head_object(self, bucket: str, key: str) -> None:
        path = self._backend_path_for(bucket, key)
        try:
            item = _stat_entry(self.config.backend, path)
        except OSError as exc:
            self._s3_failure(f"HEAD {path}", exc)
            return
        if item is None:
            self._s3_error(404, "NoSuchKey", "key not found")
            return
        if getattr(item, "is_dir", False):
            self._s3_error(404, "NoSuchKey", "key is a directory")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(_entry_size(item)))
        self.send_header("Last-Modified", _http_date(_entry_mtime(item)))
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()

    def _handle_put_object(self, bucket: str, key: str) -> None:
        path = self._backend_path_for(bucket, key)
        # Auto-create parent directories on the backend (terraform / restic
        # often PUT new keys). Best-effort.
        parent = self.config.backend.parent(path) if hasattr(self.config.backend, "parent") else ""
        if parent:
            _mkdir_best_effort(self.config.backend, parent)
        try:
            length = self._content_length(default=0)
        except ValueError as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        try:
            self._store_body(path, length)
        except ValueError as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - any failed commit is a 500, never a 200
            log.warning("reverse-s3 PUT %s failed: %s", path, exc)
            self._s3_error(500, "InternalError", str(exc))
            return
        # 200 with empty body is the S3 PUT response shape (with the
        # ETag header). We synthesise a fake ETag — restic / rclone
        # check it for non-emptiness, not validity.
        self.send_response(200)
        self.send_header("ETag", '"' + secrets.token_hex(16) + '"')
        self.send_header("Content-Length", "0")
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()

    def _handle_put_folder(self, bucket: str, key: str) -> None:
        """A zero-byte PUT of ``key/`` creates the folder ``key``."""
        try:
            length = self._content_length(default=0)
        except ValueError as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        if length:
            # The body is not read: the connection cannot carry another
            # request after it.
            self.close_connection = True
            self._s3_error(400, "InvalidArgument", "a key ending in '/' is a folder; no body")
            return
        backend = self.config.backend
        path = self._backend_path_for(bucket, key)
        parent = backend.parent(path) if hasattr(backend, "parent") else ""
        if parent:
            _mkdir_best_effort(backend, parent)
        _mkdir_best_effort(backend, path)
        try:
            is_dir = bool(getattr(backend.stat(path), "is_dir", False))
        except OSError as exc:
            log.warning("reverse-s3 folder PUT %s failed: %s", path, exc)
            self._s3_error(500, "InternalError", str(exc))
            return
        if not is_dir:
            self._s3_error(400, "InvalidArgument", "a file holds the folder's name")
            return
        self.send_response(200)
        self.send_header("ETag", _EMPTY_ETAG)
        self.send_header("Content-Length", "0")
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()

    def _handle_delete_object(self, bucket: str, key: str) -> None:
        path = self._backend_path_for(bucket, key)
        try:
            self.config.backend.remove(path)
        except OSError as exc:
            # S3 answers 204 for a key that does not exist - and only then: a
            # client takes 204 for "gone" (rclone sync, restic prune). Backends
            # differ in the error of a missing path (RamFS: plain OSError), so
            # ask whether the object is still there.
            log.debug("reverse-s3 DELETE %s failed: %s", path, exc)
            try:
                still_there = self.config.backend.exists(path)
                is_folder = still_there and self.config.backend.is_dir(path)
            except OSError:
                still_there, is_folder = True, False
            if still_there and not is_folder:  # a folder is no object: 204
                if isinstance(exc, PermissionError):
                    self._s3_error(403, "AccessDenied", str(exc))
                else:
                    self._s3_error(500, "InternalError", str(exc))
                return
        self.send_response(204)
        self.send_header("Server", HEAD_BANNER)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------- query helpers --------------------------------------------

    def _query_param(self, name: str) -> str:
        parsed = urlparse(self.path)
        for chunk in (parsed.query or "").split("&"):
            if "=" in chunk:
                k, _, v = chunk.partition("=")
                if k == name:
                    return unquote(v)
            elif chunk == name:
                return ""
        return ""


def _walk_keys(
    backend,
    root: str,
    prefix: str,
    max_keys: int,
) -> tuple[list[tuple[str, dict]], bool]:
    """List all keys under ``root`` recursively, return relative-path /
    metadata pairs plus whether traversal stopped before exhaustion.
    Cap returned entries at ``max_keys``."""
    if max_keys <= 0:
        return [], False

    out: list[tuple[str, dict]] = []
    truncated = False
    stack = [root]
    visited: set[str] = set()
    dir_visits = 0
    max_dir_visits = min(max(max_keys, MIN_WALK_DIR_VISITS), MAX_WALK_DIR_VISITS)
    while stack:
        path = stack.pop()
        if path in visited:
            continue
        visited.add(path)
        if dir_visits >= max_dir_visits:
            truncated = True
            break
        dir_visits += 1
        if len(out) >= max_keys:
            truncated = True
            break
        # A folder that vanished since its parent was listed is gone; any
        # other failure raises - skipping it would drop its keys from a
        # listing that says it is complete.
        entries = _list_entries(backend, path)
        if entries is None:
            continue
        for item in entries:
            full = _backend_join(backend, path, item.name)
            if len(full) > MAX_WALK_PATH_CHARS:
                truncated = True
                continue
            rel = full[len(root) :].lstrip("/")
            if getattr(item, "is_dir", False):
                folder = rel + "/"
                # Only folders that can hold a key with the prefix.
                if not prefix or folder.startswith(prefix) or prefix.startswith(folder):
                    stack.append(full)
                continue
            if prefix and not rel.startswith(prefix):
                continue
            out.append(
                (
                    rel,
                    {
                        "size": _entry_size(item),
                        "mtime": _entry_mtime(item),
                    },
                )
            )
            if len(out) >= max_keys:
                truncated = True
                break
    return out, truncated


def _list_page(
    entries: list[tuple[str, dict]],
    prefix: str,
    delimiter: str,
    after: str,
    max_keys: int,
) -> tuple[list[tuple[str, dict]], list[str], bool, str]:
    """One ListObjects page from the sorted *entries* below *prefix*.

    Returns ``(contents, common_prefixes, truncated, last)``: keys after
    *after*, those whose rest after the prefix holds *delimiter* rolled
    up into one common prefix each, at most *max_keys* of both together.
    *last* is the last key or common prefix returned - the next page's
    marker. A common prefix at or before *after* was returned already.
    """
    contents: list[tuple[str, dict]] = []
    prefixes: list[str] = []
    last = ""
    for rel, meta in entries:
        if after and rel <= after:
            continue
        common = None
        if delimiter:
            cut = rel.find(delimiter, len(prefix))
            if cut >= 0:
                common = rel[: cut + len(delimiter)]
                if (prefixes and prefixes[-1] == common) or (after and common <= after):
                    continue
        if len(contents) + len(prefixes) >= max_keys:
            return contents, prefixes, True, last
        if common is not None:
            prefixes.append(common)
            last = common
        else:
            contents.append((rel, meta))
            last = rel
    return contents, prefixes, False, last


def _encode_continuation_token(key: str) -> str:
    return base64.urlsafe_b64encode(key.encode("utf-8", "surrogateescape")).decode("ascii")


def _decode_continuation_token(token: str) -> str:
    """The key a NextContinuationToken names; ValueError for anything else."""
    try:
        raw = base64.b64decode(token.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(str(exc)) from exc
    return raw.decode("utf-8", "surrogateescape")


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


# ---------------------------------------------------------------------------
# Reverse-WebDAV
# ---------------------------------------------------------------------------


class _DAVHandler(_BaseHandler):
    config: ServerConfig

    # ------- routing ---------------------------------------------------

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header(
            "Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE, LOCK, UNLOCK"
        )
        self.send_header("DAV", "1, 2")
        self.send_header("MS-Author-Via", "DAV")
        self.send_header("Server", HEAD_BANNER)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        path = self._backend_path()
        if path is None:
            return
        try:
            item = _stat_entry(self.config.backend, path)
        except OSError as exc:
            self._send_failure(f"stat {path}", exc)
            return
        if item is None:
            self._send_simple(404)
            return
        self.send_response(200)
        if getattr(item, "is_dir", False):
            self.send_header("Content-Type", "httpd/unix-directory")
        else:
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(_entry_size(item)))
            self.send_header("Last-Modified", _http_date(_entry_mtime(item)))
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()

    def do_GET(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        path = self._backend_path()
        if path is None:
            return
        try:
            item = _stat_entry(self.config.backend, path)
        except OSError as exc:
            self._send_failure(f"stat {path}", exc)
            return
        if item is None:
            self._send_simple(404)
            return
        if getattr(item, "is_dir", False):
            # Render a minimal HTML index — friendly for human browsers.
            try:
                entries = self.config.backend.list_dir(path)
            except OSError as exc:
                self._send_simple(500, str(exc).encode("utf-8"))
                return
            self._send_html_index(path, entries)
            return
        try:
            handle = self.config.backend.open_read(path)
        except OSError as exc:
            self._send_simple(500, str(exc).encode("utf-8"))
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(_entry_size(item)))
            self.send_header("Last-Modified", _http_date(_entry_mtime(item)))
            self.send_header("Server", HEAD_BANNER)
            self.end_headers()
            while True:
                chunk = handle.read(PUT_CHUNK)
                if not chunk:
                    break
                self.wfile.write(chunk)
        finally:
            try:
                handle.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("reverse-dav close: %s", exc)

    def do_PUT(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        if self.config.read_only:
            self._send_simple(403, b"read-only reverse-server")
            return
        path = self._backend_path()
        if path is None:
            return
        parent = self.config.backend.parent(path) if hasattr(self.config.backend, "parent") else ""
        if parent:
            _mkdir_best_effort(self.config.backend, parent)
        try:
            length = self._content_length(default=0)
        except ValueError as exc:
            self._send_simple(400, str(exc).encode("utf-8"))
            return
        try:
            self._store_body(path, length)
        except ValueError as exc:
            self._send_simple(400, str(exc).encode("utf-8"))
            return
        except Exception as exc:  # noqa: BLE001 - any failed commit is a 500, never a 201
            log.warning("reverse-dav PUT %s failed: %s", path, exc)
            self._send_simple(500, str(exc).encode("utf-8"))
            return
        self._send_simple(201)

    def do_DELETE(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        if self.config.read_only:
            self._send_simple(403, b"read-only reverse-server")
            return
        path = self._backend_path()
        if path is None:
            return
        if self._is_served_root(path):
            self._send_simple(403, b"the served root cannot be deleted")
            return
        try:
            present = self.config.backend.exists(path)
        except OSError as exc:
            # Unknown is not "gone": try the delete, whose failure is an error.
            log.debug("reverse-dav DELETE %s: exists failed: %s", path, exc)
            present = True
        if not present:
            self._send_simple(404)
            return
        try:
            self.config.backend.remove(path, recursive=True)
        except OSError as exc:
            # Never 404 for a path that is there: a client takes it for gone.
            log.warning("reverse-dav DELETE %s failed: %s", path, exc)
            code = 403 if isinstance(exc, PermissionError) else 500
            self._send_simple(code, str(exc).encode("utf-8"))
            return
        self._send_simple(204)

    def do_MKCOL(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        if self.config.read_only:
            self._send_simple(403, b"read-only reverse-server")
            return
        path = self._backend_path()
        if path is None:
            return
        try:
            # RFC 4918 9.3.1: MKCOL on an existing resource is 405. LocalFS
            # mkdir succeeds on an existing folder, RamFS raises a plain
            # OSError - so ask first.
            if self.config.backend.exists(path):
                self._send_simple(405, b"the resource already exists")
                return
            # 409 when a parent is missing: the server MUST NOT create the
            # intermediate collections (LocalFS mkdir would - os.makedirs).
            parent = _backend_parent(self.config.backend, path)
            if parent and not self.config.backend.is_dir(parent):
                self._send_simple(409, b"a parent collection does not exist")
                return
            self.config.backend.mkdir(path)
        except FileExistsError:
            self._send_simple(405, b"directory already exists")
            return
        except OSError as exc:
            self._send_simple(409, str(exc).encode("utf-8"))
            return
        self._send_simple(201)

    def do_MOVE(self) -> None:
        self._copy_or_move(move=True)

    def do_COPY(self) -> None:
        self._copy_or_move(move=False)

    def _copy_or_move(self, *, move: bool) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        if self.config.read_only:
            self._send_simple(403, b"read-only reverse-server")
            return
        dst_url = self.headers.get("Destination", "")
        if not dst_url:
            self._send_simple(400, b"missing Destination header")
            return
        dst_path = urlparse(dst_url).path or ""
        try:
            dst_norm = _normalize_key(dst_path)
            dst_full = _rooted_join(
                self.config.backend, self.config.root_path, dst_norm.lstrip("/")
            )
        except (ValueError, PermissionError) as exc:
            self._send_simple(400, str(exc).encode("utf-8"))
            return
        src_full = self._backend_path()
        if src_full is None:
            return
        if (move and self._is_served_root(src_full)) or self._is_served_root(dst_full):
            self._send_simple(403, b"the served root cannot be moved or replaced")
            return
        if self.headers.get("Overwrite", "T").strip().upper() == "F":
            # RFC 4918 9.8.4 / 9.9.3: the client asked not to replace an
            # existing destination. LocalFS rename/copy would do it
            # silently, so check here rather than trust the backend.
            try:
                taken = self.config.backend.exists(dst_full)
            except OSError as exc:
                self._send_simple(409, str(exc).encode("utf-8"))
                return
            if taken:
                self._send_simple(412, b"destination exists and Overwrite is F")
                return
        try:
            if move:
                self.config.backend.rename(src_full, dst_full)
            elif hasattr(self.config.backend, "copy"):
                self.config.backend.copy(src_full, dst_full)
            else:
                self._send_simple(501, b"backend does not support COPY")
                return
        except OSError as exc:
            self._send_simple(409, str(exc).encode("utf-8"))
            return
        self._send_simple(201)

    def do_PROPFIND(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        path = self._backend_path()
        if path is None:
            return
        depth = self.headers.get("Depth", "1").strip()
        try:
            item = _stat_entry(self.config.backend, path)
        except OSError as exc:
            self._send_failure(f"stat {path}", exc)
            return
        if item is None:
            self._send_simple(404)
            return
        items: list[tuple[str, Any]] = [(self._url_for(path), item)]
        if depth in ("1", "infinity") and getattr(item, "is_dir", False):
            try:
                entries = _list_entries(self.config.backend, path)
            except OSError as exc:
                # An unlistable folder is no empty folder.
                self._send_failure(f"PROPFIND {path}", exc)
                return
            if entries is None:
                self._send_simple(404)
                return
            for child in entries:
                child_path = _backend_join(self.config.backend, path, child.name)
                items.append((self._url_for(child_path), child))
        body = self._build_propfind_xml(items)
        self.send_response(207)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()
        self.wfile.write(body)

    def do_LOCK(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        if self.config.read_only:
            self._send_simple(403, b"read-only reverse-server")
            return
        # No-op LOCK with a fake token; satisfies macOS Finder + davfs2.
        lock_handle = "opaque" "locktoken:" + secrets.token_hex(8)
        body = _build_webdav_lock_xml(lock_handle)
        self.send_response(200)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Lock-Token", f"<{lock_handle}>")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()
        self.wfile.write(body)

    def do_UNLOCK(self) -> None:
        if not self._is_authed():
            self._send_simple(401)
            return
        self._send_simple(204)

    # ------- helpers ---------------------------------------------------

    def _is_served_root(self, full: str) -> bool:
        flavour = _path_flavour(self.config.backend)
        root = self.config.root_path or flavour.sep
        return flavour.normcase(flavour.normpath(full)) == flavour.normcase(flavour.normpath(root))

    def _backend_path(self) -> str | None:
        try:
            key = _normalize_key(urlparse(self.path).path or "/")
            return _rooted_join(self.config.backend, self.config.root_path, key.lstrip("/"))
        except (ValueError, PermissionError) as exc:
            self._send_simple(400, str(exc).encode("utf-8"))
            return None

    def _url_for(self, backend_path: str) -> str:
        rel = backend_path
        root = self.config.root_path.rstrip("/")
        if root and rel.startswith(root):
            rel = rel[len(root) :] or "/"
        return quote(rel, safe="/")

    def _build_propfind_xml(self, items: list[tuple[str, Any]]) -> bytes:
        ns = "DAV:"
        ET.register_namespace("D", ns)
        multistatus = ET.Element(f"{{{ns}}}multistatus")
        for href, item in items:
            response = ET.SubElement(multistatus, f"{{{ns}}}response")
            href_el = ET.SubElement(response, f"{{{ns}}}href")
            href_el.text = href
            propstat = ET.SubElement(response, f"{{{ns}}}propstat")
            prop = ET.SubElement(propstat, f"{{{ns}}}prop")
            ET.SubElement(prop, f"{{{ns}}}displayname").text = item.name
            length_el = ET.SubElement(prop, f"{{{ns}}}getcontentlength")
            length_el.text = str(_entry_size(item))
            mtime_el = ET.SubElement(prop, f"{{{ns}}}getlastmodified")
            mtime_el.text = _http_date(_entry_mtime(item))
            type_el = ET.SubElement(prop, f"{{{ns}}}resourcetype")
            if getattr(item, "is_dir", False):
                ET.SubElement(type_el, f"{{{ns}}}collection")
            ET.SubElement(propstat, f"{{{ns}}}status").text = "HTTP/1.1 200 OK"
        body = ET.tostring(multistatus, encoding="utf-8", xml_declaration=True)
        return body

    def _send_html_index(self, path: str, entries: list) -> None:
        rows = "".join(
            f"<li><a href='{quote(item.name)}{'/' if getattr(item, 'is_dir', False) else ''}'>"
            f"{_xml_escape(item.name)}</a> "
            f"<span class='size'>{_entry_size(item)} bytes</span></li>"
            for item in entries
        )
        body = (
            f"<!doctype html><html><head><title>{_xml_escape(path)}</title></head>"
            f"<body><h1>{_xml_escape(path)}</h1><ul>{rows}</ul></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Server wrappers
# ---------------------------------------------------------------------------


@dataclass
class ReverseServer:
    """Live handle on a running reverse-server."""

    flavour: str  # "s3" / "webdav"
    bind: str
    port: int
    backend_label: str
    httpd: ThreadingHTTPServer = field(repr=False)
    thread: threading.Thread = field(repr=False)
    #: What clients must send (Bearer, or the Basic password); "" when the
    #: server runs without auth (``auth_token=None``). Never logged.
    auth_token: str = field(default="", repr=False)

    @property
    def base_url(self) -> str:
        scheme = "http"
        host = self.bind
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{scheme}://{host}:{self.port}"

    def shutdown(self) -> None:
        log.info("reverse-%s shutting down %s", self.flavour, self.base_url)
        try:
            self.httpd.shutdown()
        finally:
            self.httpd.server_close()
        if self.thread.is_alive():
            self.thread.join(timeout=2.0)


def _free_port(bind: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind, 0))
        return s.getsockname()[1]


_FACTORIES: dict[str, Callable[[ServerConfig], ReverseServer]] = {}


def register_server_factory(name: str, factory: Callable[[ServerConfig], ReverseServer]) -> None:
    """Register a new reverse-server flavour (e.g. ``"sftp"``)."""
    _FACTORIES[name.lower()] = factory


def supported_flavours() -> list[str]:
    return sorted(_FACTORIES.keys())


def _serve(config: ServerConfig, handler_cls: type, flavour: str) -> ReverseServer:
    local = _is_local_bind(config.bind)
    generated = False
    if config.auth_token is None:
        if not local:
            raise PermissionError(
                f"reverse-{flavour}: auth_token=None (no auth) is allowed only on a "
                f"loopback bind, not on {config.bind!r}"
            )
        config.auth_token = ""
        log.warning(
            "reverse-%s on %s runs without a token: every local user of this host "
            "can reach the exposed backend",
            flavour,
            config.bind,
        )
    else:
        config.auth_token = str(config.auth_token).strip()
        if not config.auth_token:
            if not local:
                raise PermissionError(
                    f"reverse-{flavour} refuses to bind to {config.bind!r} without "
                    "auth_token; otherwise any host that can reach this interface "
                    "can access the exposed backend."
                )
            # Loopback is not private on a shared host: a token by default,
            # as mcp_http does without TLS.
            config.auth_token = secrets.token_urlsafe(32)
            generated = True
    config.root_path = _normalize_root_path(config.root_path)
    if config.auth_token and len(config.auth_token) < 16:
        log.warning(
            "reverse-%s auth_token is short (%d chars); use a long random "
            "token for non-local binds.",
            flavour,
            len(config.auth_token),
        )

    # Build a handler subclass that closes over `config`. Avoids putting
    # a global on the module.
    handler = type(
        f"{handler_cls.__name__}_bound",
        (handler_cls,),
        {"config": config},
    )
    httpd = ThreadingHTTPServer((config.bind, int(config.port)), handler)
    httpd.timeout = 30.0
    config.port = int(httpd.server_address[1])
    label = getattr(config.backend, "name", type(config.backend).__name__)
    server = ReverseServer(
        flavour=flavour,
        bind=config.bind,
        port=config.port,
        backend_label=label,
        httpd=httpd,
        thread=threading.Thread(
            target=httpd.serve_forever,
            name=f"axross-reverse-{flavour}-{config.port}",
            daemon=True,
        ),
        auth_token=config.auth_token,
    )
    server.thread.start()
    log.info(
        "reverse-%s serving %s on %s (read_only=%s, auth=%s)",
        flavour,
        label,
        server.base_url,
        config.read_only,
        ("token generated, see .auth_token" if generated else "yes")
        if config.auth_token
        else "no",
    )
    return server


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def serve_s3(
    backend,
    *,
    bind: str = DEFAULT_BIND,
    port: int = DEFAULT_S3_PORT,
    read_only: bool = False,
    auth_token: str | None = "",
    root_path: str = "/",
) -> ReverseServer:
    """Expose ``backend`` as a minimum-viable S3 endpoint.

    Common clients:

    * ``aws s3 --endpoint-url http://127.0.0.1:9000 ls s3://<bucket>``
    * ``rclone`` with provider ``Other`` and that endpoint URL
    * ``restic`` with ``-r s3:http://127.0.0.1:9000/<bucket>``

    The first URL segment becomes the bucket name; we map it to a
    top-level directory under ``root_path`` on the backend.
    """
    config = ServerConfig(
        backend=backend,
        bind=bind,
        port=port,
        read_only=read_only,
        auth_token=auth_token,
        root_path=root_path,
    )
    return _serve(config, _S3Handler, "s3")


def serve_webdav(
    backend,
    *,
    bind: str = DEFAULT_BIND,
    port: int = DEFAULT_WEBDAV_PORT,
    read_only: bool = False,
    auth_token: str | None = "",
    root_path: str = "/",
) -> ReverseServer:
    """Expose ``backend`` as a minimum-viable WebDAV endpoint.

    Common clients: cadaver, davfs2 (``mount -t davfs``), gnome-files
    (``davs://``), macOS Finder ("Connect to Server..."), Cyberduck.
    Any browser can do read-only listings via the HTML index.
    """
    config = ServerConfig(
        backend=backend,
        bind=bind,
        port=port,
        read_only=read_only,
        auth_token=auth_token,
        root_path=root_path,
    )
    return _serve(config, _DAVHandler, "webdav")


# Plug-points for future flavours.
register_server_factory("s3", lambda cfg: _serve(cfg, _S3Handler, "s3"))
register_server_factory("webdav", lambda cfg: _serve(cfg, _DAVHandler, "webdav"))


__all__ = [
    "DEFAULT_BIND",
    "DEFAULT_S3_PORT",
    "DEFAULT_WEBDAV_PORT",
    "ReverseServer",
    "ServerConfig",
    "register_server_factory",
    "serve_s3",
    "serve_webdav",
    "supported_flavours",
]
