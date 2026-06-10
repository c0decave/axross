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
* **Shared-secret auth for non-local binds.** Pass ``auth_token=…`` and
  the server enforces it (S3: ``X-Amz-Content-Sha256``-style
  headerless-V4 won't validate; we accept ``Authorization: Bearer
  <token>`` instead, which restic / rclone tolerate via ``--header``).
  Binding to a non-loopback address without a token is refused.
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

import hmac
import ipaddress
import logging
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


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------


def _normalize_key(raw: str) -> str:
    """Decode + normalise an HTTP path/key into a backend-friendly path.

    Rejects path-traversal segments so a hostile client can't escape
    the rooted backend.
    """
    decoded = unquote(raw or "")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    parts = []
    for seg in decoded.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            raise PermissionError(f".. segment in path: {raw!r}")
        parts.append(seg)
    return "/" + "/".join(parts)


def _normalize_root_path(raw: str) -> str:
    """Normalize an operator-supplied backend root path.

    The caller is trusted, but accepting ``..`` here would undermine
    the promise that client-supplied paths stay rooted below this path.
    """
    return _normalize_key(raw or "/")


def _is_local_bind(bind: str) -> bool:
    host = (bind or "").strip().lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _backend_join(backend, *parts: str) -> str:
    if hasattr(backend, "join"):
        return backend.join(*parts)
    cleaned = [p.strip("/") for p in parts if p]
    return "/" + "/".join(cleaned)


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


# ---------------------------------------------------------------------------
# Auth + common request handler base
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    backend: Any
    bind: str = DEFAULT_BIND
    port: int = 0
    read_only: bool = False
    auth_token: str = ""  # empty → no auth required
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

    # --------------------------------- helpers ---------------------------

    def _is_authed(self) -> bool:
        if not self.config.auth_token:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return hmac.compare_digest(header[7:], self.config.auth_token)
        return False

    def _send_simple(
        self, code: int, body: bytes = b"", *, content_type: str = "text/plain"
    ) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", HEAD_BANNER)
        self.send_header("Date", _http_date(time.time()))
        self.end_headers()
        if body:
            self.wfile.write(body)

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
        if length < 0:
            raise ValueError("missing Content-Length")
        if length > MAX_BODY_BYTES:
            raise ValueError(f"Content-Length {length} exceeds cap {MAX_BODY_BYTES}")
        moved = 0
        while moved < length:
            chunk = self.rfile.read(min(PUT_CHUNK, length - moved))
            if not chunk:
                break
            written = write_handle.write(chunk)
            if written is not None and int(written) != len(chunk):
                raise OSError(f"short backend write: wrote {written} of {len(chunk)} bytes")
            moved += len(chunk)
        if moved != length:
            raise ValueError(f"short request body: received {moved} of {length} bytes")
        return moved


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
            return (path, "")
        bucket, _, key = path.partition("/")
        return (bucket, key)

    def _backend_path_for(self, bucket: str, key: str) -> str:
        """Rooted backend path. The reverse-server treats the *first
        URL segment* as the bucket name; we map it to a top-level
        directory under ``config.root_path``."""
        return _backend_join(self.config.backend, self.config.root_path, bucket, key)

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
        prefix = self._query_param("prefix") or ""
        try:
            max_keys = int(self._query_param("max-keys") or "1000")
        except ValueError:
            self._s3_error(400, "InvalidArgument", "max-keys must be an integer")
            return
        max_keys = max(1, min(max_keys, 5000))
        bucket_root = _backend_join(self.config.backend, self.config.root_path, bucket)
        try:
            entries, walk_truncated = _walk_keys(
                self.config.backend, bucket_root, prefix, max_keys
            )
        except OSError as exc:
            self._s3_error(404, "NoSuchBucket", str(exc))
            return
        # Defense-in-depth: re-enforce listing-size caps at
        # the HTTP boundary so a regression in _walk_keys cannot blow
        # the response body up.
        entries, defense_truncated = enforce_listing_caps(entries)
        contents_xml = "".join(
            f"<Contents>"
            f"<Key>{_xml_escape(rel)}</Key>"
            f"<LastModified>{_iso_date(item['mtime'])}</LastModified>"
            f"<Size>{item['size']}</Size>"
            f"<StorageClass>STANDARD</StorageClass>"
            f"</Contents>"
            for rel, item in entries
        )
        # Defense-in-depth: consolidate the three truncation
        # signals through a single boundary helper so a regression that
        # drops one signal cannot re-introduce the IsTruncated=false
        # lie when keys still remain.
        truncated = validate_truncation_flag(
            entry_count=len(entries),
            max_keys=max_keys,
            claimed_truncated=defense_truncated,
            walk_truncated=walk_truncated,
        )
        body = (
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
            f"<Name>{_xml_escape(bucket)}</Name>"
            f"<Prefix>{_xml_escape(prefix)}</Prefix>"
            f"<MaxKeys>{max_keys}</MaxKeys>"
            f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
            f"{contents_xml}"
            "</ListBucketResult>"
        ).encode("utf-8")
        self._send_simple(200, body, content_type="application/xml")

    def _handle_head_bucket(self, bucket: str) -> None:
        bucket_root = _backend_join(self.config.backend, self.config.root_path, bucket)
        try:
            self.config.backend.stat(bucket_root)
        except OSError:
            self._s3_error(404, "NoSuchBucket", "bucket not found")
            return
        self._send_simple(200)

    def _handle_get_object(self, bucket: str, key: str) -> None:
        path = self._backend_path_for(bucket, key)
        try:
            item = self.config.backend.stat(path)
        except OSError as exc:
            log.debug("reverse-s3 GET stat failed: %s", exc)
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
            item = self.config.backend.stat(path)
        except OSError:
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
            handle = self.config.backend.open_write(path)
        except OSError as exc:
            self._s3_error(500, "InternalError", str(exc))
            return
        try:
            self._stream_body_to(handle, length)
        except (OSError, ValueError) as exc:
            self._s3_error(400, "InvalidArgument", str(exc))
            return
        finally:
            try:
                handle.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("reverse-s3 close: %s", exc)
        # 200 with empty body is the S3 PUT response shape (with the
        # ETag header). We synthesise a fake ETag — restic / rclone
        # check it for non-emptiness, not validity.
        self.send_response(200)
        self.send_header("ETag", '"' + secrets.token_hex(16) + '"')
        self.send_header("Content-Length", "0")
        self.send_header("Server", HEAD_BANNER)
        self.end_headers()

    def _handle_delete_object(self, bucket: str, key: str) -> None:
        path = self._backend_path_for(bucket, key)
        try:
            self.config.backend.remove(path)
        except OSError as exc:
            log.debug("reverse-s3 DELETE failed: %s", exc)
            # S3 returns 204 even for non-existent keys.
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
        try:
            entries = backend.list_dir(path)
        except OSError:
            continue
        for item in entries:
            full = _backend_join(backend, path, item.name)
            if len(full) > MAX_WALK_PATH_CHARS:
                truncated = True
                continue
            rel = full[len(root) :].lstrip("/")
            if getattr(item, "is_dir", False):
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
            item = self.config.backend.stat(path)
        except OSError:
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
            item = self.config.backend.stat(path)
        except OSError:
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
            handle = self.config.backend.open_write(path)
        except OSError as exc:
            self._send_simple(500, str(exc).encode("utf-8"))
            return
        try:
            self._stream_body_to(handle, length)
        except (OSError, ValueError) as exc:
            self._send_simple(400, str(exc).encode("utf-8"))
            return
        finally:
            try:
                handle.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("reverse-dav close: %s", exc)
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
        try:
            self.config.backend.remove(path, recursive=True)
        except OSError as exc:
            self._send_simple(404, str(exc).encode("utf-8"))
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
        except (ValueError, PermissionError) as exc:
            self._send_simple(400, str(exc).encode("utf-8"))
            return
        dst_full = _backend_join(self.config.backend, self.config.root_path, dst_norm.lstrip("/"))
        src_full = self._backend_path()
        if src_full is None:
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
            item = self.config.backend.stat(path)
        except OSError:
            self._send_simple(404)
            return
        items: list[tuple[str, Any]] = [(self._url_for(path), item)]
        if depth in ("1", "infinity") and getattr(item, "is_dir", False):
            try:
                entries = self.config.backend.list_dir(path)
            except OSError:
                entries = []
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
        webdav_lock_handle = "opaquelocktoken:" + secrets.token_hex(8)
        body = (
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
        self.send_response(200)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Lock-Token", f"<{token}>")
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

    def _backend_path(self) -> str | None:
        try:
            key = _normalize_key(urlparse(self.path).path or "/")
        except (ValueError, PermissionError) as exc:
            self._send_simple(400, str(exc).encode("utf-8"))
            return None
        return _backend_join(self.config.backend, self.config.root_path, key.lstrip("/"))

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
    config.auth_token = str(config.auth_token or "").strip()
    config.root_path = _normalize_root_path(config.root_path)
    if not _is_local_bind(config.bind) and not config.auth_token:
        raise PermissionError(
            f"reverse-{flavour} refuses to bind to {config.bind!r} without "
            "auth_token; otherwise any host that can reach this interface "
            "can access the exposed backend."
        )
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
    )
    server.thread.start()
    log.info(
        "reverse-%s serving %s on %s (read_only=%s, auth=%s)",
        flavour,
        label,
        server.base_url,
        config.read_only,
        "yes" if config.auth_token else "no",
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
    auth_token: str = "",
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
    auth_token: str = "",
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
