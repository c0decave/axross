"""Google Drive backend implementing the FileBackend protocol.

Requires: pip install axross[gdrive]
(google-api-python-client, google-auth-oauthlib, google-auth-httplib2)

Uses OAuth2 browser redirect flow for authentication. Tokens are cached
locally so the user only needs to authorise once.

Google Docs, Sheets and Slides (Google-native files, no binary content)
are listed with the extension of their export - ``Thesis`` as
``Thesis.docx``, ``Budget`` as ``Budget.xlsx``, ``Deck`` as
``Deck.pptx``, a drawing as ``.pdf`` - without a size, and read through
``files.export_media`` (Google caps an export at 10 MB). They are
read-only here: a write to one is refused. A Google-native item without
an export (a Form, a Site) is listed and refused on reading with that
reason - not "permission denied".

Shared drives: items of a shared drive that are reachable from My Drive
(shared into it, a shortcut's folder) are listed, read and written
(``supportsAllDrives``). The shared drives themselves are not listed:
there is no "/Shared drives/<name>" root (docs/USAGE.md).
"""

from __future__ import annotations

import errno
import json
import logging
import os
import posixpath
import tempfile
import threading
from datetime import datetime, timezone
from typing import IO

from core.answer_fields import as_dict, as_list, as_size, as_str, as_utc_datetime
from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.desktop_open import install_clean_webbrowser
from core import cloud_http, transfer_hooks
from core.path_policy import refuse_folder_path, safe_leaf
from core.read_spool import new_read_spool
from core.secure_storage import adopt_legacy_secret_file, write_secret_file
from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
except ImportError:
    Credentials = None  # type: ignore[assignment,misc]

_SCOPES = ["https://www.googleapis.com/auth/drive"]


def _http_status(exc: BaseException) -> int | None:
    """The HTTP status of a googleapiclient HttpError, else None."""
    status = getattr(getattr(exc, "resp", None), "status", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None

#: 403 reasons that are a rate limit ("try later"), and the ones that
#: say the storage is full.
_RATE_LIMIT_REASONS = ("userRateLimitExceeded", "rateLimitExceeded")
_QUOTA_REASONS = ("storageQuotaExceeded", "quotaExceeded", "teamDriveFileLimitExceeded")
#: "Name not unique": a name several items of one folder hold.
_ENOTUNIQ = getattr(errno, "ENOTUNIQ", errno.EIO)
#: Pages of one name lookup at most (a page may be empty while more follow).
_LOOKUP_MAX_PAGES = 100


def _error_text(exc: BaseException) -> str:
    content = getattr(exc, "content", b"")
    if isinstance(content, bytes):
        content = content.decode("utf-8", "replace")
    return f"{content} {exc}" if isinstance(content, str) else str(exc)


def _is_retryable(exc: BaseException, idempotent: bool) -> bool:
    """A request worth sending again: 429, a 403 rate limit, and - when
    sending it twice does no harm - a 5xx or a dropped connection."""
    status = _http_status(exc)
    if status is None:
        # httplib2 / socket failures: OSError (TimeoutError, ConnectionError ...)
        return idempotent and isinstance(exc, (TimeoutError, ConnectionError))
    if status == 429:
        return True
    if status == 403:
        return any(r in _error_text(exc) for r in _RATE_LIMIT_REASONS)
    return idempotent and status in cloud_http.RETRYABLE_STATUSES


def _run(request, *, idempotent: bool = True, gone_ok: bool = False, step=None):
    """``request.execute()`` with bounded retries (cloud_http) on what
    Drive documents as "try again": 429, the 403 rate limits, 5xx.
    googleapiclient's own retry (``num_retries``) defaults to none, and
    it ignores Retry-After. A resumable upload request resumes where its
    session stands when it is executed again. The last failure is raised
    as it came; :func:`_drive_error` types it.

    *gone_ok* (a delete): a 404 on a retry after a 5xx or a lost answer
    is that first try's work - the file is gone, as asked - and returns
    None. *step*: called instead of ``request.execute`` (one chunk of a
    resumable upload); the retries are the same.
    """
    attempt = 0
    uncertain = False
    call = step if step is not None else request.execute
    while True:
        attempt += 1
        try:
            return call()
        except Exception as exc:
            if gone_ok and uncertain and _http_status(exc) in (404, 410):
                log.info("Google Drive: gone on the retry (the first try did it)")
                return None
            if attempt >= cloud_http.ATTEMPTS or not _is_retryable(exc, idempotent):
                raise
            resp = getattr(exc, "resp", None)
            retry_after = None
            if resp is not None and hasattr(resp, "get"):
                retry_after = cloud_http.retry_after_seconds(resp.get("retry-after"))
            status = _http_status(exc)
            # Not a 429 / rate limit (those were not carried out): whether
            # the first try did its work is unknown.
            uncertain = uncertain or (status is not None and status >= 500) or status is None
            log.debug("Google Drive request failed (%s); retry %d", exc, attempt)
            cloud_http.pause(attempt, retry_after)


def _drive_error(exc: BaseException, message: str, filename: str | None = None) -> OSError:
    """*message* as the typed OSError of a failed Drive request: 404
    FileNotFoundError, 403 PermissionError (ENOSPC for a full storage,
    EAGAIN for a rate limit), 429 / 5xx EAGAIN / EIO ... (cloud_http).
    A cancelled transfer (InterruptedError, core.transfer_hooks) stays
    one: the transfer engine reports it as cancelled, not failed."""
    if isinstance(exc, InterruptedError):
        return transfer_hooks.UploadCancelled(*exc.args) if isinstance(
            exc, transfer_hooks.UploadCancelled) else InterruptedError(*exc.args)
    status = _http_status(exc)
    if status is None:
        return cloud_http.rewrap(exc, message, filename)
    if status == 403:
        text = _error_text(exc)
        if "exportSizeLimitExceeded" in text:
            return cloud_http.oserror(
                errno.EFBIG, f"{message} (Google exports a document of at most 10 MB)", filename)
        if "fileNotDownloadable" in text or "cannotExportFile" in text:
            # Not a permission: the item has no file form to download.
            return cloud_http.oserror(
                errno.EOPNOTSUPP,
                f"{message} (a Google-native item without binary content that Google "
                f"Drive can download or export, such as a Form or a Site)",
                filename,
            )
        if any(r in text for r in _QUOTA_REASONS):
            return cloud_http.oserror(errno.ENOSPC, message, filename)
        if any(r in text for r in _RATE_LIMIT_REASONS):
            return cloud_http.oserror(errno.EAGAIN, message, filename)
    return cloud_http.status_oserror(status, message, filename)


_FOLDER_MIME = "application/vnd.google-apps.folder"
_NATIVE_PREFIX = "application/vnd.google-apps."
#: Google-native (Docs editors) files as axross reads them: the MIME type
#: files.export_media is asked for, and the extension the name gets.
_EXPORTS = {
    "application/vnd.google-apps.document": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"),
    "application/vnd.google-apps.spreadsheet": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"),
    "application/vnd.google-apps.presentation": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx"),
    "application/vnd.google-apps.drawing": ("application/pdf", ".pdf"),
    "application/vnd.google-apps.jam": ("application/pdf", ".pdf"),
    "application/vnd.google-apps.script": ("application/vnd.google-apps.script+json", ".json"),
}
_EXPORT_EXTENSIONS = tuple(sorted({ext for _mime, ext in _EXPORTS.values()}))
#: Items of a shared drive answer only requests that say they know of them.
_ALL_DRIVES = {"supportsAllDrives": True}
_ALL_DRIVES_LIST = {"supportsAllDrives": True, "includeItemsFromAllDrives": True}


def _is_native(mime) -> bool:
    """A Google-native item (a Doc, a Form ...) - no binary content."""
    return isinstance(mime, str) and mime.startswith(_NATIVE_PREFIX) and mime != _FOLDER_MIME


def _listed_name(name: str, mime) -> str:
    """*name* as the listing shows an item of *mime*: a Google Doc, Sheet
    or Slides deck with the extension of its export (unless it has it)."""
    export = _EXPORTS.get(mime) if isinstance(mime, str) else None
    if export is None or name.lower().endswith(export[1]):
        return name
    return name + export[1]
_FILE_FIELDS = "files(id,name,mimeType,size,modifiedTime)"
#: Bytes per download request. googleapiclient's default is 100 MiB, each
#: chunk one bytes object in RAM.
_DOWNLOAD_CHUNK = 4 * 1024 * 1024
#: Bytes per resumable-upload request (a multiple of 256 KiB, as Drive
#: asks): Cancel and the progress bar act between two of them. The
#: library's default, 100 MiB, made both wait for 100 MiB at a time.
_UPLOAD_CHUNK = 8 * 1024 * 1024


def _download_spooled(request) -> IO[bytes]:
    """A media download written chunk by chunk into a spool (small files
    stay in memory, larger ones go to a temp file) instead of a BytesIO
    holding the whole file."""
    spool = new_read_spool()
    # In a running transfer: Cancel between chunks, the bytes reported.
    hooks = transfer_hooks.current()
    try:
        downloader = MediaIoBaseDownload(spool, request, chunksize=_DOWNLOAD_CHUNK)
        done = False
        while not done:
            if hooks is not None:
                hooks.check()
            # The library's own retry of a 429 / 5xx chunk (backoff).
            status, done = downloader.next_chunk(num_retries=cloud_http.ATTEMPTS - 1)
            if hooks is not None:
                total = getattr(status, "total_size", None)
                hooks.received(spool.tell(), total if isinstance(total, int) else None)
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


def _upload(request, hooks, size: int) -> None:
    """Run a resumable upload *request*: chunk by chunk (``next_chunk``)
    in a running transfer - Cancel checked and the bytes reported between
    two chunks - else in one ``execute``. Retries as :func:`_run`."""
    if hooks is None or not callable(getattr(request, "next_chunk", None)):
        if hooks is not None:
            hooks.check()
        _run(request)
        if hooks is not None:
            hooks.sent(size, size, check=False)
        return
    while True:
        hooks.check()
        status, response = _run(request, step=request.next_chunk)
        if response is not None:
            # The last chunk made the file: too late for a Cancel.
            hooks.sent(size, size, check=False)
            return
        done = getattr(status, "resumable_progress", None)
        if isinstance(done, int):
            hooks.sent(done, size)


class _SpooledWriter:
    """Write to a temp buffer, then upload to Google Drive on close."""

    def __init__(self, service, file_name: str, parent_id: str, existing_id: str | None = None):
        self._service = service
        self._file_name = file_name
        self._parent_id = parent_id
        self._existing_id = existing_id
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        self._closed = False
        # The running transfer's Cancel and progress (core.transfer_hooks):
        # the upload happens in close(), after the copy loop.
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
            size = self._buf.seek(0, os.SEEK_END)
            self._buf.seek(0)
            media = MediaIoBaseUpload(
                self._buf,
                mimetype="application/octet-stream",
                chunksize=_UPLOAD_CHUNK,
                resumable=True,
            )
            # A resumable upload: executed again after a 429 / 5xx, the
            # request resumes its session - the file is made once.
            if self._existing_id:
                request = self._service.files().update(
                    fileId=self._existing_id,
                    media_body=media,
                )
            else:
                body = {
                    "name": self._file_name,
                    "parents": [self._parent_id],
                }
                request = self._service.files().create(
                    body=body,
                    media_body=media,
                )
            with transfer_hooks.bound(hooks):
                _upload(request, hooks, size)
        except InterruptedError:
            # Cancelled between two chunks: a resumable session commits
            # the file only with its last chunk, so nothing was made or
            # replaced (Drive drops the unfinished session).
            raise transfer_hooks.UploadCancelled(transfer_hooks.CANCELLED) from None
        except Exception as exc:
            # The SDK's HttpError is no OSError: the editor's "Cannot save"
            # and atomic_write's caller catch OSError.
            raise _drive_error(exc, f"Cannot upload {self._file_name}: {exc}") from exc
        finally:
            self._buf.close()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


class GDriveSession(SessionLifecycle):
    """Google Drive backend implementing the FileBackend protocol.

    Uses the Google Drive v3 API with OAuth2. Paths are mapped to Drive
    file IDs internally via ``_resolve_path``, with a cache to avoid
    repeated lookups.
    """

    @property
    def _service(self):
        """The Drive service of the calling thread. googleapiclient's
        service sits on one httplib2.Http, which is not thread-safe: the
        connection-health check and a transfer on two threads interleaved
        on one connection (SSL and protocol errors, one call reading the
        other's answer). Each thread gets a service of its own, built from
        the same credentials; a session made without them (tests) keeps the
        one it was given."""
        base = self.__dict__.get("_service_base")
        creds = self.__dict__.get("_creds")
        if base is None or creds is None:
            return base
        local = self.__dict__.get("_per_thread")
        if local is None:
            return base
        service = getattr(local, "service", None)
        if service is None or getattr(local, "base", None) is not base:
            service = (base if threading.current_thread() is self.__dict__.get("_owner_thread")
                       else self._build_service(creds))
            local.service, local.base = service, base
        return service

    @_service.setter
    def _service(self, value) -> None:
        self.__dict__["_service_base"] = value

    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_file: str = "~/.config/axross/gdrive_token.json",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
        legacy_token_file: str | None = None,
    ):
        if Credentials is None:
            raise ImportError(
                "Google Drive support requires google-api-python-client, "
                "google-auth-oauthlib and google-auth-httplib2. "
                "Install with: pip install axross[gdrive]"
            )

        self._client_id = client_id
        self._client_secret = client_secret
        self._token_file = os.path.expanduser(token_file)
        # The token file all profiles shared before each got its own: it
        # is taken over only when it was issued to this client id.
        self._legacy_token_file = (
            os.path.expanduser(legacy_token_file) if legacy_token_file else None
        )
        self._path_cache: dict[str, str] = {"/": "root"}
        self._service = None
        self._proxy_type = proxy_type or "none"
        self._proxy_host = proxy_host
        self._proxy_port = int(proxy_port or 0)
        self._proxy_username = proxy_username
        self._proxy_password = proxy_password
        from core.proxy import build_requests_proxies

        self._requests_proxies = build_requests_proxies(
            self._proxy_type,
            self._proxy_host,
            self._proxy_port,
            self._proxy_username,
            self._proxy_password,
        )

        self._authenticate()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _authenticate(self) -> None:
        """Load cached credentials or run the OAuth2 browser flow."""
        creds: Credentials | None = None

        adopt_legacy_secret_file(
            self._token_file,
            getattr(self, "_legacy_token_file", None),
            lambda text: json.loads(text).get("client_id") == self._client_id,
        )
        if os.path.exists(self._token_file):
            try:
                creds = Credentials.from_authorized_user_file(self._token_file, _SCOPES)
            except Exception as exc:
                log.warning(
                    "Google Drive: failed to load cached token from %s (%s: %s); "
                    "restarting OAuth flow",
                    self._token_file,
                    type(exc).__name__,
                    exc,
                )
                creds = None
        if creds is not None and creds.client_id != self._client_id:
            # Another OAuth client's token opens another account.
            log.warning(
                "Google Drive: the token in %s was issued to another client id; "
                "restarting OAuth flow",
                self._token_file,
            )
            creds = None

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(self._google_auth_request())
                log.debug("Google Drive: access token refreshed")
            except Exception as exc:
                log.warning(
                    "Google Drive: token refresh failed (%s: %s); restarting OAuth flow",
                    type(exc).__name__,
                    exc,
                )
                creds = None

        if not creds or not creds.valid:
            client_config = {
                "installed": {
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://localhost"],
                }
            }
            flow = InstalledAppFlow.from_client_config(client_config, _SCOPES)
            requests_proxies = getattr(self, "_requests_proxies", {}) or {}
            oauth_session = getattr(flow, "oauth2session", None)
            if oauth_session is not None:
                from core.proxy import lock_requests_session_to_profile_proxy

                lock_requests_session_to_profile_proxy(oauth_session)
            if requests_proxies:
                if oauth_session is None:
                    raise OSError(
                        errno.ENOTSUP,
                        "Google Drive proxy configured but the OAuth "
                        "session hook is unavailable; refusing direct "
                        "token traffic."
                    )
                from core.proxy import lock_requests_session_to_profile_proxy

                lock_requests_session_to_profile_proxy(oauth_session, requests_proxies)
                log.warning(
                    "Google Drive proxy configured: OAuth token and Drive "
                    "API calls use the profile proxy, but the browser "
                    "consent page is outside axross and may use browser or "
                    "system proxy settings."
                )
            # The consent page opens through webbrowser (core.desktop_open).
            install_clean_webbrowser()
            creds = flow.run_local_server(port=0)

            # Persist token for reuse (atomic, 0o600)
            try:
                write_secret_file(self._token_file, creds.to_json())
                log.info("OAuth2 token saved to %s", self._token_file)
            except OSError as exc:
                log.error("Google Drive: failed to save token to %s: %s", self._token_file, exc)

        self._creds = creds
        self._per_thread = threading.local()
        self._owner_thread = threading.current_thread()
        self._service = self._build_service(creds)
        log.info("Google Drive connected")

    def _google_auth_request(self):
        if not getattr(self, "_requests_proxies", None):
            return Request()
        import requests

        sess = requests.Session()
        from core.proxy import lock_requests_session_to_profile_proxy

        lock_requests_session_to_profile_proxy(sess, self._requests_proxies)
        return Request(session=sess)

    def _build_service(self, creds):
        """Construct the googleapiclient ``drive/v3`` service.

        When a proxy is configured we attach an ``httplib2.Http``
        carrying a ``ProxyInfo`` (httplib2 has native SOCKS support
        via PySocks) and wrap it in ``google_auth_httplib2.AuthorizedHttp``
        so Google's OAuth credentials still apply on top.

        Tests sometimes construct GDriveSession via ``__new__`` to
        bypass the network-touching ctor; tolerate the missing proxy
        attrs by treating them as "no proxy".
        """
        ptype = (getattr(self, "_proxy_type", "none") or "none").lower()
        phost = getattr(self, "_proxy_host", "") or ""
        if ptype == "none" or not phost:
            return build("drive", "v3", credentials=creds)
        # Apply the same SSRF guard the SOCKS / HTTP-CONNECT path uses
        # — keeps a hostile profile from making us proxy via metadata
        # endpoints or RFC1918 addresses.
        from core.proxy import (
            ProxyConfig,
            _assert_proxy_host_not_private,
            effective_http_proxy,
            parse_proxy_type,
        )

        _assert_proxy_host_not_private(phost, int(getattr(self, "_proxy_port", 0) or 0))
        transport, _auth = parse_proxy_type(ptype)
        if transport == "https" or _auth not in ("", "basic"):
            # httplib2 cannot do TLS-to-the-proxy or NTLM: use the loopback shim.
            eff = effective_http_proxy(
                ProxyConfig(
                    ptype,
                    phost,
                    int(getattr(self, "_proxy_port", 0) or 0),
                    getattr(self, "_proxy_username", "") or "",
                    getattr(self, "_proxy_password", "") or "",
                )
            )
            ptype, phost = "http", eff.host
            self._proxy_port, self._proxy_username, self._proxy_password = eff.port, "", ""
        else:
            ptype = transport
        try:
            import httplib2
            from google_auth_httplib2 import AuthorizedHttp
        except ImportError as exc:
            raise OSError(
                errno.ENOTSUP,
                "Google Drive proxy requires httplib2 + google-auth-httplib2 "
                "(both come with the [gdrive] extra).",
            ) from exc
        if ptype == "socks5":
            socks_type = httplib2.socks.PROXY_TYPE_SOCKS5
        elif ptype == "socks4":
            socks_type = httplib2.socks.PROXY_TYPE_SOCKS4
        elif ptype == "http":
            socks_type = httplib2.socks.PROXY_TYPE_HTTP
        else:
            raise ValueError(f"Unknown proxy_type: {ptype}")
        proxy_info = httplib2.ProxyInfo(
            proxy_type=socks_type,
            proxy_host=phost,
            proxy_port=int(getattr(self, "_proxy_port", 0) or 0),
            proxy_user=getattr(self, "_proxy_username", "") or None,
            proxy_pass=getattr(self, "_proxy_password", "") or None,
            proxy_rdns=True,
        )
        # build_http(), as build() uses without a proxy: a 60 s socket
        # timeout, and 308 is no redirect - Drive answers "308 Resume
        # Incomplete" to every non-final chunk of a resumable upload.
        from googleapiclient.http import build_http

        http = build_http()
        http.proxy_info = proxy_info
        return build("drive", "v3", http=AuthorizedHttp(creds, http=http))

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _resolve_path(self, path: str, *, fresh: bool = False) -> str:
        """Resolve a POSIX-style path to a Google Drive file ID.

        Walks the path components, querying for each folder by name within
        its parent. Results are cached in ``self._path_cache``. *fresh*
        asks the server for every component: what deletes or overwrites
        must not act on a cached id - renamed on the web since, that id is
        another file now.
        """
        path = self.normalize(path)
        if not fresh and path in self._path_cache:
            return self._path_cache[path]

        parts = [p for p in path.split("/") if p]
        current_id = "root"
        current_path = "/"

        for part in parts:
            current_path = posixpath.join(current_path, part)
            if not fresh and current_path in self._path_cache:
                current_id = self._path_cache[current_path]
                continue

            try:
                current_id = self._lookup_child(current_id, part, path)
            except FileNotFoundError:
                self._invalidate_cache(current_path)
                raise
            self._path_cache[current_path] = current_id

        return current_id

    def _resolve_for_change(self, path: str, action: str) -> str:
        """The id a delete, rename or overwrite of *path* acts on: asked of
        the server, and refused when it is not the file the session saw.

        stat / open_read / list_dir work from the cached path-to-id map,
        so a move that read and size-checked id A must not then delete
        id B: renamed on the web, with a new upload under the old name,
        the path names another file now - and files.delete skips the
        Drive trash. The fresh answer stays in the cache, so a retry
        after the refusal acts on the file the path names now.
        """
        path = self.normalize(path)
        seen_id = self._path_cache.get(path)
        file_id = self._resolve_path(path, fresh=True)
        if seen_id is not None and seen_id != file_id:
            raise OSError(
                errno.ESTALE,
                f"Cannot {action} {path}: it names another file on Google Drive "
                f"now than the one listed (renamed or replaced since); "
                f"refresh the folder and try again",
                path,
            )
        return file_id

    def _lookup_child(self, parent_id: str, name: str, path: str) -> str:
        """The id of the one item called *name* in folder *parent_id*,
        asked of the server (not the cache). FileNotFoundError when there
        is none; OSError when the answer fails, and ENOTUNIQ when it names
        several.

        Every page is read: Drive documents that files.list may answer
        fewer items than pageSize - even none - while a nextPageToken
        says more follow. The first page alone read as "not found", and
        open_write / mkdir then made a second item of the name.
        """
        ids = self._ids_named(parent_id, name, name, path)
        stem = name[: -len(name.rsplit(".", 1)[-1]) - 1] if "." in name else ""
        if stem and name.lower().endswith(_EXPORT_EXTENSIONS):
            # "Thesis.docx" may be the Google Doc "Thesis" (_listed_name).
            ids += [i for i in self._ids_named(parent_id, stem, name, path) if i not in ids]
        if len(ids) > 1:
            raise OSError(
                _ENOTUNIQ,
                f"Cannot resolve path '{path}': at least 2 files named {name!r} "
                f"in one folder",
                path,
            )
        if not ids:
            raise FileNotFoundError(errno.ENOENT, "Not found", path)
        if not ids[0]:
            raise OSError(errno.EPROTO,
                          f"Cannot resolve path '{path}': the answer carries no file id")
        return ids[0]

    def _ids_named(self, parent_id: str, query_name: str, name: str, path: str) -> list[str]:
        """The ids of the items of folder *parent_id* called *query_name*
        whose listed name (_listed_name) is *name*; OSError ENOTUNIQ as
        soon as there are two."""
        query = (
            f"'{parent_id}' in parents "
            f"and name = '{self._escape_query(query_name)}' "
            f"and trashed = false"
        )
        ids: list[str] = []
        page_token = ""
        seen_tokens: set[str] = set()
        for _page in range(_LOOKUP_MAX_PAGES):
            kwargs = dict(q=query, fields="nextPageToken,files(id,name,mimeType)", pageSize=2,
                          **_ALL_DRIVES_LIST)
            if page_token:
                kwargs["pageToken"] = page_token
            try:
                resp = as_dict(_run(self._service.files().list(**kwargs)))
            except Exception as e:
                raise _drive_error(e, f"Cannot resolve path '{path}': {e}") from e
            for entry in as_list(resp.get("files")):
                entry = as_dict(entry)
                # A name query may match regardless of case; the folder
                # can hold "Report.txt" beside "report.txt".
                if "name" in entry and _listed_name(as_str(entry.get("name")),
                                                    entry.get("mimeType")) != name:
                    continue
                ids.append(as_str(entry.get("id")))
            if len(ids) > 1:
                # Drive allows several files of one name in a folder; any
                # pick could delete, read or overwrite the wrong one.
                raise OSError(
                    _ENOTUNIQ,
                    f"Cannot resolve path '{path}': at least 2 files named {name!r} "
                    f"in one folder",
                    path,
                )
            page_token = as_str(resp.get("nextPageToken"))
            if not page_token:
                break
            if page_token in seen_tokens:
                raise OSError(errno.EPROTO,
                              f"Cannot resolve path '{path}': the server repeats a page token")
            seen_tokens.add(page_token)
        else:
            raise OSError(errno.EPROTO, f"Cannot resolve path '{path}': the name query does "
                          f"not end after {_LOOKUP_MAX_PAGES} pages")
        return ids

    def _existing_child(self, parent_id: str, name: str, path: str) -> str | None:
        """The id *name* already has in folder *parent_id*, None when it is
        free. Drive takes a second item of a name a folder holds, so mkdir
        and rename ask first; any answer but "not found" (a failed or
        ambiguous lookup) is an OSError, never a go-ahead."""
        try:
            return self._lookup_child(parent_id, name, path)
        except FileNotFoundError:
            return None

    @staticmethod
    def _new_leaf(name: str, path: str, action: str) -> str:
        """*name* as the name of a new item; EINVAL for one the listing
        would drop (a control character, a slash, "..": safe_leaf) - the
        item would be made, and never be seen again."""
        try:
            return safe_leaf(name)
        except ValueError as exc:
            raise OSError(errno.EINVAL, f"Cannot {action} {path}: {exc}", path) from exc

    @staticmethod
    def _escape_query(name: str) -> str:
        """Escape single quotes for the Drive API query language."""
        return name.replace("\\", "\\\\").replace("'", "\\'")

    def _invalidate_cache(self, path: str) -> None:
        """Remove a path (and its children) from the resolution cache."""
        path = self.normalize(path)
        to_remove = [k for k in self._path_cache if k == path or k.startswith(path + "/")]
        for k in to_remove:
            del self._path_cache[k]

    def _has_children(self, folder_id: str, path: str) -> bool:
        """True when the folder *folder_id* holds anything not trashed."""
        try:
            resp = (
                _run(self._service.files()
                .list(
                    q=f"'{folder_id}' in parents and trashed = false",
                    fields="files(id)",
                    pageSize=1,
                    **_ALL_DRIVES_LIST,
                ))
            )
        except Exception as e:
            raise _drive_error(e, f"Cannot list {path}: {e}") from e
        if not isinstance(resp, dict) or not isinstance(resp.get("files", []), list):
            raise OSError(errno.EPROTO, f"Cannot list {path}: the answer is not a file list")
        return bool(resp.get("files")) or bool(as_str(resp.get("nextPageToken")))

    def _get_metadata(self, file_id: str) -> dict:
        """Fetch metadata for a single file ID."""
        try:
            meta = (
                _run(self._service.files()
                .get(
                    fileId=file_id,
                    fields="id,name,mimeType,size,modifiedTime",
                    **_ALL_DRIVES,
                ))
            )
        except Exception as e:
            if _http_status(e) == 404:
                # An id from the path cache that is gone on the server.
                raise FileNotFoundError(
                    errno.ENOENT, f"Cannot get metadata for {file_id}: not found", file_id
                ) from e
            raise _drive_error(e, f"Cannot get metadata for {file_id}: {e}") from e
        if not isinstance(meta, dict):
            raise OSError(errno.EPROTO, f"Cannot get metadata for {file_id}: the answer is not a JSON object")
        return meta

    # ------------------------------------------------------------------
    # FileBackend protocol
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Google Drive"

    @property
    def connected(self) -> bool:
        if self._service is None:
            return False
        try:
            # No retries: a liveness check answers now.
            self._service.about().get(fields="user").execute()
            return True
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("Google Drive liveness check failed: %s", exc)
            return False

    def close(self) -> None:
        if self._service is not None:
            log.info("Google Drive disconnecting")
        self._service = None

    def disconnect(self) -> None:
        self.close()

    def list_dir(self, path: str) -> list[FileItem]:
        folder_id = self._resolve_path(path)

        items: list[FileItem] = []
        ids: dict[str, list[str]] = {}
        listed = 0
        page_token: str | None = None
        seen_tokens: set[str] = set()

        while True:
            try:
                resp = (
                    _run(self._service.files()
                    .list(
                        q=f"'{folder_id}' in parents and trashed = false",
                        fields=f"nextPageToken,{_FILE_FIELDS}",
                        pageSize=1000,
                        pageToken=page_token,
                        **_ALL_DRIVES_LIST,
                    ))
                )
            except Exception as e:
                raise _drive_error(e, f"Cannot list {path}: {e}") from e

            if not isinstance(resp, dict) or not isinstance(resp.get("files", []), list):
                raise OSError(errno.EPROTO, f"Cannot list {path}: the answer is not a file list")
            for f in resp.get("files", []):
                listed += 1
                if not isinstance(f, dict):
                    continue
                file_id = as_str(f.get("id"))
                try:
                    name = safe_leaf(as_str(f.get("name")))
                except ValueError as exc:
                    log.warning(
                        "Google Drive list_dir(%s): skipping unsafe child name %r: %s",
                        path,
                        f.get("name"),
                        exc,
                    )
                    continue
                if not file_id:
                    log.warning("Google Drive list_dir(%s): skipping %r without an id", path, name)
                    continue
                mime = f.get("mimeType")
                name = _listed_name(name, mime)
                is_dir = mime == _FOLDER_MIME
                size = as_size(f.get("size"), digit_strings=True) if not is_dir else 0
                modified = self._parse_time(f.get("modifiedTime", ""))
                # A Google Doc is read here as an export: read-only.
                items.append(FileItem(name=name, size=size, modified=modified, is_dir=is_dir,
                                      permissions=0o444 if _is_native(mime) else 0))
                ids.setdefault(name, []).append(file_id)

            page_token = as_str(resp.get("nextPageToken"))
            if not page_token:
                break
            # A token handed back twice would page forever.
            if page_token in seen_tokens:
                raise OSError(errno.EPROTO, f"Cannot list {path}: the server repeats a page token")
            seen_tokens.add(page_token)

        if not listed and folder_id != "root" and \
                self._get_metadata(folder_id).get("mimeType") != _FOLDER_MIME:
            # "'<id>' in parents" of a FILE is an empty answer, not an error.
            raise NotADirectoryError(errno.ENOTDIR, f"Cannot list {path}: a file", path)

        # Cache the child paths for future lookups - only names that one
        # file holds: a shared name stays out, so _resolve_path finds it
        # ambiguous instead of the cache naming one of the files.
        base = self.normalize(path)
        # Names cached before and gone from the folder now (renamed,
        # moved or deleted on the web) leave the cache with their subtree.
        prefix = base.rstrip("/") + "/"
        for cached in [k for k in self._path_cache if k.startswith(prefix)
                       and "/" not in k[len(prefix):] and k[len(prefix):] not in ids]:
            self._invalidate_cache(cached)
        for name, file_ids in ids.items():
            child_path = posixpath.join(base, name)
            if len(file_ids) == 1:
                self._path_cache[child_path] = file_ids[0]
            else:
                self._invalidate_cache(child_path)
        return items

    def stat(self, path: str) -> FileItem:
        return cloud_http.no_file_as_folder(path, self._stat(path))

    def _stat(self, path: str) -> FileItem:
        file_id = self._resolve_path(path)
        meta = self._get_metadata(file_id)
        mime = meta.get("mimeType")
        is_dir = mime == _FOLDER_MIME
        size = as_size(meta.get("size"), digit_strings=True) if not is_dir else 0
        modified = self._parse_time(meta.get("modifiedTime", ""))
        name = as_str(meta.get("name"))
        name = _listed_name(name, mime) if name else posixpath.basename(path.rstrip("/")) or "/"
        return FileItem(name=name, size=size, modified=modified, is_dir=is_dir,
                        permissions=0o444 if _is_native(mime) else 0)

    def is_dir(self, path: str) -> bool:
        """False only for "not found"; a failed lookup (timeout, 5xx, rate
        limit, a name two files share) is an OSError."""
        try:
            file_id = self._resolve_path(path)
            meta = self._get_metadata(file_id)
        except FileNotFoundError:
            return False
        return meta.get("mimeType") == _FOLDER_MIME

    def exists(self, path: str) -> bool:
        """False only for "not found"; any other failure is an OSError -
        server_side_copy(overwrite=False) takes False as its go-ahead.
        Asked of the server, not the cache: a cached parent folder renamed
        on the web since named another folder, and the no-clobber check
        said False for a file open_write() (which resolves fresh) then
        overwrote."""
        seen = self._path_cache.get(self.normalize(path))
        try:
            self._resolve_path(path, fresh=True)
        except FileNotFoundError:
            return False
        if seen is not None:
            # The id the pane listed stays what the session "saw": a write
            # that follows checks it against the server (_resolve_for_change)
            # and refuses when the name is another file's now.
            self._path_cache[self.normalize(path)] = seen
        return True

    def mkdir(self, path: str) -> None:
        path = self.normalize(path)
        parent_path = self.parent(path)
        dir_name = self._new_leaf(posixpath.basename(path), path, "create directory")
        parent_id = self._resolve_path(parent_path)
        if self._existing_child(parent_id, dir_name, path) is not None:
            raise FileExistsError(errno.EEXIST, f"Cannot create directory {path}: it exists", path)

        body = {
            "name": dir_name,
            "mimeType": _FOLDER_MIME,
            "parents": [parent_id],
        }
        try:
            result = (
                _run(self._service.files()
                .create(
                    body=body,
                    fields="id",
                ), idempotent=False)
            )
        except Exception as e:
            raise _drive_error(e, f"Cannot create directory {path}: {e}") from e

        # The folder exists now; without an id in the answer it is
        # simply resolved by name on the next lookup.
        folder_id = as_str(as_dict(result).get("id"))
        if folder_id:
            self._path_cache[path] = folder_id
        log.info("Created directory: %s", path)

    def remove(self, path: str, recursive: bool = False) -> None:
        file_id = self._resolve_for_change(path, "remove")
        # files.delete takes a folder with everything in it, so a
        # non-recursive remove refuses a folder with children first.
        if not recursive and self._get_metadata(file_id).get("mimeType") == _FOLDER_MIME:
            if self._has_children(file_id, path):
                raise OSError(errno.ENOTEMPTY, f"Directory not empty: {path}", path)
        try:
            _run(self._service.files().delete(fileId=file_id, **_ALL_DRIVES), gone_ok=True)
        except Exception as e:
            raise _drive_error(e, f"Cannot remove {path}: {e}") from e
        self._invalidate_cache(path)
        log.info("Removed: %s", path)

    def rename(self, src: str, dst: str) -> None:
        # normalize() drops the slash: "x/" named the FILE x.
        refuse_folder_path(dst, "rename to", source_is_file=lambda: not self.stat(src).is_dir)
        src = self.normalize(src)
        dst = self.normalize(dst)
        file_id = self._resolve_for_change(src, "rename")
        if src == dst:
            return
        if dst.startswith(src.rstrip("/") + "/"):
            # rename(2) answers EINVAL; Drive would cut the folder off
            # from the tree (a parent that is its own descendant).
            raise OSError(errno.EINVAL, f"Cannot move the folder {src} into itself ({dst})", dst)

        new_name = self._new_leaf(posixpath.basename(dst), dst, "rename to")
        src_parent = self.parent(src)
        dst_parent = self.parent(dst)
        # A rename never replaces: like SMB, a taken name is FileExistsError,
        # which server_ops' overwrite swaps through a backup.
        target_id = self._existing_child(self._resolve_path(dst_parent), new_name, dst)
        if target_id is not None and target_id != file_id:
            raise FileExistsError(
                errno.EEXIST, f"Cannot rename {src} -> {dst}: the target exists", dst
            )

        try:
            if src_parent == dst_parent:
                # Simple rename within the same folder
                _run(self._service.files().update(
                    fileId=file_id,
                    body={"name": new_name},
                    **_ALL_DRIVES,
                ))
            else:
                # Move to a different folder and optionally rename
                old_parent_id = self._resolve_path(src_parent)
                new_parent_id = self._resolve_path(dst_parent)
                _run(self._service.files().update(
                    fileId=file_id,
                    body={"name": new_name},
                    addParents=new_parent_id,
                    removeParents=old_parent_id,
                    **_ALL_DRIVES,
                ))
        except Exception as e:
            raise _drive_error(e, f"Cannot rename {src} -> {dst}: {e}") from e

        self._invalidate_cache(src)
        self._path_cache[dst] = file_id
        log.info("Renamed: %s -> %s", src, dst)

    def open_read(self, path: str) -> IO[bytes]:
        file_id = self._resolve_path(path)
        try:
            return _download_spooled(
                self._service.files().get_media(fileId=file_id, **_ALL_DRIVES))
        except Exception as e:
            if _http_status(e) == 403 and "fileNotDownloadable" in _error_text(e):
                # A Google Doc / Sheet / Slides deck: read as its export.
                return self._export(file_id, path, e)
            raise _drive_error(e, f"Cannot read {path}: {e}") from e

    def _export(self, file_id: str, path: str, refused: BaseException) -> IO[bytes]:
        """The Google-native file *file_id* as the file its listed name
        promises (_EXPORTS); one without an export is refused with the
        reason of get_media's 403 *refused*."""
        mime = self._get_metadata(file_id).get("mimeType")
        if mime == _FOLDER_MIME:
            raise IsADirectoryError(errno.EISDIR, f"Cannot read {path}: a folder", path)
        export = _EXPORTS.get(mime) if isinstance(mime, str) else None
        if export is None:
            raise _drive_error(refused, f"Cannot read {path}: {mime or 'this item'} cannot be "
                               f"downloaded") from refused
        try:
            return _download_spooled(
                self._service.files().export_media(fileId=file_id, mimeType=export[0]))
        except Exception as e:
            raise _drive_error(e, f"Cannot export {path} as {export[1]}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        # normalize() drops the slash: "x/" was written as the FILE x.
        path = self.normalize(refuse_folder_path(path))
        parent_path = self.parent(path)
        file_name = self._new_leaf(posixpath.basename(path), path, "write")
        parent_id = self._resolve_path(parent_path, fresh=True)

        # Check if file already exists (for update vs create). Only "not
        # found" means create: any other lookup failure (a transient API
        # error, a name two files share) would create a second file.
        # The id must be the file the caller stat'ed (an overwrite
        # decision, the append seed): a file uploaded under the name
        # since is not overwritten in its place.
        existing_id: str | None = None
        try:
            existing_id = self._resolve_for_change(path, "overwrite")
        except FileNotFoundError:
            pass
        existing_mime = self._get_metadata(existing_id).get("mimeType") if existing_id else None
        if existing_mime == _FOLDER_MIME:
            # files.update with media on a folder fails only at close().
            raise IsADirectoryError(errno.EISDIR, f"Cannot write {path}: a folder", path)
        if _is_native(existing_mime):
            # Its content is Google's own format: the upload would replace
            # the document by a binary file (or fail at close()).
            raise PermissionError(
                errno.EPERM,
                f"Cannot write {path}: it is a Google Docs editors file ({existing_mime}), "
                f"read here as an export; save under another name",
                path,
            )

        writer = _SpooledWriter(self._service, file_name, parent_id, existing_id=existing_id)

        if append and existing_id:
            # Seed the writer with the existing file's bytes so the
            # subsequent write() calls genuinely append. If we *can't*
            # read the existing bytes (permissions, transient API
            # failure, …), we MUST NOT proceed — the writer would then
            # replace the existing Drive file with only the appended
            # tail, silently truncating the user's data.
            cap = self._MAX_APPEND_EXISTING_SIZE
            data = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="GDrive",
                logger=log,
            )
            if len(data) > cap:
                raise OSError(
                    errno.EFBIG,
                    f"GDrive append: existing file exceeds {cap // (1024 * 1024)} MiB cap"
                )
            writer.write(data)

        return writer

    def normalize(self, path: str) -> str:
        path = (path or "/").replace("\\", "/")
        normalized = posixpath.normpath(path)
        if normalized == ".":
            return "/"
        if not normalized.startswith("/"):
            return f"/{normalized}"
        return normalized

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        raise OSError(errno.ENOTSUP, "Google Drive does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError(errno.ENOTSUP, "Google Drive does not support symlinks")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        """Return (total, used, free) bytes from the Drive storage quota."""
        try:
            about = _run(self._service.about().get(fields="storageQuota"))
            quota = about.get("storageQuota", {})
            limit = int(quota.get("limit", 0))
            usage = int(quota.get("usage", 0))
            free = max(0, limit - usage)
            return (limit, usage, free)
        except Exception as e:
            log.warning("Cannot fetch storage quota: %s", e)
            return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        """Drive revisions().list — newest first."""
        from models.file_version import FileVersion

        # Drive lists revisions oldest first, a page at a time: without
        # every page the newest ones - the current among them - are
        # missing. A failure yields no versions, never the pages read.
        revs: list[dict] = []
        try:
            file_id = self._resolve_path(path)
            page_token = ""
            seen_tokens: set[str] = set()
            while True:
                kwargs = dict(
                    fileId=file_id,
                    fields="nextPageToken,revisions(id,modifiedTime,size,keepForever)",
                    pageSize=1000,
                )
                if page_token:
                    kwargs["pageToken"] = page_token
                resp = as_dict(_run(self._service.revisions().list(**kwargs)))
                revs.extend(r for r in as_list(resp.get("revisions")) if isinstance(r, dict))
                page_token = as_str(resp.get("nextPageToken"))
                if not page_token:
                    break
                if page_token in seen_tokens:
                    raise OSError(errno.EPROTO, "the server repeats a page token")
                seen_tokens.add(page_token)
        except Exception as exc:
            log.warning("GDrive list_versions(%s) failed: %s", path, exc)
            return []

        # Parse modifiedTime; sort newest first. Aware throughout: a
        # naive fallback next to an aware date fails the sort.
        oldest = datetime.min.replace(tzinfo=timezone.utc)

        def _ts(r):
            return as_utc_datetime(r.get("modifiedTime"), default=oldest)

        revs.sort(key=_ts, reverse=True)
        out: list = []
        for i, r in enumerate(revs):
            rev_id = as_str(r.get("id"))
            out.append(
                FileVersion(
                    version_id=rev_id,
                    modified=_ts(r),
                    size=as_size(r.get("size"), digit_strings=True),
                    is_current=(i == 0),
                    label=f"gdrive-rev:{rev_id}",
                )
            )
        return out

    def open_version_read(self, path: str, version_id: str):
        """Fetch a historical revision via revisions().get_media."""
        try:
            file_id = self._resolve_path(path)
            req = self._service.revisions().get_media(
                fileId=file_id,
                revisionId=version_id,
            )
            return _download_spooled(req)
        except Exception as exc:
            raise _drive_error(exc, f"GDrive open_version_read failed: {exc}") from exc

    def copy(self, src: str, dst: str) -> None:
        """Drive files.copy — server-side. A taken name is FileExistsError:
        Drive would add a second item of it, and server_side_copy streams
        over the existing file instead when asked to overwrite."""
        refuse_folder_path(dst, "copy to", source_is_file=lambda: not self.stat(src).is_dir)
        src_id = self._resolve_path(src)
        # Fresh, as open_write: a cached parent id renamed on the web since
        # put the copy into the folder that now has another name.
        dst_parent = self._resolve_path(self.parent(dst), fresh=True)
        dst_name = self._new_leaf(posixpath.basename(dst.rstrip("/")), dst, "copy to")
        if self._existing_child(dst_parent, dst_name, dst) is not None:
            raise FileExistsError(
                errno.EEXIST, f"Drive copy {src} -> {dst}: the target exists", dst
            )
        try:
            _run(self._service.files().copy(
                fileId=src_id,
                body={"name": dst_name, "parents": [dst_parent]},
                **_ALL_DRIVES,
            ), idempotent=False)
        except Exception as exc:
            raise _drive_error(exc, f"Drive copy {src} -> {dst} failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Drive-specific verbs (slice 5 of API_GAPS)
    # ------------------------------------------------------------------

    def share(
        self,
        path: str,
        *,
        role: str = "reader",
        type: str = "anyone",
        email: str | None = None,
        allow_discovery: bool = False,
    ) -> dict:
        """Grant a permission on the file at ``path`` and return the
        shareable webViewLink.

        ``role``  is ``reader`` (default) / ``commenter`` / ``writer`` /
                   ``fileOrganizer`` / ``organizer`` / ``owner``.
        ``type``  is ``anyone`` (link-shareable) / ``user`` /
                   ``group`` / ``domain``.
        ``email`` is required when ``type`` is ``user`` / ``group``.

        Returns a dict::

            {"permission_id": "...", "url": "https://drive.google.com/..."}
        """
        if email and ("\r" in email or "\n" in email):
            raise ValueError("GDrive share: email must not contain CR/LF. F40.")
        if "\r" in role or "\n" in role:
            raise ValueError("GDrive share: role must not contain CR/LF")
        if "\r" in type or "\n" in type:
            raise ValueError("GDrive share: type must not contain CR/LF")
        fid = self._resolve_path(path)
        body: dict = {"role": role, "type": type}
        if email:
            body["emailAddress"] = email
        if type == "anyone":
            body["allowFileDiscovery"] = bool(allow_discovery)
        try:
            perm = as_dict(
                _run(self._service.permissions()
                .create(
                    fileId=fid,
                    body=body,
                    fields="id",
                ), idempotent=False)
            )
            meta = as_dict(
                _run(self._service.files()
                .get(
                    fileId=fid,
                    fields="webViewLink,webContentLink",
                ))
            )
        except Exception as exc:
            raise _drive_error(exc, f"Cannot share {path}: {exc}") from exc
        url = as_str(meta.get("webViewLink")) or as_str(meta.get("webContentLink"))
        # The path, never the link: an "anyone" link opens the file for
        # whoever reads the log.
        log.info(
            "Drive share: %s granted role=%s type=%s%s",
            path,
            role,
            type,
            f" email={email}" if email else "",
        )
        return {
            "permission_id": as_str(perm.get("id")),
            "url": url,
        }

    def share_revoke(self, path: str, permission_id: str) -> None:
        """Remove a permission previously granted via share()."""
        fid = self._resolve_path(path)
        _run(self._service.permissions().delete(
            fileId=fid,
            permissionId=permission_id,
        ))

    def permissions_list(self, path: str) -> list[dict]:
        """List every permission on a file (incl. owners + inherited
        permissions). One dict per permission with id/role/type/email."""
        fid = self._resolve_path(path)
        out: list[dict] = []
        page_token = ""
        seen_tokens: set[str] = set()
        while True:
            kwargs = dict(
                fileId=fid,
                fields="permissions(id,role,type,emailAddress,domain),nextPageToken",
            )
            if page_token:
                kwargs["pageToken"] = page_token
            try:
                resp = as_dict(_run(self._service.permissions().list(**kwargs)))
            except Exception as exc:
                raise _drive_error(exc, f"Cannot list permissions of {path}: {exc}") from exc
            for p in as_list(resp.get("permissions")):
                if not isinstance(p, dict):
                    continue
                out.append(
                    {
                        "id": as_str(p.get("id")),
                        "role": as_str(p.get("role")),
                        "type": as_str(p.get("type")),
                        "email": as_str(p.get("emailAddress")),
                        "domain": as_str(p.get("domain")),
                    }
                )
            page_token = as_str(resp.get("nextPageToken"))
            if not page_token:
                break
            if page_token in seen_tokens:
                raise OSError(errno.EPROTO, f"Cannot list permissions of {path}: the server repeats a page token")
            seen_tokens.add(page_token)
        return out

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return Drive's md5Checksum field.

        Drive exposes both md5Checksum (for user-uploaded files) and
        sha1Checksum / sha256Checksum for newer uploads. We try the
        requested algorithm first and fall back to md5."""
        try:
            fid = self._resolve_path(path)
        except OSError:
            raise
        try:
            field = {
                "sha256": "sha256Checksum",
                "sha1": "sha1Checksum",
                "md5": "md5Checksum",
            }.get(algorithm, "md5Checksum")
            meta = (
                _run(self._service.files()
                .get(
                    fileId=fid,
                    fields=f"{field},md5Checksum",
                ))
            )
        except Exception as exc:
            raise _drive_error(exc, f"Cannot stat {path}: {exc}") from exc
        meta = as_dict(meta)
        val = as_str(meta.get(field))
        actual_algo = algorithm if field != "md5Checksum" else "md5"
        if not val:
            # The requested hash is missing: the md5 fallback is
            # labelled md5, never as the algorithm that was asked for.
            val, actual_algo = as_str(meta.get("md5Checksum")), "md5"
        if not val:
            return ""
        return f"{actual_algo}:{val}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_time(timestamp: str) -> datetime:
        """Parse an RFC 3339 timestamp from the Drive API."""
        if not timestamp or not isinstance(timestamp, str):
            return datetime.fromtimestamp(0)
        try:
            # The trailing 'Z' is UTC; dropping it would leave a naive
            # value that FileItem reads as local time.
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.fromtimestamp(0)
