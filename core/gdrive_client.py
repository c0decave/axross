"""Google Drive backend implementing the FileBackend protocol.

Requires: pip install axross[gdrive]
(google-api-python-client, google-auth-oauthlib, google-auth-httplib2)

Uses OAuth2 browser redirect flow for authentication. Tokens are cached
locally so the user only needs to authorise once.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import posixpath
import tempfile
from datetime import datetime, timezone
from typing import IO

from core.answer_fields import as_dict, as_list, as_size, as_str, as_utc_datetime
from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.desktop_open import install_clean_webbrowser
from core.path_policy import safe_leaf
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

_FOLDER_MIME = "application/vnd.google-apps.folder"
_FILE_FIELDS = "files(id,name,mimeType,size,modifiedTime)"
#: Bytes per download request. googleapiclient's default is 100 MiB, each
#: chunk one bytes object in RAM.
_DOWNLOAD_CHUNK = 4 * 1024 * 1024


def _download_spooled(request) -> IO[bytes]:
    """A media download written chunk by chunk into a spool (small files
    stay in memory, larger ones go to a temp file) instead of a BytesIO
    holding the whole file."""
    spool = new_read_spool()
    try:
        downloader = MediaIoBaseDownload(spool, request, chunksize=_DOWNLOAD_CHUNK)
        done = False
        while not done:
            _, done = downloader.next_chunk()
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


class _SpooledWriter:
    """Write to a temp buffer, then upload to Google Drive on close."""

    def __init__(self, service, file_name: str, parent_id: str, existing_id: str | None = None):
        self._service = service
        self._file_name = file_name
        self._parent_id = parent_id
        self._existing_id = existing_id
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        self._closed = False

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
        try:
            self._buf.seek(0)
            media = MediaIoBaseUpload(
                self._buf,
                mimetype="application/octet-stream",
                resumable=True,
            )
            if self._existing_id:
                self._service.files().update(
                    fileId=self._existing_id,
                    media_body=media,
                ).execute()
            else:
                body = {
                    "name": self._file_name,
                    "parents": [self._parent_id],
                }
                self._service.files().create(
                    body=body,
                    media_body=media,
                ).execute()
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

    def _resolve_path(self, path: str) -> str:
        """Resolve a POSIX-style path to a Google Drive file ID.

        Walks the path components, querying for each folder by name within
        its parent. Results are cached in ``self._path_cache``.
        """
        path = self.normalize(path)
        if path in self._path_cache:
            return self._path_cache[path]

        parts = [p for p in path.split("/") if p]
        current_id = "root"
        current_path = "/"

        for part in parts:
            current_path = posixpath.join(current_path, part)
            if current_path in self._path_cache:
                current_id = self._path_cache[current_path]
                continue

            current_id = self._lookup_child(current_id, part, path)
            self._path_cache[current_path] = current_id

        return current_id

    def _lookup_child(self, parent_id: str, name: str, path: str) -> str:
        """The id of the one item called *name* in folder *parent_id*,
        asked of the server (not the cache). FileNotFoundError when there
        is none; OSError when the answer fails or names several."""
        query = (
            f"'{parent_id}' in parents "
            f"and name = '{self._escape_query(name)}' "
            f"and trashed = false"
        )
        try:
            resp = (
                self._service.files()
                .list(
                    q=query,
                    fields="files(id,name,mimeType)",
                    pageSize=2,
                )
                .execute()
            )
        except Exception as e:
            raise OSError(f"Cannot resolve path '{path}': {e}") from e

        files = as_list(as_dict(resp).get("files"))
        if not files:
            raise FileNotFoundError(f"Not found: {path}")
        if len(files) > 1:
            # Drive allows several files of one name in a folder; any
            # pick could delete, read or overwrite the wrong one.
            raise OSError(
                f"Cannot resolve path '{path}': at least 2 files named {name!r} in one folder"
            )
        file_id = as_str(as_dict(files[0]).get("id"))
        if not file_id:
            raise OSError(f"Cannot resolve path '{path}': the answer carries no file id")
        return file_id

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
                self._service.files()
                .list(
                    q=f"'{folder_id}' in parents and trashed = false",
                    fields="files(id)",
                    pageSize=1,
                )
                .execute()
            )
        except Exception as e:
            raise OSError(f"Cannot list {path}: {e}") from e
        if not isinstance(resp, dict) or not isinstance(resp.get("files", []), list):
            raise OSError(f"Cannot list {path}: the answer is not a file list")
        return bool(resp.get("files")) or bool(as_str(resp.get("nextPageToken")))

    def _get_metadata(self, file_id: str) -> dict:
        """Fetch metadata for a single file ID."""
        try:
            meta = (
                self._service.files()
                .get(
                    fileId=file_id,
                    fields="id,name,mimeType,size,modifiedTime",
                )
                .execute()
            )
        except Exception as e:
            if _http_status(e) == 404:
                # An id from the path cache that is gone on the server.
                raise FileNotFoundError(
                    errno.ENOENT, f"Cannot get metadata for {file_id}: not found", file_id
                ) from e
            raise OSError(f"Cannot get metadata for {file_id}: {e}") from e
        if not isinstance(meta, dict):
            raise OSError(f"Cannot get metadata for {file_id}: the answer is not a JSON object")
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
            self._service.about().get(fields="user").execute()
            return True
        except Exception:
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
        page_token: str | None = None
        seen_tokens: set[str] = set()

        while True:
            try:
                resp = (
                    self._service.files()
                    .list(
                        q=f"'{folder_id}' in parents and trashed = false",
                        fields=f"nextPageToken,{_FILE_FIELDS}",
                        pageSize=1000,
                        pageToken=page_token,
                    )
                    .execute()
                )
            except Exception as e:
                raise OSError(f"Cannot list {path}: {e}") from e

            if not isinstance(resp, dict) or not isinstance(resp.get("files", []), list):
                raise OSError(f"Cannot list {path}: the answer is not a file list")
            for f in resp.get("files", []):
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
                is_dir = f.get("mimeType") == _FOLDER_MIME
                size = as_size(f.get("size"), digit_strings=True) if not is_dir else 0
                modified = self._parse_time(f.get("modifiedTime", ""))
                items.append(
                    FileItem(
                        name=name,
                        size=size,
                        modified=modified,
                        is_dir=is_dir,
                    )
                )
                ids.setdefault(name, []).append(file_id)

            page_token = as_str(resp.get("nextPageToken"))
            if not page_token:
                break
            # A token handed back twice would page forever.
            if page_token in seen_tokens:
                raise OSError(f"Cannot list {path}: the server repeats a page token")
            seen_tokens.add(page_token)

        # Cache the child paths for future lookups - only names that one
        # file holds: a shared name stays out, so _resolve_path finds it
        # ambiguous instead of the cache naming one of the files.
        base = self.normalize(path)
        for name, file_ids in ids.items():
            child_path = posixpath.join(base, name)
            if len(file_ids) == 1:
                self._path_cache[child_path] = file_ids[0]
            else:
                self._invalidate_cache(child_path)
        return items

    def stat(self, path: str) -> FileItem:
        file_id = self._resolve_path(path)
        meta = self._get_metadata(file_id)
        is_dir = meta.get("mimeType") == _FOLDER_MIME
        size = as_size(meta.get("size"), digit_strings=True) if not is_dir else 0
        modified = self._parse_time(meta.get("modifiedTime", ""))
        name = as_str(meta.get("name")) or posixpath.basename(path.rstrip("/")) or "/"
        return FileItem(name=name, size=size, modified=modified, is_dir=is_dir)

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
        server_side_copy(overwrite=False) takes False as its go-ahead."""
        try:
            self._resolve_path(path)
            return True
        except FileNotFoundError:
            return False

    def mkdir(self, path: str) -> None:
        path = self.normalize(path)
        parent_path = self.parent(path)
        dir_name = posixpath.basename(path)
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
                self._service.files()
                .create(
                    body=body,
                    fields="id",
                )
                .execute()
            )
        except Exception as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

        # The folder exists now; without an id in the answer it is
        # simply resolved by name on the next lookup.
        folder_id = as_str(as_dict(result).get("id"))
        if folder_id:
            self._path_cache[path] = folder_id
        log.info("Created directory: %s", path)

    def remove(self, path: str, recursive: bool = False) -> None:
        file_id = self._resolve_path(path)
        # files.delete takes a folder with everything in it, so a
        # non-recursive remove refuses a folder with children first.
        if not recursive and self._get_metadata(file_id).get("mimeType") == _FOLDER_MIME:
            if self._has_children(file_id, path):
                raise OSError(errno.ENOTEMPTY, f"Directory not empty: {path}", path)
        try:
            self._service.files().delete(fileId=file_id).execute()
        except Exception as e:
            raise OSError(f"Cannot remove {path}: {e}") from e
        self._invalidate_cache(path)
        log.info("Removed: %s", path)

    def rename(self, src: str, dst: str) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        file_id = self._resolve_path(src)
        if src == dst:
            return

        new_name = posixpath.basename(dst)
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
                self._service.files().update(
                    fileId=file_id,
                    body={"name": new_name},
                ).execute()
            else:
                # Move to a different folder and optionally rename
                old_parent_id = self._resolve_path(src_parent)
                new_parent_id = self._resolve_path(dst_parent)
                self._service.files().update(
                    fileId=file_id,
                    body={"name": new_name},
                    addParents=new_parent_id,
                    removeParents=old_parent_id,
                ).execute()
        except Exception as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

        self._invalidate_cache(src)
        self._path_cache[dst] = file_id
        log.info("Renamed: %s -> %s", src, dst)

    def open_read(self, path: str) -> IO[bytes]:
        file_id = self._resolve_path(path)
        try:
            return _download_spooled(self._service.files().get_media(fileId=file_id))
        except Exception as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = self.normalize(path)
        parent_path = self.parent(path)
        file_name = posixpath.basename(path)
        parent_id = self._resolve_path(parent_path)

        # Check if file already exists (for update vs create). Only "not
        # found" means create: any other lookup failure (a transient API
        # error, a name two files share) would create a second file.
        existing_id: str | None = None
        try:
            existing_id = self._resolve_path(path)
        except FileNotFoundError:
            pass

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
        raise OSError("Google Drive does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("Google Drive does not support symlinks")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        """Return (total, used, free) bytes from the Drive storage quota."""
        try:
            about = self._service.about().get(fields="storageQuota").execute()
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
                resp = as_dict(self._service.revisions().list(**kwargs).execute())
                revs.extend(r for r in as_list(resp.get("revisions")) if isinstance(r, dict))
                page_token = as_str(resp.get("nextPageToken"))
                if not page_token:
                    break
                if page_token in seen_tokens:
                    raise OSError("the server repeats a page token")
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
            raise OSError(f"GDrive open_version_read failed: {exc}") from exc

    def copy(self, src: str, dst: str) -> None:
        """Drive files.copy — server-side. A taken name is FileExistsError:
        Drive would add a second item of it, and server_side_copy streams
        over the existing file instead when asked to overwrite."""
        src_id = self._resolve_path(src)
        dst_parent = self._resolve_path(self.parent(dst))
        dst_name = posixpath.basename(dst.rstrip("/"))
        if self._existing_child(dst_parent, dst_name, dst) is not None:
            raise FileExistsError(
                errno.EEXIST, f"Drive copy {src} -> {dst}: the target exists", dst
            )
        try:
            self._service.files().copy(
                fileId=src_id,
                body={"name": dst_name, "parents": [dst_parent]},
            ).execute()
        except Exception as exc:
            raise OSError(f"Drive copy {src} -> {dst} failed: {exc}") from exc

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
                self._service.permissions()
                .create(
                    fileId=fid,
                    body=body,
                    fields="id",
                )
                .execute()
            )
            meta = as_dict(
                self._service.files()
                .get(
                    fileId=fid,
                    fields="webViewLink,webContentLink",
                )
                .execute()
            )
        except Exception as exc:
            raise OSError(f"Cannot share {path}: {exc}") from exc
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
        self._service.permissions().delete(
            fileId=fid,
            permissionId=permission_id,
        ).execute()

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
                resp = as_dict(self._service.permissions().list(**kwargs).execute())
            except Exception as exc:
                raise OSError(f"Cannot list permissions of {path}: {exc}") from exc
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
                raise OSError(f"Cannot list permissions of {path}: the server repeats a page token")
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
                self._service.files()
                .get(
                    fileId=fid,
                    fields=f"{field},md5Checksum",
                )
                .execute()
            )
        except Exception as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
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
