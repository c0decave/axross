"""OneDrive / SharePoint backend implementing the FileBackend protocol.

Uses Microsoft Graph API with MSAL for OAuth2 authentication.

Requires: pip install axross[onedrive]  (msal>=1.24, requests>=2.28)
"""

from __future__ import annotations

import errno
import io
import json
import logging
import os
import posixpath
import tempfile
import time
from datetime import datetime
from typing import IO
from urllib.parse import quote

from core.answer_fields import as_dict, as_list, as_size, as_str, as_utc_datetime
from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.desktop_open import install_clean_webbrowser
from core.read_spool import spool_response
from core.secure_storage import adopt_legacy_secret_file, write_secret_file
from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    import msal
except ImportError:
    msal = None  # type: ignore[assignment]

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_TIMEOUT = 30


def _graph_json(resp, what: str, *, empty_ok: bool = False) -> dict:
    """The JSON object a Graph call answered with, else OSError.

    ``requests``' own JSONDecodeError is an OSError, but a body nested
    deeper than the C stack (RecursionError) or an integer above
    Python's digit limit (ValueError) escapes it, and a list or a
    string is valid JSON every caller then called ``.get()`` on.
    """
    if empty_ok and not resp.content:
        return {}
    try:
        data = resp.json()
    except (ValueError, RecursionError) as exc:
        raise OSError(f"Graph API {what}: answer is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise OSError(f"Graph API {what}: answer is not a JSON object ({type(data).__name__})")
    return data


#: Above this size a file goes up in an upload session instead of one
#: ``PUT .../content`` (documented for small files: 4 MB on many drives,
#: 250 MB at most).
_SIMPLE_UPLOAD_MAX = 4 * 1024 * 1024
#: Bytes per upload-session request; Graph wants a multiple of 320 KiB.
_UPLOAD_CHUNK = 32 * 320 * 1024


class _SpooledWriter:
    """Write to a temp file, then upload on close via Graph API."""

    def __init__(self, session: OneDriveSession, remote_path: str):
        self._session = session
        self._remote_path = remote_path
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
            size = self._buf.seek(0, io.SEEK_END)
            self._buf.seek(0)
            if size <= _SIMPLE_UPLOAD_MAX:
                self._session._upload_content(self._remote_path, self._buf.read())
            else:
                self._session._upload_in_session(self._remote_path, self._buf, size)
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


class OneDriveSession(SessionLifecycle):
    """OneDrive / SharePoint backend implementing the FileBackend protocol.

    Uses Microsoft Graph API via ``requests`` and authenticates with MSAL
    (Microsoft Authentication Library) using the OAuth2 device-code or
    interactive browser flow.

    Parameters
    ----------
    client_id : str
        Azure AD application (client) ID.
    tenant_id : str
        Azure AD tenant ID, or ``"common"`` for multi-tenant / personal
        accounts.
    token_file : str
        Path where the MSAL token cache is persisted (JSON).
    drive_type : str
        ``"personal"`` for OneDrive consumer / business, or
        ``"sharepoint"`` for a SharePoint document library.
    site_url : str
        Required when *drive_type* is ``"sharepoint"``. The full URL of the
        SharePoint site (e.g. ``https://contoso.sharepoint.com/sites/team``).
    """

    def __init__(
        self,
        client_id: str,
        tenant_id: str = "common",
        token_file: str = "~/.config/axross/onedrive_token.json",
        drive_type: str = "personal",
        site_url: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
        legacy_token_file: str | None = None,
    ):
        if msal is None:
            raise ImportError(
                "OneDrive support requires msal. Install with: pip install axross[onedrive]"
            )
        if requests is None:
            raise ImportError(
                "OneDrive support requires requests. Install with: pip install requests"
            )

        self._client_id = client_id
        self._tenant_id = tenant_id
        self._token_file = os.path.expanduser(token_file)
        self._drive_type = drive_type.lower()
        self._site_url = site_url.rstrip("/") if site_url else ""
        self._site_id: str | None = None
        self._http = requests.Session()
        # Override requests' default python-requests/X.Y.Z UA so Graph
        # audit logs don't attribute the traffic back to Axross. See
        # docs/OPSEC.md #4.
        from core.client_identity import HTTP_USER_AGENT

        self._http.headers["User-Agent"] = HTTP_USER_AGENT

        # Route Graph traffic through the configured proxy if any.
        from core.proxy import build_requests_proxies

        proxies = build_requests_proxies(
            proxy_type,
            proxy_host,
            int(proxy_port or 0),
            proxy_username,
            proxy_password,
        )
        self._proxies = dict(proxies)
        from core.proxy import lock_requests_session_to_profile_proxy

        lock_requests_session_to_profile_proxy(self._http, proxies)

        # MSAL scopes
        self._scopes = ["Files.ReadWrite.All", "User.Read"]
        if self._drive_type == "sharepoint":
            self._scopes.append("Sites.ReadWrite.All")

        # Set up MSAL token cache. MSAL keys every token by client id;
        # the cache file is the profile's own, so the first account in it
        # is this profile's. The file all profiles shared before is taken
        # over only when it holds tokens of this client id.
        adopt_legacy_secret_file(
            self._token_file,
            os.path.expanduser(legacy_token_file) if legacy_token_file else None,
            self._cache_has_client,
        )
        self._cache = msal.SerializableTokenCache()
        if os.path.isfile(self._token_file):
            try:
                with open(self._token_file, "r", encoding="utf-8") as fh:
                    self._cache.deserialize(fh.read())
            except OSError as exc:
                log.warning("OneDrive: could not read token cache %s: %s", self._token_file, exc)

        authority = f"https://login.microsoftonline.com/{self._tenant_id}"
        self._app = msal.PublicClientApplication(
            self._client_id,
            authority=authority,
            token_cache=self._cache,
            proxies=self._proxies or None,
        )

        # Acquire initial token
        self._access_token: str = self._acquire_token()

        # Resolve SharePoint site ID if needed
        if self._drive_type == "sharepoint":
            self._site_id = self._resolve_site_id()

        log.info(
            "OneDrive connected: drive_type=%s, tenant=%s",
            self._drive_type,
            self._tenant_id,
        )

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------

    def _acquire_token(self) -> str:
        """Acquire an access token, using cached credentials if possible."""
        accounts = self._app.get_accounts()
        result = None

        if accounts:
            # Try silent acquisition first
            result = self._app.acquire_token_silent(self._scopes, account=accounts[0])

        if not result:
            # Interactive browser-based login
            if self._proxies:
                log.warning(
                    "OneDrive proxy configured: Graph and MSAL token calls "
                    "use the profile proxy, but the browser consent page is "
                    "outside axross and may use browser or system proxy "
                    "settings."
                )
            # msal opens the login page through webbrowser (core.desktop_open).
            install_clean_webbrowser()
            result = self._app.acquire_token_interactive(
                scopes=self._scopes,
                redirect_uri="http://localhost",
            )

        if not isinstance(result, dict) or "access_token" not in result:
            error = "login cancelled"
            if isinstance(result, dict):
                error = result.get("error_description", result.get("error", error))
            raise OSError(f"OneDrive authentication failed: {error}")

        # Persist token cache
        self._save_cache()

        return result["access_token"]

    def _cache_has_client(self, text: str) -> bool:
        """True when the serialized MSAL cache *text* holds an entry of
        this client id."""
        sections = json.loads(text)
        return any(
            isinstance(entry, dict) and entry.get("client_id") == self._client_id
            for section in sections.values()
            if isinstance(section, dict)
            for entry in section.values()
        )

    def _save_cache(self) -> None:
        """Persist the MSAL token cache to disk (atomic, 0o600)."""
        if self._cache.has_state_changed:
            try:
                write_secret_file(self._token_file, self._cache.serialize())
            except OSError as exc:
                log.error(
                    "OneDrive: failed to persist token cache %s: %s",
                    self._token_file,
                    exc,
                )

    def _ensure_token(self) -> None:
        """Re-acquire token if expired."""
        accounts = self._app.get_accounts()
        if accounts:
            result = self._app.acquire_token_silent(self._scopes, account=accounts[0])
            if result and "access_token" in result:
                self._access_token = result["access_token"]
                self._save_cache()
                return
        # Need interactive re-auth
        self._access_token = self._acquire_token()

    def _headers(self) -> dict[str, str]:
        """Return authorization headers for Graph API requests."""
        return {"Authorization": f"Bearer {self._access_token}"}

    # ------------------------------------------------------------------
    # Graph API helpers
    # ------------------------------------------------------------------

    def _resolve_site_id(self) -> str:
        """Resolve a SharePoint site URL to a site ID."""
        # Parse site URL: https://contoso.sharepoint.com/sites/team
        from urllib.parse import urlparse

        parsed = urlparse(self._site_url)
        hostname = parsed.hostname or ""
        site_path = parsed.path.rstrip("/")

        url = f"{GRAPH_BASE}/sites/{hostname}:{site_path}"
        resp = self._graph_get(url)
        site_id = as_str(resp.get("id"))
        if not site_id:
            raise OSError(f"Cannot resolve SharePoint site: {self._site_url}")
        return site_id

    def _drive_prefix(self) -> str:
        """Return the Graph API drive prefix based on drive type."""
        if self._drive_type == "sharepoint" and self._site_id:
            return f"/sites/{self._site_id}/drive"
        return "/me/drive"

    @staticmethod
    def _escape_path(path: str) -> str:
        """``/a b/c#1`` -> ``/a%20b/c%231`` for a ``root:<path>`` segment,
        ``""`` for the root. Names may carry ``#``, ``?`` and ``%``,
        which would otherwise end the path, start a query string or be
        decoded a second time by the server."""
        normed = path.strip("/")
        return "/" + quote(normed, safe="/") if normed else ""

    def _item_path_url(self, path: str) -> str:
        """Build the Graph API URL for a given path.

        For root (``/``): ``/me/drive/root``
        For other paths: ``/me/drive/root:/path``
        """
        prefix = self._drive_prefix()
        escaped = self._escape_path(path)
        if not escaped:
            return f"{GRAPH_BASE}{prefix}/root"
        return f"{GRAPH_BASE}{prefix}/root:{escaped}"

    def _children_url(self, path: str) -> str:
        """Build the Graph API URL for listing children of *path*.

        For root: ``/me/drive/root/children``
        For other paths: ``/me/drive/root:/path:/children``
        """
        prefix = self._drive_prefix()
        escaped = self._escape_path(path)
        if not escaped:
            return f"{GRAPH_BASE}{prefix}/root/children"
        return f"{GRAPH_BASE}{prefix}/root:{escaped}:/children"

    def _graph_get(self, url: str, **kwargs) -> dict:
        """Execute a GET request against the Graph API."""
        self._ensure_token()
        kwargs.setdefault("timeout", GRAPH_TIMEOUT)
        resp = self._http.get(url, headers=self._headers(), **kwargs)
        if resp.status_code == 401:
            # Token may have expired between _ensure_token and now
            self._access_token = self._acquire_token()
            resp = self._http.get(url, headers=self._headers(), **kwargs)
        if resp.status_code == 404:
            # itemNotFound: the one answer exists() and is_dir() read as False.
            raise FileNotFoundError(
                errno.ENOENT, f"Graph API GET {url} failed (404): {resp.text[:500]}", url
            )
        if resp.status_code >= 400:
            raise OSError(f"Graph API GET {url} failed ({resp.status_code}): {resp.text[:500]}")
        return _graph_json(resp, f"GET {url}")

    def _graph_post(self, url: str, json_data: dict) -> dict:
        """Execute a POST request against the Graph API."""
        self._ensure_token()
        resp = self._http.post(url, headers=self._headers(), json=json_data, timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.post(
                url,
                headers=self._headers(),
                json=json_data,
                timeout=GRAPH_TIMEOUT,
            )
        if resp.status_code >= 400:
            raise OSError(f"Graph API POST {url} failed ({resp.status_code}): {resp.text[:500]}")
        return _graph_json(resp, f"POST {url}")

    def _graph_patch(self, url: str, json_data: dict) -> dict:
        """Execute a PATCH request against the Graph API."""
        self._ensure_token()
        resp = self._http.patch(url, headers=self._headers(), json=json_data, timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.patch(
                url,
                headers=self._headers(),
                json=json_data,
                timeout=GRAPH_TIMEOUT,
            )
        if resp.status_code >= 400:
            raise OSError(f"Graph API PATCH {url} failed ({resp.status_code}): {resp.text[:500]}")
        return _graph_json(resp, f"PATCH {url}")

    def _graph_delete(self, url: str) -> None:
        """Execute a DELETE request against the Graph API."""
        self._ensure_token()
        resp = self._http.delete(url, headers=self._headers(), timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.delete(url, headers=self._headers(), timeout=GRAPH_TIMEOUT)
        if resp.status_code >= 400:
            raise OSError(f"Graph API DELETE {url} failed ({resp.status_code}): {resp.text[:500]}")

    def _graph_put_bytes(self, url: str, data: bytes) -> dict:
        """Execute a PUT request with raw bytes."""
        self._ensure_token()
        headers = self._headers()
        headers["Content-Type"] = "application/octet-stream"
        resp = self._http.put(url, headers=headers, data=data, timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            headers = self._headers()
            headers["Content-Type"] = "application/octet-stream"
            resp = self._http.put(url, headers=headers, data=data, timeout=GRAPH_TIMEOUT)
        if resp.status_code >= 400:
            raise OSError(f"Graph API PUT {url} failed ({resp.status_code}): {resp.text[:500]}")
        return _graph_json(resp, f"PUT {url}")

    def _graph_get_spooled(self, url: str, what: str) -> IO[bytes]:
        """A file download as a spool: the body is streamed in chunks,
        not held in RAM as one bytes object."""
        self._ensure_token()
        resp = self._http.get(url, headers=self._headers(), stream=True, timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            resp.close()
            self._access_token = self._acquire_token()
            resp = self._http.get(url, headers=self._headers(), stream=True, timeout=GRAPH_TIMEOUT)
        if resp.status_code >= 400:
            try:
                detail = resp.text[:500]
            finally:
                resp.close()
            raise OSError(f"Graph API GET {url} failed ({resp.status_code}): {detail}")
        return spool_response(resp, what=what)

    # ------------------------------------------------------------------
    # Item parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_item(item: dict) -> FileItem:
        """Parse a Graph API drive-item dict into a FileItem."""
        name = as_str(item.get("name"))
        size = as_size(item.get("size"))
        is_dir = "folder" in item

        modified = datetime.fromtimestamp(0)
        raw_modified = as_str(item.get("lastModifiedDateTime"))
        if raw_modified:
            try:
                # Graph returns ISO-8601: "2024-01-15T10:30:00Z"
                clean = raw_modified.replace("Z", "+00:00")
                modified = datetime.fromisoformat(clean)
            except (ValueError, TypeError):
                pass

        permissions = 0o755 if is_dir else 0o644

        return FileItem(
            name=name,
            size=size,
            modified=modified,
            is_dir=is_dir,
            permissions=permissions,
        )

    def _get_item_id(self, path: str) -> str:
        """Retrieve the Graph item-id for the given path."""
        url = self._item_path_url(path)
        data = self._graph_get(url)
        item_id = as_str(data.get("id"))
        if not item_id:
            raise OSError(f"Cannot resolve item ID for: {path}")
        return item_id

    def _pages(self, url: str):
        """Every entry of a paged Graph collection, following
        ``@odata.nextLink``.

        A ``value`` that is not a list fails; entries that are not
        objects are skipped. A next link already followed is a loop the
        server would keep us in forever, so it fails too.
        """
        seen: set[str] = set()
        while url:
            seen.add(url)
            data = self._graph_get(url)
            value = data.get("value", [])
            if not isinstance(value, list):
                raise OSError(f"Graph API GET {url}: 'value' is not a list")
            for entry in value:
                if isinstance(entry, dict):
                    yield entry
            url = as_str(data.get("@odata.nextLink"))
            if url in seen:
                raise OSError(f"Graph API GET: paging link repeats ({url})")

    # ------------------------------------------------------------------
    # Upload helper (used by _SpooledWriter)
    # ------------------------------------------------------------------

    def _upload_content(self, path: str, data: bytes) -> None:
        """Upload raw bytes to *path* using the simple upload endpoint."""
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/root:{self._escape_path(path)}:/content"
        self._graph_put_bytes(url, data)

    def _upload_in_session(self, path: str, fh: IO[bytes], size: int) -> None:
        """createUploadSession, then PUT the bytes in Content-Range chunks.

        The upload URL is pre-authenticated: it gets no bearer token, and
        it must be https - the file's bytes go to it.
        """
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/root:{self._escape_path(path)}:/createUploadSession"
        answer = self._graph_post(
            url, {"item": {"@microsoft.graph.conflictBehavior": "replace"}}
        )
        upload_url = as_str(answer.get("uploadUrl"))
        if not upload_url.lower().startswith("https://"):
            raise OSError(f"OneDrive upload of {path}: the upload URL is not https")
        offset = 0
        while offset < size:
            chunk = fh.read(_UPLOAD_CHUNK)
            if not chunk:
                raise OSError(f"OneDrive upload of {path}: the spool ended at {offset} bytes")
            headers = {
                "Content-Length": str(len(chunk)),
                "Content-Range": f"bytes {offset}-{offset + len(chunk) - 1}/{size}",
            }
            resp = self._http.put(upload_url, headers=headers, data=chunk, timeout=GRAPH_TIMEOUT)
            if resp.status_code >= 400:
                raise OSError(
                    f"OneDrive upload of {path} failed ({resp.status_code}): {resp.text[:500]}"
                )
            offset += len(chunk)

    # ------------------------------------------------------------------
    # FileBackend protocol
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        if self._drive_type == "sharepoint":
            return f"{self._site_url} (SharePoint)"
        return f"OneDrive ({self._tenant_id})"

    @property
    def connected(self) -> bool:
        try:
            url = f"{GRAPH_BASE}{self._drive_prefix()}"
            self._graph_get(url)
            return True
        except Exception:
            return False

    def close(self) -> None:
        log.info("OneDrive disconnecting")
        self._save_cache()
        self._http.close()

    def disconnect(self) -> None:
        self.close()

    def list_dir(self, path: str) -> list[FileItem]:
        items: list[FileItem] = []
        for entry in self._pages(self._children_url(path)):
            item = self._parse_item(entry)
            if not item.name:
                log.warning("OneDrive: skipping a listing entry without a name in %s", path)
                continue
            items.append(item)
        return items

    def stat(self, path: str) -> FileItem:
        url = self._item_path_url(path)
        data = self._graph_get(url)
        item = self._parse_item(data)
        # For root, ensure a sensible name
        if not item.name:
            item = FileItem(
                name="/",
                size=item.size,
                modified=item.modified,
                is_dir=True,
                permissions=item.permissions,
            )
        return item

    def is_dir(self, path: str) -> bool:
        """False only for itemNotFound (404); a throttled, failed or
        dropped request is an OSError."""
        try:
            item = self.stat(path)
        except FileNotFoundError:
            return False
        return item.is_dir

    def exists(self, path: str) -> bool:
        """False only for itemNotFound (404); any other failure is an
        OSError - server_side_copy(overwrite=False) takes False as its
        go-ahead to write."""
        try:
            self.stat(path)
            return True
        except FileNotFoundError:
            return False

    def mkdir(self, path: str) -> None:
        normed = path.strip("/")
        if not normed:
            raise OSError("Cannot create root directory")

        parent_path = posixpath.dirname(normed)
        folder_name = posixpath.basename(normed)

        parent_url = self._children_url("/" + parent_path if parent_path else "/")
        payload = {
            "name": folder_name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "fail",
        }
        self._graph_post(parent_url, payload)

    def remove(self, path: str, recursive: bool = False) -> None:
        data = self._graph_get(self._item_path_url(path))
        item_id = as_str(data.get("id"))
        if not item_id:
            raise OSError(f"Cannot resolve item ID for: {path}")
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/items/{item_id}"
        # DELETE takes a folder with everything in it, so a non-recursive
        # remove refuses a folder with children first.
        folder = data.get("folder")
        if not recursive and folder is not None:
            count = as_dict(folder).get("childCount")
            if isinstance(count, int) and not isinstance(count, bool):
                full = count > 0
            else:
                # No usable count: one entry of the listing decides.
                full = next(self._pages(f"{url}/children?$top=1"), None) is not None
            if full:
                raise OSError(errno.ENOTEMPTY, f"Directory not empty: {path}", path)
        self._graph_delete(url)

    def rename(self, src: str, dst: str) -> None:
        item_id = self._get_item_id(src)
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/items/{item_id}"

        src_normed = src.strip("/")
        dst_normed = dst.strip("/")
        new_name = posixpath.basename(dst_normed)
        new_parent_path = posixpath.dirname(dst_normed)
        old_parent_path = posixpath.dirname(src_normed)

        payload: dict = {"name": new_name}

        # If the parent directory changed, include parentReference
        if new_parent_path != old_parent_path:
            parent_url = self._item_path_url("/" + new_parent_path if new_parent_path else "/")
            parent_id = as_str(self._graph_get(parent_url).get("id"))
            if not parent_id:
                raise OSError(f"Cannot resolve item ID for: /{new_parent_path}")
            payload["parentReference"] = {"id": parent_id}

        self._graph_patch(url, payload)

    def open_read(self, path: str) -> IO[bytes]:
        normed = path.strip("/")
        prefix = self._drive_prefix()
        if not normed:
            raise OSError("Cannot download root")
        url = f"{GRAPH_BASE}{prefix}/root:{self._escape_path(path)}:/content"
        return self._graph_get_spooled(url, f"Cannot read {path}")

    # See core/s3_client.py for the rationale on the cap.
    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            cap = self._MAX_APPEND_EXISTING_SIZE
            existing = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="OneDrive",
                logger=log,
            )
            if len(existing) > cap:
                raise OSError(
                    f"OneDrive append: existing file exceeds {cap // (1024 * 1024)} MiB cap"
                )
            writer = _SpooledWriter(self, path)
            writer.write(existing)
            return writer
        return _SpooledWriter(self, path)

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
        raise OSError("OneDrive does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("OneDrive does not support symlinks")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        """Return (total, used, remaining) bytes from the drive quota."""
        try:
            url = f"{GRAPH_BASE}{self._drive_prefix()}"
            data = self._graph_get(url)
            quota = as_dict(data.get("quota"))
            total = as_size(quota.get("total"))
            used = as_size(quota.get("used"))
            remaining = as_size(quota.get("remaining"))
            return (total, used, remaining)
        except OSError:
            return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        """Graph /items/{id}/versions — OneDrive's implicit version history."""
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from models.file_version import FileVersion

        normed = path.strip("/")
        if not normed:
            return []
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/root:{self._escape_path(path)}:/versions"
        try:
            data = self._graph_get(url)
        except Exception as exc:
            log.warning("OneDrive list_versions(%s) failed: %s", path, exc)
            return []
        items = [v for v in as_list(data.get("value")) if isinstance(v, dict)]

        # Always aware: the sort below compares them, and a naive
        # fallback next to an aware date raises TypeError.
        oldest = _dt.min.replace(tzinfo=_tz.utc)

        def _ts(v):
            return as_utc_datetime(v.get("lastModifiedDateTime"), default=oldest)

        items.sort(key=_ts, reverse=True)
        out: list = []
        for i, v in enumerate(items):
            version_id = as_str(v.get("id"))
            out.append(
                FileVersion(
                    version_id=version_id,
                    modified=_ts(v),
                    size=as_size(v.get("size")),
                    is_current=(i == 0),
                    label=f"onedrive-ver:{version_id}",
                )
            )
        return out

    def open_version_read(self, path: str, version_id: str):
        """Download a historical version via /versions/{id}/content."""
        normed = path.strip("/")
        if not normed:
            raise OSError("Cannot download root version")
        prefix = self._drive_prefix()
        url = (
            f"{GRAPH_BASE}{prefix}/root:{self._escape_path(path)}:/versions/"
            f"{quote(version_id, safe='')}/content"
        )
        try:
            return self._graph_get_spooled(url, f"Cannot read {path}@{version_id}")
        except Exception as exc:
            raise OSError(f"OneDrive open_version_read failed: {exc}") from exc

    #: Upper bound on waiting for a server-side copy, and the pause
    #: between two looks at its monitor.
    _COPY_TIMEOUT = 300.0
    _COPY_POLL_INTERVAL = 1.0

    def copy(self, src: str, dst: str) -> None:
        """Graph ``copy`` action. The server answers 202 Accepted with a
        monitor URL and copies afterwards; copy() returns when the monitor
        reports the copy completed. A failed copy is an OSError
        (FileExistsError for a taken name), and so is one still running
        after ``_COPY_TIMEOUT`` seconds.

        The destination folder is named by ``parentReference {driveId,
        id}`` - the form rename() uses for its ``{id}`` - not by a path.
        """
        what = f"OneDrive copy {src} -> {dst}"
        try:
            parent = self._graph_get(self._item_path_url(self.parent(dst)))
            parent_id = as_str(parent.get("id"))
            if not parent_id:
                raise OSError(f"Cannot resolve item ID for: {self.parent(dst)}")
            drive_id = as_str(as_dict(parent.get("parentReference")).get("driveId"))
            if not drive_id:
                # The root folder carries no parent: the drive names itself.
                drive_id = as_str(self._graph_get(f"{GRAPH_BASE}{self._drive_prefix()}").get("id"))
            reference = {"driveId": drive_id, "id": parent_id} if drive_id else {"id": parent_id}
            src_url = f"{GRAPH_BASE}{self._drive_prefix()}/root:{self._escape_path(src)}:/copy"
            body = {"parentReference": reference, "name": posixpath.basename(dst.rstrip("/"))}
            resp = self._graph_post_response(src_url, body)
        except Exception as exc:
            raise OSError(f"{what} failed: {exc}") from exc
        if resp.status_code != 202:
            return  # answered as done right away
        self._wait_for_copy(as_str(resp.headers.get("Location")), what, dst)

    def _wait_for_copy(self, monitor_url: str, what: str, dst: str) -> None:
        """Poll the copy's monitor URL until the copy completed or failed.

        The monitor URL is pre-authenticated (like the upload-session URL):
        it gets no bearer token, it must be https, and its redirect to the
        new item (when done) is not followed - that one would need a token.
        """
        if not monitor_url:
            raise OSError(f"{what}: the server accepted the copy without a monitor URL")
        if not monitor_url.lower().startswith("https://"):
            raise OSError(f"{what}: the copy monitor URL is not https")
        deadline = time.monotonic() + self._COPY_TIMEOUT
        while True:
            try:
                resp = self._http.get(monitor_url, timeout=GRAPH_TIMEOUT, allow_redirects=False)
            except Exception as exc:
                raise OSError(f"{what}: copy monitor: {exc}") from exc
            if resp.status_code in (301, 302, 303):
                return  # done: the monitor points at the new item
            if resp.status_code >= 400:
                raise OSError(
                    f"{what}: copy monitor failed ({resp.status_code}): {resp.text[:500]}"
                )
            report = _graph_json(resp, f"{what} monitor")
            status = as_str(report.get("status"))
            if status == "completed":
                return
            if status in ("failed", "deleteFailed", "cancelled"):
                error = as_dict(report.get("error"))
                code = as_str(error.get("code")) or status
                message = as_str(error.get("message"))
                if code == "nameAlreadyExists":
                    raise FileExistsError(errno.EEXIST, f"{what}: the target exists", dst)
                raise OSError(f"{what} failed on the server: {code}: {message}".rstrip(": "))
            if time.monotonic() >= deadline:
                raise OSError(
                    f"{what}: copy timed out after {self._COPY_TIMEOUT}s (status: {status})"
                )
            time.sleep(self._COPY_POLL_INTERVAL)

    # ------------------------------------------------------------------
    # OneDrive / SharePoint share verbs (slice 5 of API_GAPS)
    # ------------------------------------------------------------------

    def share(
        self,
        path: str,
        *,
        link_type: str = "view",
        scope: str = "anonymous",
        password: str | None = None,
        expires: str | None = None,
    ) -> str:
        """Create a sharing link for the file/folder at ``path``.
        Returns the URL.

        ``link_type``: ``"view"`` (read-only), ``"edit"``, or
                       ``"embed"``.
        ``scope``:     ``"anonymous"`` (anyone with the link) or
                       ``"organization"`` (signed-in tenant users).
        ``password``:  optional access password (anonymous only).
        ``expires``:   ISO-8601 datetime ``"2026-12-31T23:59:59Z"``;
                       Graph rejects shares with past expiry.
        """
        # F40: paranoia — link_type / scope / password / expires
        # all land verbatim in the JSON body that the Graph endpoint
        # logs. CR/LF in any of them would smuggle log lines via
        # JSON escapes (the requests JSON encoder escapes them but
        # Microsoft Graph's audit log might not on round-trip).
        for label, val in (
            ("link_type", link_type),
            ("scope", scope),
            ("password", password or ""),
            ("expires", expires or ""),
        ):
            if val and ("\r" in val or "\n" in val):
                raise ValueError(f"OneDrive share: {label} must not contain CR/LF. F40.")
        url = f"{GRAPH_BASE}{self._drive_prefix()}/root:{self._escape_path(path)}:/createLink"
        body: dict = {"type": link_type, "scope": scope}
        if password:
            body["password"] = password
        if expires:
            body["expirationDateTime"] = expires
        data = self._graph_post(url, body)
        link = as_str(as_dict(data.get("link")).get("webUrl"))
        if not link:
            raise OSError(f"OneDrive share({path}) returned no webUrl: {data}")
        # The path, never the link: an anonymous link opens the file for
        # whoever reads the log.
        log.info(
            "OneDrive share: %s (type=%s scope=%s%s%s)",
            path,
            link_type,
            scope,
            " password=set" if password else "",
            f" expires={expires}" if expires else "",
        )
        return link

    def permissions_list(self, path: str) -> list[dict]:
        """List every permission on a file: id, role(s), type, grantee
        link/email."""
        url = f"{GRAPH_BASE}{self._drive_prefix()}/root:{self._escape_path(path)}:/permissions"
        out: list[dict] = []
        for p in self._pages(url):
            grantee = as_dict(p.get("grantedTo") or p.get("grantedToV2"))
            user = as_dict(grantee.get("user"))
            out.append(
                {
                    "id": as_str(p.get("id")),
                    "roles": [r for r in as_list(p.get("roles")) if isinstance(r, str)],
                    "type": "link" if p.get("link") else "user",
                    "email": as_str(user.get("email")),
                    "url": as_str(as_dict(p.get("link")).get("webUrl")),
                }
            )
        return out

    # ------------------------------------------------------------------
    # SharePoint-specific verbs (API_GAPS round 2)
    # Only meaningful when drive_type=="sharepoint" — every method
    # checks and raises a structured OSError otherwise.
    # ------------------------------------------------------------------

    def lists(self) -> list[dict]:
        """Enumerate every SharePoint List in the connected site.
        Returns dicts ``{id, name, display_name, list_type, item_count,
        web_url}``. Includes both user-created lists and the
        system-generated ones (Documents, Site Pages, …) — filter
        on ``list_type`` to scope.
        """
        self._require_sharepoint("lists")
        url = f"{GRAPH_BASE}/sites/{self._site_id}/lists"
        out: list[dict] = []
        for entry in self._pages(url):
            info = as_dict(entry.get("list"))
            out.append(
                {
                    "id": as_str(entry.get("id")),
                    "name": as_str(entry.get("name")),
                    "display_name": as_str(entry.get("displayName")),
                    "list_type": as_str(info.get("template")),
                    "item_count": as_size(entry.get("@microsoft.graph.itemCount")),
                    "web_url": as_str(entry.get("webUrl")),
                }
            )
        return out

    def items(self, list_id: str, *, expand_fields: bool = True, limit: int = 100) -> list[dict]:
        """Fetch up to ``limit`` items from a SharePoint List by id.
        ``expand_fields=True`` includes the ``fields`` (column values)
        sub-object — usually what you want; the bare item record is
        nearly empty without it.

        Refuses CR/LF in ``list_id`` (interpolated into the URL).
        """
        self._require_sharepoint("items")
        if "\r" in list_id or "\n" in list_id:
            raise ValueError("items: list_id must not contain CR/LF")
        url = f"{GRAPH_BASE}/sites/{self._site_id}/lists/{list_id}/items?$top={int(limit)}"
        if expand_fields:
            url += "&$expand=fields"
        out: list[dict] = []
        if int(limit) <= 0:
            return out
        for it in self._pages(url):
            out.append(
                {
                    "id": as_str(it.get("id")),
                    "fields": as_dict(it.get("fields")),
                    "web_url": as_str(it.get("webUrl")),
                    "created": as_str(it.get("createdDateTime")),
                    "modified": as_str(it.get("lastModifiedDateTime")),
                }
            )
            if len(out) >= int(limit):
                break
        return out

    def search(
        self, query: str, *, entity_types: tuple[str, ...] = ("driveItem",), limit: int = 25
    ) -> list[dict]:
        """Microsoft Search across the site's content. ``entity_types``
        scopes to driveItem / listItem / list / site (any combination).
        Returns simplified hit dicts.

        Refuses CR/LF in ``query`` (the search payload is JSON; CR/LF
        would otherwise be smuggled through the JSON encoder fine
        but still surface in server-side logs as suspicious).
        """
        self._require_sharepoint("search")
        if "\r" in query or "\n" in query:
            raise ValueError("search: query must not contain CR/LF")
        url = f"{GRAPH_BASE}/search/query"
        body = {
            "requests": [
                {
                    "entityTypes": list(entity_types),
                    "query": {"queryString": query},
                    "from": 0,
                    "size": int(limit),
                }
            ],
        }
        data = self._graph_post(url, body)
        out: list[dict] = []
        for resp in as_list(data.get("value")):
            for hit_container in as_list(as_dict(resp).get("hitsContainers")):
                for hit in as_list(as_dict(hit_container).get("hits")):
                    if not isinstance(hit, dict):
                        continue
                    out.append(
                        {
                            "id": as_str(hit.get("hitId")),
                            "rank": as_size(hit.get("rank")),
                            "summary": as_str(hit.get("summary")),
                            "resource": as_dict(hit.get("resource")),
                        }
                    )
                    if len(out) >= int(limit):
                        return out
        return out

    def _require_sharepoint(self, verb: str) -> None:
        if self._drive_type != "sharepoint":
            raise OSError(
                f"OneDriveSession.{verb}() is SharePoint-only; this "
                f"session is drive_type={self._drive_type!r}"
            )
        if not self._site_id:
            raise OSError(
                f"OneDriveSession.{verb}(): SharePoint site_id not "
                "resolved — was the session connected?"
            )

    def _graph_post(self, url: str, body: dict) -> dict:
        """POST a JSON body to the Graph API. Mirrors _graph_get's
        auth + error-mapping pattern."""
        resp = self._graph_post_response(url, body)
        return _graph_json(resp, f"POST {url}", empty_ok=True)

    def _graph_post_response(self, url: str, body: dict):
        """POST a JSON body; the response itself (status and headers), an
        OSError for an error status."""
        self._ensure_token()
        resp = self._http.post(
            url,
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=30,
        )
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.post(
                url,
                headers={
                    "Authorization": f"Bearer {self._access_token}",
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=30,
            )
        if resp.status_code >= 400:
            raise OSError(f"Graph POST {url} → {resp.status_code}: {resp.text[:500]}")
        return resp

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return OneDrive's file.hashes.

        The Graph API exposes quickXorHash (OneDrive proprietary),
        sha1Hash, sha256Hash. We prefer the caller's requested
        algorithm if the server has it, else fall back to whatever
        the response contains."""
        try:
            url = f"{GRAPH_BASE}{self._drive_prefix()}/root:{self._escape_path(path)}"
            data = self._graph_get(url)
        except OSError:
            raise
        file_info = as_dict(data.get("file"))
        hashes = {k: v for k, v in as_dict(file_info.get("hashes")).items() if isinstance(v, str)}
        want_key = {
            "sha256": "sha256Hash",
            "sha1": "sha1Hash",
        }.get(algorithm)
        if want_key and want_key in hashes:
            return f"{algorithm}:{hashes[want_key].lower()}"
        # Fallback: whatever the server exposes
        for algo_key, algo_label in (
            ("sha256Hash", "sha256"),
            ("sha1Hash", "sha1"),
            ("quickXorHash", "onedrive-quickxor"),
        ):
            if algo_key in hashes:
                return f"{algo_label}:{hashes[algo_key].lower()}"
        return ""
