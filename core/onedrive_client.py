"""OneDrive / SharePoint backend implementing the FileBackend protocol.

Uses Microsoft Graph API with MSAL for OAuth2 authentication.

Requires: pip install axross[onedrive]  (msal>=1.24, requests>=2.28)
"""
from __future__ import annotations

import io
import json
import logging
import os
import posixpath
import tempfile
from datetime import datetime
from typing import IO

from core.secure_storage import write_secret_file
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


class _SpooledWriter:
    """Write to a temp file, then upload on close via Graph API."""

    def __init__(self, session: OneDriveSession, remote_path: str):
        self._session = session
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
        data = self._buf.read()
        self._session._upload_content(self._remote_path, data)
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class OneDriveSession:
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
    ):
        if msal is None:
            raise ImportError(
                "OneDrive support requires msal. "
                "Install with: pip install axross[onedrive]"
            )
        if requests is None:
            raise ImportError(
                "OneDrive support requires requests. "
                "Install with: pip install requests"
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

        # MSAL scopes
        self._scopes = ["Files.ReadWrite.All", "User.Read"]
        if self._drive_type == "sharepoint":
            self._scopes.append("Sites.ReadWrite.All")

        # Set up MSAL token cache
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

    def _save_cache(self) -> None:
        """Persist the MSAL token cache to disk (atomic, 0o600)."""
        if self._cache.has_state_changed:
            try:
                write_secret_file(self._token_file, self._cache.serialize())
            except OSError as exc:
                log.error(
                    "OneDrive: failed to persist token cache %s: %s",
                    self._token_file, exc,
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
        site_id = resp.get("id", "")
        if not site_id:
            raise OSError(
                f"Cannot resolve SharePoint site: {self._site_url}"
            )
        return site_id

    def _drive_prefix(self) -> str:
        """Return the Graph API drive prefix based on drive type."""
        if self._drive_type == "sharepoint" and self._site_id:
            return f"/sites/{self._site_id}/drive"
        return "/me/drive"

    def _item_path_url(self, path: str) -> str:
        """Build the Graph API URL for a given path.

        For root (``/``): ``/me/drive/root``
        For other paths: ``/me/drive/root:/path``
        """
        prefix = self._drive_prefix()
        normed = path.strip("/")
        if not normed:
            return f"{GRAPH_BASE}{prefix}/root"
        return f"{GRAPH_BASE}{prefix}/root:/{normed}"

    def _children_url(self, path: str) -> str:
        """Build the Graph API URL for listing children of *path*.

        For root: ``/me/drive/root/children``
        For other paths: ``/me/drive/root:/path:/children``
        """
        prefix = self._drive_prefix()
        normed = path.strip("/")
        if not normed:
            return f"{GRAPH_BASE}{prefix}/root/children"
        return f"{GRAPH_BASE}{prefix}/root:/{normed}:/children"

    def _graph_get(self, url: str, **kwargs) -> dict:
        """Execute a GET request against the Graph API."""
        self._ensure_token()
        kwargs.setdefault("timeout", GRAPH_TIMEOUT)
        resp = self._http.get(url, headers=self._headers(), **kwargs)
        if resp.status_code == 401:
            # Token may have expired between _ensure_token and now
            self._access_token = self._acquire_token()
            resp = self._http.get(url, headers=self._headers(), **kwargs)
        if resp.status_code >= 400:
            raise OSError(
                f"Graph API GET {url} failed ({resp.status_code}): "
                f"{resp.text[:500]}"
            )
        return resp.json()

    def _graph_post(self, url: str, json_data: dict) -> dict:
        """Execute a POST request against the Graph API."""
        self._ensure_token()
        resp = self._http.post(url, headers=self._headers(), json=json_data, timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.post(url, headers=self._headers(), json=json_data, timeout=GRAPH_TIMEOUT)
        if resp.status_code >= 400:
            raise OSError(
                f"Graph API POST {url} failed ({resp.status_code}): "
                f"{resp.text[:500]}"
            )
        return resp.json()

    def _graph_patch(self, url: str, json_data: dict) -> dict:
        """Execute a PATCH request against the Graph API."""
        self._ensure_token()
        resp = self._http.patch(url, headers=self._headers(), json=json_data, timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.patch(url, headers=self._headers(), json=json_data, timeout=GRAPH_TIMEOUT)
        if resp.status_code >= 400:
            raise OSError(
                f"Graph API PATCH {url} failed ({resp.status_code}): "
                f"{resp.text[:500]}"
            )
        return resp.json()

    def _graph_delete(self, url: str) -> None:
        """Execute a DELETE request against the Graph API."""
        self._ensure_token()
        resp = self._http.delete(url, headers=self._headers(), timeout=GRAPH_TIMEOUT)
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.delete(url, headers=self._headers(), timeout=GRAPH_TIMEOUT)
        if resp.status_code >= 400:
            raise OSError(
                f"Graph API DELETE {url} failed ({resp.status_code}): "
                f"{resp.text[:500]}"
            )

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
            raise OSError(
                f"Graph API PUT {url} failed ({resp.status_code}): "
                f"{resp.text[:500]}"
            )
        return resp.json()

    def _graph_get_bytes(self, url: str) -> bytes:
        """Execute a GET request that returns raw bytes (file download)."""
        self._ensure_token()
        resp = self._http.get(
            url,
            headers=self._headers(),
            stream=False,
            timeout=GRAPH_TIMEOUT,
        )
        if resp.status_code == 401:
            self._access_token = self._acquire_token()
            resp = self._http.get(
                url,
                headers=self._headers(),
                stream=False,
                timeout=GRAPH_TIMEOUT,
            )
        if resp.status_code >= 400:
            raise OSError(
                f"Graph API GET {url} failed ({resp.status_code}): "
                f"{resp.text[:500]}"
            )
        return resp.content

    # ------------------------------------------------------------------
    # Item parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_item(item: dict) -> FileItem:
        """Parse a Graph API drive-item dict into a FileItem."""
        name = item.get("name", "")
        size = item.get("size", 0)
        is_dir = "folder" in item

        modified = datetime.fromtimestamp(0)
        raw_modified = item.get("lastModifiedDateTime", "")
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
        item_id = data.get("id", "")
        if not item_id:
            raise OSError(f"Cannot resolve item ID for: {path}")
        return item_id

    # ------------------------------------------------------------------
    # Upload helper (used by _SpooledWriter)
    # ------------------------------------------------------------------

    def _upload_content(self, path: str, data: bytes) -> None:
        """Upload raw bytes to *path* using the simple upload endpoint."""
        normed = path.strip("/")
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/root:/{normed}:/content"
        self._graph_put_bytes(url, data)

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
        self._save_cache()
        self._http.close()

    def disconnect(self) -> None:
        self.close()

    def list_dir(self, path: str) -> list[FileItem]:
        url = self._children_url(path)
        items: list[FileItem] = []

        while url:
            data = self._graph_get(url)
            for entry in data.get("value", []):
                items.append(self._parse_item(entry))
            # Handle pagination
            url = data.get("@odata.nextLink", "")

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
        try:
            item = self.stat(path)
            return item.is_dir
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
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
        item_id = self._get_item_id(path)
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/items/{item_id}"
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
            parent_url = self._item_path_url(
                "/" + new_parent_path if new_parent_path else "/"
            )
            parent_data = self._graph_get(parent_url)
            payload["parentReference"] = {"id": parent_data["id"]}

        self._graph_patch(url, payload)

    def open_read(self, path: str) -> IO[bytes]:
        normed = path.strip("/")
        prefix = self._drive_prefix()
        if not normed:
            raise OSError("Cannot download root")
        url = f"{GRAPH_BASE}{prefix}/root:/{normed}:/content"
        data = self._graph_get_bytes(url)
        buf = io.BytesIO(data)
        buf.seek(0)
        return buf

    # See core/s3_client.py for the rationale on the cap.
    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            cap = self._MAX_APPEND_EXISTING_SIZE
            try:
                handle = self.open_read(path)
                existing = handle.read(cap + 1)
                handle.close()
            except OSError:
                existing = b""
            if len(existing) > cap:
                raise OSError(
                    f"OneDrive append: existing file exceeds "
                    f"{cap // (1024 * 1024)} MiB cap"
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
            quota = data.get("quota", {})
            total = quota.get("total", 0)
            used = quota.get("used", 0)
            remaining = quota.get("remaining", 0)
            return (total, used, remaining)
        except OSError:
            return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        """Graph /items/{id}/versions — OneDrive's implicit version history."""
        from models.file_version import FileVersion
        from datetime import datetime as _dt
        normed = path.strip("/")
        if not normed:
            return []
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/root:/{normed}:/versions"
        try:
            data = self._graph_get(url)
        except Exception as exc:
            log.warning("OneDrive list_versions(%s) failed: %s", path, exc)
            return []
        items = list(data.get("value") or [])
        def _ts(v):
            s = v.get("lastModifiedDateTime") or ""
            try:
                return _dt.fromisoformat(s.replace("Z", "+00:00"))
            except Exception:
                return _dt.min
        items.sort(key=_ts, reverse=True)
        out: list = []
        for i, v in enumerate(items):
            out.append(FileVersion(
                version_id=v.get("id") or "",
                modified=_ts(v),
                size=int(v.get("size") or 0),
                is_current=(i == 0),
                label=f"onedrive-ver:{v.get('id','')}",
            ))
        return out

    def open_version_read(self, path: str, version_id: str):
        """Download a historical version via /versions/{id}/content."""
        normed = path.strip("/")
        if not normed:
            raise OSError("Cannot download root version")
        prefix = self._drive_prefix()
        url = f"{GRAPH_BASE}{prefix}/root:/{normed}:/versions/{version_id}/content"
        try:
            data = self._graph_get_bytes(url)
        except Exception as exc:
            raise OSError(f"OneDrive open_version_read failed: {exc}") from exc
        return io.BytesIO(data)

    def copy(self, src: str, dst: str) -> None:
        """OneDrive Graph API copy action — asynchronous on the server
        side but we POST and return immediately; the file appears at
        dst once the server finishes."""
        try:
            src_url = (
                f"{GRAPH_BASE}{self._drive_prefix()}/root:"
                f"{self._escape_path(src)}:/copy"
            )
            dst_parent = self.parent(dst)
            body = {
                "parentReference": {"path": f"{self._drive_prefix()}/root:"
                                    f"{self._escape_path(dst_parent)}"},
                "name": posixpath.basename(dst.rstrip("/")),
            }
            self._graph_post(src_url, body)
        except Exception as exc:
            raise OSError(f"OneDrive copy {src} -> {dst} failed: {exc}") from exc

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
        file_info = data.get("file") or {}
        hashes = file_info.get("hashes") or {}
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
