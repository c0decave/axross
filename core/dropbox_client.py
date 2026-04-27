"""Dropbox backend implementing the FileBackend protocol.

Requires: pip install axross[dropbox]  (dropbox>=12.0)

Uses the Dropbox Python SDK with OAuth2 PKCE flow.  On first use the
user is directed to a browser-based consent page; the resulting
access / refresh tokens are persisted to a local JSON file so
subsequent sessions authenticate silently.
"""
from __future__ import annotations

import io
import json
import logging
import os
import posixpath
import sys
import tempfile
import webbrowser
from datetime import datetime
from typing import IO

from core.secure_storage import write_secret_file
from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    import dropbox
    from dropbox.files import FileMetadata, FolderMetadata, WriteMode
    from dropbox.exceptions import ApiError, AuthError
    from dropbox.oauth import DropboxOAuth2FlowNoRedirect
except ImportError:
    dropbox = None  # type: ignore[assignment]
    FileMetadata = None  # type: ignore[assignment,misc]
    FolderMetadata = None  # type: ignore[assignment,misc]
    WriteMode = None  # type: ignore[assignment,misc]
    ApiError = Exception  # type: ignore[assignment,misc]
    AuthError = Exception  # type: ignore[assignment,misc]
    DropboxOAuth2FlowNoRedirect = None  # type: ignore[assignment,misc]

_DEFAULT_TOKEN_PATH = os.path.expanduser("~/.config/axross/dropbox_token.json")


class _SpooledWriter:
    """Write to a temp spool, then upload to Dropbox on close."""

    def __init__(self, dbx, remote_path: str):
        self._dbx = dbx
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
        self._dbx.files_upload(data, self._remote_path, mode=WriteMode("overwrite"))
        self._buf.close()

    def discard(self) -> None:
        """Drop the buffered bytes without uploading. Called by
        transfer_worker on cancel / error so no partial file lands on
        the remote."""
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001 — already-closed is fine
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class DropboxSession:
    """Dropbox backend implementing the FileBackend protocol.

    Uses the official ``dropbox`` Python SDK.  Authentication is handled
    via OAuth2 PKCE (no app secret required).  Tokens are cached in a
    local JSON file so the browser consent flow only runs once.
    """

    def __init__(
        self,
        app_key: str,
        app_secret: str = "",
        token_file: str = _DEFAULT_TOKEN_PATH,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if dropbox is None:
            raise ImportError(
                "Dropbox support requires the dropbox SDK. "
                "Install with: pip install axross[dropbox]"
            )

        self._app_key = app_key
        self._app_secret = app_secret
        self._token_file = os.path.expanduser(token_file)
        # Build the requests proxies dict once; apply on every Dropbox()
        # construction in _apply_session_overrides.
        from core.proxy import build_requests_proxies
        self._proxies = build_requests_proxies(
            proxy_type, proxy_host, int(proxy_port or 0),
            proxy_username, proxy_password,
        )
        self._dbx: dropbox.Dropbox | None = None

        self._authenticate()
        log.info("Dropbox connected: %s", self.name)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _authenticate(self) -> None:
        """Load cached tokens or start the OAuth2 PKCE flow."""
        token_data = self._load_tokens()

        if token_data:
            access_token = token_data.get("access_token", "")
            refresh_token = token_data.get("refresh_token", "")

            if refresh_token:
                # Build a client that can auto-refresh using the refresh token
                self._dbx = dropbox.Dropbox(
                    oauth2_access_token=access_token,
                    oauth2_refresh_token=refresh_token,
                    app_key=self._app_key,
                    app_secret=self._app_secret or None,
                )
                self._apply_session_overrides(self._dbx)
                # Validate / refresh
                try:
                    self._dbx.users_get_current_account()
                    log.debug("Dropbox: authenticated with cached refresh token")
                    return
                except AuthError as exc:
                    log.warning(
                        "Dropbox: cached refresh token rejected (%s); "
                        "restarting OAuth flow", exc,
                    )
            elif access_token:
                self._dbx = dropbox.Dropbox(oauth2_access_token=access_token)
                self._apply_session_overrides(self._dbx)
                try:
                    self._dbx.users_get_current_account()
                    log.debug("Dropbox: authenticated with cached access token")
                    return
                except AuthError as exc:
                    log.warning(
                        "Dropbox: cached access token expired (%s); "
                        "restarting OAuth flow", exc,
                    )

        # Run the OAuth2 PKCE browser flow
        self._run_oauth_flow()

    def _run_oauth_flow(self) -> None:
        """Execute the OAuth2 PKCE flow using a local redirect server."""
        auth_flow = DropboxOAuth2FlowNoRedirect(
            self._app_key,
            use_pkce=True,
            token_access_type="offline",
        )
        authorize_url = auth_flow.start()

        log.info("Dropbox: opening browser for authorization")
        webbrowser.open(authorize_url)
        if not sys.stdin.isatty():
            log.error("Dropbox authorization requires interactive stdin")
            raise OSError(
                "Dropbox authorization requires interactive input. "
                f"Open this URL, complete the flow, and retry: {authorize_url}"
            )

        # Prompt the user to paste the authorization code
        # (DropboxOAuth2FlowNoRedirect does not use a redirect URI)
        log.info("Dropbox authorization requires a pasted code from the browser flow")
        print("=" * 60)
        print("Dropbox authorization required.")
        print("A browser window should have opened. If not, visit:")
        print(f"  {authorize_url}")
        print()
        auth_code = input("Enter the authorization code: ").strip()
        print("=" * 60)

        if not auth_code:
            raise OSError("Dropbox authorization cancelled: no code provided")

        oauth_result = auth_flow.finish(auth_code)

        self._dbx = dropbox.Dropbox(
            oauth2_access_token=oauth_result.access_token,
            oauth2_refresh_token=oauth_result.refresh_token,
            app_key=self._app_key,
            app_secret=self._app_secret or None,
        )
        self._apply_session_overrides(self._dbx)

        self._save_tokens(oauth_result.access_token, oauth_result.refresh_token)
        log.info("Dropbox: authorization successful, tokens saved")

    def _apply_session_overrides(self, dbx) -> None:
        """Override the underlying requests.Session: set the uniform
        User-Agent (per docs/OPSEC.md #4) AND the proxy dict if one
        is configured on this profile. Best-effort: private attribute;
        skipped silently when the dropbox SDK layout changes.
        """
        from core.client_identity import HTTP_USER_AGENT
        for attr in ("_session", "session"):
            sess = getattr(dbx, attr, None)
            if sess is not None and hasattr(sess, "headers"):
                try:
                    sess.headers["User-Agent"] = HTTP_USER_AGENT
                    if self._proxies:
                        sess.proxies = dict(self._proxies)
                except Exception:  # noqa: BLE001 — defensive
                    continue
                return

    def _load_tokens(self) -> dict | None:
        """Load saved tokens from disk (with shape validation)."""
        if not os.path.isfile(self._token_file):
            return None
        try:
            with open(self._token_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning(
                "Dropbox: failed to load token file %s: %s",
                self._token_file, exc,
            )
            return None

        if not isinstance(data, dict):
            log.warning(
                "Dropbox: token file %s is not a JSON object — ignoring",
                self._token_file,
            )
            return None

        access = data.get("access_token")
        refresh = data.get("refresh_token")
        if access is not None and not isinstance(access, str):
            log.warning(
                "Dropbox: access_token in %s is not a string — ignoring",
                self._token_file,
            )
            return None
        if refresh is not None and not isinstance(refresh, str):
            log.warning(
                "Dropbox: refresh_token in %s is not a string — ignoring",
                self._token_file,
            )
            return None
        if not access and not refresh:
            log.warning(
                "Dropbox: token file %s has neither access_token nor refresh_token",
                self._token_file,
            )
            return None
        return data

    def _save_tokens(self, access_token: str, refresh_token: str | None) -> None:
        """Persist tokens to the local JSON file (atomic, 0o600)."""
        data = {
            "access_token": access_token,
            "refresh_token": refresh_token or "",
        }
        try:
            write_secret_file(self._token_file, json.dumps(data, indent=2))
            log.debug("Dropbox: tokens saved to %s", self._token_file)
        except OSError as exc:
            log.error("Dropbox: failed to save tokens: %s", exc)

    # ------------------------------------------------------------------
    # FileBackend protocol
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        if self._dbx is not None:
            try:
                acct = self._dbx.users_get_current_account()
                return f"{acct.name.display_name} (Dropbox)"
            except Exception:
                pass
        return "Dropbox"

    @property
    def connected(self) -> bool:
        if self._dbx is None:
            return False
        try:
            self._dbx.users_get_current_account()
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self._dbx is not None:
            self._dbx.close()
            self._dbx = None

    def disconnect(self) -> None:
        self.close()

    def _ensure_connected(self):
        if self._dbx is None:
            raise OSError("Not connected to Dropbox")
        return self._dbx

    @staticmethod
    def _api_path(path: str) -> str:
        """Convert a UI path to a Dropbox API path.

        The Dropbox API uses "" (empty string) for the root, and all
        other paths must start with "/".
        """
        path = path.strip()
        if not path or path == "/":
            return ""
        if not path.startswith("/"):
            path = "/" + path
        return path.rstrip("/") or ""

    # ------------------------------------------------------------------
    # Directory listing
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
        items: list[FileItem] = []

        try:
            result = dbx.files_list_folder(api_path)
            while True:
                for entry in result.entries:
                    items.append(self._entry_to_item(entry))
                if not result.has_more:
                    break
                result = dbx.files_list_folder_continue(result.cursor)
        except ApiError as exc:
            raise OSError(f"Cannot list {path}: {exc}") from exc

        return items

    # ------------------------------------------------------------------
    # Stat / type queries
    # ------------------------------------------------------------------

    def stat(self, path: str) -> FileItem:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)

        if not api_path:
            # Root folder
            return FileItem(name="/", is_dir=True)

        try:
            md = dbx.files_get_metadata(api_path)
            return self._entry_to_item(md)
        except ApiError as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc

    def is_dir(self, path: str) -> bool:
        api_path = self._api_path(path)
        if not api_path:
            return True
        try:
            md = self._ensure_connected().files_get_metadata(api_path)
            return isinstance(md, FolderMetadata)
        except ApiError:
            return False

    def exists(self, path: str) -> bool:
        api_path = self._api_path(path)
        if not api_path:
            return True
        try:
            self._ensure_connected().files_get_metadata(api_path)
            return True
        except ApiError:
            return False

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def mkdir(self, path: str) -> None:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
        try:
            dbx.files_create_folder_v2(api_path)
        except ApiError as exc:
            raise OSError(f"Cannot create directory {path}: {exc}") from exc

    def remove(self, path: str, recursive: bool = False) -> None:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
        try:
            dbx.files_delete_v2(api_path)
        except ApiError as exc:
            raise OSError(f"Cannot remove {path}: {exc}") from exc

    def rename(self, src: str, dst: str) -> None:
        dbx = self._ensure_connected()
        try:
            dbx.files_move_v2(self._api_path(src), self._api_path(dst))
        except ApiError as exc:
            raise OSError(f"Cannot rename {src} -> {dst}: {exc}") from exc

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    def open_read(self, path: str) -> IO[bytes]:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
        try:
            _metadata, response = dbx.files_download(api_path)
            buf = io.BytesIO(response.content)
            buf.seek(0)
            return buf
        except ApiError as exc:
            raise OSError(f"Cannot read {path}: {exc}") from exc

    # See core/s3_client.py for the rationale on the cap.
    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
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
                    f"Dropbox append: existing file exceeds "
                    f"{cap // (1024 * 1024)} MiB cap"
                )
            writer = _SpooledWriter(dbx, api_path)
            writer.write(existing)
            return writer
        return _SpooledWriter(dbx, api_path)

    # ------------------------------------------------------------------
    # Path helpers
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

    # ------------------------------------------------------------------
    # Unsupported operations
    # ------------------------------------------------------------------

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("Dropbox does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("Dropbox does not support symlinks")

    # ------------------------------------------------------------------
    # Disk usage
    # ------------------------------------------------------------------

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        """Return (allocation, used, remaining) in bytes."""
        dbx = self._ensure_connected()
        try:
            usage = dbx.users_get_space_usage()
            used = usage.used
            allocation = usage.allocation.get_individual().allocated
            remaining = allocation - used
            return (allocation, used, remaining)
        except Exception as exc:
            log.warning("Dropbox: failed to fetch disk usage: %s", exc)
            return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        """Dropbox files_list_revisions — history of rev IDs."""
        from models.file_version import FileVersion
        dbx = self._ensure_connected()
        try:
            resp = dbx.files_list_revisions(self._norm(path), limit=100)
        except Exception as exc:
            log.warning("Dropbox list_versions(%s) failed: %s", path, exc)
            return []
        out: list = []
        entries = list(resp.entries or [])
        # Newest first: Dropbox returns newest first already in recent SDKs,
        # but sort defensively.
        entries.sort(key=lambda e: getattr(e, "server_modified", None) or datetime.min,
                     reverse=True)
        for i, e in enumerate(entries):
            out.append(FileVersion(
                version_id=e.rev,
                modified=getattr(e, "server_modified", None) or datetime.now(),
                size=int(getattr(e, "size", 0) or 0),
                is_current=(i == 0),
                label=f"dropbox:{e.rev}",
            ))
        return out

    def open_version_read(self, path: str, version_id: str):
        """Download a historical revision as a BytesIO stream."""
        dbx = self._ensure_connected()
        try:
            md, resp = dbx.files_download(self._norm(path), rev=version_id)
        except Exception as exc:
            raise OSError(f"Dropbox open_version_read failed: {exc}") from exc
        return io.BytesIO(resp.content)

    def copy(self, src: str, dst: str) -> None:
        """Dropbox files_copy_v2 — server-side."""
        dbx = self._ensure_connected()
        try:
            dbx.files_copy_v2(self._norm(src), self._norm(dst))
        except Exception as exc:
            raise OSError(f"Dropbox copy {src} -> {dst} failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Dropbox-specific verbs (slice 5 of API_GAPS)
    # ------------------------------------------------------------------

    def shared_link_create(self, path: str, *,
                           public: bool = True,
                           short: bool = False) -> str:
        """Create (or fetch existing) shared-link URL for ``path``.

        ``public=True`` makes the link viewable by anyone with the
        URL (Dropbox default). For team-only links, set False (this
        helper simply forwards Dropbox's ``visibility`` param).

        ``short`` requests a ``short_url`` instead of the full
        ``https://www.dropbox.com/scl/...`` form when available.

        Re-uses an existing link if one is already attached to the
        path (Dropbox's ``create_shared_link_with_settings`` errors
        with ``shared_link_already_exists`` otherwise — we map that
        to a ``list_shared_links`` lookup).
        """
        from dropbox.sharing import (
            SharedLinkSettings, RequestedVisibility,
        )
        from dropbox.exceptions import ApiError
        dbx = self._ensure_connected()
        norm = self._norm(path)
        vis = RequestedVisibility.public if public \
            else RequestedVisibility.team_only
        try:
            link = dbx.sharing_create_shared_link_with_settings(
                norm, settings=SharedLinkSettings(requested_visibility=vis),
            )
            return getattr(link, "url", "") or ""
        except ApiError as exc:
            # If a link already exists, look it up + return that one.
            err_text = str(exc)
            if "shared_link_already_exists" in err_text:
                existing = dbx.sharing_list_shared_links(
                    path=norm, direct_only=True,
                )
                if existing.links:
                    return existing.links[0].url
            raise OSError(f"Dropbox shared_link_create({path}): {exc}") from exc

    def shared_link_revoke(self, url: str) -> None:
        """Revoke a previously-issued shared link by URL."""
        dbx = self._ensure_connected()
        try:
            dbx.sharing_revoke_shared_link(url)
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"Dropbox shared_link_revoke: {exc}") from exc

    def account_info(self) -> dict:
        """Return basic account metadata (display_name, email,
        account_type, country) plus storage usage. Useful for
        ``axross.docs("dropbox")`` style what-am-I-connected-as
        sanity checks."""
        dbx = self._ensure_connected()
        acct = dbx.users_get_current_account()
        usage = dbx.users_get_space_usage()
        out = {
            "account_id": acct.account_id,
            "display_name": acct.name.display_name if acct.name else "",
            "email": acct.email,
            "country": getattr(acct, "country", "") or "",
            "used_bytes": usage.used,
            "allocation_bytes": getattr(
                getattr(usage.allocation, "get_individual", lambda: None)(),
                "allocated", 0,
            ) if hasattr(usage.allocation, "get_individual") else 0,
        }
        return out

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return Dropbox's content_hash.

        Dropbox's content_hash is a proprietary algorithm: SHA-256 of
        the concatenation of SHA-256 hashes of each 4 MiB block of
        the file. We surface it with a ``dropbox:`` prefix so callers
        don't mistake it for a plain SHA-256.
        """
        dbx = self._ensure_connected()
        try:
            meta = dbx.files_get_metadata(self._norm(path))
        except Exception as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        ch = getattr(meta, "content_hash", None)
        if not ch:
            return ""
        return f"dropbox:{ch}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _entry_to_item(entry) -> FileItem:
        """Convert a Dropbox metadata entry to a FileItem."""
        if isinstance(entry, FolderMetadata):
            return FileItem(
                name=entry.name,
                is_dir=True,
            )
        elif isinstance(entry, FileMetadata):
            modified = entry.server_modified or datetime.fromtimestamp(0)
            return FileItem(
                name=entry.name,
                size=entry.size or 0,
                modified=modified,
            )
        # Unknown entry type – return minimal item
        return FileItem(name=getattr(entry, "name", "unknown"))
