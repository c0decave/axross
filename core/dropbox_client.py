"""Dropbox backend implementing the FileBackend protocol.

Requires: pip install axross[dropbox]  (dropbox>=12.0)

Uses the Dropbox Python SDK with OAuth2 PKCE flow.  On first use the
user is directed to a browser-based consent page; the resulting
access / refresh tokens are persisted to a local JSON file so
subsequent sessions authenticate silently.
"""

from __future__ import annotations

import errno
import io
import json
import logging
import os
import posixpath
import sys
import tempfile
from datetime import datetime, timezone
from typing import IO

from core import auth_prompt
from core.append_helpers import read_existing_for_append
from core import cloud_http
from core.backend import SessionLifecycle
from core.desktop_open import open_in_browser
from core.path_policy import refuse_folder_path
from core.read_spool import spool_response
from core.secure_storage import adopt_legacy_secret_file, write_secret_file
from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    import dropbox
    from dropbox.exceptions import ApiError, AuthError
    from dropbox.files import (
        CommitInfo,
        FileMetadata,
        FolderMetadata,
        UploadSessionCursor,
        WriteMode,
    )
    from dropbox.oauth import DropboxOAuth2FlowNoRedirect
except ImportError:
    dropbox = None  # type: ignore[assignment]
    FileMetadata = None  # type: ignore[assignment,misc]
    FolderMetadata = None  # type: ignore[assignment,misc]
    CommitInfo = None  # type: ignore[assignment,misc]
    UploadSessionCursor = None  # type: ignore[assignment,misc]
    WriteMode = None  # type: ignore[assignment,misc]
    ApiError = Exception  # type: ignore[assignment,misc]
    AuthError = Exception  # type: ignore[assignment,misc]
    DropboxOAuth2FlowNoRedirect = None  # type: ignore[assignment,misc]

_DEFAULT_TOKEN_PATH = os.path.expanduser("~/.config/axross/dropbox_token.json")

#: files/upload takes at most 150 MiB per request; a larger file goes
#: through an upload session.
_SINGLE_UPLOAD_MAX = 150 * 1024 * 1024
#: The SDK retries a 429 (RateLimitError, honouring its backoff) without
#: end by default - a throttled account parked a transfer and its Cancel
#: for good. 5xx it retries max_retries_on_error (4) times itself.
_RATE_LIMIT_RETRIES = cloud_http.ATTEMPTS - 1
#: Bytes per upload-session request (a multiple of 4 MiB, as Dropbox asks).
_UPLOAD_CHUNK = 8 * 1024 * 1024

# What the SDK raises from inside a call besides ApiError: its other
# exception classes (HTTP 400 / 401 / 429 / 5xx answers), stone's
# ValidationError for an answer that does not match the route's schema,
# and the plain errors its JSON decoding and stone deserialisation let
# through for a garbage body (ValueError incl. JSONDecodeError and
# UnicodeDecodeError, RecursionError, TypeError, KeyError, ...). It even
# checks the content type of an error answer with ``assert``
# (DropboxBase.raise_dropbox_error_for_resp).
_SDK_ANSWER_ERRORS: tuple[type[BaseException], ...] = (
    AssertionError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    RecursionError,
)
try:
    from dropbox.exceptions import DropboxException
    from stone.backends.python_rsrc.stone_validators import ValidationError

    _SDK_ANSWER_ERRORS += (DropboxException, ValidationError)
except ImportError:  # pragma: no cover - SDK absent: nothing to guard
    pass


#: Route-error tags (the nested stone unions of an ApiError) and the
#: errno each stands for; the first tag of the chain found here decides,
#: "conflict" is read with the tag after it (see _api_errno).
_TAG_ERRNO = {
    "not_found": errno.ENOENT,
    "not_folder": errno.ENOTDIR,
    "not_file": errno.EISDIR,
    "insufficient_space": errno.ENOSPC,
    "insufficient_quota": errno.ENOSPC,
    "no_write_permission": errno.EACCES,
    "restricted_content": errno.EACCES,
    "team_folder": errno.EACCES,
    "no_permission": errno.EACCES,
    "access_denied": errno.EACCES,
    "email_unverified": errno.EACCES,
    "malformed_path": errno.EINVAL,
    "disallowed_name": errno.EINVAL,
    "cant_move_folder_into_itself": errno.EINVAL,
    "cant_copy_shared_folder": errno.EINVAL,
    "cant_nest_shared_folder": errno.EINVAL,
    "cant_move_shared_folder": errno.EINVAL,
    "duplicated_or_nested_paths": errno.EINVAL,
    "cant_transfer_ownership": errno.EINVAL,
    "invalid_revision": errno.EINVAL,
    "too_many_files": errno.EFBIG,
    "payload_too_large": errno.EFBIG,
    "too_many_write_operations": errno.EAGAIN,
    "too_many_requests": errno.EAGAIN,
    "operation_suppressed": errno.EAGAIN,
    "locked": errno.EBUSY,
}


def _route_tags(error) -> list[str]:
    """The tags of a route error's nested unions, outermost first:
    ``UploadError.path(UploadWriteFailed(reason=WriteError.conflict(
    WriteConflictError.folder)))`` -> ["path", "conflict", "folder"]."""
    tags: list[str] = []
    cur = error
    for _depth in range(10):
        tag = getattr(cur, "_tag", None)
        if not isinstance(tag, str):
            reason = getattr(cur, "reason", None)  # a struct: UploadWriteFailed
            if reason is None or reason is cur:
                break
            cur = reason
            continue
        tags.append(tag)
        cur = getattr(cur, "_value", None)
        if cur is None:
            break
    return tags


def _api_errno(exc: BaseException) -> int:
    """The errno of a dropbox ApiError. A write conflict is EEXIST - the
    name is taken - except an upload onto a FOLDER (EISDIR) and a file
    where a parent folder should be (ENOTDIR)."""
    error = getattr(exc, "error", None)
    tags = _route_tags(error)
    if "conflict" in tags:
        kind = tags[tags.index("conflict") + 1] if tags.index("conflict") + 1 < len(tags) else ""
        if kind == "file_ancestor":
            return errno.ENOTDIR
        if kind == "folder" and "Upload" in type(error).__name__:
            return errno.EISDIR
        return errno.EEXIST
    for tag in tags:
        if tag in _TAG_ERRNO:
            return _TAG_ERRNO[tag]
    return errno.EIO


def _sdk_errno(exc: BaseException) -> int:
    """The errno of anything the SDK raised from inside a call."""
    if isinstance(exc, ApiError):
        return _api_errno(exc)
    name = type(exc).__name__
    if name == "AuthError":
        return errno.EACCES
    if name == "RateLimitError":
        return errno.EAGAIN
    if name == "BadInputError":
        return errno.EINVAL
    if name == "PathRootError":
        return errno.EINVAL
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return cloud_http.errno_for_status(status)
    if isinstance(exc, TimeoutError) or "Timeout" in name:
        return errno.ETIMEDOUT
    if isinstance(exc, ConnectionError) or "ConnectionError" in name:
        return errno.ECONNRESET
    if isinstance(exc, _SDK_ANSWER_ERRORS):
        return errno.EPROTO  # an answer of the wrong shape
    return errno.EIO


def _sdk_error(exc: BaseException, message: str, filename: str | None = None) -> OSError:
    """*message* as the typed OSError of an SDK failure. An OSError with
    an errno (already typed by _GuardedDropbox) keeps it."""
    if isinstance(exc, OSError) and isinstance(exc.errno, int) and exc.errno:
        return cloud_http.rewrap(exc, message, filename)
    return cloud_http.oserror(_sdk_errno(exc), message, filename)


def _is_not_found(exc: BaseException) -> bool:
    """True for the answer that says nothing is at the path:
    ``path/not_found``, or ``path/not_folder`` (a file where the path
    needs a folder). restricted_content, locked, malformed_path, a 403
    and the rest describe a refusal, not an absence."""
    return isinstance(exc, (FileNotFoundError, NotADirectoryError))


class _GuardedDropbox:
    """The SDK client, with every call failing as a typed OSError.

    ApiError, the SDK's HTTP errors (401 / 429 / 5xx), a dropped
    connection and an answer of the wrong shape all become the OSError
    subclass of their errno (_sdk_errno): FileNotFoundError for
    path/not_found, FileExistsError for a write conflict,
    PermissionError, ENOSPC for insufficient_space ... The SDK error is
    the ``__cause__``. Only the SDK call is guarded: errors in this
    module's own code are not masked.
    """

    def __init__(self, dbx) -> None:
        self._sdk = dbx

    def __getattr__(self, name: str):
        attr = getattr(self._sdk, name)
        if not callable(attr):
            return attr

        def call(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            except OSError as exc:
                if isinstance(exc.errno, int) and exc.errno:
                    raise
                # requests' own errors are OSErrors without an errno.
                raise _sdk_error(exc, f"Dropbox {name} failed: {exc}") from exc
            except (ApiError,) + _SDK_ANSWER_ERRORS as exc:
                raise _sdk_error(
                    exc, f"Dropbox {name} failed: {type(exc).__name__}: {exc}"
                ) from exc

        return call


class _SpooledWriter:
    """Write to a temp spool, then upload to Dropbox on close."""

    def __init__(self, dbx, remote_path: str):
        self._dbx = dbx
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
            if size <= _SINGLE_UPLOAD_MAX:
                self._dbx.files_upload(
                    self._buf.read(),
                    self._remote_path,
                    mode=WriteMode("overwrite"),
                )
            else:
                self._upload_in_session(size)
        except Exception as exc:
            # The editor's "Cannot save" and atomic_write's callers catch
            # OSError: no SDK exception leaves close().
            raise _sdk_error(
                exc, f"Cannot upload {self._remote_path}: {cloud_http.reason(exc)}",
                self._remote_path,
            ) from exc
        finally:
            self._buf.close()

    def _upload_in_session(self, size: int) -> None:
        """start, append_v2 ..., finish: one chunk per request."""
        chunk = self._buf.read(_UPLOAD_CHUNK)
        started = self._dbx.files_upload_session_start(chunk)
        cursor = UploadSessionCursor(session_id=started.session_id, offset=len(chunk))
        commit = CommitInfo(path=self._remote_path, mode=WriteMode("overwrite"))
        while True:
            chunk = self._buf.read(_UPLOAD_CHUNK)
            if cursor.offset + len(chunk) >= size:
                self._dbx.files_upload_session_finish(chunk, cursor, commit)
                return
            self._dbx.files_upload_session_append_v2(chunk, cursor)
            cursor.offset += len(chunk)

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

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


class DropboxSession(SessionLifecycle):
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
        legacy_token_file: str | None = None,
    ):
        if dropbox is None:
            raise ImportError(
                "Dropbox support requires the dropbox SDK. "
                "Install with: pip install axross[dropbox]"
            )

        self._app_key = app_key
        self._app_secret = app_secret
        self._token_file = os.path.expanduser(token_file)
        # The token file all profiles shared before each got its own: it
        # is taken over only when it names this app key.
        self._legacy_token_file = (
            os.path.expanduser(legacy_token_file) if legacy_token_file else None
        )
        # Build the requests proxies dict once; apply on every Dropbox()
        # construction in _apply_session_overrides.
        from core.proxy import build_requests_proxies

        self._proxies = build_requests_proxies(
            proxy_type,
            proxy_host,
            int(proxy_port or 0),
            proxy_username,
            proxy_password,
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
                    max_retries_on_rate_limit=_RATE_LIMIT_RETRIES,
                )
                self._apply_session_overrides(self._dbx)
                # Validate / refresh
                try:
                    self._dbx.users_get_current_account()
                    log.info("Dropbox connected (cached refresh token)")
                    return
                except AuthError as exc:
                    log.warning(
                        "Dropbox: cached refresh token rejected (%s); restarting OAuth flow",
                        exc,
                    )
            elif access_token:
                self._dbx = dropbox.Dropbox(
                    oauth2_access_token=access_token,
                    max_retries_on_rate_limit=_RATE_LIMIT_RETRIES,
                )
                self._apply_session_overrides(self._dbx)
                try:
                    self._dbx.users_get_current_account()
                    log.info("Dropbox connected (cached access token)")
                    return
                except AuthError as exc:
                    log.warning(
                        "Dropbox: cached access token expired (%s); restarting OAuth flow",
                        exc,
                    )

        # Run the OAuth2 PKCE browser flow
        self._run_oauth_flow()

    def _run_oauth_flow(self) -> None:
        """Execute the OAuth2 PKCE flow using a local redirect server."""
        if self._proxies:
            log.warning(
                "Dropbox proxy configured: API calls use the proxied SDK "
                "session, but the first-time browser consent page is "
                "outside axross and the no-redirect OAuth code exchange is "
                "owned by the Dropbox SDK and may not honour SOCKS/HTTP "
                "proxy settings."
            )
        auth_flow = DropboxOAuth2FlowNoRedirect(
            self._app_key,
            use_pkce=True,
            token_access_type="offline",
        )
        authorize_url = auth_flow.start()

        log.info("Dropbox: opening browser for authorization")
        open_in_browser(authorize_url)
        # Dropbox shows a code to paste back (no redirect URI): the window
        # asks for it (core.auth_prompt); a terminal only when there is none.
        if auth_prompt.has_handler():
            auth_code = auth_prompt.ask_code("Dropbox", authorize_url) or ""
        elif sys.stdin is not None and sys.stdin.isatty():
            print("=" * 60)
            print("Dropbox authorization required.")
            print("A browser window should have opened. If not, visit:")
            print(f"  {authorize_url}")
            print()
            auth_code = input("Enter the authorization code: ").strip()
            print("=" * 60)
        else:
            log.error("Dropbox authorization needs a window or a terminal to ask for the code")
            raise OSError(
                errno.EACCES,
                "Dropbox authorization requires interactive input. "
                f"Open this URL, complete the flow, and retry: {authorize_url}"
            )

        if not auth_code:
            raise OSError(errno.ECANCELED, "Dropbox authorization cancelled: no code provided")

        oauth_result = auth_flow.finish(auth_code)

        self._dbx = dropbox.Dropbox(
            oauth2_access_token=oauth_result.access_token,
            oauth2_refresh_token=oauth_result.refresh_token,
            app_key=self._app_key,
            app_secret=self._app_secret or None,
            max_retries_on_rate_limit=_RATE_LIMIT_RETRIES,
        )
        self._apply_session_overrides(self._dbx)

        self._save_tokens(oauth_result.access_token, oauth_result.refresh_token)
        log.info("Dropbox: authorization successful, tokens saved")

    def _apply_session_overrides(self, dbx) -> None:
        """Override the underlying requests.Session: set the uniform
        User-Agent (per docs/OPSEC.md #4) AND the proxy dict if one
        is configured on this profile.

        The SDK's session is a private attribute, so if a proxy is
        configured and the hook disappears, fail closed instead of
        allowing Dropbox API calls to go direct.
        """
        from core.client_identity import HTTP_USER_AGENT
        from core.proxy import lock_requests_session_to_profile_proxy

        proxies = getattr(self, "_proxies", {}) or {}
        last_error: Exception | None = None
        for attr in ("_session", "session"):
            sess = getattr(dbx, attr, None)
            if sess is not None and hasattr(sess, "headers"):
                try:
                    sess.headers["User-Agent"] = HTTP_USER_AGENT
                    lock_requests_session_to_profile_proxy(sess, proxies)
                except Exception as exc:  # noqa: BLE001 — defensive
                    last_error = exc
                    continue
                return
        if proxies:
            raise OSError(
                errno.ENOTSUP,
                "Dropbox proxy configured but the SDK requests-session "
                "hook is unavailable; refusing direct traffic."
            ) from last_error

    def _load_tokens(self) -> dict | None:
        """Load saved tokens from disk (with shape validation)."""
        adopt_legacy_secret_file(
            self._token_file,
            getattr(self, "_legacy_token_file", None),
            lambda text: json.loads(text).get("app_key") == self._app_key,
        )
        if not os.path.isfile(self._token_file):
            return None
        try:
            with open(self._token_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning(
                "Dropbox: failed to load token file %s: %s",
                self._token_file,
                exc,
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
        if data.get("app_key") != self._app_key:
            # A token of another app key - or one saved before the key was
            # recorded - may open another account.
            log.warning(
                "Dropbox: the token in %s was not issued to this app key; "
                "restarting OAuth flow",
                self._token_file,
            )
            return None
        return data

    def _save_tokens(self, access_token: str, refresh_token: str | None) -> None:
        """Persist tokens to the local JSON file (atomic, 0o600)."""
        data = {
            "access_token": access_token,
            "refresh_token": refresh_token or "",
            "app_key": self._app_key,
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
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("Dropbox liveness check failed: %s", exc)
            return False

    def close(self) -> None:
        if self._dbx is not None:
            log.info("Dropbox disconnecting")
            self._dbx.close()
            self._dbx = None

    def disconnect(self) -> None:
        self.close()

    def _ensure_connected(self):
        if self._dbx is None:
            raise OSError(errno.ENOTCONN, "Not connected to Dropbox")
        return _GuardedDropbox(self._dbx)

    @staticmethod
    def _api_path(path: str) -> str:
        """Convert a UI path to a Dropbox API path.

        The Dropbox API uses "" (empty string) for the root, and all
        other paths must start with "/". Blanks are part of a name: a
        strip() of the whole path addressed "foo " as its namesake "foo",
        so a delete of the one removed the other.
        """
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
            cursors: set[str] = set()
            while True:
                for entry in result.entries:
                    items.append(self._entry_to_item(entry))
                if not result.has_more:
                    break
                # A cursor handed back twice would page forever.
                if result.cursor in cursors:
                    raise OSError(errno.EPROTO, f"Cannot list {path}: the server repeats a paging cursor")
                cursors.add(result.cursor)
                result = dbx.files_list_folder_continue(result.cursor)
        except OSError as exc:
            raise _sdk_error(exc, f"Cannot list {path}: {cloud_http.reason(exc)}", path) from exc

        return items

    # ------------------------------------------------------------------
    # Stat / type queries
    # ------------------------------------------------------------------

    def stat(self, path: str) -> FileItem:
        return cloud_http.no_file_as_folder(path, self._stat(path))

    def _stat(self, path: str) -> FileItem:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)

        if not api_path:
            # Root folder
            return FileItem(name="/", is_dir=True)

        try:
            md = dbx.files_get_metadata(api_path)
            return self._entry_to_item(md)
        except OSError as exc:
            raise _sdk_error(exc, f"Cannot stat {path}: {cloud_http.reason(exc)}", path) from exc

    def is_dir(self, path: str) -> bool:
        """False only for "not found"; any other route error (locked,
        restricted_content, a 403 ...) is an OSError."""
        api_path = self._api_path(path)
        if not api_path:
            return True
        try:
            md = self._ensure_connected().files_get_metadata(api_path)
        except OSError as exc:
            if _is_not_found(exc):
                return False
            raise _sdk_error(exc, f"Cannot check {path}: {cloud_http.reason(exc)}", path) from exc
        return isinstance(md, FolderMetadata)

    def exists(self, path: str) -> bool:
        """False only for "not found"; any other route error is an
        OSError - server_side_copy(overwrite=False) takes False as its
        go-ahead to write."""
        api_path = self._api_path(path)
        if not api_path:
            return True
        try:
            self._ensure_connected().files_get_metadata(api_path)
        except OSError as exc:
            if _is_not_found(exc):
                return False
            raise _sdk_error(exc, f"Cannot check {path}: {cloud_http.reason(exc)}", path) from exc
        return True

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def mkdir(self, path: str) -> None:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
        try:
            dbx.files_create_folder_v2(api_path)
        except OSError as exc:
            raise _sdk_error(exc, f"Cannot create directory {path}: {cloud_http.reason(exc)}", path) from exc

    def remove(self, path: str, recursive: bool = False) -> None:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
        try:
            # files/delete_v2 takes a folder with everything in it, so a
            # non-recursive remove refuses a folder with entries first.
            if not recursive and isinstance(dbx.files_get_metadata(api_path), FolderMetadata):
                page = dbx.files_list_folder(api_path, limit=1)
                if page.entries or page.has_more:
                    raise OSError(errno.ENOTEMPTY, f"Directory not empty: {path}", path)
            dbx.files_delete_v2(api_path)
        except OSError as exc:
            raise _sdk_error(exc, f"Cannot remove {path}: {cloud_http.reason(exc)}", path) from exc

    def rename(self, src: str, dst: str) -> None:
        dbx = self._ensure_connected()
        # The API path drops the slash: "x/" named the FILE x.
        refuse_folder_path(dst, "rename to", source_is_file=lambda: not self.stat(src).is_dir)
        try:
            dbx.files_move_v2(self._api_path(src), self._api_path(dst))
        except OSError as exc:
            raise _sdk_error(exc, f"Cannot rename {src} -> {dst}: {cloud_http.reason(exc)}", None) from exc

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    def open_read(self, path: str) -> IO[bytes]:
        dbx = self._ensure_connected()
        api_path = self._api_path(path)
        try:
            _metadata, response = dbx.files_download(api_path)
        except OSError as exc:
            raise _sdk_error(exc, f"Cannot read {path}: {cloud_http.reason(exc)}", path) from exc
        # The SDK streams a download: spooled, not one bytes object in RAM.
        return spool_response(response, what=f"Cannot read {path}")

    # See core/s3_client.py for the rationale on the cap.
    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        dbx = self._ensure_connected()
        # The API path drops the slash: "x/" was written as the FILE x.
        api_path = self._api_path(refuse_folder_path(path))
        if append:
            cap = self._MAX_APPEND_EXISTING_SIZE
            existing = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="Dropbox",
                logger=log,
            )
            if len(existing) > cap:
                raise OSError(
                    errno.EFBIG,
                    f"Dropbox append: existing file exceeds {cap // (1024 * 1024)} MiB cap"
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
        raise OSError(errno.ENOTSUP, "Dropbox does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError(errno.ENOTSUP, "Dropbox does not support symlinks")

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
            resp = dbx.files_list_revisions(self._api_path(path), limit=100)
        except Exception as exc:
            log.warning("Dropbox list_versions(%s) failed: %s", path, exc)
            return []
        out: list = []
        entries = list(resp.entries or [])
        # Newest first: Dropbox returns newest first already in recent SDKs,
        # but sort defensively.
        entries.sort(
            key=lambda e: getattr(e, "server_modified", None) or datetime.min, reverse=True
        )
        for i, e in enumerate(entries):
            out.append(
                FileVersion(
                    version_id=e.rev,
                    modified=getattr(e, "server_modified", None) or datetime.now(),
                    size=int(getattr(e, "size", 0) or 0),
                    is_current=(i == 0),
                    label=f"dropbox:{e.rev}",
                )
            )
        return out

    def open_version_read(self, path: str, version_id: str):
        """Download a historical revision as a spooled stream."""
        dbx = self._ensure_connected()
        try:
            md, resp = dbx.files_download(self._api_path(path), rev=version_id)
            return spool_response(resp, what=f"Cannot read {path}@{version_id}")
        except Exception as exc:
            raise _sdk_error(exc, f"Dropbox open_version_read failed: {cloud_http.reason(exc)}", path) from exc

    def copy(self, src: str, dst: str) -> None:
        """Dropbox files_copy_v2 — server-side."""
        dbx = self._ensure_connected()
        refuse_folder_path(dst, "copy to", source_is_file=lambda: not self.stat(src).is_dir)
        try:
            dbx.files_copy_v2(self._api_path(src), self._api_path(dst))
        except OSError as exc:
            # A taken name is FileExistsError (to/conflict): server_side_copy
            # then replaces it through a backup when asked to overwrite.
            raise _sdk_error(
                exc, f"Dropbox copy {src} -> {dst} failed: {cloud_http.reason(exc)}"
            ) from exc

    # ------------------------------------------------------------------
    # Dropbox-specific verbs (slice 5 of API_GAPS)
    # ------------------------------------------------------------------

    def shared_link_create(self, path: str, *, public: bool = True, short: bool = False) -> str:
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
            RequestedVisibility,
            SharedLinkSettings,
        )

        dbx = self._ensure_connected()
        norm = self._api_path(path)
        vis = RequestedVisibility.public if public else RequestedVisibility.team_only
        try:
            link = dbx.sharing_create_shared_link_with_settings(
                norm,
                settings=SharedLinkSettings(requested_visibility=vis),
            )
            url = getattr(link, "url", "") or ""
            # The path, never the link: a public link opens the file for
            # whoever reads the log.
            log.info(
                "Dropbox shared_link_create: %s (visibility=%s)",
                path,
                "public" if public else "team_only",
            )
            return url
        except (OSError, ApiError) as exc:  # _GuardedDropbox: the ApiError is the cause
            err_text = f"{exc} {exc.__cause__!r}"
            # If a link already exists, look it up + return that one.
            if "shared_link_already_exists" in err_text:
                existing = dbx.sharing_list_shared_links(
                    path=norm,
                    direct_only=True,
                )
                if existing.links:
                    log.info("Dropbox shared_link_create: %s (re-using existing)", path)
                    return existing.links[0].url
            raise _sdk_error(exc, f"Dropbox shared_link_create({path}): {cloud_http.reason(exc)}", path) from exc

    def shared_link_revoke(self, url: str) -> None:
        """Revoke a previously-issued shared link by URL."""
        dbx = self._ensure_connected()
        try:
            dbx.sharing_revoke_shared_link(url)
        except Exception as exc:  # noqa: BLE001
            raise _sdk_error(exc, f"Dropbox shared_link_revoke: {cloud_http.reason(exc)}") from exc

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
                "allocated",
                0,
            )
            if hasattr(usage.allocation, "get_individual")
            else 0,
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
            meta = dbx.files_get_metadata(self._api_path(path))
        except Exception as exc:
            raise _sdk_error(exc, f"Cannot stat {path}: {cloud_http.reason(exc)}", path) from exc
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
            modified = entry.server_modified
            if modified is None:
                modified = datetime.fromtimestamp(0)
            elif modified.tzinfo is None:
                # The SDK parses "...Z" into a naive datetime: it is UTC,
                # and FileItem reads a naive value as local time.
                modified = modified.replace(tzinfo=timezone.utc)
            return FileItem(
                name=entry.name,
                size=entry.size or 0,
                modified=modified,
            )
        # Unknown entry type – return minimal item
        return FileItem(name=getattr(entry, "name", "unknown"))
