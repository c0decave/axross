"""Google Drive backend implementing the FileBackend protocol.

Requires: pip install axross[gdrive]  (google-api-python-client, google-auth-oauthlib, google-auth-httplib2)

Uses OAuth2 browser redirect flow for authentication. Tokens are cached
locally so the user only needs to authorise once.
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
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
except ImportError:
    Credentials = None  # type: ignore[assignment,misc]

_SCOPES = ["https://www.googleapis.com/auth/drive"]
_FOLDER_MIME = "application/vnd.google-apps.folder"
_FILE_FIELDS = "files(id,name,mimeType,size,modifiedTime)"


class _SpooledWriter:
    """Write to a temp buffer, then upload to Google Drive on close."""

    def __init__(self, service, file_name: str, parent_id: str,
                 existing_id: str | None = None):
        self._service = service
        self._file_name = file_name
        self._parent_id = parent_id
        self._existing_id = existing_id
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
        media = MediaIoBaseUpload(self._buf, mimetype="application/octet-stream",
                                  resumable=True)
        try:
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

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class GDriveSession:
    """Google Drive backend implementing the FileBackend protocol.

    Uses the Google Drive v3 API with OAuth2. Paths are mapped to Drive
    file IDs internally via ``_resolve_path``, with a cache to avoid
    repeated lookups.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_file: str = "~/.config/axross/gdrive_token.json",
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
        self._path_cache: dict[str, str] = {"/": "root"}
        self._service = None

        self._authenticate()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _authenticate(self) -> None:
        """Load cached credentials or run the OAuth2 browser flow."""
        creds: Credentials | None = None

        if os.path.exists(self._token_file):
            try:
                creds = Credentials.from_authorized_user_file(self._token_file, _SCOPES)
            except Exception as exc:
                log.warning(
                    "Google Drive: failed to load cached token from %s (%s: %s); "
                    "restarting OAuth flow",
                    self._token_file, type(exc).__name__, exc,
                )
                creds = None

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                log.debug("Google Drive: access token refreshed")
            except Exception as exc:
                log.warning(
                    "Google Drive: token refresh failed (%s: %s); "
                    "restarting OAuth flow",
                    type(exc).__name__, exc,
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
            creds = flow.run_local_server(port=0)

            # Persist token for reuse (atomic, 0o600)
            try:
                write_secret_file(self._token_file, creds.to_json())
                log.info("OAuth2 token saved to %s", self._token_file)
            except OSError as exc:
                log.error("Google Drive: failed to save token to %s: %s",
                          self._token_file, exc)

        self._service = build("drive", "v3", credentials=creds)
        log.info("Google Drive connected")

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

            query = (
                f"'{current_id}' in parents "
                f"and name = '{self._escape_query(part)}' "
                f"and trashed = false"
            )
            try:
                resp = self._service.files().list(
                    q=query,
                    fields="files(id,name,mimeType)",
                    pageSize=1,
                ).execute()
            except Exception as e:
                raise OSError(f"Cannot resolve path '{path}': {e}") from e

            files = resp.get("files", [])
            if not files:
                raise FileNotFoundError(f"Not found: {path}")

            current_id = files[0]["id"]
            self._path_cache[current_path] = current_id

        return current_id

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

    def _get_metadata(self, file_id: str) -> dict:
        """Fetch metadata for a single file ID."""
        try:
            return self._service.files().get(
                fileId=file_id,
                fields="id,name,mimeType,size,modifiedTime",
            ).execute()
        except Exception as e:
            raise OSError(f"Cannot get metadata for {file_id}: {e}") from e

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
        self._service = None

    def disconnect(self) -> None:
        self.close()

    def list_dir(self, path: str) -> list[FileItem]:
        folder_id = self._resolve_path(path)

        items: list[FileItem] = []
        page_token: str | None = None

        while True:
            try:
                resp = self._service.files().list(
                    q=f"'{folder_id}' in parents and trashed = false",
                    fields=f"nextPageToken,{_FILE_FIELDS}",
                    pageSize=1000,
                    pageToken=page_token,
                ).execute()
            except Exception as e:
                raise OSError(f"Cannot list {path}: {e}") from e

            for f in resp.get("files", []):
                is_dir = f.get("mimeType") == _FOLDER_MIME
                size = int(f.get("size", 0)) if not is_dir else 0
                modified = self._parse_time(f.get("modifiedTime", ""))
                items.append(FileItem(
                    name=f["name"],
                    size=size,
                    modified=modified,
                    is_dir=is_dir,
                ))

                # Cache the child path for future lookups
                child_path = posixpath.join(self.normalize(path), f["name"])
                self._path_cache[child_path] = f["id"]

            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        return items

    def stat(self, path: str) -> FileItem:
        file_id = self._resolve_path(path)
        meta = self._get_metadata(file_id)
        is_dir = meta.get("mimeType") == _FOLDER_MIME
        size = int(meta.get("size", 0)) if not is_dir else 0
        modified = self._parse_time(meta.get("modifiedTime", ""))
        name = meta.get("name", posixpath.basename(path.rstrip("/")) or "/")
        return FileItem(name=name, size=size, modified=modified, is_dir=is_dir)

    def is_dir(self, path: str) -> bool:
        try:
            file_id = self._resolve_path(path)
            meta = self._get_metadata(file_id)
            return meta.get("mimeType") == _FOLDER_MIME
        except (OSError, FileNotFoundError):
            return False

    def exists(self, path: str) -> bool:
        try:
            self._resolve_path(path)
            return True
        except (OSError, FileNotFoundError):
            return False

    def mkdir(self, path: str) -> None:
        path = self.normalize(path)
        parent_path = self.parent(path)
        dir_name = posixpath.basename(path)
        parent_id = self._resolve_path(parent_path)

        body = {
            "name": dir_name,
            "mimeType": _FOLDER_MIME,
            "parents": [parent_id],
        }
        try:
            result = self._service.files().create(
                body=body,
                fields="id",
            ).execute()
        except Exception as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

        self._path_cache[path] = result["id"]
        log.info("Created directory: %s", path)

    def remove(self, path: str, recursive: bool = False) -> None:
        file_id = self._resolve_path(path)
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

        new_name = posixpath.basename(dst)
        src_parent = self.parent(src)
        dst_parent = self.parent(dst)

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
            request = self._service.files().get_media(fileId=file_id)
            buf = io.BytesIO()
            downloader = MediaIoBaseDownload(buf, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            buf.seek(0)
            return buf
        except Exception as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = self.normalize(path)
        parent_path = self.parent(path)
        file_name = posixpath.basename(path)
        parent_id = self._resolve_path(parent_path)

        # Check if file already exists (for update vs create)
        existing_id: str | None = None
        try:
            existing_id = self._resolve_path(path)
        except (OSError, FileNotFoundError):
            pass

        writer = _SpooledWriter(self._service, file_name, parent_id,
                                existing_id=existing_id)

        if append and existing_id:
            try:
                handle = self.open_read(path)
                data = handle.read()
                handle.close()
                writer.write(data)
            except OSError:
                pass

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
        try:
            file_id = self._resolve_path(path)
            resp = self._service.revisions().list(
                fileId=file_id,
                fields="revisions(id,modifiedTime,size,keepForever)",
                pageSize=200,
            ).execute()
        except Exception as exc:
            log.warning("GDrive list_versions(%s) failed: %s", path, exc)
            return []
        revs = list(resp.get("revisions") or [])
        # Parse modifiedTime; sort newest first.
        def _ts(r):
            s = r.get("modifiedTime") or ""
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except Exception:
                return datetime.min
        revs.sort(key=_ts, reverse=True)
        out: list = []
        for i, r in enumerate(revs):
            out.append(FileVersion(
                version_id=r.get("id") or "",
                modified=_ts(r),
                size=int(r.get("size") or 0),
                is_current=(i == 0),
                label=f"gdrive-rev:{r.get('id','')}",
            ))
        return out

    def open_version_read(self, path: str, version_id: str):
        """Fetch a historical revision via revisions().get_media."""
        try:
            file_id = self._resolve_path(path)
            req = self._service.revisions().get_media(
                fileId=file_id, revisionId=version_id,
            )
            buf = io.BytesIO()
            from googleapiclient.http import MediaIoBaseDownload
            downloader = MediaIoBaseDownload(buf, req)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            buf.seek(0)
            return buf
        except Exception as exc:
            raise OSError(f"GDrive open_version_read failed: {exc}") from exc

    def copy(self, src: str, dst: str) -> None:
        """Drive files.copy — server-side."""
        try:
            src_id = self._resolve_path(src)
            dst_parent = self._resolve_path(self.parent(dst))
            dst_name = posixpath.basename(dst.rstrip("/"))
            self._service.files().copy(
                fileId=src_id,
                body={"name": dst_name, "parents": [dst_parent]},
            ).execute()
        except Exception as exc:
            raise OSError(f"Drive copy {src} -> {dst} failed: {exc}") from exc

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
            meta = self._service.files().get(
                fileId=fid,
                fields=f"{field},md5Checksum",
            ).execute()
        except Exception as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        val = meta.get(field) or meta.get("md5Checksum")
        if not val:
            return ""
        actual_algo = algorithm if field != "md5Checksum" or algorithm == "md5" else "md5"
        return f"{actual_algo}:{val}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_time(timestamp: str) -> datetime:
        """Parse an RFC 3339 timestamp from the Drive API."""
        if not timestamp:
            return datetime.fromtimestamp(0)
        try:
            # Strip trailing 'Z' and parse
            clean = timestamp.rstrip("Z")
            return datetime.fromisoformat(clean)
        except (ValueError, TypeError):
            return datetime.fromtimestamp(0)
