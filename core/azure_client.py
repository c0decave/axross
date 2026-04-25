"""Azure Blob Storage and Azure Files backends implementing the FileBackend protocol.

Requires:
  pip install azure-storage-blob    (for AzureBlobSession)
  pip install azure-storage-file-share  (for AzureFilesSession)
"""
from __future__ import annotations

import io
import logging
import posixpath
import tempfile
import time
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    from azure.storage.blob import BlobServiceClient, ContainerClient
except ImportError:
    BlobServiceClient = None  # type: ignore[assignment,misc]
    ContainerClient = None  # type: ignore[assignment,misc]

try:
    from azure.storage.fileshare import ShareServiceClient, ShareDirectoryClient
except ImportError:
    ShareServiceClient = None  # type: ignore[assignment,misc]
    ShareDirectoryClient = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# _SpooledWriter helpers
# ---------------------------------------------------------------------------

class _BlobSpooledWriter:
    """Write to a temp file, then upload to Azure Blob on close."""

    def __init__(self, blob_client):
        self._blob_client = blob_client
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
        self._blob_client.upload_blob(self._buf, overwrite=True)
        self._buf.close()

    def discard(self) -> None:
        """Drop buffered bytes without uploading (transfer cancel path)."""
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _ShareSpooledWriter:
    """Write to a temp file, then upload to Azure Files share on close."""

    def __init__(self, file_client):
        self._file_client = file_client
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
        self._file_client.upload_file(data)
        self._buf.close()

    def discard(self) -> None:
        """Drop buffered bytes without uploading (transfer cancel path)."""
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# AzureBlobSession
# ---------------------------------------------------------------------------

class AzureBlobSession:
    """Azure Blob Storage backend implementing the FileBackend protocol.

    Uses BlobServiceClient from azure-storage-blob.  Treats the container
    as the root filesystem with virtual directory structure via prefixes.
    Paths are POSIX-style: /prefix/key.
    """

    def __init__(
        self,
        connection_string: str = "",
        account_name: str = "",
        account_key: str = "",
        container: str = "",
        sas_token: str = "",
    ):
        if BlobServiceClient is None:
            raise ImportError(
                "Azure Blob support requires azure-storage-blob. "
                "Install with: pip install azure-storage-blob"
            )

        self._container_name = container

        # Replace azure-sdk's verbose User-Agent (which includes glibc
        # version and Python build info) with a neutral browser UA.
        # See docs/OPSEC.md #4.
        from core.client_identity import HTTP_USER_AGENT
        ua_kwargs = {"user_agent": HTTP_USER_AGENT, "user_agent_overwrite": True}

        if connection_string:
            self._service = BlobServiceClient.from_connection_string(
                connection_string, **ua_kwargs,
            )
        elif account_name and sas_token:
            account_url = f"https://{account_name}.blob.core.windows.net"
            self._service = BlobServiceClient(
                account_url=account_url, credential=sas_token, **ua_kwargs,
            )
        elif account_name and account_key:
            account_url = f"https://{account_name}.blob.core.windows.net"
            self._service = BlobServiceClient(
                account_url=account_url,
                credential={"account_name": account_name, "account_key": account_key},
                **ua_kwargs,
            )
        else:
            raise ValueError(
                "Provide connection_string, or account_name with account_key or sas_token"
            )

        try:
            self._container = self._service.get_container_client(container)
            self._container.get_container_properties()
        except Exception as e:
            raise OSError(f"Cannot access Azure Blob container '{container}': {e}") from e

        log.info("Azure Blob connected: container=%s, account=%s", container, account_name)

    # -- properties ----------------------------------------------------------

    @property
    def name(self) -> str:
        return f"azure-blob://{self._container_name} (Azure Blob)"

    @property
    def connected(self) -> bool:
        try:
            self._container.get_container_properties()
            return True
        except Exception:
            return False

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        try:
            self._service.close()
        except Exception:
            pass

    def disconnect(self) -> None:
        self.close()

    # -- listing / stat ------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        prefix = self._to_prefix(path)
        items: list[FileItem] = []

        try:
            for item in self._container.walk_blobs(
                name_starts_with=prefix, delimiter="/"
            ):
                # item can be BlobPrefix (virtual dir) or BlobProperties (file)
                if hasattr(item, "prefix"):
                    # Virtual directory
                    dir_name = item.prefix[len(prefix):].rstrip("/")
                    if dir_name:
                        items.append(FileItem(name=dir_name, is_dir=True))
                else:
                    blob_name = item.name[len(prefix):]
                    if not blob_name or blob_name.endswith("/"):
                        continue  # directory marker or prefix itself
                    modified = item.last_modified or datetime.fromtimestamp(0)
                    if hasattr(modified, "replace"):
                        modified = modified.replace(tzinfo=None)
                    items.append(FileItem(
                        name=blob_name,
                        size=item.size or 0,
                        modified=modified,
                    ))
        except Exception as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        return items

    def stat(self, path: str) -> FileItem:
        key = self._to_key(path)
        name = posixpath.basename(path.rstrip("/")) or path

        if not key or key.endswith("/"):
            return FileItem(name=name, is_dir=True)

        # Try as blob
        try:
            blob_client = self._container.get_blob_client(key)
            props = blob_client.get_blob_properties()
            modified = props.last_modified or datetime.fromtimestamp(0)
            if hasattr(modified, "replace"):
                modified = modified.replace(tzinfo=None)
            return FileItem(
                name=name,
                size=props.size or 0,
                modified=modified,
            )
        except Exception:
            pass

        # Check as virtual directory
        prefix = key.rstrip("/") + "/"
        blobs = self._container.list_blobs(name_starts_with=prefix, results_per_page=1)
        page = next(blobs.by_page(), [])
        if list(page):
            return FileItem(name=name, is_dir=True)

        raise OSError(f"Not found: {path}")

    def is_dir(self, path: str) -> bool:
        key = self._to_key(path)
        if not key or key == "/":
            return True
        try:
            prefix = key.rstrip("/") + "/"
            blobs = self._container.list_blobs(name_starts_with=prefix, results_per_page=1)
            page = next(blobs.by_page(), [])
            return bool(list(page))
        except Exception:
            return False

    def exists(self, path: str) -> bool:
        key = self._to_key(path)
        if not key:
            return True

        try:
            blob_client = self._container.get_blob_client(key)
            blob_client.get_blob_properties()
            return True
        except Exception:
            pass

        return self.is_dir(path)

    # -- mutations -----------------------------------------------------------

    def mkdir(self, path: str) -> None:
        """Create a directory marker (zero-byte blob ending with /)."""
        key = self._to_key(path).rstrip("/") + "/"
        try:
            blob_client = self._container.get_blob_client(key)
            blob_client.upload_blob(b"", overwrite=True)
        except Exception as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        key = self._to_key(path)

        if self.is_dir(path):
            if not recursive:
                try:
                    blob_client = self._container.get_blob_client(key.rstrip("/") + "/")
                    blob_client.delete_blob()
                except Exception as e:
                    raise OSError(f"Cannot remove {path}: {e}") from e
            else:
                self._remove_prefix(key.rstrip("/") + "/")
        else:
            try:
                blob_client = self._container.get_blob_client(key)
                blob_client.delete_blob()
            except Exception as e:
                raise OSError(f"Cannot remove {path}: {e}") from e

    def _remove_prefix(self, prefix: str) -> None:
        """Delete all blobs under a prefix."""
        blobs = self._container.list_blobs(name_starts_with=prefix)
        for blob in blobs:
            self._container.delete_blob(blob.name)

    def rename(self, src: str, dst: str) -> None:
        """Azure Blob doesn't support rename -- copy + delete."""
        src_key = self._to_key(src)
        dst_key = self._to_key(dst)

        if self.is_dir(src):
            old_prefix = src_key.rstrip("/") + "/"
            new_prefix = dst_key.rstrip("/") + "/"
            blobs = self._container.list_blobs(name_starts_with=old_prefix)
            for blob in blobs:
                new_name = new_prefix + blob.name[len(old_prefix):]
                src_blob = self._container.get_blob_client(blob.name)
                dst_blob = self._container.get_blob_client(new_name)
                try:
                    dst_blob.start_copy_from_url(src_blob.url)
                    self._wait_for_copy(dst_blob)
                    src_blob.delete_blob()
                except Exception as e:
                    raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e
        else:
            try:
                src_blob = self._container.get_blob_client(src_key)
                dst_blob = self._container.get_blob_client(dst_key)
                dst_blob.start_copy_from_url(src_blob.url)
                self._wait_for_copy(dst_blob)
                src_blob.delete_blob()
            except Exception as e:
                raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    @staticmethod
    def _wait_for_copy(dst_blob, timeout: float = 300.0) -> None:
        """Poll the copy status until it completes or fails."""
        deadline = time.monotonic() + timeout
        while True:
            props = dst_blob.get_blob_properties()
            status = props.copy.status
            if status == "success":
                return
            if status in ("failed", "aborted"):
                raise OSError(
                    f"Blob copy failed with status '{status}': "
                    f"{props.copy.status_description}"
                )
            if time.monotonic() > deadline:
                raise OSError(
                    f"Blob copy timed out after {timeout}s (status: {status})"
                )
            time.sleep(0.5)

    # -- read / write --------------------------------------------------------

    def open_read(self, path: str) -> IO[bytes]:
        key = self._to_key(path)
        try:
            blob_client = self._container.get_blob_client(key)
            stream = blob_client.download_blob()
            buf = io.BytesIO(stream.readall())
            buf.seek(0)
            return buf
        except Exception as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024  # see s3_client.py

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        key = self._to_key(path)
        blob_client = self._container.get_blob_client(key)
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
                    f"Azure Blob append: existing object exceeds "
                    f"{cap // (1024 * 1024)} MiB cap"
                )
            writer = _BlobSpooledWriter(blob_client)
            writer.write(existing)
            return writer
        return _BlobSpooledWriter(blob_client)

    # -- path helpers --------------------------------------------------------

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

    # -- unsupported ---------------------------------------------------------

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("Azure Blob Storage does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("Azure Blob Storage does not support symlinks")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        raise OSError("Azure Blob Storage does not support disk usage queries")

    def list_versions(self, path: str) -> list:
        """List blob versions if the container has versioning enabled."""
        from models.file_version import FileVersion
        from datetime import datetime as _dt
        key = self._to_key(path)
        out: list = []
        try:
            blobs = self._container.list_blobs(
                name_starts_with=key, include=["versions"],
            )
            entries = []
            for b in blobs:
                if b.name != key:
                    continue
                entries.append(b)
            def _ts(b):
                return getattr(b, "last_modified", None) or _dt.min
            entries.sort(key=_ts, reverse=True)
            for i, b in enumerate(entries):
                vid = getattr(b, "version_id", None) or ""
                is_cur = getattr(b, "is_current_version", None)
                if is_cur is None:
                    is_cur = (i == 0)
                out.append(FileVersion(
                    version_id=vid,
                    modified=_ts(b) if isinstance(_ts(b), _dt) else _dt.now(),
                    size=int(getattr(b, "size", 0) or 0),
                    is_current=bool(is_cur),
                    label=f"azure-ver:{vid}",
                ))
        except Exception as exc:
            log.warning("Azure list_versions(%s) failed: %s", path, exc)
            return []
        return out

    def open_version_read(self, path: str, version_id: str):
        """Download a specific blob version via version_id."""
        import io as _io
        key = self._to_key(path)
        try:
            blob = self._container.get_blob_client(key)
            stream = blob.download_blob(version_id=version_id)
            return _io.BytesIO(stream.readall())
        except Exception as exc:
            raise OSError(f"Azure open_version_read failed: {exc}") from exc

    def copy(self, src: str, dst: str) -> None:
        """Azure Blob Copy Blob — server-side."""
        try:
            src_blob = self._container.get_blob_client(self._to_key(src))
            dst_blob = self._container.get_blob_client(self._to_key(dst))
            dst_blob.start_copy_from_url(src_blob.url)
        except Exception as exc:
            raise OSError(f"Azure copy {src} -> {dst} failed: {exc}") from exc

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return Azure's Content-MD5 property (Base64-encoded in
        the wire format; we decode to hex)."""
        try:
            key = self._to_key(path)
            blob = self._container.get_blob_client(key)
            props = blob.get_blob_properties()
        except Exception as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        cs = getattr(props.content_settings, "content_md5", None)
        if not cs:
            return ""
        import binascii
        return "md5:" + binascii.hexlify(bytes(cs)).decode("ascii")

    # -- internal ------------------------------------------------------------

    def _to_key(self, path: str) -> str:
        """Convert a UI path to a blob key (no leading slash)."""
        return path.lstrip("/")

    def _to_prefix(self, path: str) -> str:
        """Convert a UI path to a blob prefix for listing."""
        key = path.lstrip("/")
        if key and not key.endswith("/"):
            key += "/"
        return key


# ---------------------------------------------------------------------------
# AzureFilesSession
# ---------------------------------------------------------------------------

class AzureFilesSession:
    """Azure Files backend implementing the FileBackend protocol.

    Uses ShareServiceClient from azure-storage-file-share.
    Azure Files has real directory structure (not virtual).
    """

    def __init__(
        self,
        connection_string: str = "",
        account_name: str = "",
        account_key: str = "",
        share_name: str = "",
        sas_token: str = "",
    ):
        if ShareServiceClient is None:
            raise ImportError(
                "Azure Files support requires azure-storage-file-share. "
                "Install with: pip install azure-storage-file-share"
            )

        self._share_name = share_name

        # Replace azure-sdk default UA — see docs/OPSEC.md #4.
        from core.client_identity import HTTP_USER_AGENT
        ua_kwargs = {"user_agent": HTTP_USER_AGENT, "user_agent_overwrite": True}

        if connection_string:
            self._service = ShareServiceClient.from_connection_string(
                connection_string, **ua_kwargs,
            )
        elif account_name and sas_token:
            account_url = f"https://{account_name}.file.core.windows.net"
            self._service = ShareServiceClient(
                account_url=account_url, credential=sas_token, **ua_kwargs,
            )
        elif account_name and account_key:
            account_url = f"https://{account_name}.file.core.windows.net"
            self._service = ShareServiceClient(
                account_url=account_url,
                credential={"account_name": account_name, "account_key": account_key},
                **ua_kwargs,
            )
        else:
            raise ValueError(
                "Provide connection_string, or account_name with account_key or sas_token"
            )

        try:
            self._share = self._service.get_share_client(share_name)
            self._share.get_share_properties()
        except Exception as e:
            raise OSError(f"Cannot access Azure Files share '{share_name}': {e}") from e

        log.info("Azure Files connected: share=%s, account=%s", share_name, account_name)

    # -- properties ----------------------------------------------------------

    @property
    def name(self) -> str:
        return f"azure-files://{self._share_name} (Azure Files)"

    @property
    def connected(self) -> bool:
        try:
            self._share.get_share_properties()
            return True
        except Exception:
            return False

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        try:
            self._service.close()
        except Exception:
            pass

    def disconnect(self) -> None:
        self.close()

    # -- listing / stat ------------------------------------------------------

    def _dir_client(self, path: str):
        """Return a ShareDirectoryClient for the given path."""
        dir_path = self._to_path(path)
        return self._share.get_directory_client(dir_path) if dir_path else self._share.get_directory_client("")

    def list_dir(self, path: str) -> list[FileItem]:
        dir_path = self._to_path(path)
        items: list[FileItem] = []

        try:
            dir_client = self._share.get_directory_client(dir_path)
            for item in dir_client.list_directories_and_files():
                if item.get("is_directory", False):
                    items.append(FileItem(
                        name=item["name"],
                        is_dir=True,
                    ))
                else:
                    last_modified = item.get("last_modified") or datetime.fromtimestamp(0)
                    if hasattr(last_modified, "replace"):
                        last_modified = last_modified.replace(tzinfo=None)
                    items.append(FileItem(
                        name=item["name"],
                        size=item.get("size", 0),
                        modified=last_modified,
                    ))
        except Exception as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        return items

    def stat(self, path: str) -> FileItem:
        rel = self._to_path(path)
        base_name = posixpath.basename(rel) or path

        if not rel:
            return FileItem(name="/", is_dir=True)

        # Try as file first
        parent_dir = posixpath.dirname(rel)
        try:
            file_client = self._share.get_directory_client(parent_dir).get_file_client(base_name)
            props = file_client.get_file_properties()
            modified = props.get("last_modified") or datetime.fromtimestamp(0)
            if hasattr(modified, "replace"):
                modified = modified.replace(tzinfo=None)
            return FileItem(
                name=base_name,
                size=props.get("size", 0) or props.get("content_length", 0),
                modified=modified,
            )
        except Exception:
            pass

        # Try as directory
        try:
            dir_client = self._share.get_directory_client(rel)
            props = dir_client.get_directory_properties()
            modified = props.get("last_modified") or datetime.fromtimestamp(0)
            if hasattr(modified, "replace"):
                modified = modified.replace(tzinfo=None)
            return FileItem(
                name=base_name,
                is_dir=True,
                modified=modified,
            )
        except Exception:
            pass

        raise OSError(f"Not found: {path}")

    def is_dir(self, path: str) -> bool:
        rel = self._to_path(path)
        if not rel:
            return True
        try:
            dir_client = self._share.get_directory_client(rel)
            dir_client.get_directory_properties()
            return True
        except Exception:
            return False

    def exists(self, path: str) -> bool:
        rel = self._to_path(path)
        if not rel:
            return True

        # Check as directory
        try:
            dir_client = self._share.get_directory_client(rel)
            dir_client.get_directory_properties()
            return True
        except Exception:
            pass

        # Check as file
        parent_dir = posixpath.dirname(rel)
        file_name = posixpath.basename(rel)
        try:
            file_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)
            file_client.get_file_properties()
            return True
        except Exception:
            return False

    # -- mutations -----------------------------------------------------------

    def mkdir(self, path: str) -> None:
        rel = self._to_path(path)
        try:
            dir_client = self._share.get_directory_client(rel)
            dir_client.create_directory()
            log.debug("Azure Files mkdir: %s", rel)
        except Exception as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        rel = self._to_path(path)

        if self.is_dir(path):
            if recursive:
                self._remove_dir_recursive(rel)
            else:
                try:
                    dir_client = self._share.get_directory_client(rel)
                    dir_client.delete_directory()
                except Exception as e:
                    raise OSError(f"Cannot remove {path}: {e}") from e
        else:
            parent_dir = posixpath.dirname(rel)
            file_name = posixpath.basename(rel)
            try:
                file_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)
                file_client.delete_file()
            except Exception as e:
                raise OSError(f"Cannot remove {path}: {e}") from e

    def _remove_dir_recursive(self, dir_path: str) -> None:
        """Recursively remove all files and subdirectories."""
        dir_client = self._share.get_directory_client(dir_path)
        for item in dir_client.list_directories_and_files():
            child_path = posixpath.join(dir_path, item["name"]) if dir_path else item["name"]
            if item.get("is_directory", False):
                self._remove_dir_recursive(child_path)
            else:
                file_client = dir_client.get_file_client(item["name"])
                file_client.delete_file()
        dir_client.delete_directory()

    def rename(self, src: str, dst: str) -> None:
        src_rel = self._to_path(src)
        dst_rel = self._to_path(dst)

        try:
            if self.is_dir(src):
                src_client = self._share.get_directory_client(src_rel)
                src_client.rename_directory(self._share_name + "/" + dst_rel)
            else:
                parent_dir = posixpath.dirname(src_rel)
                file_name = posixpath.basename(src_rel)
                src_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)
                src_client.rename_file(self._share_name + "/" + dst_rel)
        except Exception as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    # -- read / write --------------------------------------------------------

    def open_read(self, path: str) -> IO[bytes]:
        rel = self._to_path(path)
        parent_dir = posixpath.dirname(rel)
        file_name = posixpath.basename(rel)

        try:
            file_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)
            stream = file_client.download_file()
            buf = io.BytesIO(stream.readall())
            buf.seek(0)
            return buf
        except Exception as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        rel = self._to_path(path)
        parent_dir = posixpath.dirname(rel)
        file_name = posixpath.basename(rel)

        file_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)

        if append:
            cap = 256 * 1024 * 1024  # see s3_client.py for rationale
            try:
                handle = self.open_read(path)
                existing = handle.read(cap + 1)
                handle.close()
            except OSError:
                existing = b""
            if len(existing) > cap:
                raise OSError(
                    f"Azure Files append: existing file exceeds "
                    f"{cap // (1024 * 1024)} MiB cap"
                )
            writer = _ShareSpooledWriter(file_client)
            writer.write(existing)
            return writer
        return _ShareSpooledWriter(file_client)

    # -- path helpers --------------------------------------------------------

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

    # -- unsupported ---------------------------------------------------------

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("Azure Files does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("Azure Files does not support symlinks")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        raise OSError("Azure Files does not support disk usage queries")

    def copy(self, src: str, dst: str) -> None:
        """Azure Files start_copy_from_url between two paths in the share."""
        try:
            src_parent, src_name = self._split(src)
            dst_parent, dst_name = self._split(dst)
            src_file = (
                self._share.get_directory_client(src_parent)
                           .get_file_client(src_name)
            )
            dst_file = (
                self._share.get_directory_client(dst_parent)
                           .get_file_client(dst_name)
            )
            dst_file.start_copy_from_url(src_file.url)
        except Exception as exc:
            raise OSError(
                f"Azure Files copy {src} -> {dst} failed: {exc}"
            ) from exc

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        try:
            parent, name = self._split(path)
            file_client = (
                self._share.get_directory_client(parent).get_file_client(name)
            )
            props = file_client.get_file_properties()
        except Exception as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        cs = getattr(props.content_settings, "content_md5", None)
        if not cs:
            return ""
        import binascii
        return "md5:" + binascii.hexlify(bytes(cs)).decode("ascii")

    # -- internal ------------------------------------------------------------

    def _to_path(self, path: str) -> str:
        """Convert a UI path to a relative directory/file path (no leading slash)."""
        return path.strip("/")
