"""Azure Blob Storage and Azure Files backends implementing the FileBackend protocol.

Requires:
  pip install azure-storage-blob    (for AzureBlobSession)
  pip install azure-storage-file-share  (for AzureFilesSession)
"""

from __future__ import annotations

import errno
import logging
import posixpath
import tempfile
import time
from datetime import datetime
from typing import IO

from core.answer_fields import as_size
from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.path_policy import safe_leaf
from core.read_spool import spool_chunks
from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    from azure.storage.blob import BlobServiceClient, ContainerClient
except ImportError:
    BlobServiceClient = None  # type: ignore[assignment,misc]
    ContainerClient = None  # type: ignore[assignment,misc]

try:
    from azure.storage.fileshare import ShareDirectoryClient, ShareServiceClient
except ImportError:
    ShareServiceClient = None  # type: ignore[assignment,misc]
    ShareDirectoryClient = None  # type: ignore[assignment,misc]


def _is_folder_placeholder(metadata) -> bool:
    """True for the 0-byte blob a hierarchical-namespace (Data Lake)
    account keeps for every folder: metadata hdi_isfolder=true."""
    if not isinstance(metadata, dict):
        return False
    return str(metadata.get("hdi_isfolder", "")).strip().lower() == "true"


def _is_not_found(exc: BaseException) -> bool:
    """True for the SDK's "not found" answer (404: BlobNotFound,
    ResourceNotFound, ParentNotFound ...). Only that may mean "absent":
    a throttled, refused or dropped request says nothing about it."""
    try:
        from azure.core.exceptions import ResourceNotFoundError
    except ImportError:  # pragma: no cover - the SDK is required here
        return False
    return isinstance(exc, ResourceNotFoundError)


def _is_not_a_directory(exc: BaseException) -> bool:
    """A directory probe of an Azure Files path that is absent, or that is
    a file (ResourceTypeMismatch)."""
    code = getattr(exc, "error_code", None)
    return _is_not_found(exc) or getattr(code, "value", code) == "ResourceTypeMismatch"


def _each_page_once(paged, what: str):
    """The items of an SDK listing, page by page.

    The SDK follows the server's NextMarker as long as there is one; a
    marker it was already handed is a loop that never ends (and grows
    the listing without bound), so it fails instead.
    """
    if not hasattr(paged, "by_page"):  # a plain iterable has no markers
        yield from paged
        return
    pages = paged.by_page()
    seen: set[str] = set()
    for page in pages:
        yield from page
        token = pages.continuation_token
        if token:
            if token in seen:
                raise OSError(f"{what}: the server repeats a paging marker")
            seen.add(token)


def _spool_checked(stream, what: str) -> IO[bytes]:
    """The whole download as a spool, or OSError when it is not the size
    announced.

    The SDK fetches a blob in ranges and stitches whatever each range
    answer carried, without checking its length: a server answering
    short (or long) ranges produced a complete-looking, wrong file.
    The chunks go to a spooled file: ``readall()`` held the whole file
    in RAM.
    """
    expected = getattr(stream, "size", None)
    return spool_chunks(
        stream.chunks(),
        expected_size=expected if isinstance(expected, int) else None,
        what=what,
    )


def _axross_azure_transport_kwargs(
    proxy_type: str,
    proxy_host: str,
    proxy_port: int,
    proxy_username: str,
    proxy_password: str,
) -> dict:
    """Build the kwargs azure-sdk Service constructors need to route
    every HTTP call through a SOCKS / HTTP proxy.

    Returns a dict containing ``transport=...`` keyed to a
    ``RequestsTransport`` whose underlying ``requests.Session`` has
    the proxies dict pre-set (built via ``core.proxy.build_requests_proxies``).
    Returns ``{}`` when no proxy is configured.

    Why a custom transport: azure-sdk's pipeline uses its own
    HTTP transport abstraction; setting ``proxies`` on a stray
    requests.Session inside the SDK doesn't propagate. The
    RequestsTransport class accepts a pre-built ``session=`` so we
    can configure it before handing it over.
    """
    from core.proxy import build_requests_proxies

    proxies = build_requests_proxies(
        proxy_type,
        proxy_host,
        proxy_port,
        proxy_username,
        proxy_password,
    )
    if not proxies:
        return {}
    try:
        import requests as _requests
        from azure.core.pipeline.transport import RequestsTransport
    except ImportError as exc:
        raise OSError(
            "Azure proxy configured but requests/azure-core transport "
            "is unavailable; refusing to connect without the proxy"
        ) from exc
    sess = _requests.Session()
    from core.proxy import lock_requests_session_to_profile_proxy

    lock_requests_session_to_profile_proxy(sess, proxies)
    return {"transport": RequestsTransport(session=sess)}


# ---------------------------------------------------------------------------
# _SpooledWriter helpers
# ---------------------------------------------------------------------------


class _BlobSpooledWriter:
    """Write to a temp file, then upload to Azure Blob on close."""

    def __init__(self, blob_client):
        self._blob_client = blob_client
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
            self._blob_client.upload_blob(self._buf, overwrite=True)
        finally:
            self._buf.close()

    def discard(self) -> None:
        """Drop buffered bytes without uploading (transfer cancel path)."""
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


class _ShareSpooledWriter:
    """Write to a temp file, then upload to Azure Files share on close."""

    def __init__(self, file_client):
        self._file_client = file_client
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
            # The spool itself with its length: reading it into one bytes
            # object held the whole file in RAM.
            size = self._buf.seek(0, 2)
            self._buf.seek(0)
            self._file_client.upload_file(self._buf, length=size)
        finally:
            self._buf.close()

    def discard(self) -> None:
        """Drop buffered bytes without uploading (transfer cancel path)."""
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


# ---------------------------------------------------------------------------
# AzureBlobSession
# ---------------------------------------------------------------------------


def _wait_for_copy(get_properties, timeout: float = 300.0) -> None:
    """Poll a server-side copy (``get_properties().copy.status``) until
    it completes; failed, aborted or still pending at *timeout* is an
    OSError."""
    deadline = time.monotonic() + timeout
    while True:
        props = get_properties()
        status = props.copy.status
        if status == "success":
            return
        if status in ("failed", "aborted"):
            raise OSError(f"Copy failed with status '{status}': {props.copy.status_description}")
        if time.monotonic() > deadline:
            raise OSError(f"Copy timed out after {timeout}s (status: {status})")
        time.sleep(0.5)


class AzureBlobSession(SessionLifecycle):
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
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if BlobServiceClient is None:
            raise ImportError(
                "Azure Blob support requires azure-storage-blob. "
                "Install with: pip install azure-storage-blob"
            )

        self._container_name = container

        # Replace azure-sdk's verbose User-Agent (which includes glibc
        # version and Python build info) with a neutral browser UA.
        # See docs/OPSEC.md #4. Per-profile proxy goes via a custom
        # RequestsTransport whose underlying requests.Session has the
        # proxies dict pre-set; azure's pipeline then routes every
        # request through it.
        from core.client_identity import HTTP_USER_AGENT

        ua_kwargs = {"user_agent": HTTP_USER_AGENT, "user_agent_overwrite": True}
        ua_kwargs.update(
            _axross_azure_transport_kwargs(
                proxy_type,
                proxy_host,
                int(proxy_port or 0),
                proxy_username,
                proxy_password,
            )
        )

        # Stash the account-key locally so sas_url() (which signs
        # SAS tokens client-side with the symmetric key) can reach
        # it without re-prompting. None when token-based auth is in
        # use; sas_url raises a structured OSError in that case.
        self._account_key = account_key or ""
        if connection_string:
            self._service = BlobServiceClient.from_connection_string(
                connection_string,
                **ua_kwargs,
            )
            # Pull the account key out of the connection string for
            # sas_url; the SDK exposes it on the client as
            # ``credential.account_key`` after parsing.
            try:
                self._account_key = self._service.credential.account_key or ""
            except AttributeError:
                pass
        elif account_name and sas_token:
            account_url = f"https://{account_name}.blob.core.windows.net"
            self._service = BlobServiceClient(
                account_url=account_url,
                credential=sas_token,
                **ua_kwargs,
            )
        elif account_name and account_key:
            account_url = f"https://{account_name}.blob.core.windows.net"
            self._service = BlobServiceClient(
                account_url=account_url,
                credential={"account_name": account_name, "account_key": account_key},
                **ua_kwargs,
            )
        elif account_name:
            # No key and no SAS: anonymous read of a public container
            # (Microsoft's Open Datasets, any container whose access level
            # allows it). A private container answers the first request
            # with an authorisation error.
            self._service = BlobServiceClient(
                account_url=f"https://{account_name}.blob.core.windows.net",
                credential=None,
                **ua_kwargs,
            )
        else:
            raise ValueError(
                "Provide connection_string, or account_name (with account_key or "
                "sas_token, or neither for a public container)"
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
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("Azure Blob liveness check of %s failed: %s", self._container_name, exc)
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
        folders: set[str] = set()

        def add_folder(name: str) -> None:
            # A hierarchical-namespace folder comes twice: as the prefix
            # "name/" and as its placeholder blob "name".
            if name and name not in folders:
                folders.add(name)
                items.append(FileItem(name=name, is_dir=True))

        try:
            for item in _each_page_once(
                self._container.walk_blobs(
                    name_starts_with=prefix, delimiter="/", include=["metadata"]
                ),
                f"Cannot list {path}",
            ):
                # item can be BlobPrefix (virtual dir) or BlobProperties (file)
                if hasattr(item, "prefix"):
                    add_folder(item.prefix[len(prefix) :].rstrip("/"))
                else:
                    blob_name = item.name[len(prefix) :]
                    if not blob_name or blob_name.endswith("/"):
                        continue  # directory marker or prefix itself
                    if _is_folder_placeholder(getattr(item, "metadata", None)):
                        add_folder(blob_name)
                        continue
                    # Aware UTC from the SDK; FileItem converts it.
                    modified = item.last_modified or datetime.fromtimestamp(0)
                    items.append(
                        FileItem(
                            name=blob_name,
                            size=as_size(item.size),
                            modified=modified,
                        )
                    )
        except Exception as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        return items

    def stat(self, path: str) -> FileItem:
        key = self._to_key(path)
        name = posixpath.basename(path.rstrip("/")) or path

        if not key or key.endswith("/"):
            return FileItem(name=name, is_dir=True)

        # Try as blob. Only "not found" moves on to the folder check: a
        # throttled or dropped probe of a file "x" beside blobs under "x/"
        # would otherwise call the file a folder.
        try:
            props = self._container.get_blob_client(key).get_blob_properties()
        except Exception as e:
            if not _is_not_found(e):
                raise OSError(f"Cannot stat {path}: {e}") from e
        else:
            modified = props.last_modified or datetime.fromtimestamp(0)
            if _is_folder_placeholder(getattr(props, "metadata", None)):
                return FileItem(name=name, is_dir=True, modified=modified)
            return FileItem(
                name=name,
                size=as_size(props.size),
                modified=modified,
            )

        # Check as virtual directory
        prefix = key.rstrip("/") + "/"
        try:
            blobs = self._container.list_blobs(name_starts_with=prefix, results_per_page=1)
            page = next(blobs.by_page(), [])
            if list(page):
                return FileItem(name=name, is_dir=True)
        except Exception as e:
            raise OSError(f"Cannot stat {path}: {e}") from e

        raise FileNotFoundError(errno.ENOENT, "Not found", path)

    def is_dir(self, path: str) -> bool:
        """True for a prefix with blobs under it or a Data Lake folder
        placeholder. A request that fails other than "not found" is an
        OSError: remove() and rename() pick their action from this."""
        key = self._to_key(path)
        if not key or key == "/":
            return True
        try:
            prefix = key.rstrip("/") + "/"
            blobs = self._container.list_blobs(name_starts_with=prefix, results_per_page=1)
            page = next(blobs.by_page(), [])
            if list(page):
                return True
        except Exception as e:
            raise OSError(f"Cannot check {path}: {e}") from e
        # An empty Data Lake folder is only its placeholder blob.
        try:
            props = self._container.get_blob_client(key.rstrip("/")).get_blob_properties()
        except Exception as e:
            if _is_not_found(e):
                return False
            raise OSError(f"Cannot check {path}: {e}") from e
        return _is_folder_placeholder(getattr(props, "metadata", None))

    def exists(self, path: str) -> bool:
        """Only "not found" means False; any other failure is an OSError
        (server_side_copy(overwrite=False) takes False as its go-ahead)."""
        key = self._to_key(path)
        if not key:
            return True

        try:
            blob_client = self._container.get_blob_client(key)
            blob_client.get_blob_properties()
            return True
        except Exception as e:
            if not _is_not_found(e):
                raise OSError(f"Cannot check {path}: {e}") from e

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
            prefix = key.rstrip("/") + "/"
            # "file": a blob "X" beside the prefix "X/"; "folder": the Data
            # Lake placeholder blob "X" that IS the folder (hierarchical
            # namespace); None: only the flat-account marker "X/".
            kind = self._blob_at(key.rstrip("/"), path)
            if not recursive:
                # The file beside the folder is what a non-recursive remove
                # means; the folder only when nothing is under its prefix.
                if kind == "file":
                    target = key
                else:
                    self._refuse_non_empty(prefix, path)
                    target = key.rstrip("/") if kind == "folder" else prefix
                try:
                    blob_client = self._container.get_blob_client(target)
                    blob_client.delete_blob()
                except Exception as e:
                    raise OSError(f"Cannot remove {path}: {e}") from e
            else:
                try:
                    self._remove_prefix(prefix)
                    if kind == "folder":
                        # Last: the placeholder is the folder itself.
                        self._container.get_blob_client(key.rstrip("/")).delete_blob()
                except OSError:
                    raise
                except Exception as e:
                    raise OSError(f"Cannot remove {path}: {e}") from e
        else:
            try:
                blob_client = self._container.get_blob_client(key)
                blob_client.delete_blob()
            except Exception as e:
                raise OSError(f"Cannot remove {path}: {e}") from e

    def _refuse_non_empty(self, prefix: str, path: str) -> None:
        """ENOTEMPTY when any blob besides the folder marker *prefix* lies
        under it: deleting the marker alone would report a removed folder
        whose files are all still there."""
        try:
            pages = self._container.list_blobs(name_starts_with=prefix, results_per_page=2)
            page = list(next(pages.by_page(), []))
        except Exception as e:
            raise OSError(f"Cannot remove {path}: {e}") from e
        if any(getattr(blob, "name", None) != prefix for blob in page):
            raise OSError(errno.ENOTEMPTY, f"Directory not empty: {path}", path)

    def _blob_at(self, key: str, path: str) -> str | None:
        """What the blob named exactly *key* is: ``"file"``, ``"folder"``
        (a Data Lake placeholder, metadata hdi_isfolder=true) or None when
        there is none. An error other than not-found is an OSError."""
        if not key or key.endswith("/"):
            return None
        try:
            props = self._container.get_blob_client(key).get_blob_properties()
        except Exception as e:
            if _is_not_found(e):
                return None
            raise OSError(f"Cannot check {path}: {e}") from e
        return "folder" if _is_folder_placeholder(getattr(props, "metadata", None)) else "file"

    # Blob Batch: at most 256 sub-requests per batch request.
    _DELETE_BATCH = 256

    def _remove_prefix(self, prefix: str) -> None:
        """Delete all blobs under a prefix, up to 256 per request."""
        chunk: list[str] = []
        for blob in _each_page_once(
            self._container.list_blobs(name_starts_with=prefix), f"Cannot list {prefix}"
        ):
            chunk.append(blob.name)
            if len(chunk) == self._DELETE_BATCH:
                self._delete_chunk(chunk)
                chunk = []
        if chunk:
            self._delete_chunk(chunk)

    def _delete_chunk(self, names: list[str]) -> None:
        from azure.storage.blob import PartialBatchErrorException

        try:
            self._container.delete_blobs(*names)
        except PartialBatchErrorException as exc:
            # Some sub-requests failed - or the whole batch was refused in
            # the shape of one: Azurite answers ANY batch with a single
            # "400 InvalidInput" part. The blobs whose part failed (all of
            # them when the parts cannot be matched to the requests) are
            # deleted one by one; a blob that fails alone too raises.
            parts = list(getattr(exc, "parts", None) or [])
            if len(parts) == len(names):
                retry = [
                    name
                    for name, part in zip(names, parts)
                    if not 200 <= int(getattr(part, "status_code", 0) or 0) < 300
                ]
            else:
                retry = list(names)
            log.debug(
                "Azure batch delete: %d of %d blob(s) not deleted (%s); deleting them one by one",
                len(retry),
                len(names),
                exc,
            )
            for name in retry:
                self._container.delete_blob(name)
        except Exception as exc:  # noqa: BLE001
            # The batch call itself was refused (no batch support on this
            # account / emulator): delete one by one, as before.
            log.debug("Azure batch delete unavailable (%s); deleting one by one", exc)
            for name in names:
                self._container.delete_blob(name)

    def rename(self, src: str, dst: str) -> None:
        """Azure Blob doesn't support rename -- copy + delete."""
        src_key = self._to_key(src)
        dst_key = self._to_key(dst)

        src_is_dir = self.is_dir(src)
        # Copy + delete onto an existing folder merged into it (namesakes
        # replaced, the source deleted) or put a file beside it that hid it.
        if self.is_dir(dst):
            raise IsADirectoryError(
                errno.EISDIR, f"Cannot rename {src} -> {dst}: the destination is a folder", dst
            )
        if src_is_dir and self.exists(dst):
            raise FileExistsError(
                errno.EEXIST, f"Cannot rename the folder {src} over the file {dst}", dst
            )

        if src_is_dir:
            kind = self._blob_at(src_key, src)
            if kind == "file":
                # Moving the folder tree would leave the file behind and
                # moving the file would not be what a folder rename means.
                raise OSError(
                    f"Cannot rename {src}: both a file and a folder are named "
                    f"{posixpath.basename(src_key)!r} here; the name does not say which one"
                )
            if kind == "folder":
                # A Data Lake folder IS its placeholder blob: first the new
                # one (Copy Blob carries the hdi_isfolder metadata), so a
                # failure moves nothing; the old one goes last, as remove()
                # deletes it after the folder's contents.
                try:
                    placeholder = self._container.get_blob_client(dst_key.rstrip("/"))
                    placeholder.start_copy_from_url(
                        self._container.get_blob_client(src_key).url
                    )
                    self._wait_for_copy(placeholder)
                except Exception as e:
                    raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e
            old_prefix = src_key.rstrip("/") + "/"
            new_prefix = dst_key.rstrip("/") + "/"
            try:
                blobs = list(
                    _each_page_once(
                        self._container.list_blobs(name_starts_with=old_prefix),
                        f"Cannot rename {src} -> {dst}",
                    )
                )
            except OSError:
                raise
            except Exception as e:
                raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e
            for blob in blobs:
                new_name = new_prefix + blob.name[len(old_prefix) :]
                src_blob = self._container.get_blob_client(blob.name)
                dst_blob = self._container.get_blob_client(new_name)
                try:
                    dst_blob.start_copy_from_url(src_blob.url)
                    self._wait_for_copy(dst_blob)
                    src_blob.delete_blob()
                except Exception as e:
                    raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e
            if kind == "folder":
                try:
                    self._container.get_blob_client(src_key).delete_blob()
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
        _wait_for_copy(dst_blob.get_blob_properties, timeout)

    # -- read / write --------------------------------------------------------

    def open_read(self, path: str) -> IO[bytes]:
        key = self._to_key(path)
        try:
            blob_client = self._container.get_blob_client(key)
            stream = blob_client.download_blob()
            return _spool_checked(stream, f"Cannot read {path}")
        except OSError:
            raise
        except Exception as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024  # see s3_client.py

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        key = self._to_key(path)
        blob_client = self._container.get_blob_client(key)
        if append:
            cap = self._MAX_APPEND_EXISTING_SIZE
            existing = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="Azure Blob",
                logger=log,
            )
            if len(existing) > cap:
                raise OSError(
                    f"Azure Blob append: existing object exceeds {cap // (1024 * 1024)} MiB cap"
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

    # ------------------------------------------------------------------
    # Azure Blob-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def snapshots_list(self, path: str) -> list[dict]:
        """List existing snapshots of the blob at ``path``. Returns
        dicts ``{snapshot, etag, size, modified}`` where ``snapshot``
        is the timestamp ID Azure assigns (use it with
        ``snapshot_open_read`` or pass to ``snapshot_delete``)."""
        key = self._to_key(path)
        out: list[dict] = []
        try:
            for blob in _each_page_once(
                self._container.list_blobs(name_starts_with=key, include=["snapshots"]),
                f"Cannot list snapshots of {path}",
            ):
                if blob.snapshot is None:
                    continue
                if blob.name != key:
                    continue
                out.append(
                    {
                        "snapshot": blob.snapshot,
                        "etag": blob.etag,
                        "size": blob.size,
                        "modified": blob.last_modified,
                    }
                )
        except OSError:
            raise
        except Exception as e:
            raise OSError(f"Cannot list snapshots of {path}: {e}") from e
        return out

    def snapshot_create(self, path: str, metadata: dict[str, str] | None = None) -> str:
        """Create a snapshot of the blob at ``path``. Returns the
        snapshot ID (a timestamp string Azure assigns).

        ``metadata`` keys/values are simple strings; refused if any
        contain CR/LF (Azure's HTTP backend is permissive but the
        SDK passes these through to headers — the explicit guard
        defends against header smuggling)."""
        if metadata:
            for k, v in metadata.items():
                if "\r" in k or "\n" in k or "\r" in v or "\n" in v:
                    raise ValueError("snapshot_create: CR/LF in metadata refused")
        key = self._to_key(path)
        try:
            blob = self._container.get_blob_client(key)
            result = blob.create_snapshot(metadata=metadata)
        except Exception as e:
            raise OSError(f"Cannot snapshot {path}: {e}") from e
        # SDK returns a dict; ``snapshot`` is the timestamp ID.
        snapshot = (
            result.get("snapshot") if isinstance(result, dict) else getattr(result, "snapshot", "")
        )
        return snapshot if isinstance(snapshot, str) else ""

    def lease_acquire(
        self, path: str, *, duration_seconds: int = 60, proposed_lease_id: str | None = None
    ) -> str:
        """Acquire an exclusive lease on the blob at ``path`` —
        prevents other writers from modifying it for ``duration_seconds``
        (15..60, or -1 for infinite). Returns the lease ID, which the
        caller must pass to ``lease_release``.

        Use cases: serialised state-file updates across multiple
        axross instances; coordinating long-running writes."""
        if duration_seconds != -1 and not (15 <= duration_seconds <= 60):
            raise ValueError("lease duration must be 15..60 seconds, or -1 for infinite")
        key = self._to_key(path)
        try:
            blob = self._container.get_blob_client(key)
            lease = blob.acquire_lease(
                lease_duration=duration_seconds,
                lease_id=proposed_lease_id,
            )
        except Exception as e:
            raise OSError(f"Cannot lease {path}: {e}") from e
        log.info(
            "Azure lease acquired: container=%s blob=%s id=%s duration=%s",
            self._container_name,
            key,
            lease.id,
            "infinite" if duration_seconds == -1 else f"{duration_seconds}s",
        )
        return lease.id

    def lease_release(self, path: str, lease_id: str) -> None:
        """Release a previously-acquired lease."""
        from azure.storage.blob import BlobLeaseClient

        key = self._to_key(path)
        try:
            blob = self._container.get_blob_client(key)
            BlobLeaseClient(blob, lease_id=lease_id).release()
        except Exception as e:
            raise OSError(f"Cannot release the lease on {path}: {e}") from e
        log.info(
            "Azure lease released: container=%s blob=%s id=%s",
            self._container_name,
            key,
            lease_id,
        )

    def tier_set(self, path: str, tier: str) -> None:
        """Set the access tier of a blob (``Hot``, ``Cool``, ``Cold``,
        ``Archive``). Mostly useful for cost optimisation on rarely-
        accessed blobs.

        ``Archive`` blobs cannot be read until rehydrated to ``Hot``/
        ``Cool`` first — that takes hours and Azure charges for the
        rehydration. Be intentional."""
        valid = {"Hot", "Cool", "Cold", "Archive"}
        if tier not in valid:
            raise ValueError(f"tier must be one of {sorted(valid)}, got {tier!r}")
        key = self._to_key(path)
        try:
            blob = self._container.get_blob_client(key)
            blob.set_standard_blob_tier(tier)
        except Exception as e:
            raise OSError(f"Cannot set the tier of {path}: {e}") from e
        log.info(
            "Azure tier_set: container=%s blob=%s tier=%s",
            self._container_name,
            key,
            tier,
        )

    def sas_url(self, path: str, *, expires_in: int = 3600, permissions: str = "r") -> str:
        """Generate a time-limited Shared Access Signature URL for
        ``path``. Equivalent to S3's ``presign``.

        ``permissions`` is the standard SAS code (``r`` read,
        ``w`` write, ``d`` delete, ``rwd`` for all three).
        ``expires_in`` is seconds from now.

        Requires the session to have been instantiated with an
        account key (not an OAuth token) since SAS signing needs
        the key locally.
        """
        from datetime import datetime, timedelta, timezone

        from azure.storage.blob import (
            BlobSasPermissions,
            generate_blob_sas,
        )

        if not self._account_key:
            raise OSError(
                "sas_url requires an account-key auth (not token-based) "
                "— SAS signing needs the symmetric key locally"
            )
        if "\r" in permissions or "\n" in permissions:
            raise ValueError("sas_url permissions must not contain CR/LF")
        perms_map = {
            "r": "read",
            "w": "write",
            "d": "delete",
            "l": "list",
            "a": "add",
            "c": "create",
        }
        kw = {perms_map[c]: True for c in permissions if c in perms_map}
        if not kw:
            raise ValueError(f"sas_url: no recognised permission chars in {permissions!r}")
        sas = generate_blob_sas(
            account_name=self._service.account_name,
            container_name=self._container_name,
            blob_name=self._to_key(path),
            account_key=self._account_key,
            permission=BlobSasPermissions(**kw),
            expiry=datetime.now(timezone.utc) + timedelta(seconds=int(expires_in)),
        )
        url = (
            f"https://{self._service.account_name}.blob.core.windows.net/"
            f"{self._container_name}/{self._to_key(path)}?{sas}"
        )
        log.info(
            "Azure SAS-URL: container=%s blob=%s perms=%s expires=%ds",
            self._container_name,
            self._to_key(path),
            permissions,
            int(expires_in),
        )
        return url

    def list_versions(self, path: str) -> list:
        """List blob versions if the container has versioning enabled."""
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from models.file_version import FileVersion

        key = self._to_key(path)
        out: list = []
        try:
            blobs = _each_page_once(
                self._container.list_blobs(name_starts_with=key, include=["versions"]),
                f"Cannot list versions of {path}",
            )
            entries = []
            for b in blobs:
                if b.name != key:
                    continue
                entries.append(b)

            def _ts(b):
                # Aware like the SDK's dates: a naive fallback fails the sort.
                return getattr(b, "last_modified", None) or _dt.min.replace(tzinfo=_tz.utc)

            entries.sort(key=_ts, reverse=True)
            for i, b in enumerate(entries):
                vid = getattr(b, "version_id", None) or ""
                is_cur = getattr(b, "is_current_version", None)
                if is_cur is None:
                    is_cur = i == 0
                out.append(
                    FileVersion(
                        version_id=vid,
                        modified=_ts(b) if isinstance(_ts(b), _dt) else _dt.now(),
                        size=int(getattr(b, "size", 0) or 0),
                        is_current=bool(is_cur),
                        label=f"azure-ver:{vid}",
                    )
                )
        except Exception as exc:
            log.warning("Azure list_versions(%s) failed: %s", path, exc)
            return []
        return out

    def open_version_read(self, path: str, version_id: str):
        """Download a specific blob version via version_id."""
        key = self._to_key(path)
        try:
            blob = self._container.get_blob_client(key)
            stream = blob.download_blob(version_id=version_id)
            return _spool_checked(stream, f"Cannot read {path}@{version_id}")
        except Exception as exc:
            raise OSError(f"Azure open_version_read failed: {exc}") from exc

    def copy(self, src: str, dst: str) -> None:
        """Azure Blob Copy Blob — server-side."""
        try:
            src_blob = self._container.get_blob_client(self._to_key(src))
            dst_blob = self._container.get_blob_client(self._to_key(dst))
            # start_copy_from_url only starts the copy: a pending one ends
            # later, possibly failed - copy() returns when it is done.
            dst_blob.start_copy_from_url(src_blob.url)
            self._wait_for_copy(dst_blob)
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


class AzureFilesSession(SessionLifecycle):
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
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if ShareServiceClient is None:
            raise ImportError(
                "Azure Files support requires azure-storage-file-share. "
                "Install with: pip install azure-storage-file-share"
            )

        self._share_name = share_name

        # Replace azure-sdk default UA — see docs/OPSEC.md #4. Plus
        # per-profile proxy via custom RequestsTransport.
        from core.client_identity import HTTP_USER_AGENT

        ua_kwargs = {"user_agent": HTTP_USER_AGENT, "user_agent_overwrite": True}
        ua_kwargs.update(
            _axross_azure_transport_kwargs(
                proxy_type,
                proxy_host,
                int(proxy_port or 0),
                proxy_username,
                proxy_password,
            )
        )

        if connection_string:
            self._service = ShareServiceClient.from_connection_string(
                connection_string,
                **ua_kwargs,
            )
        elif account_name and sas_token:
            account_url = f"https://{account_name}.file.core.windows.net"
            self._service = ShareServiceClient(
                account_url=account_url,
                credential=sas_token,
                **ua_kwargs,
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
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("Azure Files liveness check of %s failed: %s", self._share_name, exc)
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
        if dir_path:
            return self._share.get_directory_client(dir_path)
        return self._share.get_directory_client("")

    def list_dir(self, path: str) -> list[FileItem]:
        dir_path = self._to_path(path)
        items: list[FileItem] = []

        try:
            dir_client = self._share.get_directory_client(dir_path)
            for item in _each_page_once(
                dir_client.list_directories_and_files(), f"Cannot list {path}"
            ):
                if not isinstance(item.get("name"), str) or not item.get("name"):
                    # An entry without a name cannot be shown or addressed.
                    log.warning("Azure Files list_dir(%s): skipping an entry without a name", path)
                    continue
                if item.get("is_directory", False):
                    items.append(
                        FileItem(
                            name=item["name"],
                            is_dir=True,
                        )
                    )
                else:
                    # Aware UTC from the SDK; FileItem converts it.
                    last_modified = item.get("last_modified") or datetime.fromtimestamp(0)
                    items.append(
                        FileItem(
                            name=item["name"],
                            size=as_size(item.get("size")),
                            modified=last_modified,
                        )
                    )
        except Exception as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        return items

    def stat(self, path: str) -> FileItem:
        rel = self._to_path(path)
        base_name = posixpath.basename(rel) or path

        if not rel:
            return FileItem(name="/", is_dir=True)

        # Try as file first. Only "no such file" (404, or the type
        # mismatch of a directory) moves on to the directory check; any
        # other failure says nothing about what is there.
        parent_dir = posixpath.dirname(rel)
        try:
            file_client = self._share.get_directory_client(parent_dir).get_file_client(base_name)
            props = file_client.get_file_properties()
        except Exception as e:
            if not _is_not_a_directory(e):
                raise OSError(f"Cannot stat {path}: {e}") from e
        else:
            modified = props.get("last_modified") or datetime.fromtimestamp(0)
            return FileItem(
                name=base_name,
                size=as_size(props.get("size")) or as_size(props.get("content_length")),
                modified=modified,
            )

        # Try as directory
        try:
            props = self._share.get_directory_client(rel).get_directory_properties()
        except Exception as e:
            if _is_not_a_directory(e):
                raise FileNotFoundError(errno.ENOENT, "Not found", path) from e
            raise OSError(f"Cannot stat {path}: {e}") from e
        modified = props.get("last_modified") or datetime.fromtimestamp(0)
        return FileItem(
            name=base_name,
            is_dir=True,
            modified=modified,
        )

    def is_dir(self, path: str) -> bool:
        """False only when the share says there is no directory; any other
        failure is an OSError (remove() picks its action from this)."""
        rel = self._to_path(path)
        if not rel:
            return True
        try:
            dir_client = self._share.get_directory_client(rel)
            dir_client.get_directory_properties()
            return True
        except Exception as e:
            if _is_not_a_directory(e):
                return False
            raise OSError(f"Cannot check {path}: {e}") from e

    def exists(self, path: str) -> bool:
        """Only "not found" means False; any other failure is an OSError."""
        if self.is_dir(path):
            return True

        # Check as file
        rel = self._to_path(path)
        parent_dir = posixpath.dirname(rel)
        file_name = posixpath.basename(rel)
        try:
            file_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)
            file_client.get_file_properties()
            return True
        except Exception as e:
            if _is_not_found(e):
                return False
            raise OSError(f"Cannot check {path}: {e}") from e

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
                try:
                    self._remove_dir_recursive(rel)
                except OSError:
                    raise
                except Exception as e:
                    raise OSError(f"Cannot remove {path}: {e}") from e
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
                file_client = self._share.get_directory_client(parent_dir).get_file_client(
                    file_name
                )
                file_client.delete_file()
            except Exception as e:
                raise OSError(f"Cannot remove {path}: {e}") from e

    def _remove_dir_recursive(self, dir_path: str) -> None:
        """Recursively remove all files and subdirectories."""
        dir_client = self._share.get_directory_client(dir_path)
        for item in _each_page_once(
            dir_client.list_directories_and_files(), f"Cannot list {dir_path}"
        ):
            try:
                name = safe_leaf(item["name"])
            except ValueError as exc:
                raise OSError(
                    f"Azure Files remove: unsafe child name {item.get('name')!r}: {exc}"
                ) from exc
            child_path = posixpath.join(dir_path, name) if dir_path else name
            if item.get("is_directory", False):
                self._remove_dir_recursive(child_path)
            else:
                file_client = dir_client.get_file_client(name)
                file_client.delete_file()
        dir_client.delete_directory()

    def rename(self, src: str, dst: str) -> None:
        src_rel = self._to_path(src)
        dst_rel = self._to_path(dst)

        # ``new_name`` is a path inside the share: the SDK builds the
        # target from its own share_name plus this value.
        try:
            if self.is_dir(src):
                src_client = self._share.get_directory_client(src_rel)
                src_client.rename_directory(dst_rel)
            else:
                parent_dir = posixpath.dirname(src_rel)
                file_name = posixpath.basename(src_rel)
                src_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)
                src_client.rename_file(dst_rel)
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
            return _spool_checked(stream, f"Cannot read {path}")
        except OSError:
            raise
        except Exception as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        rel = self._to_path(path)
        parent_dir = posixpath.dirname(rel)
        file_name = posixpath.basename(rel)

        file_client = self._share.get_directory_client(parent_dir).get_file_client(file_name)

        if append:
            cap = 256 * 1024 * 1024  # see s3_client.py for rationale
            existing = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="Azure Files",
                logger=log,
            )
            if len(existing) > cap:
                raise OSError(
                    f"Azure Files append: existing file exceeds {cap // (1024 * 1024)} MiB cap"
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
            src_file = self._share.get_directory_client(src_parent).get_file_client(src_name)
            dst_file = self._share.get_directory_client(dst_parent).get_file_client(dst_name)
            # start_copy_from_url only starts the copy: a pending one ends
            # later, possibly failed - copy() returns when it is done.
            dst_file.start_copy_from_url(src_file.url)
            _wait_for_copy(dst_file.get_file_properties)
        except Exception as exc:
            raise OSError(f"Azure Files copy {src} -> {dst} failed: {exc}") from exc

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        try:
            parent, name = self._split(path)
            file_client = self._share.get_directory_client(parent).get_file_client(name)
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

    def _split(self, path: str) -> tuple[str, str]:
        """``(parent directory, file name)`` of *path* inside the share.
        copy() and checksum() called it, but it did not exist: both
        always failed with an AttributeError turned OSError."""
        rel = self._to_path(path)
        return posixpath.dirname(rel), posixpath.basename(rel)
