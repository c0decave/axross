"""S3-compatible backend implementing the FileBackend protocol.

Requires: pip install axross[s3]  (boto3>=1.28)

Works with AWS S3, MinIO, Ceph RGW, Wasabi, Cloudflare R2, etc.
"""

from __future__ import annotations

import errno
import logging
import posixpath
import tempfile
from datetime import datetime
from typing import IO

from core import cloud_http, transfer_hooks
from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.read_spool import read_chunks, spool_chunks
from models.file_item import FileItem

log = logging.getLogger(__name__)


def _spool_body(body, what: str) -> IO[bytes]:
    """A GetObject body as a spool, not one bytes object in RAM.

    Read in sized chunks to the end, so botocore still checks the bytes
    against the Content-Length; the body is closed either way.
    """
    try:
        return spool_chunks(read_chunks(body), what=what)
    finally:
        close = getattr(body, "close", None)
        if close is not None:
            close()

from core.client_identity import HTTP_USER_AGENT  # noqa: E402 — after log= for clean attribution

try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    boto3 = None  # type: ignore[assignment]
    UNSIGNED = None  # type: ignore[assignment]
    BotoConfig = None  # type: ignore[assignment]
    ClientError = Exception  # type: ignore[assignment,misc]
    BotoCoreError = Exception  # type: ignore[assignment,misc]


#: S3 error codes and the errno each stands for; a code not listed here is
#: read by its HTTP status (cloud_http.errno_for_status).
_CODE_ERRNO = {
    "NoSuchKey": errno.ENOENT,
    "NotFound": errno.ENOENT,
    "NoSuchBucket": errno.ENOENT,
    "NoSuchUpload": errno.ENOENT,
    "NoSuchVersion": errno.ENOENT,
    "AccessDenied": errno.EACCES,
    "AllAccessDisabled": errno.EACCES,
    "AccountProblem": errno.EACCES,
    "InvalidAccessKeyId": errno.EACCES,
    "SignatureDoesNotMatch": errno.EACCES,
    "ExpiredToken": errno.EACCES,
    "InvalidToken": errno.EACCES,
    "RequestTimeTooSkewed": errno.EACCES,
    "SlowDown": errno.EAGAIN,
    "Throttling": errno.EAGAIN,
    "ThrottlingException": errno.EAGAIN,
    "RequestLimitExceeded": errno.EAGAIN,
    "TooManyRequests": errno.EAGAIN,
    "ServiceUnavailable": errno.EAGAIN,
    "QuotaExceeded": errno.ENOSPC,
    "XMinioStorageFull": errno.ENOSPC,
    "XMinioAdminBucketQuotaExceeded": errno.ENOSPC,
    "EntityTooLarge": errno.EFBIG,
    "PreconditionFailed": errno.ESTALE,
    "BucketNotEmpty": errno.ENOTEMPTY,
    "RequestTimeout": errno.ETIMEDOUT,
    "KeyTooLongError": errno.ENAMETOOLONG,
    "InvalidArgument": errno.EINVAL,
    "InvalidRequest": errno.EINVAL,
    "InvalidObjectName": errno.EINVAL,
    "NotImplemented": errno.ENOTSUP,
    "InternalError": errno.EIO,
}


def _s3_errno(exc: BaseException) -> int:
    """The errno of a boto3 / botocore failure: the S3 error code, else
    the HTTP status (both through core.cloud_http), else the kind of
    transport failure."""
    if isinstance(exc, OSError) and isinstance(exc.errno, int) and exc.errno:
        return exc.errno
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error") or {}
        code = str(error.get("Code", "")) if isinstance(error, dict) else ""
        if code in _CODE_ERRNO:
            return _CODE_ERRNO[code]
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        if not isinstance(status, int) and code.isdigit():
            status = int(code)  # a HEAD answer carries no body: Code is the status
        if isinstance(status, int):
            return cloud_http.errno_for_status(status)
        return errno.EIO
    name = type(exc).__name__
    if "Timeout" in name:
        return errno.ETIMEDOUT
    if "Connection" in name or "Endpoint" in name:
        return errno.ECONNRESET
    if "Credentials" in name or "NoAuth" in name:
        return errno.EACCES
    if isinstance(exc, ValueError):
        return errno.EPROTO  # an answer botocore cannot parse
    return errno.EIO


def _s3_error(exc: BaseException, message: str, filename: str | None = None) -> OSError:
    """*message* as the typed OSError of a failed S3 call (cloud_http):
    FileNotFoundError for NoSuchKey / 404, PermissionError for
    AccessDenied / 403, EAGAIN for SlowDown / 503, ENOSPC for a quota ...
    botocore's ClientError is no OSError at all - an editor's Save ended
    in the global exception hook - and the errno-less OSError of old was
    read by a FUSE mount as ENOENT. A cancelled transfer stays an
    InterruptedError."""
    if isinstance(exc, InterruptedError):
        if isinstance(exc, transfer_hooks.UploadCancelled):
            return transfer_hooks.UploadCancelled(*exc.args)
        return InterruptedError(*exc.args)
    return cloud_http.oserror(_s3_errno(exc), message, filename)


def _is_not_found(exc: Exception) -> bool:
    """True for the ClientError S3 answers for a missing key (HEAD carries
    no body, so botocore names it by the status: "404")."""
    code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
    return code in ("404", "NoSuchKey", "NotFound")


def _lists_anything(resp: dict) -> bool:
    """Whether a ListObjectsV2 answer names any key or prefix. KeyCount
    is optional in S3-compatible stores (older Ceph RGW, some MinIO
    gateways leave it out): without it every folder looked absent - an
    empty listing that is_dir() said was no folder, and a recursive
    delete that called it "not found"."""
    if "KeyCount" in resp:
        try:
            return int(resp["KeyCount"]) > 0
        except (TypeError, ValueError):
            pass
    return bool(resp.get("Contents") or resp.get("CommonPrefixes"))


# CopyObject copies at most 5 GiB in one request; a bigger object is copied
# with a multipart upload whose parts are UploadPartCopy byte ranges.
_MAX_SINGLE_COPY = 5 * 1024**3
_COPY_PART_SIZE = 512 * 1024**2
_MAX_PARTS = 10_000


#: Above this a transfer's upload is a multipart upload (s3transfer's
#: default threshold), which a Cancel aborts; below it one PutObject that
#: runs to its end.
_MULTIPART_THRESHOLD = 8 * 1024 * 1024
#: Seconds between two looks at Cancel and progress while s3transfer's
#: threads upload (the end of the upload wakes the wait at once).
_POLL = 0.05


def _is_boto_client(client) -> bool:
    try:
        from botocore.client import BaseClient
    except ImportError:  # pragma: no cover - the S3 backend needs botocore
        return False
    return isinstance(client, BaseClient)


class _UploadProgress:
    """An s3transfer subscriber: the bytes its threads have sent."""

    def __init__(self) -> None:
        import threading

        self._lock = threading.Lock()
        self.done = 0
        #: Set when the transfer has ended (s3transfer runs on_done after
        #: its result is set): the watching loop needs no further pause.
        self.finished = threading.Event()

    # s3transfer calls on_queued / on_progress / on_done on its subscribers
    def on_queued(self, future, **kwargs) -> None:
        pass

    def on_progress(self, future, bytes_transferred, **kwargs) -> None:
        with self._lock:
            self.done += bytes_transferred  # negative when a part is retried

    def on_done(self, future, **kwargs) -> None:
        self.finished.set()


def _upload_cancellable(client, fileobj, bucket: str, key: str, size: int, hooks) -> None:
    """``upload_fileobj`` as s3transfer runs it (multipart above 8 MiB, ten
    parts at a time), watched from this thread: the bytes sent go to
    *hooks* and a Cancel cancels the transfer - s3transfer then aborts the
    multipart upload (AbortMultipartUpload, its failure cleanup), so no
    part of it is ever committed and the old object stays. A single
    PutObject (up to 8 MiB) is not cut off - once sent it may already have
    replaced the object: the caller sends those without this."""
    from s3transfer.manager import TransferManager

    progress = _UploadProgress()
    hooks.check()
    with TransferManager(client) as manager:
        future = manager.upload(fileobj, bucket, key, subscribers=[progress])
        cancelled = False
        while not future.done():
            if hooks.cancelled():
                future.cancel()
                cancelled = True
                break
            hooks.sent(max(progress.done, 0), size, check=False)
            progress.finished.wait(_POLL)
        try:
            future.result()
        except Exception as exc:
            if cancelled:
                # Raised once every part in flight is back and the
                # multipart upload was aborted.
                raise transfer_hooks.UploadCancelled(transfer_hooks.CANCELLED) from exc
            raise
    hooks.sent(size, size, check=False)


class _SpooledWriter:
    """Write to a temp file, then upload on close.

    In a running transfer (core.transfer_hooks) the upload reports its
    bytes and a Cancel aborts it (see _upload_cancellable); every failure
    of close() is a typed OSError (_s3_error)."""

    def __init__(self, s3_client, bucket: str, key: str):
        self._s3 = s3_client
        self._bucket = bucket
        self._key = key
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        self._closed = False
        # The running transfer's Cancel and progress: the upload happens in
        # close(), after the copy loop.
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
        path = "/" + self._key
        try:
            size = self._buf.seek(0, 2)
            self._buf.seek(0)
            if hooks is not None and size > _MULTIPART_THRESHOLD and _is_boto_client(self._s3):
                _upload_cancellable(self._s3, self._buf, self._bucket, self._key, size, hooks)
            else:
                if hooks is not None:
                    hooks.check()
                self._s3.upload_fileobj(self._buf, self._bucket, self._key)
                if hooks is not None:
                    hooks.sent(size, size, check=False)
        except InterruptedError:
            # Cancelled before the upload began, or a multipart upload
            # aborted: nothing was committed, the old object stays.
            raise transfer_hooks.UploadCancelled(transfer_hooks.CANCELLED) from None
        except Exception as exc:
            # botocore's ClientError is no OSError: the editor's "Cannot
            # save" and atomic_write's callers catch OSError.
            raise _s3_error(exc, f"Cannot upload {path}: {exc}", path) from exc
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


class S3Session(SessionLifecycle):
    """S3-compatible backend implementing the FileBackend protocol.

    Uses boto3. Treats the bucket as the root filesystem.
    Paths are POSIX-style: /prefix/key. Directories are virtual
    (represented by common prefixes or zero-byte keys ending with /).
    """

    @staticmethod
    def _parse_s3_url(bucket: str, region: str) -> tuple[str, str]:
        """Extract bucket name and region from an S3 URL or hostname.

        Handles:
          - dev-s1.s3.ap-south-1.amazonaws.com → ("dev-s1", "ap-south-1")
          - https://dev-s1.s3.ap-south-1.amazonaws.com → ("dev-s1", "ap-south-1")
          - s3://dev-s1 → ("dev-s1", region)
          - dev-s1.s3.amazonaws.com → ("dev-s1", "us-east-1")
          - dev-s1 → ("dev-s1", region)  (plain bucket name, unchanged)
        """
        import re

        raw = bucket.strip().rstrip("/")
        # Strip scheme
        for prefix in ("https://", "http://", "s3://"):
            if raw.lower().startswith(prefix):
                raw = raw[len(prefix) :]
                break
        # Strip trailing path components (e.g. /index.html)
        raw = raw.split("/")[0]

        # Pattern: <bucket>.s3[.<region>].amazonaws.com
        m = re.match(
            r"^(.+)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com$",
            raw,
            re.IGNORECASE,
        )
        if m:
            parsed_bucket = m.group(1)
            parsed_region = m.group(2) or "us-east-1"
            return parsed_bucket, parsed_region

        # Plain bucket name — return as-is
        return raw, region

    def __init__(
        self,
        bucket: str,
        region: str = "",
        access_key: str = "",
        secret_key: str = "",
        endpoint: str | None = None,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if boto3 is None:
            raise ImportError("S3 support requires boto3. Install with: pip install axross[s3]")

        # Auto-parse S3 URLs into bucket + region
        bucket, auto_region = self._parse_s3_url(bucket, region or "us-east-1")
        if not region:
            region = auto_region

        self._bucket = bucket
        self._region = region or "us-east-1"
        self._access_key = access_key
        self._anonymous = not access_key and not secret_key

        proxy_type = (proxy_type or "none").lower()

        kwargs: dict = {
            "service_name": "s3",
            "region_name": self._region,
        }
        # Replace botocore's default User-Agent so requests don't
        # advertise Boto3/python/OS/glibc. See docs/OPSEC.md #4.
        # Plus optional per-profile proxy via botocore's `proxies`
        # config field (accepts {'http': '...', 'https': '...'} as
        # produced by ``core.proxy.build_requests_proxies``).
        from core.proxy import (
            ProxyConfig,
            build_requests_proxies,
            effective_http_proxy,
        )

        proxies: dict[str, str] = {}
        s3_proxy = ProxyConfig(
            proxy_type, proxy_host, int(proxy_port or 0), proxy_username, proxy_password
        )
        if s3_proxy.enabled:
            # botocore only understands plain HTTP proxies: SOCKS, TLS to the
            # proxy and NTLM / Negotiate go through the loopback shim.
            http_cfg = effective_http_proxy(s3_proxy)
            proxies = build_requests_proxies(
                "http",
                http_cfg.host,
                http_cfg.port,
                http_cfg.username,
                http_cfg.password,
            )
        base_kwargs: dict = {"user_agent": HTTP_USER_AGENT}
        if proxies:
            base_kwargs["proxies"] = dict(proxies)
        base_config = BotoConfig(**base_kwargs)
        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key
            kwargs["config"] = base_config
        elif self._anonymous:
            # Anonymous / public bucket access (no credentials)
            kwargs["config"] = base_config.merge(BotoConfig(signature_version=UNSIGNED))
        else:
            kwargs["config"] = base_config
        if endpoint:
            kwargs["endpoint_url"] = endpoint
            # botocore 1.36+ adds a CRC checksum to every upload (an
            # aws-chunked body with a trailer) and asks for one on every
            # download. Many S3-compatible stores (older MinIO and Ceph
            # RGW, Wasabi, R2 at first, Backblaze B2) refuse such uploads
            # or answer without the checksum: "when_required" sends and
            # checks one only where the operation demands it - as every
            # botocore before 1.36 did. AWS itself keeps the default.
            try:
                kwargs["config"] = kwargs["config"].merge(BotoConfig(
                    request_checksum_calculation="when_required",
                    response_checksum_validation="when_required",
                ))
            except TypeError:  # botocore < 1.36: no such options, nothing to turn off
                pass

        # Validate bucket name before connecting
        import re

        if not re.fullmatch(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$", bucket):
            raise OSError(
                errno.EINVAL,
                f"Invalid S3 bucket name '{bucket}'. "
                "Bucket names must be 3-63 characters, lowercase letters, digits, "
                "hyphens, and dots only. If you have a full URL, just paste it — "
                "it will be parsed automatically."
            )

        # A boto3 Session of this S3Session's own. boto3.client() would
        # build the client from the shared default session, and "invoking
        # boto3.client() inside of a concurrent context may result in
        # response ordering issues or interpreter failures from underlying
        # SSL modules" (boto3 guide, clients.html) - two profiles connecting
        # at once, or a transfer worker connecting one. The low-level client
        # itself is thread safe as long as no custom event hooks are
        # registered on it, and none are; it is not replaced after the
        # connection test, so several transfer jobs may share it
        # (core.transfer_pool).
        self._boto_session = boto3.session.Session()
        self._s3 = self._boto_session.client(**kwargs)

        # Test connection — handle region redirects and try multiple methods
        self._connect_with_redirect(bucket, kwargs)

        log.info(
            "S3 connected: %s (region=%s, endpoint=%s, anonymous=%s)",
            bucket,
            self._region,
            endpoint or "default",
            self._anonymous,
        )

    def _connect_with_redirect(self, bucket: str, kwargs: dict) -> None:
        """Test connection, auto-following region redirects."""
        try:
            self._test_bucket(bucket)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            headers = e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})

            # Handle region redirect (301 PermanentRedirect)
            if code in ("PermanentRedirect", "301"):
                real_region = headers.get("x-amz-bucket-region", "")
                # Fallback: parse region from Error.Endpoint in the XML body
                if not real_region:
                    import re as _re

                    endpoint_str = e.response.get("Error", {}).get("Endpoint", "")
                    m = _re.search(r"\.s3[.-]([a-z0-9-]+)\.amazonaws\.com", endpoint_str)
                    if m:
                        real_region = m.group(1)
                if real_region and real_region != self._region:
                    log.info("S3 bucket '%s' redirected to region %s", bucket, real_region)
                    self._region = real_region
                    kwargs["region_name"] = real_region
                    self._s3 = self._boto_session.client(**kwargs)
                    try:
                        self._test_bucket(bucket)
                        return
                    except ClientError as e2:
                        e = e2
                        code = e.response.get("Error", {}).get("Code", "")

            if code in ("NoSuchBucket", "404"):
                raise _s3_error(e, f"S3 bucket '{bucket}' does not exist") from e
            if code in ("AccessDenied", "403", "AllAccessDisabled"):
                raise OSError(
                    errno.EACCES,
                    f"Access denied to S3 bucket '{bucket}'. "
                    "Check credentials or try anonymous access."
                ) from e
            raise _s3_error(e, f"Cannot access S3 bucket '{bucket}': {e}") from e
        except Exception as e:
            raise _s3_error(e, f"Cannot access S3 bucket '{bucket}': {e}") from e

    def _test_bucket(self, bucket: str) -> None:
        """Try to access the bucket, preferring list then head."""
        if self._anonymous:
            try:
                self._s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
                return
            except ClientError as list_err:
                code = list_err.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchBucket", "PermanentRedirect", "301"):
                    raise
                # list failed — try head_bucket as fallback
                try:
                    self._s3.head_bucket(Bucket=bucket)
                    return
                except ClientError as head_err:
                    # Chain so the reader sees both failures; don't
                    # ``raise list_err`` (drops the head_bucket trace).
                    raise list_err from head_err
        else:
            self._s3.head_bucket(Bucket=bucket)

    @property
    def name(self) -> str:
        return f"s3://{self._bucket} (S3)"

    @property
    def connected(self) -> bool:
        try:
            self._s3.head_bucket(Bucket=self._bucket)
            return True
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("S3 liveness check of bucket %s failed: %s", self._bucket, exc)
            return False

    def close(self) -> None:
        pass  # boto3 client doesn't need explicit close

    def disconnect(self) -> None:
        self.close()

    def list_dir(self, path: str) -> list[FileItem]:
        prefix = self._to_prefix(path)
        items: list[FileItem] = []
        seen_any = not prefix  # the bucket root is always there

        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            pages = paginator.paginate(
                Bucket=self._bucket,
                Prefix=prefix,
                Delimiter="/",
            )

            for page in pages:
                seen_any = seen_any or bool(page.get("CommonPrefixes") or page.get("Contents"))
                # Directories (common prefixes)
                for cp in page.get("CommonPrefixes", []):
                    dir_prefix = cp["Prefix"]
                    dir_name = dir_prefix[len(prefix) :].rstrip("/")
                    if dir_name:
                        items.append(
                            FileItem(
                                name=dir_name,
                                is_dir=True,
                            )
                        )

                # Files (objects)
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    name = key[len(prefix) :]
                    if not name or name.endswith("/"):
                        continue  # Skip the prefix itself or directory markers
                    items.append(
                        FileItem(
                            name=name,
                            size=obj.get("Size", 0),
                            modified=obj.get("LastModified", datetime.fromtimestamp(0)),
                        )
                    )

        except (ClientError, Exception) as e:
            raise _s3_error(e, f"Cannot list {path}: {e}") from e

        if not seen_any:
            # Nothing under the prefix - not even a folder marker: no folder
            # (a typo listed as an empty one), or the name of a file.
            if self._object_beside_prefix(prefix.rstrip("/"), path):
                raise NotADirectoryError(errno.ENOTDIR, f"Cannot list {path}: a file", path)
            raise FileNotFoundError(errno.ENOENT, f"Cannot list {path}: not found", path)
        return items

    def stat(self, path: str) -> FileItem:
        key = self._to_key(path)
        name = posixpath.basename(path.rstrip("/")) or path

        if not key:
            return FileItem(name=name, is_dir=True)
        if key.endswith("/"):
            # A folder only when it is there: "x/" was a folder for any x.
            if self.is_dir(path):
                return FileItem(name=name, is_dir=True)
            raise FileNotFoundError(errno.ENOENT, "Not found", path)

        # Try as object first
        try:
            resp = self._s3.head_object(Bucket=self._bucket, Key=key)
            modified = resp.get("LastModified", datetime.fromtimestamp(0))
            return FileItem(
                name=name,
                size=resp.get("ContentLength", 0),
                modified=modified,
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code != "404":
                raise _s3_error(e, f"Cannot stat {path}: {e}") from e
        except Exception as e:
            # botocore raises ValueError for a HEAD answer it cannot parse
            # and BotoCoreError (not an OSError) when the endpoint hangs up.
            raise _s3_error(e, f"Cannot stat {path}: {e}") from e

        # Check if it's a directory prefix
        try:
            resp = self._s3.list_objects_v2(
                Bucket=self._bucket,
                Prefix=key.rstrip("/") + "/",
                MaxKeys=1,
            )
            if _lists_anything(resp):
                return FileItem(name=name, is_dir=True)
        except (ClientError, Exception) as e:
            raise _s3_error(e, f"Cannot stat {path}: {e}") from e

        raise FileNotFoundError(errno.ENOENT, "Not found", path)

    def is_dir(self, path: str) -> bool:
        """True when objects exist under ``path/``. A listing that fails
        (throttled, refused, dropped) is an OSError, never "no folder":
        remove() and rename() pick their action from this answer."""
        key = self._to_key(path)
        if not key or key == "/":
            return True

        # Check if any objects exist under this prefix
        try:
            resp = self._s3.list_objects_v2(
                Bucket=self._bucket,
                Prefix=key.rstrip("/") + "/",
                MaxKeys=1,
            )
        except Exception as e:
            raise _s3_error(e, f"Cannot check {path}: {e}") from e
        return _lists_anything(resp)

    def exists(self, path: str) -> bool:
        """Only a not-found answer means False. Any other failure (503
        SlowDown, 403, 500, a dropped connection) is an OSError: it says
        nothing about the object, and server_side_copy(overwrite=False)
        takes False as the go-ahead to write."""
        key = self._to_key(path)
        if not key:
            return True  # Root always exists

        # Check as object
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError as e:
            if not _is_not_found(e):
                raise _s3_error(e, f"Cannot check {path}: {e}") from e
        except Exception as e:
            # An answer botocore cannot parse, or a dropped connection, says
            # nothing about existence (see stat()).
            raise _s3_error(e, f"Cannot check {path}: {e}") from e

        # Check as directory prefix
        return self.is_dir(path)

    def mkdir(self, path: str) -> None:
        """Create a directory marker (zero-byte object ending with /)."""
        if self._anonymous:
            raise OSError(errno.EROFS, "Cannot write to anonymous/public S3 bucket (read-only)")
        key = self._to_key(path).rstrip("/") + "/"
        try:
            self._s3.put_object(Bucket=self._bucket, Key=key, Body=b"")
        except (ClientError, Exception) as e:
            raise _s3_error(e, f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        if self._anonymous:
            raise OSError(errno.EROFS, "Cannot write to anonymous/public S3 bucket (read-only)")
        key = self._to_key(path)

        if self.is_dir(path):
            if not recursive:
                # An object "X" beside the prefix "X/" is the FILE the
                # caller removes (recursive=False); the folder marker is
                # only the target when there is no such file - and only
                # when nothing else is under the prefix.
                if self._object_beside_prefix(key, path):
                    target = key
                else:
                    target = key.rstrip("/") + "/"
                    self._refuse_non_empty(target, path)
                try:
                    self._s3.delete_object(Bucket=self._bucket, Key=target)
                except (ClientError, Exception) as e:
                    raise _s3_error(e, f"Cannot remove {path}: {e}") from e
            else:
                self._remove_prefix(key.rstrip("/") + "/")
        else:
            # DeleteObject answers 204 for a key that is not there: a typo
            # was reported as removed. Look first, as unlink(2) does.
            if not self._object_beside_prefix(key, path):
                raise FileNotFoundError(errno.ENOENT, f"Cannot remove {path}: not found", path)
            try:
                self._s3.delete_object(Bucket=self._bucket, Key=key)
            except (ClientError, Exception) as e:
                raise _s3_error(e, f"Cannot remove {path}: {e}") from e

    def _refuse_non_empty(self, prefix: str, path: str) -> None:
        """ENOTEMPTY when any key besides the folder marker *prefix* lies
        under it: deleting the marker alone would report a removed folder
        whose files are all still there."""
        try:
            resp = self._s3.list_objects_v2(Bucket=self._bucket, Prefix=prefix, MaxKeys=2)
        except Exception as e:
            raise _s3_error(e, f"Cannot remove {path}: {e}") from e
        if any(obj.get("Key") != prefix for obj in resp.get("Contents") or []):
            raise OSError(errno.ENOTEMPTY, f"Directory not empty: {path}", path)

    def _object_beside_prefix(self, key: str, path: str) -> bool:
        """True when an object named exactly *key* exists - a file next to
        the folder ``key/``. A HEAD error other than not-found is an
        OSError: it says nothing about which of the two is meant."""
        if not key or key.endswith("/"):
            return False
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError as e:
            if _is_not_found(e):
                return False
            raise _s3_error(e, f"Cannot check {path}: {e}") from e
        except Exception as e:
            raise _s3_error(e, f"Cannot check {path}: {e}") from e

    def _remove_prefix(self, prefix: str) -> None:
        """Delete all objects under a prefix.

        DeleteObjects answers 200 also when it refused keys (access,
        object lock): those are listed in ``Errors``. Every page is
        still deleted; afterwards the refusals fail the remove.
        """
        paginator = self._s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=self._bucket, Prefix=prefix)

        refused: list[str] = []
        try:
            for page in pages:
                objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
                if objects:
                    resp = self._s3.delete_objects(
                        Bucket=self._bucket,
                        Delete={"Objects": objects},
                    )
                    for err in (resp or {}).get("Errors") or []:
                        code, message = err.get("Code"), err.get("Message")
                        refused.append(f"{err.get('Key')} ({code}: {message})")
        except Exception as e:  # noqa: BLE001 - every SDK failure, typed
            raise _s3_error(e, f"Cannot delete under {prefix}: {e}") from e
        if refused:
            shown = "; ".join(refused[:5])
            more = f" and {len(refused) - 5} more" if len(refused) > 5 else ""
            raise OSError(errno.EACCES,
                          f"Cannot delete {len(refused)} object(s) under {prefix}: {shown}{more}")

    def rename(self, src: str, dst: str) -> None:
        """S3 doesn't support rename — copy + delete."""
        if self._anonymous:
            raise OSError(errno.EROFS, "Cannot write to anonymous/public S3 bucket (read-only)")
        src_key = self._to_key(src)
        dst_key = self._to_key(dst)

        src_is_dir = self.is_dir(src)
        if not src_is_dir:
            self._file_key(dst, "rename to")
        if posixpath.normpath("/" + src_key) == posixpath.normpath("/" + dst_key):
            # Copy onto itself, then delete the source: that deleted the
            # only copy. rename(2) leaves the entry as it is.
            if not src_is_dir and not self.exists(src):
                raise FileNotFoundError(errno.ENOENT, f"Cannot rename {src}: not found", src)
            return
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
        if src_is_dir and (dst_key.rstrip("/") + "/").startswith(src_key.rstrip("/") + "/"):
            # rename(2) answers EINVAL: copy+delete moved the folder's files
            # into a folder of its own and deleted them from their place.
            raise OSError(errno.EINVAL, f"Cannot move the folder {src} into itself ({dst})", dst)

        if src_is_dir:
            if self._object_beside_prefix(src_key, src):
                # Moving the folder tree would leave the file behind and
                # moving the file would not be what a folder rename means.
                raise OSError(
                    errno.EINVAL,
                    f"Cannot rename {src}: both a file and a folder are named "
                    f"{posixpath.basename(src_key)!r} here; the name does not say which one"
                )
            # Rename all objects under the prefix
            old_prefix = src_key.rstrip("/") + "/"
            new_prefix = dst_key.rstrip("/") + "/"
            what = f"Cannot rename {src} -> {dst}"
            try:
                paginator = self._s3.get_paginator("list_objects_v2")
                pages = iter(paginator.paginate(Bucket=self._bucket, Prefix=old_prefix))
            except Exception as e:  # noqa: BLE001 - every SDK failure, typed
                raise _s3_error(e, f"{what}: {e}", src) from e

            while True:
                # Each page is a request: a refused or throttled listing
                # mid-way is a typed OSError, not botocore's ClientError.
                try:
                    page = next(pages)
                except StopIteration:
                    break
                except Exception as e:  # noqa: BLE001 - every SDK failure, typed
                    raise _s3_error(e, f"{what}: {e}", src) from e
                for obj in page.get("Contents", []):
                    old_key = obj["Key"]
                    new_key = new_prefix + old_key[len(old_prefix) :]
                    self._copy_key(old_key, new_key, what, size=obj.get("Size"))
                    try:
                        self._s3.delete_object(Bucket=self._bucket, Key=old_key)
                    except (ClientError, Exception) as e:
                        raise _s3_error(e, f"{what}: {e}") from e
        else:
            what = f"Cannot rename {src} -> {dst}"
            self._copy_key(src_key, dst_key, what, path=src)
            try:
                self._s3.delete_object(Bucket=self._bucket, Key=src_key)
            except (ClientError, Exception) as e:
                raise _s3_error(e, f"{what}: {e}") from e

    def _copy_key(
        self, src_key: str, dst_key: str, what: str, *, size: int | None = None, path: str = ""
    ) -> None:
        """Server-side copy of one object. CopyObject is capped at 5 GiB;
        above that the copy is a multipart upload of UploadPartCopy ranges
        (it failed with InvalidRequest before). *size* is the source size
        when a listing already gave it; otherwise a HEAD finds it - and a
        missing source is a FileNotFoundError."""
        head: dict = {}
        if size is None:
            head = self._head_for_copy(src_key, what, path)
            size = int(head.get("ContentLength") or 0)
        source = {"Bucket": self._bucket, "Key": src_key}
        if size <= _MAX_SINGLE_COPY:
            try:
                self._s3.copy_object(Bucket=self._bucket, CopySource=source, Key=dst_key)
            except (ClientError, Exception) as e:
                raise _s3_error(e, f"{what}: {e}") from e
            return
        if not head:
            head = self._head_for_copy(src_key, what, path)
        create: dict = {"Bucket": self._bucket, "Key": dst_key}
        # CopyObject carries type and user metadata; a multipart upload
        # only gets what CreateMultipartUpload is given.
        for field in ("ContentType", "ContentEncoding", "ContentDisposition", "CacheControl"):
            if head.get(field):
                create[field] = head[field]
        if head.get("Metadata"):
            create["Metadata"] = head["Metadata"]
        # Every part is copied from the version the HEAD saw: a source
        # replaced mid-copy fails the next part (412 PreconditionFailed)
        # instead of mixing the parts of two versions in one object.
        condition = {"CopySourceIfMatch": head["ETag"]} if head.get("ETag") else {}
        part_size = max(_COPY_PART_SIZE, -(-size // _MAX_PARTS))
        try:
            upload_id = self._s3.create_multipart_upload(**create)["UploadId"]
        except (ClientError, Exception) as e:
            raise _s3_error(e, f"{what}: {e}") from e
        parts = []
        try:
            for number, start in enumerate(range(0, size, part_size), start=1):
                end = min(start + part_size, size) - 1
                resp = self._s3.upload_part_copy(
                    Bucket=self._bucket,
                    Key=dst_key,
                    UploadId=upload_id,
                    PartNumber=number,
                    CopySource=source,
                    CopySourceRange=f"bytes={start}-{end}",
                    **condition,
                )
                parts.append({"PartNumber": number, "ETag": resp["CopyPartResult"]["ETag"]})
            self._s3.complete_multipart_upload(
                Bucket=self._bucket,
                Key=dst_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except (ClientError, Exception) as e:
            try:
                self._s3.abort_multipart_upload(
                    Bucket=self._bucket, Key=dst_key, UploadId=upload_id
                )
            except Exception:  # noqa: BLE001 - the copy error is the one to report
                log.warning("S3: could not abort the multipart copy to %s", dst_key)
            raise _s3_error(e, f"{what}: {e}") from e

    def _head_for_copy(self, src_key: str, what: str, path: str) -> dict:
        try:
            return self._s3.head_object(Bucket=self._bucket, Key=src_key) or {}
        except ClientError as e:
            if _is_not_found(e):
                where = path or "/" + src_key
                raise FileNotFoundError(errno.ENOENT, f"{what}: not found", where) from e
            raise _s3_error(e, f"{what}: {e}") from e
        except Exception as e:
            raise _s3_error(e, f"{what}: {e}") from e

    def open_read(self, path: str) -> IO[bytes]:
        key = self._to_key(path)
        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=key)
            return _spool_body(resp["Body"], f"Cannot read {path}")
        except Exception as e:
            if isinstance(e, ClientError) and _is_not_found(e):
                # NoSuchKey: no object - maybe a folder (a prefix).
                try:
                    folder = self.is_dir(path)
                except OSError:
                    folder = False
                if folder:
                    raise IsADirectoryError(
                        errno.EISDIR, f"Cannot read {path}: it is a folder", path
                    ) from e
                raise FileNotFoundError(errno.ENOENT, f"Cannot read {path}: {e}", path) from e
            raise _s3_error(e, f"Cannot read {path}: {e}") from e

    # Hard cap on "download existing then re-upload" append semantics.
    # Above this the operation is almost certainly not what the user
    # wanted and a malicious backend returning a huge file would OOM
    # the client.
    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024  # 256 MiB

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if self._anonymous:
            raise OSError(errno.EROFS, "Cannot write to anonymous/public S3 bucket (read-only)")
        key = self._file_key(path, "write")
        if append:
            # S3 doesn't support append — download, concatenate, re-upload.
            # Bounded so a hostile object can't OOM us.
            cap = self._MAX_APPEND_EXISTING_SIZE
            existing = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="S3",
                logger=log,
            )
            if len(existing) > cap:
                raise OSError(
                    errno.EFBIG,
                    f"S3 append: existing object exceeds "
                    f"{cap // (1024 * 1024)} MiB cap "
                    f"(read-modify-write not safe at this size)"
                )
            writer = _SpooledWriter(self._s3, self._bucket, key)
            writer.write(existing)
            return writer
        return _SpooledWriter(self._s3, self._bucket, key)

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

    def chmod(self, path: str, mode: int) -> None:
        raise OSError(errno.ENOTSUP, "S3 does not support Unix permissions", path)

    def readlink(self, path: str) -> str:
        raise OSError(errno.EINVAL, "S3 does not support symlinks", path)

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        """S3 ListObjectVersions. Requires versioning enabled on
        the bucket; returns [] for unversioned buckets."""
        from models.file_version import FileVersion

        versions = []
        target_key = self._to_key(path)
        request = {"Bucket": self._bucket, "Prefix": target_key}
        while True:
            try:
                resp = self._s3.list_object_versions(**request)
            except Exception as exc:
                raise _s3_error(exc, f"S3 list_versions {path}: {exc}") from exc
            past_target = False
            for v in resp.get("Versions", []):
                key = v.get("Key")
                if key != target_key:
                    # Keys come in order; the prefix also matches
                    # siblings such as "a.txt.bak", which sort after it.
                    past_target = past_target or (key or "") > target_key
                    continue
                versions.append(
                    FileVersion(
                        version_id=v.get("VersionId", ""),
                        modified=v.get("LastModified") or datetime.fromtimestamp(0),
                        size=int(v.get("Size", 0) or 0),
                        is_current=bool(v.get("IsLatest", False)),
                    )
                )
            # At most 1 000 entries per call: an object with more versions
            # continues on the next page.
            if past_target or not resp.get("IsTruncated"):
                return versions
            key_marker = resp.get("NextKeyMarker")
            marker = (key_marker, resp.get("NextVersionIdMarker"))
            if not key_marker or marker == (
                request.get("KeyMarker"),
                request.get("VersionIdMarker"),
            ):
                raise OSError(
                    errno.EPROTO,
                    f"S3 list_versions {path}: truncated listing without a new continuation marker"
                )
            request["KeyMarker"] = key_marker
            version_marker = resp.get("NextVersionIdMarker")
            if version_marker:
                request["VersionIdMarker"] = version_marker
            else:
                request.pop("VersionIdMarker", None)

    def open_version_read(self, path: str, version_id: str):
        """GET a specific VersionId of an object."""
        try:
            resp = self._s3.get_object(
                Bucket=self._bucket,
                Key=self._to_key(path),
                VersionId=version_id,
            )
            return _spool_body(resp["Body"], f"Cannot read {path}@{version_id}")
        except Exception as exc:
            raise _s3_error(exc, f"S3 get_object {path}@{version_id}: {exc}") from exc

    def copy(self, src: str, dst: str) -> None:
        """S3 CopyObject (UploadPartCopy above 5 GiB) — no client bytes."""
        dst_key = self._file_key(dst, "copy to")
        self._copy_key(self._to_key(src), dst_key, f"S3 copy {src} -> {dst} failed", path=src)

    # ------------------------------------------------------------------
    # S3-specific verbs (slice 5 of API_GAPS)
    # ------------------------------------------------------------------

    def presign(
        self,
        path: str,
        *,
        expires: int = 3600,
        method: str = "get_object",
        response_headers: dict | None = None,
    ) -> str:
        """Return a pre-signed URL for ``path`` valid for ``expires``
        seconds. ``method`` is the boto3 ``ClientMethod`` name —
        ``get_object`` for download links, ``put_object`` for
        upload-anywhere flows, ``delete_object``, etc.

        ``response_headers`` lets you override the ``Content-*``
        headers the bucket will return when the URL is fetched
        (handy for forcing a download filename:
        ``{"ResponseContentDisposition": 'attachment; filename="x.zip"'}``).
        """
        params: dict = {"Bucket": self._bucket, "Key": self._to_key(path)}
        if response_headers:
            params.update(response_headers)
        url = self._s3.generate_presigned_url(
            method,
            Params=params,
            ExpiresIn=int(expires),
        )
        log.info(
            "S3 presign: bucket=%s key=%s method=%s expires=%ds",
            self._bucket,
            self._to_key(path),
            method,
            int(expires),
        )
        return url

    def versioning_status(self) -> str:
        """Return the bucket's versioning state: ``Enabled``,
        ``Suspended``, or ``Disabled`` (boto3 returns ``""`` /
        absent for never-enabled buckets — we normalise that)."""
        try:
            resp = self._s3.get_bucket_versioning(Bucket=self._bucket)
        except Exception as exc:
            raise _s3_error(exc, f"S3 get_bucket_versioning: {exc}") from exc
        return resp.get("Status") or "Disabled"

    def lifecycle_get(self) -> list[dict]:
        """Return the bucket's lifecycle rules as a list of dicts.
        Empty list if no policy is configured (boto3 raises
        ``NoSuchLifecycleConfiguration`` in that case; we map it to
        ``[]`` so a script can branch on truthiness)."""
        try:
            resp = self._s3.get_bucket_lifecycle_configuration(
                Bucket=self._bucket,
            )
            return resp.get("Rules", []) or []
        except Exception as exc:  # noqa: BLE001
            # NoSuchLifecycleConfiguration → no rules. Anything else
            # surfaces as OSError with the original message.
            err = getattr(exc, "response", {}) or {}
            code = err.get("Error", {}).get("Code") if isinstance(err, dict) else ""
            if code == "NoSuchLifecycleConfiguration":
                return []
            raise _s3_error(exc, f"S3 get_bucket_lifecycle: {exc}") from exc

    def checksum_kinds(self, path: str = "", *, written: bool = False) -> frozenset[str]:
        """What :meth:`checksum` can answer: an ETag, as ``md5:`` or as the
        ``s3-etag:`` fingerprint - never a SHA-256. The transfer engine
        skips the HEAD request when neither can be compared with the
        other side (a local file has only its SHA-256)."""
        return frozenset({"md5", "s3-etag"})

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return the object ETag.

        ``md5:`` only where the ETag IS the content MD5: a single-part
        upload, unencrypted or SSE-S3. A multipart ETag (a composite of
        part MD5s followed by ``-<partcount>``) and the ETag of an SSE-KMS
        or SSE-C object are ``s3-etag:`` - a stable fingerprint for
        change detection, but no content hash: the same bytes stored
        again can carry another one.
        """
        try:
            resp = self._s3.head_object(Bucket=self._bucket, Key=self._to_key(path))
        except Exception as exc:
            raise _s3_error(exc, f"Cannot stat {path}: {exc}") from exc
        etag = (resp.get("ETag") or "").strip('"')
        if not etag:
            return ""
        sse = str(resp.get("ServerSideEncryption") or "").lower()
        is_content_md5 = (
            len(etag) == 32
            and all(c in "0123456789abcdefABCDEF" for c in etag)
            and not sse.startswith("aws:kms")
            and not resp.get("SSECustomerAlgorithm")
        )
        if not is_content_md5:
            return f"s3-etag:{etag}"
        return f"md5:{etag.lower()}"

    def _to_key(self, path: str) -> str:
        """Convert a UI path to an S3 object key (no leading slash)."""
        return path.lstrip("/")

    def _file_key(self, path: str, action: str) -> str:
        """The object key a FILE at *path* is written to. A key ending in
        "/" is a folder marker: data put there vanished from the listing
        (shown as a folder) and the next mkdir() replaced it with an empty
        marker. Such a destination - and the root - is refused."""
        key = self._to_key(path)
        if not key or key.endswith("/"):
            raise IsADirectoryError(
                errno.EISDIR,
                f"Cannot {action} {path}: a path ending in '/' names a folder, not a file",
                path,
            )
        return key

    def _to_prefix(self, path: str) -> str:
        """Convert a UI path to an S3 prefix for listing."""
        key = path.lstrip("/")
        if key and not key.endswith("/"):
            key += "/"
        return key
