"""S3-compatible backend implementing the FileBackend protocol.

Requires: pip install axross[s3]  (boto3>=1.28)

Works with AWS S3, MinIO, Ceph RGW, Wasabi, Cloudflare R2, etc.
"""
from __future__ import annotations

import io
import logging
import posixpath
import tempfile
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

from core.client_identity import HTTP_USER_AGENT

try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None  # type: ignore[assignment]
    UNSIGNED = None  # type: ignore[assignment]
    BotoConfig = None  # type: ignore[assignment]
    ClientError = Exception  # type: ignore[assignment,misc]


class _SpooledWriter:
    """Write to a temp file, then upload on close."""

    def __init__(self, s3_client, bucket: str, key: str):
        self._s3 = s3_client
        self._bucket = bucket
        self._key = key
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
        self._s3.upload_fileobj(self._buf, self._bucket, self._key)
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class S3Session:
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
                raw = raw[len(prefix):]
                break
        # Strip trailing path components (e.g. /index.html)
        raw = raw.split("/")[0]

        # Pattern: <bucket>.s3[.<region>].amazonaws.com
        m = re.match(
            r"^(.+)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com$", raw, re.IGNORECASE,
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
            raise ImportError(
                "S3 support requires boto3. "
                "Install with: pip install axross[s3]"
            )

        # Auto-parse S3 URLs into bucket + region
        bucket, auto_region = self._parse_s3_url(bucket, region or "us-east-1")
        if not region:
            region = auto_region

        self._bucket = bucket
        self._region = region or "us-east-1"
        self._access_key = access_key
        self._anonymous = not access_key and not secret_key

        kwargs: dict = {
            "service_name": "s3",
            "region_name": self._region,
        }
        # Replace botocore's default User-Agent so requests don't
        # advertise Boto3/python/OS/glibc. See docs/OPSEC.md #4.
        # Plus optional per-profile proxy via botocore's `proxies`
        # config field (accepts {'http': '...', 'https': '...'} as
        # produced by ``core.proxy.build_requests_proxies``).
        from core.proxy import build_requests_proxies
        proxies = build_requests_proxies(
            proxy_type, proxy_host, int(proxy_port or 0),
            proxy_username, proxy_password,
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
            kwargs["config"] = base_config.merge(
                BotoConfig(signature_version=UNSIGNED)
            )
        else:
            kwargs["config"] = base_config
        if endpoint:
            kwargs["endpoint_url"] = endpoint

        # Validate bucket name before connecting
        import re
        if not re.match(r'^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$', bucket):
            raise OSError(
                f"Invalid S3 bucket name '{bucket}'. "
                "Bucket names must be 3-63 characters, lowercase letters, digits, "
                "hyphens, and dots only. If you have a full URL, just paste it — "
                "it will be parsed automatically."
            )

        self._s3 = boto3.client(**kwargs)

        # Test connection — handle region redirects and try multiple methods
        self._connect_with_redirect(bucket, kwargs)

        log.info("S3 connected: %s (region=%s, endpoint=%s, anonymous=%s)",
                 bucket, self._region, endpoint or "default", self._anonymous)

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
                    self._s3 = boto3.client(**kwargs)
                    try:
                        self._test_bucket(bucket)
                        return
                    except ClientError as e2:
                        e = e2
                        code = e.response.get("Error", {}).get("Code", "")

            if code in ("NoSuchBucket", "404"):
                raise OSError(f"S3 bucket '{bucket}' does not exist") from e
            if code in ("AccessDenied", "403", "AllAccessDisabled"):
                raise OSError(
                    f"Access denied to S3 bucket '{bucket}'. "
                    "Check credentials or try anonymous access."
                ) from e
            raise OSError(f"Cannot access S3 bucket '{bucket}': {e}") from e
        except Exception as e:
            raise OSError(f"Cannot access S3 bucket '{bucket}': {e}") from e

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
        except Exception:
            return False

    def close(self) -> None:
        pass  # boto3 client doesn't need explicit close

    def disconnect(self) -> None:
        self.close()

    def list_dir(self, path: str) -> list[FileItem]:
        prefix = self._to_prefix(path)
        items: list[FileItem] = []

        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            pages = paginator.paginate(
                Bucket=self._bucket,
                Prefix=prefix,
                Delimiter="/",
            )

            for page in pages:
                # Directories (common prefixes)
                for cp in page.get("CommonPrefixes", []):
                    dir_prefix = cp["Prefix"]
                    dir_name = dir_prefix[len(prefix):].rstrip("/")
                    if dir_name:
                        items.append(FileItem(
                            name=dir_name,
                            is_dir=True,
                        ))

                # Files (objects)
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    name = key[len(prefix):]
                    if not name or name.endswith("/"):
                        continue  # Skip the prefix itself or directory markers
                    items.append(FileItem(
                        name=name,
                        size=obj.get("Size", 0),
                        modified=obj.get("LastModified", datetime.fromtimestamp(0)),
                    ))

        except (ClientError, Exception) as e:
            raise OSError(f"Cannot list {path}: {e}") from e

        return items

    def stat(self, path: str) -> FileItem:
        key = self._to_key(path)
        name = posixpath.basename(path.rstrip("/")) or path

        # Check if it's a "directory" (has objects with this prefix)
        if not key or key.endswith("/"):
            return FileItem(name=name, is_dir=True)

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
                raise OSError(f"Cannot stat {path}: {e}") from e

        # Check if it's a directory prefix
        try:
            resp = self._s3.list_objects_v2(
                Bucket=self._bucket,
                Prefix=key.rstrip("/") + "/",
                MaxKeys=1,
            )
            if resp.get("KeyCount", 0) > 0:
                return FileItem(name=name, is_dir=True)
        except (ClientError, Exception) as e:
            raise OSError(f"Cannot stat {path}: {e}") from e

        raise OSError(f"Not found: {path}")

    def is_dir(self, path: str) -> bool:
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
            return resp.get("KeyCount", 0) > 0
        except (ClientError, Exception):
            return False

    def exists(self, path: str) -> bool:
        key = self._to_key(path)
        if not key:
            return True  # Root always exists

        # Check as object
        try:
            self._s3.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError:
            pass

        # Check as directory prefix
        return self.is_dir(path)

    def mkdir(self, path: str) -> None:
        """Create a directory marker (zero-byte object ending with /)."""
        if self._anonymous:
            raise OSError("Cannot write to anonymous/public S3 bucket (read-only)")
        key = self._to_key(path).rstrip("/") + "/"
        try:
            self._s3.put_object(Bucket=self._bucket, Key=key, Body=b"")
        except (ClientError, Exception) as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        if self._anonymous:
            raise OSError("Cannot write to anonymous/public S3 bucket (read-only)")
        key = self._to_key(path)

        if self.is_dir(path):
            if not recursive:
                # Just remove the directory marker
                try:
                    self._s3.delete_object(Bucket=self._bucket, Key=key.rstrip("/") + "/")
                except (ClientError, Exception) as e:
                    raise OSError(f"Cannot remove {path}: {e}") from e
            else:
                self._remove_prefix(key.rstrip("/") + "/")
        else:
            try:
                self._s3.delete_object(Bucket=self._bucket, Key=key)
            except (ClientError, Exception) as e:
                raise OSError(f"Cannot remove {path}: {e}") from e

    def _remove_prefix(self, prefix: str) -> None:
        """Delete all objects under a prefix."""
        paginator = self._s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=self._bucket, Prefix=prefix)

        for page in pages:
            objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if objects:
                self._s3.delete_objects(
                    Bucket=self._bucket,
                    Delete={"Objects": objects},
                )

    def rename(self, src: str, dst: str) -> None:
        """S3 doesn't support rename — copy + delete."""
        if self._anonymous:
            raise OSError("Cannot write to anonymous/public S3 bucket (read-only)")
        src_key = self._to_key(src)
        dst_key = self._to_key(dst)

        if self.is_dir(src):
            # Rename all objects under the prefix
            old_prefix = src_key.rstrip("/") + "/"
            new_prefix = dst_key.rstrip("/") + "/"
            paginator = self._s3.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=self._bucket, Prefix=old_prefix)

            for page in pages:
                for obj in page.get("Contents", []):
                    old_key = obj["Key"]
                    new_key = new_prefix + old_key[len(old_prefix):]
                    try:
                        self._s3.copy_object(
                            Bucket=self._bucket,
                            CopySource={"Bucket": self._bucket, "Key": old_key},
                            Key=new_key,
                        )
                        self._s3.delete_object(Bucket=self._bucket, Key=old_key)
                    except (ClientError, Exception) as e:
                        raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e
        else:
            try:
                self._s3.copy_object(
                    Bucket=self._bucket,
                    CopySource={"Bucket": self._bucket, "Key": src_key},
                    Key=dst_key,
                )
                self._s3.delete_object(Bucket=self._bucket, Key=src_key)
            except (ClientError, Exception) as e:
                raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    def open_read(self, path: str) -> IO[bytes]:
        key = self._to_key(path)
        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=key)
            buf = io.BytesIO(resp["Body"].read())
            buf.seek(0)
            return buf
        except (ClientError, Exception) as e:
            raise OSError(f"Cannot read {path}: {e}") from e

    # Hard cap on "download existing then re-upload" append semantics.
    # Above this the operation is almost certainly not what the user
    # wanted and a malicious backend returning a huge file would OOM
    # the client.
    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024  # 256 MiB

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if self._anonymous:
            raise OSError("Cannot write to anonymous/public S3 bucket (read-only)")
        key = self._to_key(path)
        if append:
            # S3 doesn't support append — download, concatenate, re-upload.
            # Bounded so a hostile object can't OOM us.
            cap = self._MAX_APPEND_EXISTING_SIZE
            try:
                handle = self.open_read(path)
                existing = handle.read(cap + 1)
                handle.close()
            except OSError:
                existing = b""
            if len(existing) > cap:
                raise OSError(
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
        raise OSError("S3 does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("S3 does not support symlinks")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        """S3 ListObjectVersions. Requires versioning enabled on
        the bucket; returns [] for unversioned buckets."""
        from models.file_version import FileVersion
        try:
            resp = self._s3.list_object_versions(
                Bucket=self._bucket,
                Prefix=self._to_key(path),
            )
        except Exception as exc:
            raise OSError(f"S3 list_versions {path}: {exc}") from exc
        versions = []
        target_key = self._to_key(path)
        for v in resp.get("Versions", []):
            if v.get("Key") != target_key:
                continue
            versions.append(FileVersion(
                version_id=v.get("VersionId", ""),
                modified=v.get("LastModified") or datetime.fromtimestamp(0),
                size=int(v.get("Size", 0) or 0),
                is_current=bool(v.get("IsLatest", False)),
            ))
        return versions

    def open_version_read(self, path: str, version_id: str):
        """GET a specific VersionId of an object."""
        import io
        try:
            resp = self._s3.get_object(
                Bucket=self._bucket,
                Key=self._to_key(path),
                VersionId=version_id,
            )
        except Exception as exc:
            raise OSError(
                f"S3 get_object {path}@{version_id}: {exc}"
            ) from exc
        return io.BytesIO(resp["Body"].read())

    def copy(self, src: str, dst: str) -> None:
        """S3 CopyObject — no client bytes."""
        try:
            self._s3.copy_object(
                Bucket=self._bucket,
                Key=self._to_key(dst),
                CopySource={"Bucket": self._bucket, "Key": self._to_key(src)},
            )
        except Exception as exc:
            raise OSError(f"S3 copy {src} -> {dst} failed: {exc}") from exc

    # ------------------------------------------------------------------
    # S3-specific verbs (slice 5 of API_GAPS)
    # ------------------------------------------------------------------

    def presign(self, path: str, *, expires: int = 3600,
                method: str = "get_object",
                response_headers: dict | None = None) -> str:
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
        return self._s3.generate_presigned_url(
            method, Params=params, ExpiresIn=int(expires),
        )

    def versioning_status(self) -> str:
        """Return the bucket's versioning state: ``Enabled``,
        ``Suspended``, or ``Disabled`` (boto3 returns ``""`` /
        absent for never-enabled buckets — we normalise that)."""
        try:
            resp = self._s3.get_bucket_versioning(Bucket=self._bucket)
        except Exception as exc:
            raise OSError(f"S3 get_bucket_versioning: {exc}") from exc
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
            raise OSError(f"S3 get_bucket_lifecycle: {exc}") from exc

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return the object ETag.

        For non-multipart uploads this IS an MD5 hash of the content.
        For multipart uploads the ETag is a composite of part-MD5s
        followed by ``-<partcount>`` — still useful as a stable
        fingerprint for change detection. Prefix indicates source.
        """
        try:
            resp = self._s3.head_object(Bucket=self._bucket,
                                        Key=self._to_key(path))
        except Exception as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        etag = (resp.get("ETag") or "").strip('"')
        if not etag:
            return ""
        if "-" in etag:
            return f"s3-etag:{etag}"
        return f"md5:{etag}"

    def _to_key(self, path: str) -> str:
        """Convert a UI path to an S3 object key (no leading slash)."""
        return path.lstrip("/")

    def _to_prefix(self, path: str) -> str:
        """Convert a UI path to an S3 prefix for listing."""
        key = path.lstrip("/")
        if key and not key.endswith("/"):
            key += "/"
        return key
