"""WebDAV backend implementing the FileBackend protocol.

Requires: pip install axross[webdav]  (webdavclient3>=3.14)
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

try:
    from webdav3.client import Client as WebDAVClient
    from webdav3.exceptions import WebDavException
except ImportError:
    WebDAVClient = None  # type: ignore[assignment,misc]
    WebDavException = Exception  # type: ignore[assignment,misc]


def _build_requests_proxies(
    proxy_type: str, host: str, port: int,
    username: str = "", password: str = "",
) -> dict[str, str]:
    """Build a ``requests``-style proxies mapping from ProxyConfig fields.

    Returns an empty dict when no proxy is configured. The resulting
    dict is suitable to assign to ``requests.Session().proxies``.

    Routes through the same SSRF guard as core/proxy.py so the
    WebDAV path (via requests.Session) gets the same Layer 6
    defense as the SSH / Telnet path.
    """
    if not proxy_type or proxy_type == "none" or not host:
        return {}
    # Apply the SSRF guard here too — requests' own proxy path
    # bypasses core/proxy.create_proxy_socket.
    from core.proxy import _assert_proxy_host_not_private
    _assert_proxy_host_not_private(host)
    if proxy_type == "http":
        scheme = "http"
    elif proxy_type == "socks4":
        scheme = "socks4"
    elif proxy_type == "socks5":
        scheme = "socks5h"  # 'h' = remote DNS via the proxy (safer)
    else:
        raise ValueError(f"Unknown proxy type: {proxy_type}")
    from urllib.parse import quote
    cred = ""
    if username:
        cred = quote(username, safe="")
        if password:
            cred += ":" + quote(password, safe="")
        cred += "@"
    url = f"{scheme}://{cred}{host}:{int(port)}"
    return {"http": url, "https": url}


def _redact_proxy_url(url: str) -> str:
    """Strip userinfo for logging (``scheme://user:pw@host:port`` →
    ``scheme://host:port``)."""
    if "://" not in url or "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    _creds, _, hostpart = rest.rpartition("@")
    return f"{scheme}://<REDACTED>@{hostpart}"


class _SpooledWriter:
    """Write to a temp file, then upload on close."""

    def __init__(self, client: WebDAVClient, remote_path: str):
        self._client = client
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
        self._client.upload_to(self._buf, self._remote_path)
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


class WebDavSession:
    """WebDAV backend implementing the FileBackend protocol.

    Uses webdavclient3. Compatible with Nextcloud, ownCloud, Apache mod_dav, etc.
    """

    def __init__(
        self,
        url: str,
        username: str = "",
        password: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if WebDAVClient is None:
            raise ImportError(
                "WebDAV support requires webdavclient3. "
                "Install with: pip install axross[webdav]"
            )

        self._url = url.rstrip("/")
        self._username = username
        self._password = password
        self._proxy = _build_requests_proxies(
            proxy_type, proxy_host, proxy_port,
            proxy_username, proxy_password,
        )

        options = {
            "webdav_hostname": self._url,
            "webdav_login": username,
            "webdav_password": password,
        }
        self._options = options
        self._client = WebDAVClient(options)
        self._apply_proxy(self._client)
        self._apply_user_agent(self._client)

        # Test connection
        try:
            self._client.list("/")
        except Exception as e:
            raise OSError(f"Cannot connect to WebDAV server: {e}") from e

        log.info("WebDAV connected: %s@%s", username, url)

    def _reconnect(self) -> None:
        """Re-create the WebDAV client (fixes stale session issues)."""
        self._client = WebDAVClient(self._options)
        self._apply_proxy(self._client)
        self._apply_user_agent(self._client)
        log.debug("WebDAV client re-created for %s", self._url)

    @staticmethod
    def _apply_user_agent(client) -> None:
        """Override the default requests.Session User-Agent so WebDAV
        traffic doesn't identify itself as ``python-requests/X.Y.Z``.
        See docs/OPSEC.md #4.
        """
        from core.client_identity import HTTP_USER_AGENT
        sess = getattr(client, "session", None)
        if sess is not None and hasattr(sess, "headers"):
            sess.headers["User-Agent"] = HTTP_USER_AGENT

    def _apply_proxy(self, client) -> None:
        """Push proxy settings onto the webdav3.Client's requests.Session.

        webdavclient3 exposes ``session`` as a plain
        :class:`requests.Session`; assigning its ``proxies`` dict is
        enough for every subsequent GET/PUT/PROPFIND to route through
        the proxy. SOCKS schemes need ``requests[socks]`` (PySocks),
        which axross already depends on via ``core.proxy``.
        """
        if not self._proxy:
            return
        sess = getattr(client, "session", None)
        if sess is None:
            log.warning(
                "WebDAV: could not apply proxy — client has no .session"
            )
            return
        sess.proxies = dict(self._proxy)
        log.info(
            "WebDAV via proxy: %s",
            {k: _redact_proxy_url(v) for k, v in self._proxy.items()},
        )

    @property
    def name(self) -> str:
        return f"{self._username}@{self._url} (WebDAV)"

    @property
    def connected(self) -> bool:
        try:
            self._client.list("/")
            return True
        except Exception:
            return False

    def close(self) -> None:
        pass  # webdavclient3 doesn't have explicit close

    def disconnect(self) -> None:
        self.close()

    def list_dir(self, path: str) -> list[FileItem]:
        path = self._norm(path)
        try:
            entries = self._client.list(path, get_info=True)
        except (WebDavException, Exception):
            # webdavclient3 caches OPTIONS results and can get into a stale
            # state after concurrent use.  Reconnect and retry once.
            try:
                self._reconnect()
                entries = self._client.list(path, get_info=True)
            except (WebDavException, Exception) as e:
                raise OSError(f"Cannot list {path}: {e}") from e

        items: list[FileItem] = []
        for entry in entries:
            name = entry.get("name") or ""
            # webdavclient3 may return name=None; extract from path instead
            if not name:
                entry_path = entry.get("path", "")
                name = posixpath.basename(entry_path.rstrip("/"))
            if not name or name == posixpath.basename(path.rstrip("/")):
                continue  # Skip self-reference

            is_dir = entry.get("isdir", False)
            if isinstance(is_dir, str):
                is_dir = is_dir.lower() in ("true", "1")

            size = 0
            raw_size = entry.get("size", 0)
            if raw_size:
                try:
                    size = int(raw_size)
                except (ValueError, TypeError):
                    pass

            modified = datetime.fromtimestamp(0)
            raw_modified = entry.get("modified", "")
            if raw_modified:
                for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        modified = datetime.strptime(raw_modified, fmt)
                        break
                    except ValueError:
                        continue

            items.append(FileItem(
                name=name,
                size=size,
                modified=modified,
                is_dir=is_dir,
            ))
        return items

    def stat(self, path: str) -> FileItem:
        path = self._norm(path)
        try:
            info = self._client.info(path)
        except (WebDavException, Exception):
            try:
                self._reconnect()
                info = self._client.info(path)
            except (WebDavException, Exception) as e:
                raise OSError(f"Cannot stat {path}: {e}") from e

        name = posixpath.basename(path.rstrip("/")) or path

        # webdavclient3's info() does not populate an "isdir" key for
        # Apache mod_dav responses — instead the HTTP content-type is
        # "httpd/unix-directory" (or similar "*/directory"). We honour
        # both signals so the backend matches what list_dir() reports.
        is_dir = info.get("isdir", None)
        if isinstance(is_dir, str):
            is_dir = is_dir.lower() in ("true", "1")
        if is_dir is None or is_dir is False:
            ctype = (info.get("content_type") or "").lower()
            if ctype.endswith("/directory") or ctype == "httpd/unix-directory":
                is_dir = True
            else:
                is_dir = bool(is_dir)

        size = 0
        raw_size = info.get("size", 0)
        if raw_size:
            try:
                size = int(raw_size)
            except (ValueError, TypeError):
                pass

        modified = datetime.fromtimestamp(0)
        raw_modified = info.get("modified", "")
        if raw_modified:
            for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
                try:
                    modified = datetime.strptime(raw_modified, fmt)
                    break
                except ValueError:
                    continue

        return FileItem(name=name, size=size, modified=modified, is_dir=is_dir)

    def is_dir(self, path: str) -> bool:
        try:
            return self._client.is_dir(self._norm(path))
        except (WebDavException, Exception):
            try:
                self._reconnect()
                return self._client.is_dir(self._norm(path))
            except (WebDavException, Exception):
                return False

    def exists(self, path: str) -> bool:
        try:
            return self._client.check(self._norm(path))
        except (WebDavException, Exception):
            try:
                self._reconnect()
                return self._client.check(self._norm(path))
            except (WebDavException, Exception):
                return False

    def mkdir(self, path: str) -> None:
        try:
            self._client.mkdir(self._norm(path))
        except (WebDavException, Exception):
            try:
                self._reconnect()
                self._client.mkdir(self._norm(path))
            except (WebDavException, Exception) as e:
                raise OSError(f"Cannot create directory {path}: {e}") from e

    def remove(self, path: str, recursive: bool = False) -> None:
        try:
            self._client.clean(self._norm(path))
        except (WebDavException, Exception):
            try:
                self._reconnect()
                self._client.clean(self._norm(path))
            except (WebDavException, Exception) as e:
                raise OSError(f"Cannot remove {path}: {e}") from e

    def rename(self, src: str, dst: str) -> None:
        try:
            self._client.move(self._norm(src), self._norm(dst))
        except (WebDavException, Exception):
            try:
                self._reconnect()
                self._client.move(self._norm(src), self._norm(dst))
            except (WebDavException, Exception) as e:
                raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    def open_read(self, path: str) -> IO[bytes]:
        buf = io.BytesIO()
        try:
            self._client.download_from(buf, self._norm(path))
        except (WebDavException, Exception):
            buf = io.BytesIO()
            try:
                self._reconnect()
                self._client.download_from(buf, self._norm(path))
            except (WebDavException, Exception) as e:
                raise OSError(f"Cannot read {path}: {e}") from e
        buf.seek(0)
        return buf

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            # WebDAV doesn't support append — download, concatenate, re-upload
            try:
                with self.open_read(path) as f:
                    existing = f.read()
            except OSError:
                existing = b""
            writer = _SpooledWriter(self._client, self._norm(path))
            writer.write(existing)
            return writer
        return _SpooledWriter(self._client, self._norm(path))

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
        raise OSError("WebDAV does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("WebDAV does not support symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """WebDAV COPY method — server-side, no client bytes."""
        try:
            self._client.copy(remote_path_from=self._norm(src),
                              remote_path_to=self._norm(dst))
        except Exception as exc:
            raise OSError(f"WebDAV copy {src} -> {dst} failed: {exc}") from exc

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return the DAV:getetag as a fingerprint.

        Strong etags on mod_dav are typically inode-based and change
        whenever the file content changes, so they work as a content
        fingerprint even though they are not technically a hash.
        Nextcloud additionally exposes oc:checksum with real SHA1 /
        MD5 / ADLER32 — if present and matching the requested
        algorithm, we return that instead.
        """
        try:
            info = self._client.info(self._norm(path))
        except Exception as exc:
            raise OSError(f"Cannot stat {path}: {exc}") from exc
        # Nextcloud-style checksum comes through as "oc:checksum" if
        # the server exposes it.
        oc_sum = info.get("oc:checksum") or info.get("checksum") or ""
        if oc_sum and ":" in oc_sum:
            algo, hexpart = oc_sum.split(":", 1)
            if algo.lower() == algorithm.lower():
                return f"{algorithm}:{hexpart.lower()}"
        etag = (info.get("etag") or "").strip('"')
        if etag:
            return f"etag:{etag}"
        return ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        # Try RFC 4331 quota properties via raw PROPFIND request
        try:
            import requests
            # Parse the remote WebDAV response with defusedxml to block XXE,
            # billion-laughs, and external-entity attacks from a hostile /
            # compromised server. We DO NOT fall back to the stdlib parser:
            # fail-closed is the right call for a trust boundary crossing
            # (server could be compromised / malicious), and defusedxml is
            # in requirements.txt.
            try:
                from defusedxml.ElementTree import fromstring as _xml_fromstring
            except ImportError:
                log.warning(
                    "defusedxml is required for disk_usage() on WebDAV "
                    "(install via `pip install defusedxml`). Skipping "
                    "quota query."
                )
                return (0, 0, 0)

            propfind_body = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<D:propfind xmlns:D="DAV:">'
                '<D:prop>'
                '<D:quota-available-bytes/>'
                '<D:quota-used-bytes/>'
                '</D:prop>'
                '</D:propfind>'
            )
            url = self._url.rstrip("/") + self._norm(path)
            resp = requests.request(
                "PROPFIND",
                url,
                data=propfind_body,
                headers={
                    "Content-Type": "application/xml",
                    "Depth": "0",
                },
                auth=(self._username, self._password) if self._username else None,
                timeout=10,
            )
            if resp.status_code in (207, 200):
                ns = {"D": "DAV:"}
                tree = _xml_fromstring(resp.content)
                avail_el = tree.find(".//" + "{DAV:}quota-available-bytes")
                used_el = tree.find(".//" + "{DAV:}quota-used-bytes")
                if avail_el is not None and used_el is not None:
                    available = int(avail_el.text or "0")
                    used = int(used_el.text or "0")
                    total = used + available
                    return (total, used, available)
                log.debug("WebDAV server did not return quota properties")
            else:
                log.debug("WebDAV PROPFIND for quota returned status %d", resp.status_code)
        except ImportError:
            log.debug("requests library not available for WebDAV quota query")
        except Exception as e:
            log.debug("WebDAV disk_usage query failed: %s", e)
        return (0, 0, 0)

    @staticmethod
    def _norm(path: str) -> str:
        """Ensure path has leading slash and no trailing slash (except root)."""
        if not path.startswith("/"):
            path = "/" + path
        return path
