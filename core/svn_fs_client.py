"""Subversion (SVN) read-only FileBackend.

Treats an SVN repository (file:// or http(s):// or svn(+ssh)://) as a
read-only filesystem. Implemented via subprocess calls to the system
``svn`` binary so we don't need a heavyweight Python SVN binding —
``pysvn`` ships C bindings that are awkward to package, and the
``svn`` Python wrapper still requires the CLI underneath.

Layout::

    /                       — branches/tags/trunk (whatever the
                              repo layout exposes at HEAD)
    /<dir>/                 — same as ``svn ls`` listing
    /<dir>/file             — content streamed via ``svn cat``

Capabilities & guard rails:

* **Read-only.** No commits, no checkouts, no working tree. The user
  edits via a real svn client; axross only browses + reads.
* **HEAD revision** by default. Profile field ``revision`` (or the
  URL fragment ``...?rev=42``) pins to a specific revision.
* **Auth via URL or profile.** ``svn://user:pass@host/path`` is
  sanitised to remove embedded credentials before we store or log the
  URL. Credentials are then passed to ``svn`` via ``--username`` /
  ``--password`` plus ``--non-interactive --no-auth-cache`` so the
  binary never prompts on the terminal and never writes credentials
  to ``~/.subversion``. Caveat: the portable SVN CLI exposes
  ``--password`` in process arguments while the command is running.
* **Listing parsed from XML** (``svn ls --xml``) — no fragile
  whitespace parsing. ``stat`` falls back to the parent dir's
  listing when the leaf is missing.
* **Subprocess timeout** clamped at 60s so a hung svn server can't
  freeze the UI thread.

Requires: the ``svn`` binary in ``$PATH``. Auto-detected via
``shutil.which`` at registry-build time; otherwise the protocol
shows up as unavailable.
"""

from __future__ import annotations

import io
import logging
import posixpath
import shutil
import subprocess
import threading
import urllib.parse
from datetime import datetime
from typing import IO, cast
from xml.etree import ElementTree as ET

from models.file_item import FileItem

log = logging.getLogger(__name__)

try:  # Prefer hardened XML parsing when the dependency is present.
    from defusedxml.common import DefusedXmlException
    from defusedxml.ElementTree import fromstring as _xml_fromstring

    _XML_PARSE_ERRORS = (ET.ParseError, DefusedXmlException)
except ImportError:  # pragma: no cover - exercised on minimal installs
    _xml_fromstring = ET.fromstring
    _XML_PARSE_ERRORS = (ET.ParseError,)

# Wall-clock ceiling on every svn invocation. SVN over high-latency
# links can be slow, but a hung server should never block the UI
# beyond this. Tunable per-call where needed.
_DEFAULT_TIMEOUT = 60.0

# Cap on size for `svn cat` streaming into memory. SVN doesn't have a
# range-fetch primitive over WebDAV/HTTP-mode in a portable CLI flag,
# so we have to load the full file. 256 MiB is the same ceiling we
# use for in-memory archive inspection.
_MAX_CAT_BYTES = 256 * 1024 * 1024


def _svn_available() -> bool:
    """Used by backend_registry to decide whether to expose SVN."""
    return shutil.which("svn") is not None


def _strip_url_password(url: str) -> tuple[str, str, str]:
    """Return ``(sanitised_url, username, password)`` for URL userinfo.

    We only rewrite URLs that actually contain a password. A plain
    ``svn+ssh://user@host/repo`` may rely on the userinfo for the SSH
    transport; stripping that would be a compatibility regression with
    no secret to protect. ``user:password@`` is different: the password
    would otherwise leak through ``self.name``, debug/error output and
    subprocess arguments as part of every SVN URL we pass to the CLI.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url, "", ""
    if not parts.scheme or not parts.netloc or parts.password is None:
        return url, "", ""

    username = urllib.parse.unquote(parts.username or "")
    password = urllib.parse.unquote(parts.password or "")
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return url, username, password

    if ":" in host and not host.startswith("["):
        clean_netloc = f"[{host}]"
    else:
        clean_netloc = host
    if port is not None:
        clean_netloc = f"{clean_netloc}:{port}"
    clean_url = urllib.parse.urlunsplit(
        (
            parts.scheme,
            clean_netloc,
            parts.path,
            parts.query,
            parts.fragment,
        )
    )
    return clean_url, username, password


class SvnFsSession:
    """Read-only Subversion-as-FS backend."""

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        url: str = "",
        username: str = "",
        password: str = "",
        revision: str = "HEAD",
        **_ignored,
    ):
        from core.proxy import warn_unsupported_proxy

        warn_unsupported_proxy(
            "SVN",
            _ignored.get("proxy_type", "none"),
            _ignored.get("proxy_host", ""),
            "The system svn binary is not wired through core.proxy.",
        )
        if not _svn_available():
            raise ImportError(
                "SVN backend requires the 'svn' command-line client. "
                "Install (Arch: pacman -S subversion · Debian: apt "
                "install subversion · Fedora: dnf install subversion)."
            )
        if not url:
            raise OSError("SVN backend needs a repository url= argument")
        clean_url, url_username, url_password = _strip_url_password(url)
        # Store only the sanitised URL. Credentials embedded in an SVN
        # URL otherwise spread into subprocess argv, session names and
        # logs because the URL is repeated for every ``svn`` operation.
        self._url = clean_url
        self._username = username or url_username
        self._password = password or url_password
        if self._password:
            log.warning(
                "SVN password authentication uses the svn CLI --password "
                "option; the password may be visible to local process "
                "inspectors while svn is running."
            )
        self._revision = revision or "HEAD"
        self._lock = threading.RLock()
        self._closed = False
        # Lazy probe: a cheap `svn info` to validate connectivity +
        # fail fast on bad creds before the user starts navigating.
        self._info()

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        if self._revision == "HEAD":
            return f"SVN: {self._url}"
        return f"SVN: {self._url}@{self._revision}"

    @property
    def connected(self) -> bool:
        return not self._closed

    def close(self) -> None:
        if not self._closed:
            log.info("SVN closing: %s", self._url)
        self._closed = True

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path) or "/"

    def _full_url(self, path: str) -> str:
        """Build the absolute SVN URL for ``path``. Path is relative
        to the repository root URL the session was configured with."""
        path = self.normalize(path)
        if path == "/":
            return self._url
        return self._url.rstrip("/") + path

    # ------------------------------------------------------------------
    # Subprocess helper
    # ------------------------------------------------------------------

    def _build_argv(self, *args: str) -> list[str]:
        argv = ["svn", "--non-interactive", "--no-auth-cache"]
        if self._username:
            argv += ["--username", self._username]
        if self._password:
            argv += ["--password", self._password]
        # SVN clients vary on whether they trust unknown server certs;
        # for HTTPS repos we leave validation strictly enabled — the
        # user can pin the cert via their system trust store.
        argv += list(args)
        return argv

    def _run(
        self,
        *args: str,
        timeout: float = _DEFAULT_TIMEOUT,
        binary: bool = False,
    ) -> bytes | str:
        """Run ``svn ...`` and return stdout. Raises OSError on
        non-zero exit so callers can let it surface as a directory
        listing failure.

        ``binary=True`` returns bytes (used for ``svn cat``);
        otherwise stdout is decoded as UTF-8 (with replacement)."""
        argv = self._build_argv(*args)
        log.debug(
            "SVN exec: %s",
            argv[:1]
            + [
                a if not isinstance(a, str) else ("<password>" if a == self._password and a else a)
                for a in argv[1:]
            ],
        )
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError(f"SVN command timed out after {timeout:.0f}s: {args[0]}") from exc
        except FileNotFoundError as exc:
            raise OSError("svn binary disappeared mid-session") from exc
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", "replace").strip()
            # SVN error codes worth surfacing distinctly:
            # E170000-range = remote-side errors (bad URL / 404)
            # E215004 = no creds
            # E230001 = SSL
            raise OSError(f"svn {args[0]} failed: {stderr or '(no stderr)'}")
        return (
            result.stdout
            if binary
            else result.stdout.decode(
                "utf-8",
                "replace",
            )
        )

    def _info(self) -> dict:
        """Cheap connectivity + auth probe at session start. Parses
        ``svn info --xml`` for the root URL the user supplied."""
        out = self._run(
            "info",
            self._url,
            "--xml",
            "--revision",
            self._revision,
            timeout=10.0,
        )
        try:
            root = _xml_fromstring(out)
        except _XML_PARSE_ERRORS as exc:
            raise OSError(f"svn info returned malformed XML: {exc}") from exc
        entry = root.find("entry")
        if entry is None:
            raise OSError("svn info: no <entry> in response")
        return {
            "kind": entry.get("kind", ""),
            "rev": entry.get("revision", ""),
            "root": entry.findtext("repository/root", ""),
        }

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        url = self._full_url(path)
        out = self._run(
            "ls",
            url,
            "--xml",
            "--revision",
            self._revision,
        )
        try:
            root = _xml_fromstring(out)
        except _XML_PARSE_ERRORS as exc:
            raise OSError(f"svn ls returned malformed XML: {exc}") from exc

        items: list[FileItem] = []
        for entry in root.iter("entry"):
            name = entry.findtext("name", "")
            if not name:
                continue
            kind = entry.get("kind", "file")
            size_raw = entry.findtext("size", "0")
            try:
                size = int(size_raw) if size_raw else 0
            except ValueError:
                size = 0
            commit = entry.find("commit")
            mtime: datetime
            if commit is not None:
                mtime_str = commit.findtext("date", "")
                mtime = _parse_iso(mtime_str) if mtime_str else (datetime.fromtimestamp(0))
                author = commit.findtext("author", "")
            else:
                mtime = datetime.fromtimestamp(0)
                author = ""
            items.append(
                FileItem(
                    name=name,
                    size=size if kind == "file" else 0,
                    modified=mtime,
                    permissions=0o755 if kind == "dir" else 0o644,
                    is_dir=(kind == "dir"),
                    is_link=False,
                    owner=author,
                )
            )
        # SVN does not guarantee ordering; sort to give the UI a
        # stable view.
        items.sort(key=lambda f: (not f.is_dir, f.name.lower()))
        return items

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="",
                is_dir=True,
                size=0,
                permissions=0o755,
                modified=datetime.fromtimestamp(0),
            )
        parent_path = self.parent(path)
        leaf = posixpath.basename(path.rstrip("/"))
        for entry in self.list_dir(parent_path):
            if entry.name == leaf:
                return entry
        raise FileNotFoundError(f"SVN: {path} not found")

    def is_dir(self, path: str) -> bool:
        try:
            return self.stat(path).is_dir
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def open_read(self, path: str) -> IO[bytes]:
        url = self._full_url(path)
        # svn cat doesn't stream incrementally over the CLI — we get
        # the whole blob in stdout. Cap to _MAX_CAT_BYTES so a hostile
        # repo can't OOM us.
        data = cast(
            bytes,
            self._run(
                "cat",
                url,
                "--revision",
                self._revision,
                timeout=_DEFAULT_TIMEOUT,
                binary=True,
            ),
        )
        if len(data) > _MAX_CAT_BYTES:
            raise OSError(
                f"SVN: {path} is {len(data)} bytes — exceeds the "
                f"{_MAX_CAT_BYTES // (1024 * 1024)} MiB read cap"
            )
        return io.BytesIO(data)

    # ------------------------------------------------------------------
    # FileBackend — write surface (refused, read-only backend)
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        raise OSError(
            "SVN backend is read-only. Use a real svn client to "
            "commit changes; axross only browses + reads."
        )

    def remove(self, path: str, recursive: bool = False) -> None:
        raise OSError("SVN backend is read-only.")

    def mkdir(self, path: str, mode: int = 0o755) -> None:
        raise OSError("SVN backend is read-only.")

    def rmdir(self, path: str) -> None:
        raise OSError("SVN backend is read-only.")

    def rename(self, src: str, dst: str) -> None:
        raise OSError("SVN backend is read-only.")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("SVN backend is read-only.")


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def _parse_iso(s: str) -> datetime:
    """SVN emits RFC 3339 / ISO 8601 with trailing Z. ``datetime``
    tolerates the form via ``fromisoformat`` once we replace ``Z``
    with ``+00:00``. Any parse failure → epoch (so the FileItem stays
    consistent with directories that have no commit metadata)."""
    if not s:
        return datetime.fromtimestamp(0)
    # Strip nanoseconds if present (Python only handles microseconds).
    if "." in s:
        head, _, tail = s.partition(".")
        # tail looks like '123456789Z' or '123456789+00:00'
        for marker in ("Z", "+", "-"):
            idx = tail.find(marker)
            if idx > 0:
                frac = tail[:6].ljust(6, "0")
                s = f"{head}.{frac}{tail[idx:]}"
                break
        else:
            frac = tail[:6].ljust(6, "0")
            s = f"{head}.{frac}"
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return datetime.fromtimestamp(0)
