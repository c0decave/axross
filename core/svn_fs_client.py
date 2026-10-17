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
  URL. Credentials are then passed to ``svn`` via ``--username`` and
  ``--password-from-stdin`` (svn >= 1.10) plus ``--non-interactive
  --no-auth-cache`` so the binary never prompts on the terminal, never
  writes credentials to ``~/.subversion`` and the password never shows
  up in the process arguments other local users can read.
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

import errno
import io
import logging
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import threading
import urllib.parse
from datetime import datetime
from typing import IO
from xml.etree import ElementTree as ET

from core.backend import SessionLifecycle
from core.subprocess_env import clean_child_env
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
#: Bytes per read of svn cat's output, and of its stderr kept for the error.
_CAT_CHUNK = 256 * 1024
_STDERR_KEEP = 64 * 1024
# SVN_ERR_FS_NOT_FOUND: "URL '...' non-existent in revision N". svn ls
# prints it as a warning (W160013) ahead of E200009, others as E160013.
_SVN_NOT_FOUND = re.compile(r"\b[EW]160013\b")
#: What stays unencoded in a path of an SVN URL: "/" and the sub-delims
#: ("@" for the peg revision rule of _full_url).
_URL_SAFE = "/@!$&'()*+,;=:~"


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


class SvnFsSession(SessionLifecycle):
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
        self._tunnel = None
        self._config_dir = ""
        self._connect_url = ""
        self._child_env: dict = {}
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
        if "\n" in self._password or "\r" in self._password:
            # ``--password-from-stdin`` reads a single line. Refuse rather
            # than fall back to ``--password``, which would expose the
            # secret in argv.
            raise OSError("SVN password must not contain a line break")
        self._setup_proxy(clean_url, _ignored)
        self._revision = revision or "HEAD"
        self._lock = threading.RLock()
        self._closed = False
        # Lazy probe: a cheap `svn info` to validate connectivity +
        # fail fast on bad creds before the user starts navigating.
        try:
            self._info()
        except BaseException:
            self._teardown_proxy()
            raise

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
        self._teardown_proxy()

    def _setup_proxy(self, url: str, kwargs: dict) -> None:
        """Wire the profile proxy into the ``svn`` child process.

        * ``svn://`` and ``svn+ssh://``: a loopback tunnel; the URL the
          binary sees points at it (ssh keeps the real host identity via
          ``HostKeyAlias``).
        * ``http(s)://``: only HTTP proxies exist in the svn client; the
          settings go into a private ``servers`` file so the proxy
          password never lands in argv. SOCKS, TLS-to-the-proxy and NTLM
          proxies are fronted by the loopback shim (``effective_http_proxy``).
        * ``file://``: local, nothing to proxy.
        """
        from core import proxy as proxy_mod

        cfg = proxy_mod.proxy_config_from_kwargs(kwargs)
        self._connect_url = url
        if cfg is None:
            return
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme in ("http", "https"):
            self._write_servers_file(proxy_mod.effective_http_proxy(cfg))
            return
        if scheme not in ("svn", "svn+ssh"):
            return
        host = parts.hostname or ""
        if not host or host.startswith("-"):
            raise OSError(f"SVN remote host {host!r} is not acceptable")
        port = parts.port or (3690 if scheme == "svn" else 22)
        self._tunnel = proxy_mod.LocalTunnel(cfg, host, port).start()
        userinfo = parts.netloc.rpartition("@")[0]
        netloc = f"{userinfo + '@' if userinfo else ''}{self._tunnel.host}:{self._tunnel.port}"
        self._connect_url = urllib.parse.urlunsplit(
            (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
        )
        if scheme == "svn+ssh":
            self._child_env["SVN_SSH"] = f"ssh -o HostKeyAlias={shlex.quote(host)}"

    def _write_servers_file(self, cfg) -> None:
        import tempfile

        from core.proxy import _assert_proxy_host_not_private, _validate_proxy_port

        _assert_proxy_host_not_private(cfg.host, cfg.port)
        self._config_dir = tempfile.mkdtemp(prefix="axross-svn-")  # 0700
        lines = [
            "[global]",
            f"http-proxy-host = {cfg.host}",
            f"http-proxy-port = {_validate_proxy_port(cfg.port)}",
        ]
        if cfg.username:
            lines.append(f"http-proxy-username = {cfg.username}")
        if cfg.password:
            lines.append(f"http-proxy-password = {cfg.password}")
        path = os.path.join(self._config_dir, "servers")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def _teardown_proxy(self) -> None:
        if self._tunnel is not None:
            self._tunnel.close()
        if self._config_dir:
            shutil.rmtree(self._config_dir, ignore_errors=True)
            self._config_dir = ""

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
            return self._connect_url
        # svn decodes %XX in a URL: the raw name "100%25.txt" read the
        # file "100%.txt" (measured with svn 1.14). Every name is sent
        # percent-encoded; "@" stays as it is for the peg rule below.
        url = self._connect_url.rstrip("/") + urllib.parse.quote(path, safe=_URL_SAFE)
        # svn reads what follows the last "@" of a target as a peg
        # revision ("icon@2x.png" -> "icon" at revision "2x.png"); a
        # trailing "@" (empty peg) keeps the "@" in the name.
        return url + "@" if "@" in path else url

    # ------------------------------------------------------------------
    # Subprocess helper
    # ------------------------------------------------------------------

    def _build_argv(self, *args: str) -> list[str]:
        argv = ["svn", "--non-interactive", "--no-auth-cache"]
        if self._username:
            argv += ["--username", self._username]
        if self._password:
            # The secret itself is written to the child's stdin by
            # ``_run``; argv is world-readable via /proc/<pid>/cmdline.
            argv += ["--password-from-stdin"]
        # SVN clients vary on whether they trust unknown server certs;
        # for HTTPS repos we leave validation strictly enabled — the
        # user can pin the cert via their system trust store.
        if self._config_dir:
            argv += ["--config-dir", self._config_dir]
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
        log.debug("SVN exec: %s", argv)
        try:
            result = subprocess.run(
                argv,
                input=(self._password + "\n").encode("utf-8") if self._password else None,
                capture_output=True,
                timeout=timeout,
                check=False,
                env=clean_child_env(**self._child_env),
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError(f"SVN command timed out after {timeout:.0f}s: {args[0]}") from exc
        except FileNotFoundError as exc:
            raise OSError("svn binary disappeared mid-session") from exc
        if result.returncode != 0:
            self._raise_failure(args, result.stderr)
        return (
            result.stdout
            if binary
            else result.stdout.decode(
                "utf-8",
                "replace",
            )
        )

    def _raise_failure(self, args, stderr_raw: bytes) -> None:
        stderr = stderr_raw.decode("utf-8", "replace").strip()
        if self._password and "password-from-stdin" in stderr:
            raise OSError(
                "svn client is too old: password authentication needs "
                "svn 1.10 or newer (--password-from-stdin)"
            )
        # SVN error codes worth surfacing distinctly:
        # E170000-range = remote-side errors (bad URL / 404)
        # E215004 = no creds
        # E230001 = SSL
        message = f"svn {args[0]} failed: {stderr or '(no stderr)'}"
        if _SVN_NOT_FOUND.search(stderr):
            # The one answer exists() and is_dir() read as "absent".
            raise FileNotFoundError(errno.ENOENT, message)
        raise OSError(message)

    def _run_capped(self, *args: str, cap: int, timeout: float = _DEFAULT_TIMEOUT) -> bytes:
        """``svn ...``'s stdout, read as it comes and refused - the
        process killed - as soon as it passes *cap* bytes. subprocess.run
        would collect all of it (and wait for svn) before a cap could be
        checked."""
        argv = self._build_argv(*args)
        log.debug("SVN exec: %s", argv)
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if self._password else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=clean_child_env(**self._child_env),
            )
        except FileNotFoundError as exc:
            raise OSError("svn binary disappeared mid-session") from exc
        out = bytearray()
        err = bytearray()
        over = threading.Event()

        def pump_out() -> None:
            while True:
                chunk = proc.stdout.read1(_CAT_CHUNK)
                if not chunk:
                    return
                if len(out) + len(chunk) > cap:
                    over.set()
                    return
                out.extend(chunk)

        def pump_err() -> None:
            for line in iter(proc.stderr.readline, b""):
                if len(err) < _STDERR_KEEP:
                    err.extend(line)

        readers = [
            threading.Thread(target=pump_out, daemon=True),
            threading.Thread(target=pump_err, daemon=True),
        ]
        try:
            for reader in readers:
                reader.start()
            if self._password:
                try:
                    proc.stdin.write((self._password + "\n").encode("utf-8"))
                    proc.stdin.close()
                except OSError:
                    pass  # svn ended early; its exit status says why
            readers[0].join(timeout)
            if over.is_set():
                raise OSError(f"svn {args[0]}: more than the {cap // (1024 * 1024)} MiB read cap")
            if readers[0].is_alive():
                raise OSError(f"SVN command timed out after {timeout:.0f}s: {args[0]}")
            code = proc.wait(timeout=10)
            readers[1].join(2)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            for stream in (proc.stdout, proc.stderr):
                stream.close()
        if code != 0:
            self._raise_failure(args, bytes(err))
        return bytes(out)

    def _info(self) -> dict:
        """Cheap connectivity + auth probe at session start. Parses
        ``svn info --xml`` for the root URL the user supplied."""
        out = self._run(
            "info",
            self._connect_url,
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
        """False only for "not found"; a listing that failed (server
        unreachable, credentials refused, timeout) is an OSError."""
        try:
            return self.stat(path).is_dir
        except FileNotFoundError:
            return False

    def exists(self, path: str) -> bool:
        """False only for "not found"; any other failure is an OSError -
        server_side_copy(overwrite=False) takes False as its go-ahead."""
        try:
            self.stat(path)
        except FileNotFoundError:
            return False
        return True

    def open_read(self, path: str) -> IO[bytes]:
        url = self._full_url(path)
        # svn cat doesn't stream incrementally over the CLI — we get
        # the whole blob in stdout. Cap to _MAX_CAT_BYTES so a hostile
        # repo can't OOM us.
        try:
            data = self._run_capped("cat", url, "--revision", self._revision, cap=_MAX_CAT_BYTES)
        except OSError as exc:
            if "read cap" in str(exc):
                raise OSError(
                    f"SVN: {path} exceeds the {_MAX_CAT_BYTES // (1024 * 1024)} MiB read cap"
                ) from exc
            raise
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
