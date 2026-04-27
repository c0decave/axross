"""Axross scripting surface — the curated namespace exposed to the
embedded REPL and to ``axross --script`` CLI mode.

This module re-exports a small, stable API on top of the existing
core modules so end-users have one umbrella to write small scripts
against without spelunking through the entire codebase. Anything
reachable from here is intended to remain stable across minor
versions; the helpers in `core/*` themselves may be re-shaped.

Example session::

    >>> import axross
    >>> b = axross.open("backup-server")        # by saved profile name
    >>> for f in b.list_dir("/var/log"):
    ...     print(f.name, f.size)
    >>> axross.copy(b, "/etc/passwd", axross.localfs(), "/tmp/passwd")
    >>> axross.checksum(b, "/etc/passwd")
    'sha256:e3b0c44…'

The surface is deliberately small. ``axross.help()`` lists every
public function with a one-line summary; this is the canonical
cheat-sheet.
"""
from __future__ import annotations

import logging
import textwrap
from typing import Any
from urllib.parse import unquote, urlsplit

log = logging.getLogger(__name__)


def _ensure_registry() -> None:
    """Populate the backend registry lazily. The CLI / GUI entry
    points already call ``init_registry()``; the REPL may be reached
    via ``axross --script`` before any GUI bootstrap, so we make sure
    the registry is loaded before any open() / list_backends() call."""
    from core.backend_registry import all_backends, init_registry
    if not all_backends():
        init_registry()


# ---------------------------------------------------------------------------
# Profile + backend lookup
# ---------------------------------------------------------------------------

def list_profiles() -> list[str]:
    """Return the names of all saved connection profiles."""
    from core.profiles import ProfileManager
    return ProfileManager().list_names()


def get_profile(name: str):
    """Look up a saved :class:`ConnectionProfile` by name.

    Returns ``None`` if no profile matches. Use :func:`list_profiles`
    to discover the available names.
    """
    from core.profiles import ProfileManager
    return ProfileManager().get(name)


def list_backends() -> list[str]:
    """Return the protocol IDs of every registered backend (sftp,
    smb, s3, …) regardless of whether the optional dependency is
    installed. Use :func:`available_backends` for the installed
    subset."""
    _ensure_registry()
    from core.backend_registry import all_backends
    return [b.protocol_id for b in all_backends()]


def available_backends() -> list[str]:
    """Return the protocol IDs of backends whose dependencies are
    actually installed."""
    _ensure_registry()
    from core.backend_registry import available_backends as _avail
    return [b.protocol_id for b in _avail()]


# ---------------------------------------------------------------------------
# Opening backends
# ---------------------------------------------------------------------------

def open(profile_name: str, password: str | None = None,
         key_passphrase: str | None = None):
    """Open a backend by saved profile name. Returns a FileBackend
    session. Raises :class:`KeyError` if the profile doesn't exist
    and :class:`OSError` for connection failure."""
    profile = get_profile(profile_name)
    if profile is None:
        raise KeyError(f"No saved profile named {profile_name!r}")
    _ensure_registry()
    from core.connection_manager import ConnectionManager
    cm = ConnectionManager()
    cm.set_profile_resolver(get_profile)
    # ConnectionManager owns the auth fallback chain (key, agent,
    # password); we only override when the caller hands us a value.
    return cm.connect(profile, password=password, key_passphrase=key_passphrase)


def open_url(url: str, **kwargs):
    """Open a backend from a URL like ``sftp://user@host/``,
    ``s3://bucket``, ``smb://server/share``, ``gopher://host:70``.

    Sensitive credentials in the URL are honoured but a saved profile
    is preferred for anything you'll re-use — :func:`open` looks up
    keys / passphrases via ``keyring`` so they don't end up in
    process history.

    Recognised schemes match the registered backend protocol IDs.
    """
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower().replace("+", "_")
    if not scheme:
        raise ValueError(f"URL has no scheme: {url!r}")
    _ensure_registry()
    from core.backend_registry import get as get_backend_info
    from core.backend_registry import load_backend_class
    info = get_backend_info(scheme)
    if info is None:
        # tolerate gophers/sftp+key/etc. with a tiny remap table
        remap = {"gophers": "gopher", "sftp": "sftp"}
        info = get_backend_info(remap.get(scheme, scheme))
    if info is None:
        raise ValueError(f"Unknown backend scheme: {scheme!r}")
    cls = load_backend_class(info.protocol_id)
    init_kwargs: dict[str, Any] = dict(kwargs)
    init_kwargs.setdefault("host", parts.hostname or "")
    if parts.port:
        init_kwargs.setdefault("port", parts.port)
    elif info.default_port:
        init_kwargs.setdefault("port", info.default_port)
    if parts.username:
        init_kwargs.setdefault("username", unquote(parts.username))
    if parts.password:
        init_kwargs.setdefault("password", unquote(parts.password))
    if scheme == "gophers":
        init_kwargs.setdefault("use_tls", True)
    # Some backends (sqlite, postgres, mongo, redis, git) accept a
    # full URL via ``url=`` so the session can parse the path /
    # database segment themselves. Pass through ONLY when the
    # backend's signature actually advertises ``url`` or accepts
    # **kwargs — older sessions like GopherSession have neither and
    # would raise TypeError on unknown args.
    import inspect
    try:
        sig = inspect.signature(cls)
        accepts_url = (
            "url" in sig.parameters
            or any(
                p.kind is inspect.Parameter.VAR_KEYWORD
                for p in sig.parameters.values()
            )
        )
    except (TypeError, ValueError):
        accepts_url = False
    if accepts_url:
        init_kwargs.setdefault("url", url)
    return cls(**init_kwargs)


def localfs():
    """Return a LocalFS session pointed at the host's filesystem."""
    from core.local_fs import LocalFS
    return LocalFS()


def ramfs(max_bytes: int | None = None):
    """Return a fresh RamFS session — bytes never touch disk.
    ``max_bytes`` overrides the default per-instance cap."""
    from core.ram_fs import RamFsSession
    if max_bytes is None:
        return RamFsSession()
    return RamFsSession(max_bytes=max_bytes)


# ---------------------------------------------------------------------------
# Cross-backend file ops
# ---------------------------------------------------------------------------

def copy(src_backend, src_path: str, dst_backend, dst_path: str,
         buffer_size: int = 1024 * 1024) -> int:
    """Copy bytes from one backend to another. Returns the number of
    bytes transferred. Same-backend copies use the backend's native
    ``copy()`` if available; cross-backend copies always stream.
    """
    if src_backend is dst_backend:
        from core.server_ops import server_side_copy
        server_side_copy(src_backend, src_path, dst_path)
        return src_backend.stat(dst_path).size if hasattr(src_backend, "stat") else 0

    transferred = 0
    with src_backend.open_read(src_path) as rf, \
         dst_backend.open_write(dst_path) as wf:
        while True:
            chunk = rf.read(buffer_size)
            if not chunk:
                break
            wf.write(chunk)
            transferred += len(chunk)
    return transferred


def move(src_backend, src_path: str, dst_backend, dst_path: str) -> int:
    """Move a file from one backend to another. Same-backend uses
    rename; cross-backend uses copy + delete-source."""
    if src_backend is dst_backend:
        from core.server_ops import server_side_move
        server_side_move(src_backend, src_path, dst_path)
        return 0
    transferred = copy(src_backend, src_path, dst_backend, dst_path)
    src_backend.remove(src_path)
    return transferred


def checksum(backend, path: str, algorithm: str = "sha256") -> str:
    """Return the backend's content fingerprint for ``path``. Falls
    back to a streaming hash when the backend has no cheap server-side
    checksum."""
    if hasattr(backend, "checksum"):
        try:
            cs = backend.checksum(path, algorithm)
            if cs:
                return cs
        except OSError:
            pass
    # Stream-hash fallback
    import hashlib
    h = hashlib.new(algorithm)
    with backend.open_read(path) as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return f"{algorithm}:{h.hexdigest()}"


def read_bytes(backend, path: str) -> bytes:
    """Read an entire file into memory. Convenience wrapper — the
    REPL user usually wants this for small files."""
    with backend.open_read(path) as fh:
        return fh.read()


def write_bytes(backend, path: str, data: bytes) -> int:
    """Write ``data`` to ``path`` on ``backend``. Returns bytes written."""
    with backend.open_write(path) as wf:
        wf.write(data)
    return len(data)


def read_text(backend, path: str, encoding: str = "utf-8") -> str:
    """Read an entire file as text. Decodes the bytes via ``encoding``
    with ``errors="replace"`` so a stray non-UTF-8 byte never raises;
    use :func:`read_bytes` when you need exact-bytes round-trip."""
    return read_bytes(backend, path).decode(encoding, errors="replace")


def write_text(backend, path: str, text: str, encoding: str = "utf-8") -> int:
    """Write a UTF-8 text file. Convenience wrapper around
    :func:`write_bytes` — encodes ``text`` and forwards. Returns the
    number of bytes written."""
    return write_bytes(backend, path, text.encode(encoding))


# ---------------------------------------------------------------------------
# Encryption helper (axross-encrypted overlay)
# ---------------------------------------------------------------------------

def encrypt(backend, path: str, passphrase: str,
            keep_original: bool = False) -> str:
    """Encrypt ``path`` with the axross encrypted-overlay format and
    write the ciphertext to ``<path>.axenc``. Returns the new path.
    Removes the original unless ``keep_original=True``.
    """
    from core.encrypted_overlay import _ensure_enc_suffix, write_encrypted
    data = read_bytes(backend, path)
    out_path = _ensure_enc_suffix(path)
    write_encrypted(backend, out_path, data, passphrase=passphrase)
    if not keep_original and out_path != path:
        try:
            backend.remove(path)
        except OSError:
            pass
    return out_path


def decrypt(backend, path: str, passphrase: str) -> bytes:
    """Read and decrypt an .axenc file. Returns the plaintext bytes —
    the caller decides where to put them (write_bytes to disk, hand
    them to a parser, etc.)."""
    from core.encrypted_overlay import read_encrypted
    return read_encrypted(backend, path, passphrase)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hex digest of ``data`` under ``algorithm`` (anything
    :mod:`hashlib.new` accepts: sha1, sha256, sha512, md5, …)."""
    import hashlib
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file(backend, path: str, algorithm: str = "sha256",
              chunk_size: int = 1024 * 1024) -> str:
    """Streaming hex digest of a backend-side file. Same as
    :func:`checksum` but never tries to use a server-side fingerprint
    — use this when you specifically want algorithm parity across
    different backends."""
    import hashlib
    h = hashlib.new(algorithm)
    with backend.open_read(path) as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Bookmarks (saved navigation pins)
# ---------------------------------------------------------------------------

def list_bookmarks() -> list:
    """Return all saved bookmarks (list of :class:`Bookmark`)."""
    from core.bookmarks import BookmarkManager
    return list(BookmarkManager()._bookmarks)  # noqa: SLF001 — read-only


def add_bookmark(name: str, path: str, backend_name: str = "Local",
                 profile_name: str = "", icon_name: str = "bookmark") -> None:
    """Create a new bookmark. Idempotent on (path, backend_name)."""
    from core.bookmarks import Bookmark, BookmarkManager
    mgr = BookmarkManager()
    mgr.add(Bookmark(
        name=name, path=path,
        backend_name=backend_name, profile_name=profile_name,
        icon_name=icon_name,
    ))


def remove_bookmark(index: int) -> None:
    """Remove the bookmark at ``index`` (zero-based)."""
    from core.bookmarks import BookmarkManager
    mgr = BookmarkManager()
    mgr.remove(index)
    mgr.save()


# ---------------------------------------------------------------------------
# Profile CRUD (create / save / delete connection profiles from a script)
# ---------------------------------------------------------------------------

def save_profile(profile) -> None:
    """Persist a :class:`core.profiles.ConnectionProfile`. The profile
    object itself can be constructed via ``ConnectionProfile(name=...,
    protocol=..., host=...)`` — see ``help(core.profiles.ConnectionProfile)``."""
    from core.profiles import ProfileManager
    mgr = ProfileManager()
    mgr.add(profile)


def delete_profile(name: str) -> None:
    """Delete a saved profile by name. No-op if the profile doesn't
    exist."""
    from core.profiles import ProfileManager
    mgr = ProfileManager()
    mgr.remove(name)


# ---------------------------------------------------------------------------
# Archive helpers
# ---------------------------------------------------------------------------

def extract_archive(local_path: str, dst_dir: str,
                    on_progress=None) -> str:
    """Extract a local archive (zip / tar / 7z) to ``dst_dir``. Returns
    the directory the archive expanded into. Refuses zip-bombs and
    zip-slip via the same guards used by the file-manager UI."""
    from core.archive import extract
    return extract(local_path, dst_dir, on_progress=on_progress)


def is_archive(path: str) -> bool:
    """True when ``path`` looks like a zip / tar / 7z by extension."""
    from core.archive import is_supported_archive
    return is_supported_archive(path)


# ---------------------------------------------------------------------------
# Network + search helpers — re-exported from core.net_helpers so that
# `axross.tcp_banner(...)` etc. all live on the same module surface that
# the REPL globals expose. See core/net_helpers.py for the implementations.
# ---------------------------------------------------------------------------

from core.net_helpers import (  # noqa: E402 — kept inline for visibility
    tcp_banner,
    port_scan, ping, PingResult,
    mac_lookup, OuiInfo,
    whois, WhoisInfo,
    time_skew, TimeSkew,
    tls_cert, TlsCert,
    ssh_hostkey, SshHostKey,
    dns_records, dns_reverse,
    http_probe, HttpProbe,
    subnet_hosts,
    find_files,
    grep, GrepHit,
    diff_files,
    magic_type, text_encoding,
    entropy,
    archive_inspect, ArchiveEntry,
)

# SNMP helpers — separate module because pysnmp is heavy + optional.
# Re-export under ``axross.snmp_*`` so they sit alongside dns_records/
# port_scan in the network-helpers group.
try:
    from core.snmp_helpers import (
        snmp_get, snmp_walk, snmp_set, SnmpVar,
    )
except ImportError:
    # pysnmp not installed — define stubs that raise a helpful OSError
    # at call time so axross.help() can still list the names.
    class SnmpVar:  # type: ignore[no-redef]
        """Placeholder when pysnmp is missing."""

    def _snmp_unavailable(*_a, **_kw):
        raise OSError(
            "SNMP support requires pysnmp — install with "
            "`pip install pysnmp` (or via the axross[snmp] extra)"
        )
    snmp_get = snmp_walk = snmp_set = _snmp_unavailable  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Network helpers (small + frequently useful in scripts)
# ---------------------------------------------------------------------------

def dns_resolve(host: str, family: str = "any") -> list[str]:
    """Return the IPs ``host`` resolves to. ``family`` is ``"v4"``,
    ``"v6"``, or ``"any"``."""
    import socket
    fam_map = {
        "v4": socket.AF_INET, "v6": socket.AF_INET6,
        "any": socket.AF_UNSPEC,
    }
    fam = fam_map.get(family, socket.AF_UNSPEC)
    out: list[str] = []
    try:
        for info in socket.getaddrinfo(host, None, fam):
            ip = info[4][0]
            if ip not in out:
                out.append(ip)
    except socket.gaierror:
        pass
    return out


def port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """``True`` if a TCP connect to ``host:port`` succeeds within
    ``timeout`` seconds. Useful for lab-up probes in scripts."""
    import socket
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Per-protocol passthroughs
# ---------------------------------------------------------------------------

def find_tftp_files(backend, wordlist=None, on_progress=None) -> list:
    """Walk ``backend.find_files()`` (TFTP wordlist scan). The backend
    must be a :class:`TftpSession`; raises :class:`AttributeError`
    otherwise."""
    return backend.find_files(wordlist=wordlist, on_progress=on_progress)


def slp_discover(host: str, scope: str = "DEFAULT", port: int = 427,
                 use_tcp: bool = False) -> dict:
    """One-shot SLPv2 discover: returns ``{service_type: [(url, ttl)]}``
    for everything the daemon at ``host`` advertises in ``scope``.
    Pure read; no SrvReg path is ever exercised
    (CVE-2023-29552 mitigation)."""
    from core.slp_client import SlpSession
    sess = SlpSession(host=host, port=port, scope=scope, use_tcp=use_tcp)
    try:
        return {
            t: sess._fetch_urls(t)  # noqa: SLF001 — read-only API
            for t in sess._fetch_types()
        }
    finally:
        sess.close()


def nntp_post(backend, group: str, subject: str, body: str,
              author: str = "axross <noreply@axross>") -> None:
    """Post a fully-formed article to ``group`` on ``backend`` (an
    :class:`NntpSession`). Builds a minimal RFC 5322 envelope around
    ``subject`` + ``body``; for richer headers, hand the writer a
    pre-built bytes payload via ``backend.open_write(...)``.

    Header values are validated for CR/LF before being formatted into
    the envelope so a tainted ``subject`` cannot smuggle additional
    headers / body content into the post (RFC 5322 / RFC 3977 header-
    injection class of bug)."""
    for label, value in (("group", group), ("subject", subject),
                         ("author", author)):
        if "\r" in value or "\n" in value:
            raise ValueError(
                f"NNTP post header {label!r} must not contain CR/LF"
            )
    article = (
        f"From: {author}\r\n"
        f"Newsgroups: {group}\r\n"
        f"Subject: {subject}\r\n"
        f"\r\n"
        f"{body}"
    ).encode("utf-8")
    with backend.open_write(f"/{group}/draft.eml") as fh:
        fh.write(article)


def git_push(backend, branch: str | None = None) -> None:
    """Push committed work on ``backend`` (a :class:`GitFsSession`) to
    its origin. Raises :class:`GitForceRefused` on non-fast-forward.
    Pass ``branch=None`` to push every branch the session has touched."""
    backend.flush_push(branch=branch)


def ldap_search(backend, base_dn: str, filter: str = "(objectClass=*)",
                *, scope: str = "subtree",
                attributes: list[str] | None = None,
                limit: int = 1000) -> list[dict]:
    """Run a raw LDAP search via the connected ``LdapFsSession``.
    Returns up to ``limit`` entries as dicts ``{dn, attributes}``::

        users = axross.ldap_search(
            b, "ou=people,dc=example,dc=com",
            "(objectClass=inetOrgPerson)",
            attributes=["cn", "mail", "uid"],
        )
    """
    if not hasattr(backend, "search") or not hasattr(backend, "_path_to_dn"):
        raise TypeError(
            f"backend {type(backend).__name__} is not an LDAP session"
        )
    return backend.search(base_dn, filter, scope=scope,
                          attributes=attributes, limit=limit)


def share(backend, path: str, **kwargs) -> str:
    """Create a shareable link for ``path`` on a cloud backend that
    supports it. Dispatches to:

    * ``S3Session.presign(path, expires=...)`` → pre-signed URL
    * ``DropboxSession.shared_link_create(path, public=...)`` → URL
    * ``GDriveSession.share(path, role=...)`` → ``{"url": ...}``  (just the URL)
    * ``OneDriveSession.share(path, link_type=...)`` → URL

    The keyword args differ per backend — pass them through; we keep
    the signature loose because each cloud's notion of "share" is
    nominally the same but parameter-named differently.
    """
    if hasattr(backend, "presign") and not hasattr(backend, "share"):
        return backend.presign(path, **kwargs)
    if hasattr(backend, "shared_link_create"):
        return backend.shared_link_create(path, **kwargs)
    if hasattr(backend, "share"):
        result = backend.share(path, **kwargs)
        # GDrive returns dict; others return str.
        if isinstance(result, dict):
            return result.get("url") or ""
        return result
    raise TypeError(
        f"backend {type(backend).__name__} doesn't expose a share/presign "
        "verb (only S3 / Dropbox / GDrive / OneDrive do today)"
    )


def imap_search(backend, criteria: str = "ALL", *,
                mailbox: str = "INBOX") -> list[int]:
    """Wrapper around ``ImapSession.search()`` — returns the list of
    UIDs matching an IMAP search expression (RFC 3501)::

        uids = axross.imap_search(b, 'UNSEEN SUBJECT "invoice"')
    """
    if not hasattr(backend, "search"):
        raise TypeError(
            f"backend {type(backend).__name__} does not implement "
            "search() — only the IMAP/Exchange backends do today."
        )
    return backend.search(criteria, mailbox=mailbox)


def imap_move(backend, uid: int, src_mailbox: str, dst_mailbox: str) -> None:
    """Move an IMAP message by UID. Uses MOVE if the server supports
    it, COPY+\\Deleted+EXPUNGE otherwise. See ``ImapSession.move``."""
    if not hasattr(backend, "move") or not hasattr(backend, "set_flags"):
        raise TypeError(
            f"backend {type(backend).__name__} is not an IMAP session"
        )
    backend.move(uid, src_mailbox, dst_mailbox)


def imap_set_flags(backend, uid: int, flags: list[str], *,
                   mailbox: str = "INBOX", mode: str = "set") -> None:
    """STORE flags on an IMAP message by UID. ``mode`` is ``set`` /
    ``add`` / ``remove``."""
    if not hasattr(backend, "set_flags"):
        raise TypeError(
            f"backend {type(backend).__name__} is not an IMAP session"
        )
    backend.set_flags(uid, flags, mailbox=mailbox, mode=mode)


def query(backend, sql_or_args, *args, **kwargs):
    """Generic database-query dispatch. Calls ``backend.query()`` for
    SQL backends (SQLite / Postgres) or ``backend.find()`` for Mongo
    when ``sql_or_args`` looks like a collection name + filter dict.

    SQL form::

        rows = axross.query(b, "SELECT * FROM users WHERE id = ?", (1,))

    Mongo form::

        rows = axross.query(b, "orders", {"status": "open"}, limit=50)

    Redis is intentionally NOT dispatched here — Redis isn't SQL.
    Use ``b.cmd("CONFIG", "GET", "maxmemory")`` directly.
    """
    if hasattr(backend, "find") and not hasattr(backend, "query"):
        # Mongo-shaped backend.
        coll = sql_or_args
        filt = args[0] if args else None
        return backend.find(coll, filt, **kwargs)
    if not hasattr(backend, "query"):
        raise TypeError(
            f"backend {type(backend).__name__} does not implement "
            "query() — only SQLite/Postgres/Mongo do today. For "
            "Redis use backend.cmd('SCAN', ...) directly."
        )
    return backend.query(sql_or_args, *args, **kwargs)


def tables(backend) -> list[str]:
    """Return every table (SQLite/Postgres) or collection (Mongo) on
    ``backend``. Wraps the per-backend method of the same name."""
    if hasattr(backend, "tables"):
        return backend.tables()
    if hasattr(backend, "collections"):
        return backend.collections()
    raise TypeError(
        f"backend {type(backend).__name__} does not implement "
        "tables() / collections()"
    )


def exec(
    backend,
    cmd: str,
    *,
    timeout: float | None = 30.0,
    stdin: bytes | str | None = None,
    stdout_cap: int = 1024 * 1024,
    stderr_cap: int = 64 * 1024,
    env: dict[str, str] | None = None,
):
    """Run a shell command on a remote backend. Returns
    :class:`models.exec_result.ExecResult` with ``returncode``,
    ``stdout``, ``stderr`` and the corresponding ``truncated_*`` flags.

    Works on any backend whose session implements ``.exec()`` —
    currently SSH/SFTP and SCP. For protocols where ``exec`` is the
    wrong shape (Cisco IOS, IMAP, S3 …) use the per-protocol helper
    instead (``axross.show()``, ``axross.imap_search()``, …).

    Quote untrusted arguments yourself::

        import shlex
        r = axross.exec(b, f"ls -la {shlex.quote(path)}").check()

    Pass ``stdin`` as ``bytes`` (or a ``str`` that we'll utf-8 encode)
    to feed input to the remote process before reading its output.
    """
    if not hasattr(backend, "exec"):
        raise TypeError(
            f"backend {type(backend).__name__} does not implement "
            "exec() — only SSH/SFTP and SCP do today. Use the "
            "protocol-specific helper instead."
        )
    if isinstance(stdin, str):
        stdin = stdin.encode("utf-8")
    return backend.exec(
        cmd,
        timeout=timeout,
        stdin=stdin,
        stdout_cap=stdout_cap,
        stderr_cap=stderr_cap,
        env=env,
    )


# ---------------------------------------------------------------------------
# Script directory
# ---------------------------------------------------------------------------

SCRIPT_DIR = pathlib_path = None  # set lazily inside the helpers below


def script_dir() -> str:
    """Return the script-storage directory path. Created on first
    access. Mode 0700 so other local users can't read scripts that
    might contain credentials."""
    import os
    from pathlib import Path as _Path
    p = _Path.home() / ".config" / "axross" / "scripts"
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return str(p)


def list_scripts() -> list[str]:
    """Names of every saved script in :func:`script_dir`."""
    import os
    d = script_dir()
    out: list[str] = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".py") and not name.startswith("."):
            out.append(name[:-3])
    return out


def _validate_script_name(name: str) -> str:
    """Refuse path-traversal / unsafe characters before writing into
    the script dir."""
    import re
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", name):
        raise ValueError(
            f"script name {name!r} must match [A-Za-z0-9_-]+"
        )
    return name


def save_script(name: str, source: str) -> str:
    """Write ``source`` to ``script_dir()/<name>.py`` (mode 0o600).
    Overwrites any existing file with the same name. Returns the
    final on-disk path."""
    import os
    from pathlib import Path as _Path
    safe = _validate_script_name(name)
    target = _Path(script_dir()) / f"{safe}.py"
    fd = os.open(str(target),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, source.encode("utf-8"))
    finally:
        os.close(fd)
    return str(target)


def load_script(name: str) -> str:
    """Read the source of a saved script as a UTF-8 string. Raises
    ``FileNotFoundError`` when the script doesn't exist; ``ValueError``
    when the name contains characters outside the allow-list."""
    import builtins
    import os
    safe = _validate_script_name(name)
    path = os.path.join(script_dir(), f"{safe}.py")
    # builtins.open — our own ``open()`` shadows the builtin in this
    # module's namespace.
    with builtins.open(path, encoding="utf-8") as fh:
        return fh.read()


def delete_script(name: str) -> None:
    """Remove a saved script. No-op if the file is already gone."""
    import os
    safe = _validate_script_name(name)
    path = os.path.join(script_dir(), f"{safe}.py")
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def run_script(name: str, env: dict | None = None) -> dict:
    """Execute a saved script in a fresh namespace pre-populated with
    ``axross`` (this module). Returns the post-exec namespace so the
    caller can inspect any variables it left behind. ``env`` overrides
    / augments the initial namespace."""
    source = load_script(name)
    import sys as _sys
    ns: dict = {
        "__name__": "__axross_script__",
        "__file__": f"<axross:{name}>",
        "axross": _sys.modules[__name__],
    }
    if env:
        ns.update(env)
    # Use the builtin via builtins.exec — our module-level ``exec``
    # function (the remote-shell one) shadows the name otherwise.
    import builtins as _builtins
    _builtins.exec(compile(source, ns["__file__"], "exec"), ns)
    return ns


# ---------------------------------------------------------------------------
# Cheat-sheet — auto-built from __all__ + each function's docstring
# ---------------------------------------------------------------------------

# Topical groupings so the cheat-sheet reads sensibly. The renderer
# falls back to "Other" for anything not listed here.
_HELP_GROUPS: list[tuple[str, list[str]]] = [
    ("Open / connect", [
        "open", "open_url", "localfs", "ramfs",
        "list_profiles", "get_profile", "save_profile", "delete_profile",
        "list_backends", "available_backends",
    ]),
    ("File I/O", [
        "copy", "move", "read_bytes", "write_bytes",
        "read_text", "write_text", "checksum",
        "hash_bytes", "hash_file",
    ]),
    ("Encryption + archives", [
        "encrypt", "decrypt", "extract_archive", "is_archive",
    ]),
    ("Bookmarks + scripts", [
        "list_bookmarks", "add_bookmark", "remove_bookmark",
        "script_dir", "list_scripts", "save_script", "load_script",
        "delete_script", "run_script",
    ]),
    ("Per-protocol", [
        "find_tftp_files", "slp_discover", "nntp_post", "git_push",
        "exec", "query", "tables",
        "imap_search", "imap_move", "imap_set_flags",
        "share", "ldap_search",
    ]),
    ("Network helpers", [
        "dns_resolve", "dns_records", "dns_reverse",
        "port_open", "port_scan", "subnet_hosts",
        "tcp_banner", "tls_cert", "ssh_hostkey", "http_probe",
        "snmp_get", "snmp_walk", "snmp_set",
        "ping", "mac_lookup", "whois", "time_skew",
    ]),
    ("Search across backends", [
        "find_files", "grep", "diff_files",
    ]),
    ("Content inspection", [
        "magic_type", "text_encoding", "entropy", "archive_inspect",
    ]),
    ("Result types (dataclasses returned by helpers above)", [
        "TlsCert", "SshHostKey", "HttpProbe", "GrepHit", "SnmpVar",
        "ArchiveEntry", "PingResult", "OuiInfo", "WhoisInfo",
        "TimeSkew",
    ]),
    ("Misc", [
        "help",
    ]),
]


def _docstring_summary(fn) -> str:
    doc = (fn.__doc__ or "").strip()
    if not doc:
        return "(no docstring)"
    return doc.splitlines()[0].rstrip(".") + "."


# ---------------------------------------------------------------------------
# Cheat-sheet
# ---------------------------------------------------------------------------

def _help_entries() -> list[tuple[str, list[tuple[str, str]]]]:
    """Build the cheat-sheet from ``_HELP_GROUPS`` + each function's
    real docstring summary. New functions only need to register in
    ``_HELP_GROUPS``; the printed output picks up their docstring
    automatically. The doc-pane uses the same data."""
    import sys as _sys
    me = _sys.modules[__name__]
    out: list[tuple[str, list[tuple[str, str]]]] = []
    listed: set[str] = set()
    for group_name, fn_names in _HELP_GROUPS:
        items: list[tuple[str, str]] = []
        for name in fn_names:
            fn = getattr(me, name, None)
            if fn is None:
                continue
            items.append((f"axross.{name}", _docstring_summary(fn)))
            listed.add(name)
        if items:
            out.append((group_name, items))
    # "Other" — anything in __all__ that wasn't claimed above.
    leftover = [n for n in __all__ if n not in listed]
    if leftover:
        items = []
        for name in leftover:
            fn = getattr(me, name, None)
            if fn is None:
                continue
            items.append((f"axross.{name}", _docstring_summary(fn)))
        if items:
            out.append(("Other", items))
    return out


def help() -> None:
    """Print the curated cheat-sheet of the scripting surface."""
    print("Axross scripting cheat-sheet")
    print("=" * 60)
    for group, items in _help_entries():
        print(f"-- {group} --")
        for sig, summary in items:
            wrapped = textwrap.fill(
                summary, width=58,
                initial_indent="    ", subsequent_indent="    ",
            )
            print(f"  {sig}()")
            print(wrapped)
        print()
    print("Tab-completion is enabled. `dir(<backend>)` shows everything")
    print("a backend object exposes; `help(<x>)` shows its docstring.")
    print("Detailed reference: axross.docs() or docs/SCRIPTING_REFERENCE.md.")


# ---------------------------------------------------------------------------
# Full reference (long-form) — what `axross.help()` only summarises.
# ---------------------------------------------------------------------------

def docs(name: str | None = None) -> str:
    """Return long-form documentation as Markdown.

    * ``axross.docs()`` — every public ``axross.*`` function with full
      signature + docstring, grouped by topic. Useful for piping into
      a viewer or saving to a file.
    * ``axross.docs("open")`` — just one function. Same shape as
      ``help(axross.open)`` but as a string and including the
      one-paragraph topical context where applicable.
    * ``axross.docs("slash")`` — REPL slash-command reference.
    * ``axross.docs("scripts")`` — bundled-script reference (names +
      one-line summary pulled from each script's docstring).
    * ``axross.docs("backend")`` — the ``FileBackend`` protocol every
      backend implements (``list_dir``, ``open_read``, ``copy``, …).

    The output is plain Markdown. The doc-pane in the GUI calls this
    too — same source-of-truth for the headless and the GUI surface.
    """
    if name is None:
        return _render_full_reference()
    if name == "slash":
        return _render_slash_reference()
    if name == "scripts":
        return _render_scripts_reference()
    if name == "backend":
        return _render_backend_protocol_reference()
    # Strict allow-list against ``__all__`` so ``docs("logging")`` or
    # ``docs("os")`` can't surface random module-level attributes the
    # scripting module happens to import. Without this guard, the
    # helper would happily leak the stdlib's logging.__doc__ as if it
    # were part of the axross API.
    if name not in __all__:
        raise KeyError(
            f"axross.docs: unknown topic {name!r}. Try one of: "
            "(no arg), 'slash', 'scripts', 'backend', "
            "or any function name from axross.__all__."
        )
    import sys as _sys
    fn = getattr(_sys.modules[__name__], name, None)
    if fn is None:
        raise KeyError(f"axross.docs: {name!r} listed in __all__ but missing")
    return _render_function_block(name, fn)


def _render_function_block(name: str, fn) -> str:
    """Single function rendered as a Markdown sub-section."""
    import inspect
    try:
        sig = str(inspect.signature(fn))
    except (TypeError, ValueError):
        sig = "(...)"
    doc = inspect.getdoc(fn) or "(no docstring)"
    return f"### `axross.{name}{sig}`\n\n{doc}\n"


def _render_full_reference() -> str:
    """Build the entire reference as one Markdown blob."""
    import sys as _sys
    me = _sys.modules[__name__]
    chunks: list[str] = [
        "# `axross.*` Scripting Reference\n",
        "Auto-generated from the live `core.scripting` module — every "
        "public function with its full signature and docstring, "
        "grouped by topic.\n",
        "\nAlso available at runtime: `axross.docs()` returns this "
        "same Markdown; `axross.docs(name)` returns a single section. "
        "The GUI doc-pane renders the same content.\n",
        "\n---\n",
    ]
    listed: set[str] = set()
    for group_name, fn_names in _HELP_GROUPS:
        chunks.append(f"\n## {group_name}\n")
        for fn_name in fn_names:
            fn = getattr(me, fn_name, None)
            if fn is None:
                continue
            chunks.append(_render_function_block(fn_name, fn))
            listed.add(fn_name)
    leftover = [n for n in __all__ if n not in listed]
    if leftover:
        chunks.append("\n## Other\n")
        for n in leftover:
            fn = getattr(me, n, None)
            if fn is None:
                continue
            chunks.append(_render_function_block(n, fn))
    chunks.append("\n---\n")
    chunks.append(_render_slash_reference())
    chunks.append("\n---\n")
    chunks.append(_render_scripts_reference())
    chunks.append("\n---\n")
    chunks.append(_render_backend_protocol_reference())
    return "\n".join(chunks)


def _render_slash_reference() -> str:
    return (
        "## REPL slash-commands\n\n"
        "Typed at the `>>> ` prompt; not Python. They never touch the "
        "interpreter namespace.\n\n"
        "| Command | Effect |\n"
        "|---|---|\n"
        "| `.help` | This list |\n"
        "| `.scripts` | Names of every saved script |\n"
        "| `.save <name>` | Save the current session's history into "
        "`<name>.py` (mode 0o600) |\n"
        "| `.load <name>` | Print the source of a saved script |\n"
        "| `.run <name>` | Execute a saved script in the live REPL "
        "namespace |\n"
        "| `.delete <name>` | Remove a saved script |\n"
        "| `.open` | Print the script-directory path "
        "(`~/.config/axross/scripts/`) |\n"
    )


def _render_scripts_reference() -> str:
    """Walk ``resources/scripts/*.py`` and render one block per script
    with the docstring's first paragraph."""
    import os
    me_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scripts_dir = os.path.join(me_dir, "resources", "scripts")
    parts: list[str] = ["## Bundled example scripts\n"]
    if not os.path.isdir(scripts_dir):
        parts.append("(scripts directory not present in this install)\n")
        return "\n".join(parts)
    parts.append(
        "Every script is runnable as `axross --script "
        "resources/scripts/<name>.py` or via the REPL `.run <name>` "
        "command after copying into `~/.config/axross/scripts/`.\n"
    )
    for fname in sorted(os.listdir(scripts_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(scripts_dir, fname)
        try:
            with __import__("builtins").open(path, encoding="utf-8") as fh:
                src = fh.read()
        except OSError:
            continue
        # The script's module-level docstring is the first triple-quoted
        # block. We don't import (would leak side effects); just yank
        # the literal.
        ds = _extract_module_docstring(src)
        first_para = ds.split("\n\n", 1)[0].strip() if ds else "(no docstring)"
        parts.append(f"### `{fname}`\n\n{first_para}\n")
    return "\n".join(parts)


def _extract_module_docstring(source: str) -> str:
    """Return the literal text of a module-level docstring without
    importing the module. Robust to leading ``from __future__`` lines
    and shebang."""
    import ast
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    return ast.get_docstring(tree) or ""


def _render_backend_protocol_reference() -> str:
    """Document the ``FileBackend`` protocol that every backend
    implements — the methods you can call on any session returned by
    ``axross.open(...)``, ``axross.localfs()``, etc."""
    import inspect
    try:
        from core.backend import FileBackend
    except ImportError:
        return "## FileBackend protocol\n\n(unavailable: import failed)\n"
    parts: list[str] = [
        "## `FileBackend` protocol\n",
        "Every session object (the thing `axross.open(...)` returns) "
        "implements this protocol. Methods are spelled the same on "
        "every backend; semantic gaps are surfaced via "
        "`BackendCapabilities` and clean `OSError` raises.\n",
    ]
    seen: set[str] = set()
    for cls in (FileBackend,):
        for member, _ in inspect.getmembers(cls):
            if member.startswith("_") or member in seen:
                continue
            seen.add(member)
            attr = getattr(cls, member, None)
            if attr is None or not callable(attr):
                continue
            try:
                sig = str(inspect.signature(attr))
            except (TypeError, ValueError):
                sig = "(self, ...)"
            doc = inspect.getdoc(attr) or "(no docstring)"
            parts.append(f"### `backend.{member}{sig}`\n\n{doc}\n")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public namespace export
# ---------------------------------------------------------------------------

__all__ = [
    # connect / backend factory
    "open", "open_url", "localfs", "ramfs",
    "list_backends", "available_backends",
    "list_profiles", "get_profile", "save_profile", "delete_profile",
    # file I/O
    "copy", "move", "checksum",
    "read_bytes", "write_bytes", "read_text", "write_text",
    "hash_bytes", "hash_file",
    # encryption + archives
    "encrypt", "decrypt", "extract_archive", "is_archive",
    # bookmarks
    "list_bookmarks", "add_bookmark", "remove_bookmark",
    # script directory
    "script_dir", "list_scripts", "save_script", "load_script",
    "delete_script", "run_script",
    # per-protocol passthroughs
    "find_tftp_files", "slp_discover", "nntp_post", "git_push", "exec",
    "query", "tables",
    "imap_search", "imap_move", "imap_set_flags",
    "share", "ldap_search",
    # network helpers
    "dns_resolve", "dns_records", "dns_reverse",
    "port_open", "port_scan", "subnet_hosts",
    "ping", "PingResult",
    "mac_lookup", "OuiInfo",
    "whois", "WhoisInfo",
    "time_skew", "TimeSkew",
    "tcp_banner", "tls_cert", "TlsCert",
    "ssh_hostkey", "SshHostKey",
    "http_probe", "HttpProbe",
    "snmp_get", "snmp_walk", "snmp_set", "SnmpVar",
    # search across backends
    "find_files", "grep", "GrepHit", "diff_files",
    # content inspection
    "magic_type", "text_encoding", "entropy",
    "archive_inspect", "ArchiveEntry",
    # cheat-sheet
    "help",
]
