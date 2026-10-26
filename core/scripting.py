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

import logging as _logging
import textwrap as _textwrap
from typing import TYPE_CHECKING as _TYPE_CHECKING
from typing import Any as _Any
from urllib.parse import unquote as _unquote
from urllib.parse import urlsplit as _urlsplit
from urllib.parse import urlunsplit as _urlunsplit

from core import posix_compat

if _TYPE_CHECKING:  # names of the type hints only; nothing here is imported at run time
    import os
    from collections.abc import Callable, Iterable
    from typing import Any

    from core.backend import FileBackend
    from core.cas import CasEntry, DedupeResult, ScanRecord
    from core.conn_health import HealthRecord
    from core.copy_resume import ResumeReport
    from core.cred_attack import AttackReport, AttemptOutcome, EnumReport, EnumResult
    from core.file_type import FileTypeInfo
    from core.inspect import ExplainResult, Summary
    from core.local_fs import LocalFS
    from core.metadata_tools import MetadataReport
    from core.multi_view import CompareReport, InspectReport
    from core.profiles import ConnectionProfile
    from core.ram_fs import RamFsSession
    from core.reverse_serve import ReverseServer
    from core.search_federation import SearchHit, SearchQuery, SearchResult
    from core.trail import Snapshot, TrailDiff
    from core.visit_history import HostVisit
    from models.exec_result import ExecResult
    from models.file_item import FileItem
    from models.interactive_shell import InteractiveShell

log = _logging.getLogger(__name__)

MAX_SCRIPT_READ_BYTES = 64 * 1024 * 1024
_SCRIPT_READ_CHUNK = 1024 * 1024

#: Attribute holding a public function's declared traits (see :func:`_api`).
_API_TRAITS_ATTR = "__axross_api__"


def _api(*, mutates: bool, prompts: bool = False):
    """Declare what a public function may do, for :func:`api_schema`.

    ``mutates``: the call can change state somewhere - files, a remote
    service, saved settings - with at least some arguments. ``prompts``:
    the call can wait for a human (a dialog, a terminal prompt, the
    production tarpit, a browser consent) and raises
    :class:`NonInteractiveError` or blocks where there is none. Every
    public function declares both; tests/test_scripting_api_schema.py
    fails for one that does not.
    """

    def mark(fn):
        setattr(fn, _API_TRAITS_ATTR, {"mutates": bool(mutates), "prompts": bool(prompts)})
        return fn

    return mark


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


@_api(mutates=False)
def list_profiles() -> list[str]:
    """Return the names of all saved connection profiles."""
    from core.profiles import ProfileManager

    return ProfileManager().list_names()


@_api(mutates=False)
def get_profile(name: str) -> ConnectionProfile | None:
    """Look up a saved :class:`ConnectionProfile` by name.

    Returns ``None`` if no profile matches. Use :func:`list_profiles`
    to discover the available names.
    """
    from core.profiles import ProfileManager

    return ProfileManager().get(name)


@_api(mutates=False)
def list_backends() -> list[str]:
    """Return the protocol IDs of every registered backend (sftp,
    smb, s3, …) regardless of whether the optional dependency is
    installed. Use :func:`available_backends` for the installed
    subset."""
    _ensure_registry()
    from core.backend_registry import all_backends

    return [b.protocol_id for b in all_backends()]


@_api(mutates=False)
def available_backends() -> list[str]:
    """Return the protocol IDs of backends whose dependencies are
    actually installed."""
    _ensure_registry()
    from core.backend_registry import available_backends as _avail

    return [b.protocol_id for b in _avail()]


# ---------------------------------------------------------------------------
# Opening backends
# ---------------------------------------------------------------------------


@_api(mutates=False, prompts=True)
def open(
    profile_name: str, password: str | None = None, key_passphrase: str | None = None
) -> FileBackend:
    """Open a backend by saved profile name. Returns a FileBackend
    session. Raises :class:`KeyError` if the profile doesn't exist
    and :class:`OSError` for connection failure.

    Every session supports ``with``; leaving the block ends the
    connection (``close()`` does the same by hand)::

        with axross.open("backup-server") as b:
            print(b.list_dir("/"))
    """
    profile = get_profile(profile_name)
    if profile is None:
        raise KeyError(f"No saved profile named {profile_name!r}")
    _ensure_registry()
    from core.connection_manager import ConnectionManager

    cm = ConnectionManager()
    cm.set_profile_resolver(get_profile)
    log.info(
        "axross.open(%r) — protocol=%s host=%s user=%s",
        profile_name,
        profile.protocol,
        profile.host,
        profile.username,
    )
    # ConnectionManager owns the auth fallback chain (key, agent,
    # password); we only override when the caller hands us a value.
    session = cm.connect(
        profile,
        password=password or "",
        key_passphrase=key_passphrase or "",
    )
    return _hand_out(cm, profile, session)


def _hand_out(cm, profile, session):
    """Return ``session`` with a hook that gives back the reference
    ``cm.connect`` took: leaving ``with session:`` releases it, so the
    health monitor stops probing a session the script has closed."""
    import functools

    from core.backend import RELEASE_ATTR

    try:
        setattr(session, RELEASE_ATTR, functools.partial(cm.release, profile))
    except (AttributeError, TypeError) as exc:  # a session refusing attributes
        log.debug("axross: cannot attach the release hook: %s", exc)
    return session


_PROXY_KWARG_NAMES = (
    "proxy_type",
    "proxy_host",
    "proxy_port",
    "proxy_username",
    "proxy_password",
)


@_api(mutates=False, prompts=True)
def open_url(url: str, **kwargs: Any) -> FileBackend:
    """Open a backend from a URL like ``sftp://user@host/``,
    ``s3://bucket``, ``smb://server/share``, ``gopher://host:70``.

    Sensitive credentials in the URL are honoured but a saved profile
    is preferred for anything you'll re-use — :func:`open` looks up
    keys / passphrases via ``keyring`` so they don't end up in
    process history.

    **Proxy support** (SOCKS4 / SOCKS5 / HTTP CONNECT). Pass any of
    ``proxy_type``, ``proxy_host``, ``proxy_port``, ``proxy_username``,
    ``proxy_password`` as kwargs; for proxy-capable protocols
    (sftp, scp, ftp/s, smb/dfsn, webdav, rsync, telnet,
    cisco-telnet, imap, pop3, nntp, gopher, pjl, adb-tcp,
    azure_blob/files, onedrive, sharepoint, gdrive, dropbox, winrm,
    and S3 over HTTP CONNECT), the proxy is wired into the backend's
    transport. Backends without clean SOCKS/HTTP support log a warning
    instead of silently ignoring the proxy fields. Per-protocol caveats
    still apply: S3 is HTTP-CONNECT only, and rsync's OpenBSD-nc path
    cannot carry ``proxy_password``. Requests-based SDK sessions
    controlled by Axross ignore process-level ``HTTP_PROXY`` /
    ``HTTPS_PROXY`` so the profile/script proxy is the route source of
    truth. OAuth browser consent pages are external and may follow
    browser/system proxy settings. When ``proxy_type`` is not ``"none"``,
    ``proxy_host`` and a non-zero ``proxy_port`` are required;
    half-configured proxies fail closed instead of falling back to
    direct traffic.

    Example::

        b = axross.open_url(
            "sftp://alice@gateway.example.com/",
            password="hunter2",
            proxy_type="socks5",
            proxy_host="127.0.0.1",
            proxy_port=1080,
        )

    Recognised schemes match registered backend protocol IDs, with
    a few ergonomic aliases: ``http://`` / ``https://`` open WebDAV,
    ``gophers://`` opens TLS Gopher, ``nntps://`` opens TLS NNTP,
    ``git+local://`` opens a local Git repository path, and
    ``sftp+key://`` / ``sftp+agent://`` select SSH auth mode.
    """
    if not isinstance(url, str) or not url:
        raise TypeError(
            f"axross.open_url(url=...) requires a non-empty string; "
            f"got {type(url).__name__}={url!r}"
        )
    # Validate proxy_port early so callers get a clear error rather
    # than a cryptic socket failure deep in the backend.
    if "proxy_port" in kwargs:
        try:
            pp = int(kwargs["proxy_port"])
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"proxy_port must be an integer; got {kwargs['proxy_port']!r}"
            ) from exc
        if pp != 0 and not (1 <= pp <= 65535):
            raise ValueError(f"proxy_port must be in range 1..65535 (or 0 for unset); got {pp}")
        kwargs["proxy_port"] = pp
    parts = _urlsplit(url)
    raw_scheme = (parts.scheme or "").lower()
    scheme = raw_scheme.replace("+", "_")
    if not raw_scheme:
        raise ValueError(f"URL has no scheme: {url!r}")
    _ensure_registry()
    from core.backend_registry import get as get_backend_info
    from core.backend_registry import load_backend_class

    proto_hint = _scheme_to_protocol(raw_scheme)
    info = get_backend_info(proto_hint)
    if info is None:
        raise ValueError(f"Unknown backend scheme: {scheme!r}")

    # Pull proxy kwargs out so we can route them via the same plumbing
    # ConnectionManager uses for profile-based connects. The user can
    # also override host/port/username/password via kwargs (URL
    # components win on conflict — explicit URL is the most-specific
    # signal).
    proxy_kwargs = {k: kwargs.pop(k) for k in _PROXY_KWARG_NAMES if k in kwargs}
    if "proxy_type" not in proxy_kwargs:
        # No proxy named: the application default (Tools > Network & Proxy)
        # applies, subject to its bypass list / PAC. An explicit
        # ``proxy_type="none"`` stays a direct connection.
        from core import proxy_settings as _ps

        proxy_kwargs = _ps.default_proxy_kwargs(
            parts.hostname or "", parts.port or info.default_port or None, info.protocol_id
        )
    proxy_type = (proxy_kwargs.get("proxy_type", "none") or "none").lower()
    if proxy_type != "none" and not proxy_kwargs.get("proxy_host", ""):
        raise ValueError(
            f"proxy_type={proxy_kwargs.get('proxy_type')!r} requires "
            "proxy_host; refusing direct traffic."
        )
    if proxy_type != "none" and int(proxy_kwargs.get("proxy_port", 0) or 0) == 0:
        raise ValueError(
            f"proxy_type={proxy_kwargs.get('proxy_type')!r} requires "
            "proxy_port; refusing direct traffic."
        )
    proto_id = info.protocol_id
    from core.security_mode import require_protocol_allowed

    require_protocol_allowed(proto_id)

    # Protocols routed through ConnectionManager get full proxy +
    # auth-fallback support. We synthesise an ad-hoc ConnectionProfile
    # so the existing code paths handle everything uniformly.
    if proto_id in _cm_protocols():
        log.info(
            "axross.open_url(%s://…) — via ConnectionManager proxy=%s://%s:%s",
            proto_id,
            proxy_kwargs.get("proxy_type", "none"),
            proxy_kwargs.get("proxy_host", ""),
            proxy_kwargs.get("proxy_port", 0),
        )
        return _open_url_via_cm(
            proto_id,
            parts,
            kwargs,
            url,
            proxy_kwargs,
            default_port=info.default_port,
            raw_scheme=raw_scheme,
        )

    init_kwargs: dict[str, _Any] = dict(kwargs)
    init_kwargs.setdefault("host", parts.hostname or "")
    # A scheme with its own port comes before the registry default:
    # nntp's default is 563 (NNTPS), which plain nntp:// must not inherit.
    scheme_port = {"nntp": 119, "nntps": 563, "nntp+ssl": 563}.get(raw_scheme)
    if parts.port:
        init_kwargs.setdefault("port", parts.port)
    elif scheme_port:
        init_kwargs.setdefault("port", scheme_port)
    elif info.default_port:
        init_kwargs.setdefault("port", info.default_port)
    if parts.username:
        init_kwargs.setdefault("username", _unquote(parts.username))
    if parts.password:
        init_kwargs.setdefault("password", _unquote(parts.password))
    if raw_scheme == "gophers":
        init_kwargs.setdefault("use_tls", True)
    elif raw_scheme == "nntp":
        init_kwargs.setdefault("use_tls", False)
        init_kwargs.setdefault("port", parts.port or 119)
    elif raw_scheme in {"nntps", "nntp+ssl"}:
        init_kwargs.setdefault("use_tls", True)
        init_kwargs.setdefault("port", parts.port or 563)
    suppress_url = False
    if proto_id == "git" and raw_scheme == "git+local":
        init_kwargs.setdefault("path", _unquote(parts.path or ""))
        suppress_url = True
    # Best-effort proxy passthrough for backends that aren't routed
    # via ConnectionManager but DO explicitly accept proxy_* kwargs
    # (for example direct gopher:// / nntp:// construction). Do not
    # rely on a catch-all **kwargs signature here: several backends
    # accept **_ignored for unrelated future-proofing and would
    # otherwise silently drop proxy settings. The backends that DO read
    # the proxy from **kwargs are listed by ConnectionManager.
    if proxy_kwargs:
        import inspect

        from core.connection_manager import (
            _PROTOCOLS_HONOURING_KWARG_PROXY,
            _PROTOCOLS_NO_NETWORK,
        )

        try:
            sig = inspect.signature(load_backend_class(proto_id))
        except (TypeError, ValueError):
            sig = None
        via_kwargs = proto_id in _PROTOCOLS_HONOURING_KWARG_PROXY
        accepted = False
        for k, v in proxy_kwargs.items():
            if via_kwargs or (sig is not None and k in sig.parameters):
                init_kwargs[k] = v
                accepted = True
        if not accepted:
            if proxy_type != "none" and proto_id not in _PROTOCOLS_NO_NETWORK and not suppress_url:
                # Never connect around a proxy the caller (or the
                # application default) asked for.
                from core.proxy import refuse_unsupported_proxy

                refuse_unsupported_proxy(
                    proto_id,
                    proxy_type,
                    str(proxy_kwargs.get("proxy_host", "")),
                    f"The {proto_id} backend has no SOCKS/HTTP proxy support.",
                )
            log.warning(
                "axross.open_url(%s://…) received proxy settings, but the "
                "%s backend has no network transport to proxy. The proxy "
                "settings are ignored. See docs/PROXY_SUPPORT.md.",
                proto_id,
                proto_id,
            )
    cls = load_backend_class(proto_id)
    # Some backends (sqlite, postgres, mongo, redis, git, svn) accept a
    # full URL via ``url=`` so the session can parse the path /
    # database segment themselves. Pass through ONLY when the
    # backend's signature actually advertises ``url`` or accepts
    # **kwargs — older sessions like GopherSession have neither and
    # would raise TypeError on unknown args.
    import inspect

    try:
        sig = inspect.signature(cls)
        accepts_url = "url" in sig.parameters or any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )
    except (TypeError, ValueError):
        accepts_url = False
    if accepts_url and not suppress_url:
        init_kwargs.setdefault("url", url)
    return cls(**init_kwargs)


def _scheme_to_protocol(raw_scheme: str) -> str:
    """Map friendly URL schemes to registry protocol IDs.

    ``urllib.parse`` treats ``+`` as part of the scheme, while registry
    IDs use plain protocol names. Keep these aliases narrow and
    explicit so ``open_url`` does not unexpectedly claim arbitrary URL
    schemes.
    """
    scheme = raw_scheme.lower()
    if scheme in {"http", "https", "webdav", "webdav+http", "webdav+https"}:
        return "webdav"
    if scheme == "gophers":
        return "gopher"
    if scheme.startswith("git+"):
        return "git"
    if scheme in {"imaps", "imap+ssl"}:
        return "imap"
    if scheme in {"pop3s", "pop3+ssl"}:
        return "pop3"
    if scheme in {"nntps", "nntp+ssl"}:
        return "nntp"
    if scheme in {"sftp+key", "sftp+agent"}:
        return "sftp"
    return scheme.replace("+", "_")


def _path_segments(parts) -> list[str]:
    path = _unquote(parts.path or "")
    return [seg for seg in path.split("/") if seg]


def _url_without_userinfo(parts, *, scheme: str | None = None) -> str:
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return _urlunsplit(
        (
            scheme or parts.scheme,
            netloc,
            parts.path or "",
            parts.query or "",
            parts.fragment or "",
        )
    )


def _webdav_url_from_parts(parts, raw_scheme: str, original_url: str) -> str:
    if raw_scheme in {"http", "https"}:
        return _url_without_userinfo(parts, scheme=raw_scheme)
    if raw_scheme == "webdav+http":
        return _url_without_userinfo(parts, scheme="http")
    if raw_scheme in {"webdav", "webdav+https"}:
        return _url_without_userinfo(parts, scheme="https")
    return original_url


def _cm_protocols() -> frozenset[str]:
    """Protocols that are safer to open through ConnectionManager.

    This is intentionally broader than the proxy-support set: the
    manager owns saved-profile parity, default ports, security-mode
    checks, unsupported-proxy warnings and protocol-specific profile
    fields. A few URL-first backends stay direct because their
    constructors expose richer knobs than ConnectionProfile currently
    models.
    """
    from core.profiles import VALID_PROTOCOLS

    direct_is_better = {
        "gopher",
        "nntp",
        "pjl",
        "cisco-telnet",
        "winrm",
    }
    return frozenset(set(VALID_PROTOCOLS) - direct_is_better)


def _open_url_via_cm(
    proto_id,
    parts,
    kwargs,
    original_url,
    proxy_kwargs,
    *,
    default_port: int = 0,
    raw_scheme: str = "",
):
    """Build a transient :class:`ConnectionProfile` from URL + kwargs +
    proxy config, then connect through :class:`ConnectionManager` so
    auth fallback (key/agent/password) and proxy plumbing apply
    uniformly. Used by :func:`open_url` for proxied connections."""
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile

    # Map URL → Profile fields. The user may override any of these
    # via kwargs.
    host = kwargs.pop("host", None) or (parts.hostname or "")
    explicit_port = kwargs.pop("port", None)
    if explicit_port:
        port = explicit_port
    elif parts.port:
        port = parts.port
    elif proto_id == "imap" and raw_scheme in {"imap", "imap+plain"}:
        port = 143
    elif proto_id == "pop3" and raw_scheme in {"pop3", "pop3+plain"}:
        port = 110
    else:
        port = default_port or 0
    username = kwargs.pop("username", None) or (_unquote(parts.username) if parts.username else "")
    password = kwargs.pop("password", None) or (_unquote(parts.password) if parts.password else "")
    auth_type = kwargs.pop("auth_type", None)
    if auth_type is None:
        auth_type = {
            "sftp+key": "key",
            "sftp+agent": "agent",
        }.get(raw_scheme, "password")
    key_file = kwargs.pop("key_file", "")
    key_passphrase = kwargs.pop("key_passphrase", "")
    proxy_password = proxy_kwargs.get("proxy_password", "")

    profile = ConnectionProfile(
        name=f"open_url:{proto_id}://{host}",
        protocol=proto_id,
        host=host,
        port=int(port) if port else 0,
        username=username,
        auth_type=auth_type,
        key_file=key_file,
        store_password=False,
        proxy_type=proxy_kwargs.get("proxy_type", "none"),
        proxy_host=proxy_kwargs.get("proxy_host", ""),
        proxy_port=int(proxy_kwargs.get("proxy_port", 0) or 0),
        proxy_username=proxy_kwargs.get("proxy_username", ""),
    )
    if proxy_password:

        def _transient_proxy_password(_pw=proxy_password):
            return _pw

        profile.get_proxy_password = _transient_proxy_password  # type: ignore[method-assign]

    segments = _path_segments(parts)
    if proto_id == "webdav":
        profile.webdav_url = kwargs.pop(
            "webdav_url",
            _webdav_url_from_parts(parts, raw_scheme, original_url),
        )
    elif proto_id == "s3":
        profile.s3_bucket = kwargs.pop(
            "s3_bucket",
            host or (segments[0] if segments else ""),
        )
        profile.s3_region = kwargs.pop("s3_region", "")
        profile.s3_endpoint = kwargs.pop("s3_endpoint", "")
    elif proto_id in ("smb", "dfsn"):
        profile.smb_share = kwargs.pop(
            "smb_share",
            segments[0] if segments else "",
        )
    elif proto_id == "rsync":
        profile.rsync_module = kwargs.pop(
            "rsync_module",
            segments[0] if segments else "",
        )
        profile.rsync_ssh = bool(kwargs.pop("rsync_ssh", False))
        profile.rsync_ssh_key = kwargs.pop("rsync_ssh_key", "")
        profile.rsync_preserve_metadata = bool(kwargs.pop("rsync_preserve_metadata", False))
    elif proto_id == "nfs":
        profile.nfs_export = kwargs.pop(
            "nfs_export",
            "/" + "/".join(segments) if segments else "/",
        )
        if "nfs_version" in kwargs:
            profile.nfs_version = int(kwargs.pop("nfs_version"))
    elif proto_id == "imap":
        if raw_scheme in {"imap", "imap+plain"}:
            profile.imap_ssl = bool(kwargs.pop("imap_ssl", False))
        else:
            profile.imap_ssl = bool(kwargs.pop("imap_ssl", True))
    elif proto_id == "pop3":
        if raw_scheme in {"pop3", "pop3+plain"}:
            profile.pop3_ssl = bool(kwargs.pop("pop3_ssl", False))
        else:
            profile.pop3_ssl = bool(kwargs.pop("pop3_ssl", True))
    elif proto_id == "adb":
        profile.adb_mode = kwargs.pop("adb_mode", "tcp")
        profile.adb_usb_serial = kwargs.pop("adb_usb_serial", "")
    elif proto_id == "svn":
        profile.host = kwargs.pop("url", original_url)

    # Apply any remaining protocol-specific kwargs
    # (s3_bucket, smb_share, webdav_url, etc.) onto the profile so
    # the backend ctor sees them.
    for k, v in kwargs.items():
        if hasattr(profile, k):
            setattr(profile, k, v)
    cm = ConnectionManager()
    cm.set_profile_resolver(get_profile)
    session = cm.connect(
        profile,
        password=password,
        key_passphrase=key_passphrase,
    )
    return _hand_out(cm, profile, session)


@_api(mutates=False)
def localfs() -> LocalFS:
    """Return a LocalFS session pointed at the host's filesystem."""
    from core.local_fs import LocalFS

    return LocalFS()


@_api(mutates=False)
def ramfs(max_bytes: int | None = None) -> RamFsSession:
    """Return a fresh RamFS session — bytes never touch disk.
    ``max_bytes`` overrides the default per-instance cap."""
    from core.ram_fs import RamFsSession

    if max_bytes is None:
        return RamFsSession()
    return RamFsSession(max_bytes=max_bytes)


# ---------------------------------------------------------------------------
# Cross-backend file ops
# ---------------------------------------------------------------------------


def _backend_label(backend) -> str:
    return getattr(backend, "name", type(backend).__name__)


def _backend_profile(backend):
    """Best-effort profile metadata attached by ConnectionManager."""
    return (
        getattr(backend, "_axross_profile", None)
        or getattr(backend, "_profile", None)
        or getattr(backend, "profile", None)
    )


def _mutation_gate(backend, op_desc: str):
    """Production-tarpit gate for mutating scripting verbs.

    Local/direct backends without profile metadata no-op. Sessions
    opened through ConnectionManager carry ``_axross_profile`` and a
    stable per-session id so the tarpit fires once per opened session.
    """
    from contextlib import nullcontext

    profile = _backend_profile(backend)
    if profile is None:
        return nullcontext()
    session_id = getattr(backend, "_axross_profile_key", "") or f"scripting:{id(backend)}"
    from core.safety_tarpit import production_gate

    return production_gate(profile, op_desc, session_id=str(session_id))


def _record_backend_visit(
    backend,
    path: str,
    *,
    verb: str,
    desc: str = "",
) -> None:
    profile = _backend_profile(backend)
    if profile is None:
        return
    try:
        from core.visit_history import record_visit

        record_visit(
            getattr(profile, "protocol", ""),
            getattr(profile, "host", ""),
            getattr(profile, "username", ""),
            path=path,
            verb=verb,
            desc=desc,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("axross.%s visit-history hook failed: %s", verb, exc)


def _path_exists(backend, path: str) -> bool:
    """Backend-agnostic existence check for safety guards.

    ``FileBackend`` exposes ``exists()``, but a few tests and user
    scripts pass light-weight doubles. Fall back to ``stat()`` so the
    destructive-operation guard still behaves sensibly there.
    """
    if hasattr(backend, "exists"):
        return bool(backend.exists(path))
    if hasattr(backend, "stat"):
        try:
            backend.stat(path)
            return True
        except OSError:
            return False
    raise OSError(f"backend {_backend_label(backend)!r} cannot check whether {path!r} exists")


def _refuse_existing_target_unless_overwrite(
    backend,
    path: str,
    *,
    overwrite: bool,
    operation: str,
) -> bool:
    existed = _path_exists(backend, path)
    if existed and not overwrite:
        raise FileExistsError(
            f"axross.{operation} target already exists: {path!r}; "
            "pass overwrite=True to replace it explicitly"
        )
    if existed:
        log.warning(
            "axross.%s replacing existing target on %s: %s",
            operation,
            _backend_label(backend),
            path,
        )
    return existed


@_api(mutates=True, prompts=True)
def copy(
    src_backend: FileBackend,
    src_path: str,
    dst_backend: FileBackend,
    dst_path: str,
    buffer_size: int = 1024 * 1024,
    *,
    overwrite: bool = False,
) -> int:
    """Copy bytes from one backend to another. Returns the number of
    bytes transferred. Same-backend copies use the backend's native
    ``copy()`` if available; cross-backend copies always stream.

    Existing destinations are refused by default. Pass
    ``overwrite=True`` when replacement is intentional.
    """
    src_label = _backend_label(src_backend)
    dst_label = _backend_label(dst_backend)
    if src_backend is dst_backend:
        from core.server_ops import server_side_copy

        log.info(
            "axross.copy server-side: %s : %s -> %s overwrite=%s",
            src_label,
            src_path,
            dst_path,
            overwrite,
        )
        with _mutation_gate(
            dst_backend,
            f"copy {src_path!r} to {dst_path!r}",
        ):
            server_side_copy(src_backend, src_path, dst_path, overwrite=overwrite)
        _record_backend_visit(
            dst_backend,
            dst_path,
            verb="copy",
            desc=f"from {src_path}",
        )
        # Best-effort size report — server-side ops don't return it,
        # so we re-stat. ``stat`` is part of FileBackend; the hasattr
        # guard catches sub-classes that monkeypatched it away.
        if hasattr(src_backend, "stat"):
            try:
                return int(src_backend.stat(dst_path).size)
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "axross.copy: post-op stat failed (returning 0): %s",
                    exc,
                )
        return 0

    _refuse_existing_target_unless_overwrite(
        dst_backend,
        dst_path,
        overwrite=overwrite,
        operation="copy",
    )
    log.info(
        "axross.copy stream: %s:%s -> %s:%s overwrite=%s",
        src_label,
        src_path,
        dst_label,
        dst_path,
        overwrite,
    )
    from core.server_ops import stream_copy_between_backends

    with _mutation_gate(
        dst_backend,
        f"copy {src_label}:{src_path!r} to {dst_path!r}",
    ):
        transferred = stream_copy_between_backends(
            src_backend,
            src_path,
            dst_backend,
            dst_path,
            buffer_size=buffer_size,
        )
    log.info(
        "axross.copy stream done: %d bytes %s:%s -> %s:%s",
        transferred,
        src_label,
        src_path,
        dst_label,
        dst_path,
    )
    _record_backend_visit(
        src_backend,
        src_path,
        verb="read",
        desc=f"copied to {dst_label}:{dst_path}",
    )
    _record_backend_visit(
        dst_backend,
        dst_path,
        verb="copy",
        desc=f"from {src_label}:{src_path}",
    )
    return transferred


@_api(mutates=True, prompts=True)
def move(
    src_backend: FileBackend,
    src_path: str,
    dst_backend: FileBackend,
    dst_path: str,
    *,
    overwrite: bool = False,
) -> int:
    """Move a file from one backend to another. Same-backend uses
    rename; cross-backend uses copy + delete-source.

    Existing destinations are refused by default. Cross-backend moves
    also refuse replacing an existing destination even with
    ``overwrite=True`` because a later source-delete failure cannot
    restore the replaced remote object reliably across all protocols.
    """
    src_label = _backend_label(src_backend)
    dst_label = _backend_label(dst_backend)
    if src_backend is dst_backend:
        from core.server_ops import server_side_move

        log.info(
            "axross.move server-side: %s : %s -> %s overwrite=%s",
            src_label,
            src_path,
            dst_path,
            overwrite,
        )
        with _mutation_gate(
            src_backend,
            f"move {src_path!r} to {dst_path!r}",
        ):
            server_side_move(src_backend, src_path, dst_path, overwrite=overwrite)
        _record_backend_visit(
            src_backend,
            dst_path,
            verb="move",
            desc=f"from {src_path}",
        )
        return 0
    target_exists = _path_exists(dst_backend, dst_path)
    if target_exists:
        if overwrite:
            raise OSError(
                "axross.move refuses cross-backend overwrite because "
                "source-delete rollback cannot restore the old destination "
                f"reliably: {dst_path!r}"
            )
        raise FileExistsError(
            f"axross.move target already exists: {dst_path!r}; "
            "choose a free destination or delete/rename it explicitly first"
        )
    log.info("axross.move cross-backend: %s:%s -> %s:%s", src_label, src_path, dst_label, dst_path)
    from contextlib import ExitStack

    from core.server_ops import refuse_changed_source, refuse_short_copy, source_size

    with ExitStack() as gates:
        gates.enter_context(
            _mutation_gate(
                dst_backend,
                f"move target write {dst_path!r}",
            )
        )
        gates.enter_context(
            _mutation_gate(
                src_backend,
                f"move source remove {src_path!r}",
            )
        )
        # Compared after the copy: data written to the source meanwhile
        # would otherwise be deleted with it and be in neither place.
        size_before = source_size(src_backend, src_path)
        transferred = copy(
            src_backend,
            src_path,
            dst_backend,
            dst_path,
            overwrite=False,
        )
        try:
            refuse_short_copy(src_path, size_before, transferred, dst_path)
            refuse_changed_source(src_backend, src_path, size_before, dst_path)
            src_backend.remove(src_path)
        except OSError as exc:
            log.warning(
                "axross.move: copied %s:%s -> %s:%s but the source was not removed: %s; "
                "undoing destination",
                src_label,
                src_path,
                dst_label,
                dst_path,
                exc,
            )
            try:
                dst_backend.remove(dst_path)
            except OSError as undo_exc:
                log.error(
                    "axross.move: undo failed after the source was not removed; "
                    "duplicate data may remain at %s:%s: %s",
                    dst_label,
                    dst_path,
                    undo_exc,
                )
            raise
    log.info("axross.move done: %d bytes; src removed", transferred)
    _record_backend_visit(
        src_backend,
        src_path,
        verb="remove",
        desc=f"moved to {dst_label}:{dst_path}",
    )
    _record_backend_visit(
        dst_backend,
        dst_path,
        verb="move",
        desc=f"from {src_label}:{src_path}",
    )
    return transferred


@_api(mutates=True, prompts=True)
def remove(
    backend: FileBackend, path: str, *, recursive: bool = False, confirm: bool = False
) -> str:
    """Delete ``path`` from ``backend`` after an explicit opt-in.

    This scripting helper deliberately refuses to run unless
    ``confirm=True`` is passed. Use :func:`preview_delete` first and
    pair this with :func:`confirm` in interactive scripts.

    Returns the pre-operation preview summary when available.
    """
    if confirm is not True:
        raise PermissionError(
            "axross.remove refuses destructive deletes unless confirm=True is passed explicitly"
        )
    summary = ""
    try:
        from core.destructive_preview import preview_delete as _preview_delete

        summary = _preview_delete(backend, [path]).summary()
    except Exception as exc:  # noqa: BLE001
        log.debug("axross.remove preview failed for %s: %s", path, exc)
    log.warning(
        "axross.remove confirmed on %s: %s recursive=%s%s",
        _backend_label(backend),
        path,
        recursive,
        f" ({summary})" if summary else "",
    )
    with _mutation_gate(
        backend,
        f"remove {path!r} recursive={recursive}",
    ):
        backend.remove(path, recursive=recursive)
    _record_backend_visit(
        backend,
        path,
        verb="remove",
        desc=f"recursive={recursive}",
    )
    return summary


@_api(mutates=True, prompts=True)
def trash(
    backend: FileBackend, path: str, *, root: str | None = None, confirm: bool = False
) -> str:
    """Move ``path`` to Axross trash after an explicit opt-in.

    This is the recoverable alternative to :func:`remove`, but it is
    still destructive from the source path, so ``confirm=True`` is
    required. Returns the trash id.
    """
    if confirm is not True:
        raise PermissionError(
            "axross.trash refuses to move entries unless confirm=True is passed explicitly"
        )
    log.warning(
        "axross.trash confirmed on %s: %s root=%s",
        _backend_label(backend),
        path,
        root or "(default)",
    )
    from core import trash as _trash

    with _mutation_gate(backend, f"trash {path!r}"):
        trash_id = _trash.trash(backend, path, root=root)
    _record_backend_visit(
        backend,
        path,
        verb="trash",
        desc=trash_id,
    )
    return trash_id


@_api(mutates=False)
def checksum(backend: FileBackend, path: str, algorithm: str = "sha256") -> str:
    """Return the backend's content fingerprint for ``path``. Falls
    back to a streaming hash when the backend has no cheap server-side
    checksum."""
    if hasattr(backend, "checksum"):
        try:
            cs = backend.checksum(path, algorithm)
            if cs:
                return cs
        except OSError as exc:
            # Native fingerprint refused (algorithm unsupported, ACL,
            # missing remote tool). Falling back to client-side stream
            # hash — log at DEBUG so an operator who suspects an
            # unexpectedly slow checksum can grep for it.
            log.debug(
                "axross.checksum native %s on %s failed (%s) — falling "
                "back to client-side stream hash",
                getattr(backend, "name", type(backend).__name__),
                path,
                exc,
            )
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


def _read_all_capped(handle, *, max_bytes: int | None) -> bytes:
    if max_bytes is None:
        data = handle.read()
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        return bytes(data)
    cap = int(max_bytes)
    if cap < 0:
        raise ValueError("max_bytes must be >= 0 or None")
    out = bytearray()
    while True:
        room = cap + 1 - len(out)
        if room <= 0:
            raise OSError(f"read exceeds {cap} byte cap")
        chunk = handle.read(min(_SCRIPT_READ_CHUNK, room))
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", errors="replace")
        out.extend(chunk)
        if len(out) > cap:
            raise OSError(f"read exceeds {cap} byte cap")
    return bytes(out)


@_api(mutates=False)
def read_bytes(
    backend: FileBackend,
    path: str,
    *,
    max_bytes: int | None = MAX_SCRIPT_READ_BYTES,
) -> bytes:
    """Read a file into memory.

    Capped by default so a hostile backend cannot make a REPL/script
    pull unbounded data into the process. Pass ``max_bytes=None`` for
    an explicit uncapped read.
    """
    with backend.open_read(path) as fh:
        data = _read_all_capped(fh, max_bytes=max_bytes)
    _record_backend_visit(
        backend,
        path,
        verb="read",
        desc=f"{len(data)} bytes",
    )
    return data


@_api(mutates=True, prompts=True)
def write_bytes(backend: FileBackend, path: str, data: bytes, *, overwrite: bool = False) -> int:
    """Write ``data`` to ``path`` on ``backend``. Returns bytes written.

    Existing destinations are refused by default. Pass
    ``overwrite=True`` when replacement is intentional.
    """
    _refuse_existing_target_unless_overwrite(
        backend,
        path,
        overwrite=overwrite,
        operation="write_bytes",
    )
    from core.atomic_io import atomic_write

    with _mutation_gate(backend, f"write {path!r} ({len(data)} bytes)"):
        atomic_write(backend, path, data)
    log.info(
        "axross.write_bytes %s: %s (%d bytes) overwrite=%s",
        _backend_label(backend),
        path,
        len(data),
        overwrite,
    )
    _record_backend_visit(
        backend,
        path,
        verb="write",
        desc=f"{len(data)} bytes overwrite={overwrite}",
    )
    return len(data)


@_api(mutates=False)
def read_text(
    backend: FileBackend,
    path: str,
    encoding: str = "utf-8",
    *,
    max_bytes: int | None = MAX_SCRIPT_READ_BYTES,
) -> str:
    """Read an entire file as text. Decodes the bytes via ``encoding``
    with ``errors="replace"`` so a stray non-UTF-8 byte never raises;
    use :func:`read_bytes` when you need exact-bytes round-trip."""
    return read_bytes(backend, path, max_bytes=max_bytes).decode(
        encoding,
        errors="replace",
    )


@_api(mutates=True, prompts=True)
def write_text(
    backend: FileBackend, path: str, text: str, encoding: str = "utf-8", *, overwrite: bool = False
) -> int:
    """Write a UTF-8 text file. Convenience wrapper around
    :func:`write_bytes` — encodes ``text`` and forwards. Returns the
    number of bytes written. Existing destinations are refused unless
    ``overwrite=True`` is passed."""
    return write_bytes(
        backend,
        path,
        text.encode(encoding),
        overwrite=overwrite,
    )


# ---------------------------------------------------------------------------
# Encryption helper (axross-encrypted overlay)
# ---------------------------------------------------------------------------


@_api(mutates=True)
def encrypt(
    backend: FileBackend,
    path: str,
    passphrase: str,
    keep_original: bool = True,
    *,
    overwrite: bool = False,
) -> str:
    """Encrypt ``path`` with the axross encrypted-overlay format and
    write the ciphertext to ``<path>.axenc``. Returns the new path.

    The plaintext is kept by default. Pass ``keep_original=False`` to
    remove it after the ciphertext has been written. Existing
    ciphertext destinations are refused unless ``overwrite=True`` is
    passed.
    """
    from core.encrypted_overlay import _ensure_enc_suffix, write_encrypted

    data = read_bytes(backend, path)
    out_path = _ensure_enc_suffix(path)
    _refuse_existing_target_unless_overwrite(
        backend,
        out_path,
        overwrite=overwrite,
        operation="encrypt",
    )
    write_encrypted(backend, out_path, data, passphrase=passphrase)
    log.info(
        "axross.encrypt %s: %s -> %s (%d bytes plaintext, keep_original=%s)",
        _backend_label(backend),
        path,
        out_path,
        len(data),
        keep_original,
    )
    if not keep_original and out_path != path:
        try:
            backend.remove(path)
        except OSError as exc:
            # The new ciphertext is on disk; failure to remove the
            # plaintext leaves both side-by-side, which is a real
            # problem (the plaintext was supposed to be deleted).
            # WARN so the user actually sees it; the original
            # decision was a silent ``pass``.
            log.warning(
                "axross.encrypt: ciphertext written to %s but failed "
                "to remove plaintext %s — both files still exist on "
                "the backend (%s). Caller should clean up.",
                out_path,
                path,
                exc,
            )
            raise OSError(
                f"ciphertext written to {out_path!r}, but plaintext "
                f"removal failed for {path!r}: {exc}"
            ) from exc
    return out_path


@_api(mutates=False)
def decrypt(backend: FileBackend, path: str, passphrase: str) -> bytes:
    """Read and decrypt an .axenc file. Returns the plaintext bytes —
    the caller decides where to put them (write_bytes to disk, hand
    them to a parser, etc.)."""
    from core.encrypted_overlay import read_encrypted

    plaintext = read_encrypted(backend, path, passphrase)
    log.info(
        "axross.decrypt %s: %s -> %d bytes plaintext",
        _backend_label(backend),
        path,
        len(plaintext),
    )
    return plaintext


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


@_api(mutates=False)
def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hex digest of ``data`` under ``algorithm`` (anything
    :mod:`hashlib.new` accepts: sha1, sha256, sha512, md5, …)."""
    import hashlib

    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


@_api(mutates=False)
def hash_file(
    backend: FileBackend, path: str, algorithm: str = "sha256", chunk_size: int = 1024 * 1024
) -> str:
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


@_api(mutates=False)
def list_bookmarks() -> list:
    """Return all saved bookmarks (list of :class:`Bookmark`)."""
    from core.bookmarks import BookmarkManager

    return list(BookmarkManager()._bookmarks)  # noqa: SLF001 — read-only


@_api(mutates=True)
def add_bookmark(
    name: str,
    path: str,
    backend_name: str = "Local",
    profile_name: str = "",
    icon_name: str = "bookmark",
) -> None:
    """Create a new bookmark. Idempotent on (path, backend_name)."""
    from core.bookmarks import Bookmark, BookmarkManager

    mgr = BookmarkManager()
    mgr.add(
        Bookmark(
            name=name,
            path=path,
            backend_name=backend_name,
            profile_name=profile_name,
            icon_name=icon_name,
        )
    )
    log.info(
        "axross.add_bookmark %r -> %s on %s%s",
        name,
        path,
        backend_name,
        f" (profile={profile_name})" if profile_name else "",
    )


@_api(mutates=True)
def remove_bookmark(index: int) -> None:
    """Remove the bookmark at ``index`` (zero-based)."""
    from core.bookmarks import BookmarkManager

    mgr = BookmarkManager()
    # Capture name BEFORE the remove for the audit log.
    try:
        target_name = mgr._bookmarks[index].name  # noqa: SLF001
    except (IndexError, AttributeError):
        target_name = "?"
    mgr.remove(index)
    mgr.save()
    log.info("axross.remove_bookmark idx=%d (was %r)", index, target_name)


# ---------------------------------------------------------------------------
# Profile CRUD (create / save / delete connection profiles from a script)
# ---------------------------------------------------------------------------


@_api(mutates=True)
def save_profile(profile: ConnectionProfile) -> None:
    """Persist a :class:`core.profiles.ConnectionProfile`. The profile
    object itself can be constructed via ``ConnectionProfile(name=...,
    protocol=..., host=...)`` — see ``help(core.profiles.ConnectionProfile)``."""
    from core.profiles import ProfileManager

    mgr = ProfileManager()
    mgr.add(profile)
    log.info(
        "axross.save_profile %r — protocol=%s host=%s user=%s",
        getattr(profile, "name", "?"),
        getattr(profile, "protocol", "?"),
        getattr(profile, "host", "?"),
        getattr(profile, "username", "?"),
    )


@_api(mutates=True)
def delete_profile(name: str) -> None:
    """Delete a saved profile by name. No-op if the profile doesn't
    exist."""
    from core.profiles import ProfileManager

    mgr = ProfileManager()
    existed = name in mgr.list_names() if hasattr(mgr, "list_names") else True
    mgr.remove(name)
    if existed:
        log.info("axross.delete_profile %r", name)
    else:
        log.debug("axross.delete_profile %r — no-op (not found)", name)


# ---------------------------------------------------------------------------
# Archive helpers
# ---------------------------------------------------------------------------


@_api(mutates=True)
def extract_archive(
    local_path: str, dst_dir: str, progress: Callable[[int, int, str], None] | None = None
) -> str:
    """Extract a local archive (zip / tar / 7z) to ``dst_dir``. Returns
    the destination directory after the extract. Refuses zip-bombs
    and zip-slip via the same guards used by the file-manager UI.

    ``progress`` is an optional callable ``(current, total, name)``
    invoked once per archive entry.
    """
    from core.archive import extract

    log.info("axross.extract_archive: %s -> %s", local_path, dst_dir)
    file_count = extract(local_path, dst_dir, progress=progress)
    log.info("axross.extract_archive done: %d files into %s", file_count, dst_dir)
    return dst_dir


@_api(mutates=False)
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
    ArchiveEntry,
    GrepHit,
    HttpProbe,
    OuiInfo,
    PingResult,
    SshHostKey,
    TimeSkew,
    TlsCert,
    WhoisInfo,
    archive_inspect,
    diff_files,
    dns_records,
    dns_reverse,
    entropy,
    find_files,
    grep,
    http_probe,
    mac_lookup,
    magic_type,
    ping,
    port_scan,
    ssh_hostkey,
    subnet_hosts,
    tcp_banner,
    text_encoding,
    time_skew,
    tls_cert,
    whois,
)

# SNMP helpers — separate module because pysnmp is heavy + optional.
# Re-export under ``axross.snmp_*`` so they sit alongside dns_records/
# port_scan in the network-helpers group.
try:
    from core.snmp_helpers import (
        SnmpVar,
        snmp_get,
        snmp_set,
        snmp_walk,
    )
except ImportError:
    # pysnmp not installed — define stubs that raise a helpful OSError
    # at call time so axross.help() can still list the names.
    class SnmpVar:  # type: ignore[no-redef]
        """Placeholder when pysnmp is missing."""

    def _snmp_unavailable(name: str):
        # One stub per name: each carries its own traits for api_schema().
        def stub(*_args: Any, **_kwargs: Any) -> Any:
            raise OSError(
                "SNMP support requires pysnmp — install with "
                "`pip install pysnmp` (or via the axross[snmp] extra)"
            )

        stub.__name__ = stub.__qualname__ = name
        stub.__doc__ = "Unavailable here: SNMP support requires pysnmp."
        return stub

    snmp_get = _snmp_unavailable("snmp_get")
    snmp_walk = _snmp_unavailable("snmp_walk")
    snmp_set = _snmp_unavailable("snmp_set")

# The re-exported helpers declare their traits here (see _api).
for _helper in (
    archive_inspect, diff_files, dns_records, dns_reverse, entropy, find_files, grep,
    http_probe, mac_lookup, magic_type, ping, port_scan, ssh_hostkey, subnet_hosts,
    tcp_banner, text_encoding, time_skew, tls_cert, whois, snmp_get, snmp_walk,
):  # fmt: skip
    _api(mutates=False)(_helper)
_api(mutates=True)(snmp_set)
del _helper

# ---------------------------------------------------------------------------
# Network helpers (small + frequently useful in scripts)
# ---------------------------------------------------------------------------


@_api(mutates=False)
def dns_resolve(host: str, family: str = "any") -> list[str]:
    """Return the IPs ``host`` resolves to. ``family`` is ``"v4"``,
    ``"v6"``, or ``"any"``.

    Returns an empty list when the name doesn't resolve — caller should
    distinguish this from "no records of the requested family" by
    enabling axross's DEBUG log: every resolution failure is logged
    there with the exception text.
    """
    import socket

    fam_map = {
        "v4": socket.AF_INET,
        "v6": socket.AF_INET6,
        "any": socket.AF_UNSPEC,
    }
    fam = fam_map.get(family, socket.AF_UNSPEC)
    out: list[str] = []
    try:
        for info in socket.getaddrinfo(host, None, fam):
            ip = info[4][0]
            if isinstance(ip, str) and ip not in out:
                out.append(ip)
    except socket.gaierror as exc:
        log.debug(
            "axross.dns_resolve(%r, family=%r) failed: %s",
            host,
            family,
            exc,
        )
    return out


@_api(mutates=False)
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


@_api(mutates=False)
def find_tftp_files(
    backend: FileBackend,
    wordlist: list[str] | str | None = None,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> list[FileItem]:
    """Walk ``backend.find_files()`` (TFTP wordlist scan). The backend
    must be a :class:`TftpSession`; raises :class:`AttributeError`
    otherwise."""
    return backend.find_files(wordlist=wordlist, on_progress=on_progress)


@_api(mutates=False)
def slp_discover(host: str, scope: str = "DEFAULT", port: int = 427, use_tcp: bool = False) -> dict:
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


@_api(mutates=True)
def nntp_post(
    backend: FileBackend,
    group: str,
    subject: str,
    body: str,
    author: str = "axross <noreply@axross>",
) -> None:
    """Post a fully-formed article to ``group`` on ``backend`` (an
    :class:`NntpSession`). Builds a minimal RFC 5322 envelope around
    ``subject`` + ``body``; for richer headers, hand the writer a
    pre-built bytes payload via ``backend.open_write(...)``.

    Header values are validated for CR/LF before being formatted into
    the envelope so a tainted ``subject`` cannot smuggle additional
    headers / body content into the post (RFC 5322 / RFC 3977 header-
    injection class of bug)."""
    for label, value in (("group", group), ("subject", subject), ("author", author)):
        if "\r" in value or "\n" in value:
            raise ValueError(f"NNTP post header {label!r} must not contain CR/LF")
    article = (f"From: {author}\r\nNewsgroups: {group}\r\nSubject: {subject}\r\n\r\n{body}").encode(
        "utf-8"
    )
    with backend.open_write(f"/{group}/draft.eml") as fh:
        fh.write(article)
    log.info(
        "axross.nntp_post: group=%s subject=%r author=%r (%d bytes body)",
        group,
        subject,
        author,
        len(body),
    )


@_api(mutates=True)
def git_push(backend: FileBackend, branch: str | None = None) -> None:
    """Push committed work on ``backend`` (a :class:`GitFsSession`) to
    its origin. Raises :class:`GitForceRefused` on non-fast-forward.
    Pass ``branch=None`` to push every branch the session has touched."""
    log.info("axross.git_push: branch=%s", branch or "<all touched>")
    backend.flush_push(branch=branch)


@_api(mutates=False)
def ldap_search(
    backend: FileBackend,
    base_dn: str,
    filter: str = "(objectClass=*)",
    *,
    scope: str = "subtree",
    attributes: list[str] | None = None,
    limit: int = 1000,
) -> list[dict]:
    """Run a raw LDAP search via the connected ``LdapFsSession``.
    Returns up to ``limit`` entries as dicts ``{dn, attributes}``::

        users = axross.ldap_search(
            b, "ou=people,dc=example,dc=com",
            "(objectClass=inetOrgPerson)",
            attributes=["cn", "mail", "uid"],
        )
    """
    if not hasattr(backend, "search") or not hasattr(backend, "_path_to_dn"):
        raise TypeError(f"backend {type(backend).__name__} is not an LDAP session")
    return backend.search(base_dn, filter, scope=scope, attributes=attributes, limit=limit)


@_api(mutates=True)
def share(backend: FileBackend, path: str, **kwargs: Any) -> str:
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


@_api(mutates=False)
def imap_search(backend: FileBackend, criteria: str = "ALL", *, mailbox: str = "INBOX") -> list:
    """Wrapper around message-backend search. For IMAP this returns
    the list of UIDs matching an IMAP search expression (RFC 3501);
    for Exchange it returns the backend's lightweight message dicts::

        uids = axross.imap_search(b, 'UNSEEN SUBJECT "invoice"')
    """
    if not hasattr(backend, "search"):
        raise TypeError(
            f"backend {type(backend).__name__} does not implement "
            "search() — only the IMAP/Exchange backends do today."
        )
    import inspect

    try:
        params = inspect.signature(backend.search).parameters
    except (TypeError, ValueError):
        params = {}
    if "mailbox" in params:
        return backend.search(criteria, mailbox=mailbox)
    if "folder" in params:
        folder = None if mailbox.upper() == "INBOX" else mailbox
        return backend.search(criteria, folder=folder)
    raise TypeError(
        f"backend {type(backend).__name__}.search() is not shaped like IMAP or Exchange search."
    )


@_api(mutates=True)
def imap_move(backend: FileBackend, uid: int, src_mailbox: str, dst_mailbox: str) -> None:
    """Move an IMAP message by UID. Uses MOVE if the server supports
    it, COPY+\\Deleted+EXPUNGE otherwise. See ``ImapSession.move``."""
    if not hasattr(backend, "move") or not hasattr(backend, "set_flags"):
        raise TypeError(f"backend {type(backend).__name__} is not an IMAP session")
    log.info(
        "axross.imap_move: uid=%d %s -> %s",
        uid,
        src_mailbox,
        dst_mailbox,
    )
    backend.move(uid, src_mailbox, dst_mailbox)


@_api(mutates=True)
def imap_set_flags(
    backend: FileBackend, uid: int, flags: list[str], *, mailbox: str = "INBOX", mode: str = "set"
) -> None:
    """STORE flags on an IMAP message by UID. ``mode`` is ``set`` /
    ``add`` / ``remove``."""
    if not hasattr(backend, "set_flags"):
        raise TypeError(f"backend {type(backend).__name__} is not an IMAP session")
    log.info(
        "axross.imap_set_flags: uid=%d mailbox=%s mode=%s flags=%s",
        uid,
        mailbox,
        mode,
        flags,
    )
    backend.set_flags(uid, flags, mailbox=mailbox, mode=mode)


@_api(mutates=True)
def query(backend: FileBackend, sql_or_args: str, *args: Any, **kwargs: Any) -> list[dict]:
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


@_api(mutates=False)
def tables(backend: FileBackend) -> list[str]:
    """Return every table (SQLite/Postgres) or collection (Mongo) on
    ``backend``. Wraps the per-backend method of the same name."""
    if hasattr(backend, "tables"):
        return backend.tables()
    if hasattr(backend, "collections"):
        return backend.collections()
    raise TypeError(f"backend {type(backend).__name__} does not implement tables() / collections()")


@_api(mutates=True)
def interactive_shell(
    backend: FileBackend,
    *,
    term: str = "xterm-256color",
    cols: int = 80,
    rows: int = 24,
    env: dict[str, str] | None = None,
) -> InteractiveShell:
    """Open an interactive shell on the same SSH transport ``backend``
    is already using. Multiplexing — file ops on ``backend`` keep
    working while the shell is open. Returns a
    :class:`models.interactive_shell.InteractiveShell` wrapper with
    ``read`` / ``write`` / ``read_until`` / ``resize_pty`` /
    ``close`` / ``interact`` / iter-as-lines.

    Currently supported on SSH/SFTP and SCP backends — both reuse
    the same paramiko Transport. Other backends raise TypeError::

        with axross.open("alpha-ssh") as b:
            sh = axross.interactive_shell(b, cols=200, rows=50)
            sh.write(b"htop\\n")
            ...
    """
    if not hasattr(backend, "interactive_shell"):
        raise TypeError(
            f"backend {type(backend).__name__} does not implement "
            "interactive_shell() — only SSH/SFTP and SCP do today."
        )
    return backend.interactive_shell(term=term, cols=cols, rows=rows, env=env)


@_api(mutates=True)
def exec(
    backend: FileBackend,
    cmd: str,
    *,
    timeout: float | None = 30.0,
    stdin: bytes | str | None = None,
    stdout_cap: int = 1024 * 1024,
    stderr_cap: int = 64 * 1024,
    env: dict[str, str] | None = None,
) -> ExecResult:
    """Run a shell command on a remote backend. Returns
    :class:`models.exec_result.ExecResult` with ``returncode``,
    ``stdout``, ``stderr`` and the corresponding ``truncated_*`` flags.

    Works on any backend whose session implements ``.exec()`` —
    currently SSH/SFTP and SCP. For protocols where ``exec`` is the
    wrong shape (Cisco IOS, IMAP, S3 …) use the per-protocol helper
    instead (``show()`` on a Cisco-telnet session, ``axross.imap_search()``,
    …).

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
# Safety, diagnostics and recovery
# ---------------------------------------------------------------------------


@_api(mutates=True)
def diagnose(backend: FileBackend, *, root: str | None = None, write_test: bool = False) -> str:
    """Run live diagnostics against an open backend and return a
    plain-text report.

    ``write_test=True`` performs a reversible write/rename/delete
    probe in ``root`` (or the backend home directory when omitted).
    Keep it false for read-only targets or when you only want cheap
    connectivity checks.
    """
    from core.diagnostics import diagnose_backend

    return diagnose_backend(
        backend,
        root=root,
        write_test=write_test,
    ).to_text()


@_api(mutates=False)
def preview_delete(backend: FileBackend, paths: list[str], *, max_entries: int = 10_000) -> str:
    """Preview a delete/trash operation before executing it.

    Returns a compact summary with item counts, total bytes and warning
    or truncation counts.
    """
    from core.destructive_preview import preview_delete as _preview_delete

    return _preview_delete(
        backend,
        paths,
        max_entries=max_entries,
    ).summary()


@_api(mutates=False)
def preview_transfer(
    source_backend: FileBackend,
    dest_backend: FileBackend,
    source_paths: list[str],
    dest_dir: str,
    *,
    operation: str = "copy",
    max_entries: int = 10_000,
) -> str:
    """Preview a copy/move before queueing it.

    Returns a compact summary with item counts, total bytes and
    destination conflict counts.
    """
    from core.destructive_preview import preview_transfer as _preview_transfer

    return _preview_transfer(
        source_backend,
        dest_backend,
        source_paths,
        dest_dir,
        operation=operation,
        max_entries=max_entries,
    ).summary()


@_api(mutates=False)
def recovery_scan(backend: FileBackend, root: str | None = None) -> str:
    """Scan a backend location for recoverable temp/trash items and
    return a plain-text report."""
    from core.recovery import format_findings, scan_backend_recovery

    if root is None:
        try:
            root = backend.home()
        except Exception:  # noqa: BLE001
            root = "/"
    return format_findings(scan_backend_recovery(backend, root))


@_api(mutates=False)
def recent_operations(limit: int = 20) -> list[dict]:
    """Return recent operation-journal events: secrets redacted, paths
    as they are on disk (undo needs them)."""
    from core.operation_journal import read_recent

    return read_recent(limit=limit)


@_api(mutates=True)
def security_mode(name: str | None = None) -> str:
    """Get or set the runtime security mode.

    Passing ``"paranoid"`` disables external viewers, automatic
    previews, scripts, legacy protocols and private-proxy overrides.
    Passing ``"normal"`` restores the default policy.
    """
    from core.security_mode import current_policy, set_policy

    if name is not None:
        return set_policy(name).name
    return current_policy().name


# ---------------------------------------------------------------------------
# Credential testing (bruteforce / spray / user enumeration)
#
# Thin wrappers over :mod:`core.cred_attack`. The whole surface refuses
# to run unless the caller passes ``authorized=True`` — see
# ``docs/CRED_ATTACK.md`` for the OPSEC checklist before calling any of
# these from a script. The functions are exposed here so REPL / scripts
# / MCP can reach them through the same ``axross.*`` namespace as the
# rest of the API.
# ---------------------------------------------------------------------------


@_api(mutates=True)
def bruteforce(
    profile: ConnectionProfile | str,
    *,
    users: Iterable[str],
    passwords: Iterable[str],
    rate_per_min: float = 30.0,
    timeout_per_attempt: float = 10.0,
    abort_on_lockout: bool = True,
    abort_after_n_lockouts: int = 1,
    abort_after_n_failures: int | None = None,
    max_attempts: int | None = None,
    stop_on_first_success_per_user: bool = True,
    progress: Callable[[AttemptOutcome], None] | None = None,
    on_unknown_host: Callable[[object], bool] | None = None,
    state_file: str | os.PathLike[str] | None = None,
    dry_run: bool = False,
    jitter_s: float = 0.0,
    authorized: bool = False,
) -> AttackReport:
    """Run a brute-force credential test in user-major order against a
    saved profile (name or :class:`ConnectionProfile`).

    Iterates every password in ``passwords`` against every user in
    ``users`` (user 1 → all passwords → user 2 → all passwords → …).
    Lockout-aware: the first attempt that classifies as LOCKOUT stops
    the entire run unless ``abort_on_lockout=False`` is set with an
    explicit ``abort_after_n_lockouts`` budget.

    ``authorized=True`` is **mandatory** — this gate is a hard refusal
    from the underlying module, not a polite hint. Read
    ``docs/CRED_ATTACK.md`` and the OPSEC checklist before calling.

    Returns an :class:`core.cred_attack.AttackReport`. Successful
    credentials live on ``report.successes`` as ``Credential`` objects
    (cleartext password — handle with care).
    For SSH/SCP profiles, ``on_unknown_host`` is forwarded to the
    host-key decision callback; leave it unset unless you have an
    explicit trust policy for the target.
    """
    from core.cred_attack import bruteforce as _impl

    return _impl(
        profile,
        users=users,
        passwords=passwords,
        rate_per_min=rate_per_min,
        timeout_per_attempt=timeout_per_attempt,
        abort_on_lockout=abort_on_lockout,
        abort_after_n_lockouts=abort_after_n_lockouts,
        abort_after_n_failures=abort_after_n_failures,
        max_attempts=max_attempts,
        stop_on_first_success_per_user=stop_on_first_success_per_user,
        progress=progress,
        on_unknown_host=on_unknown_host,
        state_file=state_file,
        dry_run=dry_run,
        jitter_s=jitter_s,
        authorized=authorized,
    )


@_api(mutates=True)
def spray(
    profile: ConnectionProfile | str,
    *,
    users: Iterable[str],
    password: str | None = None,
    passwords: Iterable[str] | None = None,
    rate_per_min: float = 30.0,
    timeout_per_attempt: float = 10.0,
    abort_on_lockout: bool = True,
    abort_after_n_lockouts: int = 1,
    max_attempts: int | None = None,
    stop_on_first_success_per_user: bool = True,
    progress: Callable[[AttemptOutcome], None] | None = None,
    on_unknown_host: Callable[[object], bool] | None = None,
    state_file: str | os.PathLike[str] | None = None,
    dry_run: bool = False,
    jitter_s: float = 0.0,
    authorized: bool = False,
) -> AttackReport:
    """Run a password spray in password-major order — the safer
    pattern for AD-style targets where lockout is per-user-per-window.

    Try ``password`` (or the first item in ``passwords``) against
    every user in ``users``, then move to the next password. Pass
    either ``password=`` (single) or ``passwords=`` (list).

    ``authorized=True`` is mandatory. See :func:`bruteforce` for the
    other arguments. Returns an
    :class:`core.cred_attack.AttackReport`.
    """
    from core.cred_attack import spray as _impl

    return _impl(
        profile,
        users=users,
        password=password,
        passwords=passwords,
        rate_per_min=rate_per_min,
        timeout_per_attempt=timeout_per_attempt,
        abort_on_lockout=abort_on_lockout,
        abort_after_n_lockouts=abort_after_n_lockouts,
        max_attempts=max_attempts,
        stop_on_first_success_per_user=stop_on_first_success_per_user,
        progress=progress,
        on_unknown_host=on_unknown_host,
        state_file=state_file,
        dry_run=dry_run,
        jitter_s=jitter_s,
        authorized=authorized,
    )


@_api(mutates=True)
def enumerate_users(
    profile: ConnectionProfile | str,
    candidates: Iterable[str],
    *,
    method: str = "auto",
    timeout_per_probe: float = 10.0,
    timing_samples: int = 5,
    rate_per_min: float = 30.0,
    jitter_s: float = 0.0,
    progress: Callable[[EnumResult], None] | None = None,
    on_unknown_host: Callable[[object], bool] | None = None,
    authorized: bool = False,
) -> EnumReport:
    """Probe whether each candidate username exists on the target.

    ``method="auto"`` (default) uses a registered per-protocol oracle
    when one exists (POP3, FTP, FTPS today) and falls back to
    statistical timing comparison otherwise. ``method="oracle"``
    refuses to run if the protocol has no oracle; ``method="timing"``
    forces the timing path even when an oracle exists.

    Oracle probes and timing attempts are paced with ``rate_per_min``
    and optional ``jitter_s`` just like spray/bruteforce attempts.

    Returns an :class:`core.cred_attack.EnumReport`. ``authorized=True``
    is mandatory.
    """
    from core.cred_attack import enumerate_users as _impl

    return _impl(
        profile,
        candidates,
        method=method,
        timeout_per_probe=timeout_per_probe,
        timing_samples=timing_samples,
        rate_per_min=rate_per_min,
        jitter_s=jitter_s,
        progress=progress,
        on_unknown_host=on_unknown_host,
        authorized=authorized,
    )


# ---------------------------------------------------------------------------
# Multi-system / daily-driver verbs
#
# Thin wrappers over the modules in core/{visit_history,conn_health,
# inspect,multi_view,search_federation,copy_resume,trail,dashboard,
# reverse_serve}.py. Real work + docstrings live in the underlying
# modules; these exist so REPL / scripts / MCP reach them through the
# same ``axross.*`` namespace as the rest of the API.
# ---------------------------------------------------------------------------


@_api(mutates=False)
def where_was_i(host: str | None = None) -> list[HostVisit] | HostVisit | None:
    """Look up the visit-history record(s).

    With no argument, returns every recorded host (most-recent first)
    as a list of :class:`core.visit_history.HostVisit`. With a host
    string, returns the single best-matching record (substring match
    over hostnames) or ``None``.

    History is recorded automatically by ``connect`` / file-op verbs
    when they pass through :mod:`core.visit_history.record_visit`. The
    JSON store lives at ``~/.config/axross/visit_history.json`` (mode
    0o600); treat it as sensitive engagement data — it carries the
    path layout of every host you've touched.
    """
    from core.visit_history import where_was_i as _impl

    return _impl(host)


@_api(mutates=False)
def health_pulse() -> list[HealthRecord]:
    """Snapshot the live connection-health pulse for every enrolled
    session — last-probe latency, median latency, staleness flag.

    Returns a list of :class:`core.conn_health.HealthRecord`. Empty
    when no sessions have been enrolled.
    """
    from core.conn_health import health_pulse as _impl

    return _impl()


@_api(mutates=False)
def summarize(backend: FileBackend, path: str = "", *, max_entries: int = 2000) -> Summary:
    """One-paragraph synopsis of a directory: file/dir/link counts,
    extension histogram, age buckets, newest/oldest entries, top-5
    largest files. Reads metadata only — no file contents are fetched.

    Returns a :class:`core.inspect.Summary`; call ``.render()`` for a
    one-line human string. LLM-friendly: a single network round-trip
    yields the gist of "what's in this place" without an N-thousand
    entry ``list_dir`` dump.
    """
    from core.inspect import summarize as _impl

    return _impl(backend, path, max_entries=max_entries)


@_api(mutates=False)
def explain(backend: FileBackend, path: str = "") -> ExplainResult:
    """Heuristic best-guess "what IS this directory?" — git repo,
    PostgreSQL data dir, nginx config tree, k8s manifests, Maildir,
    web-server log dir, and friends. Returns the highest-confidence
    pattern match as a :class:`core.inspect.ExplainResult`, or an
    empty result if nothing scored above 0.2.
    """
    from core.inspect import explain as _impl

    return _impl(backend, path)


@_api(mutates=False)
def compare_file(
    backends: list[FileBackend],
    path: str,
    *,
    content: bool = True,
    content_cap_bytes: int | None = None,
    parallelism: int = 8,
    per_target_timeout_s: float = 30.0,
) -> CompareReport:
    """Compare the SAME path across N backends in parallel.

    Returns a :class:`core.multi_view.CompareReport` with per-backend
    metadata + sha256 + pairwise unified-diff strings against the
    first probe with text content. ``content=False`` skips the body
    download and only diffs metadata (cheaper on cloud backends).
    """
    from core.multi_view import DEFAULT_CONTENT_CAP_BYTES
    from core.multi_view import compare_file as _impl

    return _impl(
        backends,
        path,
        content=content,
        content_cap_bytes=(content_cap_bytes or DEFAULT_CONTENT_CAP_BYTES),
        parallelism=parallelism,
        per_target_timeout_s=per_target_timeout_s,
    )


@_api(mutates=False)
def inspect_targets(
    targets: list[tuple[FileBackend, str]],
    *,
    content: bool = True,
    content_cap_bytes: int | None = None,
    parallelism: int = 8,
    per_target_timeout_s: float = 30.0,
) -> InspectReport:
    """Inspect a list of ``(backend, path)`` pairs in parallel.

    Returns :class:`core.multi_view.InspectReport` aligned with input
    order. Use this to answer "is the local /tmp/foo.bin the same
    file as the S3 object and the SFTP copy?".
    """
    from core.multi_view import DEFAULT_CONTENT_CAP_BYTES
    from core.multi_view import inspect_targets as _impl

    return _impl(
        targets,
        content=content,
        content_cap_bytes=(content_cap_bytes or DEFAULT_CONTENT_CAP_BYTES),
        parallelism=parallelism,
        per_target_timeout_s=per_target_timeout_s,
    )


@_api(mutates=False)
def federated_search(
    backends: list[FileBackend],
    query: SearchQuery | None = None,
    *,
    name: str = "",
    regex: str = "",
    contains: str = "",
    contains_is_regex: bool = False,
    min_size: int = -1,
    max_size: int = -1,
    modified_after: float = 0.0,
    modified_before: float = 0.0,
    roots: list[str] | None = None,
    max_depth: int = 6,
    max_hits_per_backend: int = 500,
    max_hits_total: int = 5000,
    parallelism: int = 8,
    per_backend_timeout_s: float = 60.0,
    progress: Callable[[SearchHit], None] | None = None,
) -> SearchResult:
    """Run one search query against many backends in parallel.

    Every backend is walked client-side (``core.file_search``); an
    adapter registered for its protocol replaces the walk. A backend
    none of whose roots can be read is in ``errors``, not a quiet zero.
    Pass either a pre-built :class:`core.search_federation.SearchQuery`
    (``query=…``) or the individual filter kwargs to construct one
    inline.

    Returns a :class:`core.search_federation.SearchResult`.
    """
    from core.search_federation import (
        SearchQuery,
    )
    from core.search_federation import (
        federated_search as _impl,
    )

    if query is None:
        query = SearchQuery(
            name=name,
            regex=regex,
            contains=contains,
            contains_is_regex=contains_is_regex,
            min_size=min_size,
            max_size=max_size,
            modified_after=modified_after,
            modified_before=modified_before,
            roots=list(roots or []),
            max_depth=max_depth,
        )
    return _impl(
        backends,
        query,
        max_hits_per_backend=max_hits_per_backend,
        max_hits_total=max_hits_total,
        parallelism=parallelism,
        per_backend_timeout_s=per_backend_timeout_s,
        progress=progress,
    )


@_api(mutates=True)
def resumable_copy(
    src_backend: FileBackend,
    src_path: str,
    dst_backend: FileBackend,
    dst_path: str,
    *,
    segment_size: int = 4 * 1024 * 1024,
    manifest_path: str | os.PathLike[str] | None = None,
    overwrite: bool = False,
    progress: Callable[[int, int], None] | None = None,
) -> ResumeReport:
    """Cross-backend copy with checkpoint-resume.

    Splits the source into segments, writes a manifest after each
    completed segment, and on a re-run picks up from the first
    incomplete segment after verifying the destination matches the
    recorded hashes. Returns a
    :class:`core.copy_resume.ResumeReport`.
    """
    from core.copy_resume import resumable_copy as _impl

    return _impl(
        src_backend,
        src_path,
        dst_backend,
        dst_path,
        segment_size=segment_size,
        manifest_path=manifest_path,
        overwrite=overwrite,
        progress=progress,
    )


@_api(mutates=True)
def snapshot_now(
    backend: FileBackend,
    path: str,
    *,
    name: str = "",
    head_hash: bool = False,
    max_files: int = 5000,
) -> Snapshot:
    """Take a single time-lapse snapshot of a directory tree.

    Records ``(name, size, mtime, optional sha-prefix)`` per file plus
    a synthesised tree-hash, into the local SQLite trail database
    (``~/.config/axross/trail.db``). Pair with :func:`start_trail` to
    take snapshots on a recurring interval and :func:`diff_snapshots`
    to compare any two snapshots of the same trail.
    """
    from core.trail import snapshot_now as _impl

    return _impl(
        backend,
        path,
        name=name,
        head_hash=head_hash,
        max_files=max_files,
    )


@_api(mutates=True)
def start_trail(
    backend: FileBackend,
    path: str,
    *,
    name: str = "",
    interval_s: float = 300.0,
    head_hash: bool = False,
    max_files: int = 5000,
    on_snapshot: Callable[[Snapshot], None] | None = None,
) -> str:
    """Start a background trail — periodic snapshots until
    :func:`stop_trail` is called. Returns the trail name.
    """
    from core.trail import start_trail as _impl

    return _impl(
        backend,
        path,
        name=name,
        interval_s=interval_s,
        head_hash=head_hash,
        max_files=max_files,
        on_snapshot=on_snapshot,
    )


@_api(mutates=True)
def stop_trail(name: str) -> bool:
    """Stop a named background trail. Returns True if one was found."""
    from core.trail import stop_trail as _impl

    return _impl(name)


@_api(mutates=False)
def list_trails() -> list[dict]:
    """List every recorded trail with its metadata."""
    from core.trail import list_trails as _impl

    return _impl()


@_api(mutates=False)
def list_snapshots(trail_name: str, *, limit: int = 100) -> list[Snapshot]:
    """List the most recent snapshots of one trail (newest first).

    Returns a list of :class:`core.trail.Snapshot`.
    """
    from core.trail import list_snapshots as _impl

    return _impl(trail_name, limit=limit)


@_api(mutates=False)
def diff_snapshots(snapshot_a: int, snapshot_b: int) -> TrailDiff:
    """Compare snapshot A to snapshot B (B is the newer / target).

    Returns a :class:`core.trail.TrailDiff` with added / removed /
    modified path lists.
    """
    from core.trail import diff_snapshots as _impl

    return _impl(snapshot_a, snapshot_b)


@_api(mutates=False)
def dashboard(
    *,
    with_capacity: bool = False,
    recent_ops_limit: int = 10,
    fmt: str = "text",
    backends: list[FileBackend] | None = None,
) -> str:
    """Federation-status dashboard — one screen, every connection.

    ``fmt`` selects the renderer:

    * ``"text"`` (default) — fixed-width text for the REPL.
    * ``"markdown"`` — markdown table for MCP / LLM responses.
    * ``"json"`` — structured JSON the GUI / scripts can consume.

    Read-only — never performs mutating ops. Capacity columns require
    opened backend objects; pass ``backends=[...]`` with
    ``with_capacity=True``.
    """
    from core.dashboard import (
        render_json,
        render_markdown,
        render_text,
        snapshot,
        snapshot_with_backends,
    )

    if with_capacity and backends is not None:
        snap = snapshot_with_backends(
            backends,
            recent_ops_limit=recent_ops_limit,
        )
    else:
        snap = snapshot(
            with_capacity=with_capacity,
            recent_ops_limit=recent_ops_limit,
        )
    fmt = fmt.strip().lower()
    if fmt == "json":
        return render_json(snap)
    if fmt == "markdown":
        return render_markdown(snap)
    return render_text(snap, with_capacity=with_capacity)


@_api(mutates=True)
def serve_s3(
    backend: FileBackend,
    *,
    bind: str = "127.0.0.1",
    port: int = 9000,
    read_only: bool = False,
    auth_token: str | None = "",
    root_path: str = "/",
) -> ReverseServer:
    """Expose ``backend`` as a minimum-viable S3 endpoint so any
    existing S3 client (aws-cli / restic / rclone / terraform) can
    speak to it.

    Localhost-bound by default, and with a token by default: the
    handle's ``.auth_token`` is what clients send - as the AWS access
    key id (``AWS_ACCESS_KEY_ID=<token>``, any secret: aws-cli, restic,
    rclone, boto3), as ``Authorization: Bearer <token>`` or as the Basic
    password. ``auth_token="…"`` sets your own; ``auth_token=None``
    turns auth off - on loopback only, as every local user can then
    reach the backend.
    Pass ``bind="0.0.0.0"`` only when you intentionally want LAN access;
    non-local binds need an explicit ``auth_token``. Returns a live
    :class:`core.reverse_serve.ReverseServer` handle; call
    ``.shutdown()`` to stop.
    """
    from core.reverse_serve import serve_s3 as _impl

    return _impl(
        backend,
        bind=bind,
        port=port,
        read_only=read_only,
        auth_token=auth_token,
        root_path=root_path,
    )


@_api(mutates=True)
def serve_webdav(
    backend: FileBackend,
    *,
    bind: str = "127.0.0.1",
    port: int = 8080,
    read_only: bool = False,
    auth_token: str | None = "",
    root_path: str = "/",
) -> ReverseServer:
    """Expose ``backend`` as a minimum-viable WebDAV endpoint —
    ``davfs2 mount``, gnome-files (``davs://``), macOS Finder, browser
    read-only listings all work; they ask for the token as the password
    (any user name). Same token rules as :func:`serve_s3`. Returns a
    :class:`core.reverse_serve.ReverseServer`.
    """
    from core.reverse_serve import serve_webdav as _impl

    return _impl(
        backend,
        bind=bind,
        port=port,
        read_only=read_only,
        auth_token=auth_token,
        root_path=root_path,
    )


# ---------------------------------------------------------------------------
# Script directory
# ---------------------------------------------------------------------------

_SCRIPT_DIR = _pathlib_path = None  # set lazily inside the helpers below
MAX_SCRIPT_NAME_CHARS = 80
MAX_SCRIPT_SOURCE_BYTES = 1 * 1024 * 1024


def _nofollow_flag() -> int:
    import os

    return int(getattr(os, "O_NOFOLLOW", 0))


def _validate_script_file_fd(fd: int, path: str) -> None:
    import os
    import stat

    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"script path is not a regular file: {path}")
    if st.st_size > MAX_SCRIPT_SOURCE_BYTES:
        raise OSError(
            f"script source is too large ({st.st_size} > {MAX_SCRIPT_SOURCE_BYTES} bytes): {path}"
        )
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise OSError(f"script file is not owned by the current user: {path}")


@_api(mutates=False)
def script_dir() -> str:
    """Return the script-storage directory path. Created on first
    access. Mode 0700 so other local users can't read scripts that
    might contain credentials."""
    import os
    from pathlib import Path as _Path

    p = _Path.home() / ".config" / "axross" / "scripts"
    if p.is_symlink():
        raise OSError(f"Refusing symlinked script directory: {p}")
    p.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        raise OSError(f"Refusing symlinked script directory: {p}")
    if not p.is_dir():
        raise OSError(f"Script path is not a directory: {p}")
    try:
        st = p.stat()
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise OSError(f"Script directory is not owned by the current user: {p}")
    except OSError:
        raise
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return str(p)


@_api(mutates=False)
def list_scripts() -> list[str]:
    """Names of every saved script in :func:`script_dir`."""
    import os

    d = script_dir()
    out: list[str] = []
    for entry in sorted(os.scandir(d), key=lambda e: e.name):
        name = entry.name
        try:
            is_regular = entry.is_file(follow_symlinks=False)
        except OSError:
            continue
        if is_regular and name.endswith(".py") and not name.startswith("."):
            out.append(name[:-3])
    return out


def _validate_script_name(name: str) -> str:
    """Refuse path-traversal / unsafe characters before writing into
    the script dir."""
    import re

    if not isinstance(name, str):
        raise ValueError("script name must be a string")
    if len(name) > MAX_SCRIPT_NAME_CHARS:
        raise ValueError(f"script name is too long ({len(name)} > {MAX_SCRIPT_NAME_CHARS})")
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", name):
        raise ValueError(f"script name {name!r} must match [A-Za-z0-9_-]+")
    return name


@_api(mutates=True)
def save_script(name: str, source: str) -> str:
    """Write ``source`` to ``script_dir()/<name>.py`` (mode 0o600).
    Overwrites any existing file with the same name. Returns the
    final on-disk path."""
    import os
    import tempfile
    from pathlib import Path as _Path

    safe = _validate_script_name(name)
    if not isinstance(source, str):
        raise ValueError("script source must be a string")
    encoded = source.encode("utf-8")
    if len(encoded) > MAX_SCRIPT_SOURCE_BYTES:
        raise ValueError(
            f"script source is too large ({len(encoded)} > {MAX_SCRIPT_SOURCE_BYTES} bytes)"
        )
    directory = script_dir()
    target = _Path(directory) / f"{safe}.py"
    tmp_path = ""
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{safe}.",
        suffix=".tmp",
        dir=directory,
        text=False,
    )
    try:
        posix_compat.fchmod_private(fd, 0o600)
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(tmp_path, target)
        os.chmod(target, 0o600)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return str(target)


@_api(mutates=False)
def load_script(name: str) -> str:
    """Read the source of a saved script as a UTF-8 string. Raises
    ``FileNotFoundError`` when the script doesn't exist; ``ValueError``
    when the name contains characters outside the allow-list."""
    import builtins
    import os
    import stat

    safe = _validate_script_name(name)
    path = os.path.join(script_dir(), f"{safe}.py")
    try:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise OSError(f"Refusing symlinked script file: {path}")
    except FileNotFoundError:
        raise
    fd = os.open(path, os.O_RDONLY | _nofollow_flag())
    try:
        _validate_script_file_fd(fd, path)
    except BaseException:
        os.close(fd)
        raise
    # builtins.open — our own ``open()`` shadows the builtin in this
    # module's namespace.
    with builtins.open(fd, encoding="utf-8") as fh:
        return fh.read()


@_api(mutates=True)
def delete_script(name: str) -> None:
    """Remove a saved script. No-op if the file is already gone."""
    import os

    safe = _validate_script_name(name)
    path = os.path.join(script_dir(), f"{safe}.py")
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


@_api(mutates=True, prompts=True)
def run_script(name: str, env: dict | None = None) -> dict:
    """Execute a saved script in a fresh namespace pre-populated with
    ``axross`` (this module). Returns the post-exec namespace so the
    caller can inspect any variables it left behind. ``env`` overrides
    / augments the initial namespace."""
    from core.security_mode import current_policy, require

    require("saved script execution", current_policy().allow_scripts)
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
# Duplicate index (the Duplicate Finder's CAS index and its scan history)
# ---------------------------------------------------------------------------


def _scan_id_of(scan) -> int | None:
    if scan is None:
        return None
    return int(getattr(scan, "scan_id", scan))


@_api(mutates=False)
def duplicate_scans() -> list[ScanRecord]:
    """Return the Duplicate Finder's scan history, newest first.

    Each item is a :class:`core.cas.ScanRecord` with ``scan_id``,
    ``root``, ``backend_id``, ``started_at`` / ``finished_at``,
    ``files_indexed``, ``files_in_index``, ``duplicate_groups`` and
    ``status`` (``complete`` / ``cancelled`` / ``failed`` / ``running``).
    Rows indexed before scans were recorded appear as a last pseudo
    entry with ``scan_id == 0`` and status ``earlier``.

    Example::

        for scan in axross.duplicate_scans():
            print(scan.scan_id, scan.status, scan.root, scan.duplicate_groups)
    """
    from core import cas as _cas

    return _cas.list_scans(None)


@_api(mutates=False)
def duplicates(
    *,
    scan: ScanRecord | int | None = None,
    folder: str | None = None,
    algorithm: str | None = None,
) -> list[list[CasEntry]]:
    """Return the duplicate groups of the Duplicate Finder's index.

    A list of groups; each group is a list of :class:`core.cas.CasEntry`
    (``backend_id``, ``path``, ``size``, ``mtime``, ``value``) in survivor
    order — the first entry is the copy :func:`dedupe` keeps (the oldest
    by modification time; ties go to the shorter, then the alphabetically
    first path).

    * ``scan`` — a ``scan_id`` or a record from :func:`duplicate_scans`:
      only groups with at least one copy from that scan (all copies shown).
    * ``folder`` — only copies strictly inside that folder count.
    * ``algorithm`` — ``"sha256"``, ``"md5"``, …; ``None`` means all.

    The index is a claim about the past; nothing is read from a backend.
    """
    from core import cas as _cas

    return _cas.duplicates(None, algorithm, scan_id=_scan_id_of(scan), folder=folder)


@_api(mutates=True, prompts=True)
def dedupe(
    *,
    keep: str = "oldest",
    dry_run: bool = True,
    scan: ScanRecord | int | None = None,
    folder: str | None = None,
    algorithm: str | None = None,
    backends: list[FileBackend] | None = None,
) -> DedupeResult:
    """Keep the first copy of every duplicate group, trash the others.

    **A dry run unless ``dry_run=False`` is passed**: the default returns
    the plan (a :class:`core.cas.DedupeResult` with ``keep``, ``trash``,
    ``groups``, ``undated_groups``; ``.render()`` prints it) and touches
    nothing. ``keep="oldest"`` is the survivor rule (the only one): the
    oldest copy by modification time stays, ties go to the shorter, then
    the alphabetically first path; copies without a time sort last.

    With ``dry_run=False`` every planned copy goes to the axross trash —
    restorable — after the same live re-check as the Duplicate Finder:
    the copy must still hold the indexed content and the kept copy must be
    a genuine, intact other copy; otherwise it is reported in ``refused``.
    ``backends`` are the connected backends to act on (default: the local
    filesystem); copies on any other backend are refused, never guessed.
    ``scan`` / ``folder`` / ``algorithm`` narrow the groups like
    :func:`duplicates`.

    Example::

        plan = axross.dedupe(folder="/home/me/Photos")
        print(plan.render())
        if axross.confirm(f"Trash {len(plan.trash)} copies?"):
            axross.dedupe(folder="/home/me/Photos", dry_run=False)
    """
    import contextlib

    from core import cas as _cas

    if keep not in _cas.KEEP_RULES:
        raise ValueError(f"axross.dedupe: keep must be one of {_cas.KEEP_RULES}, not {keep!r}")
    if backends is None:
        backends = [localfs()]
    by_id = {_cas.backend_id_for(b): b for b in backends}
    groups = _cas.duplicates(None, algorithm, scan_id=_scan_id_of(scan), folder=folder)
    if dry_run:
        return _cas.dedupe(groups, by_id, keep=keep, dry_run=True)
    with contextlib.ExitStack() as gates:
        for backend in by_id.values():
            gates.enter_context(_mutation_gate(backend, "dedupe: move duplicates to trash"))
        result = _cas.dedupe(groups, by_id, keep=keep, dry_run=False)
    log.warning(
        "axross.dedupe moved %d duplicate(s) to the axross trash (%d kept after re-checking)",
        len(result.removed),
        len(result.refused),
    )
    return result


# ---------------------------------------------------------------------------
# File metadata (EXIF / XMP / IPTC, Office properties, PDF info, media tags)
# ---------------------------------------------------------------------------


def _is_folder(backend, path: str) -> bool:
    try:
        return bool(backend.is_dir(path))
    except OSError:
        return False


@_api(mutates=False)
def metadata(backend: FileBackend, path: str) -> MetadataReport:
    """Return the metadata of one file as a ``MetadataReport``.

    Supported: images (JPEG, PNG, WebP, GIF, TIFF), Office (docx / xlsx /
    pptx, odt / ods / odp), PDF and audio / video (through ffprobe). The
    report has ``kind``, ``fields`` (each with ``group``, ``name``,
    ``value`` and ``removable`` - False for what removal keeps, such as the
    orientation and the colour profile), ``removable`` (the count) and
    ``error`` when the file could not be read; values are length-bounded.
    A remote file is read through a temporary copy bounded by the open-size
    limit. For a folder use :func:`export_metadata`.

    Example::

        report = axross.metadata(axross.localfs(), "/home/me/IMG_0001.jpg")
        for f in report.fields:
            print(f.group, f.name, f.value)
    """
    from core import metadata_tools as _mt

    if _is_folder(backend, path):
        raise IsADirectoryError(
            f"{path} is a folder; use axross.export_metadata(b, folder) to read every file in it"
        )
    return _mt.read_metadata(backend, path)


@_api(mutates=True, prompts=True)
def remove_metadata(
    backend: FileBackend, path: str, *, mode: str | None = None, recursive: bool = False
) -> list:
    """Remove the metadata of a file, or of every supported file in a folder.

    Returns a list of ``RemoveResult`` (one for a file) with ``status``
    (``cleaned`` / ``unchanged`` / ``unsupported`` / ``error``), ``output``
    (where the cleaned file is), ``error`` and ``note``.

    ``mode`` defaults to the setting (Tools -> Metadata Settings…):

    * ``"in_place"`` - the file is replaced atomically and its original
      kept in the axross trash; Edit -> Undo (Ctrl+Z) puts it back.
    * ``"copy"`` - a cleaned ``name.clean.ext`` next to it; nothing is
      ever overwritten.

    Images keep only their EXIF orientation and ICC profile, never
    re-encoded (the pixels are verified identical). PDF removal needs
    pypdf (``pip install 'axross[metadata]'``), audio / video needs ffmpeg.
    ``recursive`` descends into subfolders (symlinked folders are not
    followed). The whole call is one undo step.

    Example::

        for r in axross.remove_metadata(b, "/photos/trip", recursive=True):
            print(r.status, r.path, r.error)
    """
    from core import metadata_tools as _mt

    if mode is not None and mode not in _mt.MODES:
        raise ValueError(f"axross.remove_metadata: mode must be one of {_mt.MODES}, not {mode!r}")
    folder = _is_folder(backend, path)
    if not folder and not backend.exists(path):
        raise FileNotFoundError(path)
    with _mutation_gate(backend, f"remove metadata {path!r} recursive={recursive}"):
        if folder:
            batch = _mt.remove_folder(backend, path, recursive=recursive, mode=mode)
        else:
            batch = _mt.remove_many(backend, [path], mode=mode, source=path)
    _record_backend_visit(
        backend,
        path,
        verb="remove_metadata",
        desc=f"{sum(r.status == 'cleaned' for r in batch.results)} cleaned",
    )
    return batch.results


@_api(mutates=True)
def export_metadata(
    backend: FileBackend,
    root: str,
    *,
    fmt: str = "json",
    recursive: bool = False,
    out: str | None = None,
) -> str:
    """Return the metadata of a file or of every supported file in a folder,
    as JSON (``{"files": [...]}``) or CSV (one row per field).

    ``recursive`` descends into subfolders. ``out`` additionally writes the
    text to that LOCAL file (never overwriting an existing one). In CSV a
    value that starts like a spreadsheet formula is prefixed with ``'``.

    Example::

        text = axross.export_metadata(b, "/photos", fmt="csv", recursive=True,
                                      out="/tmp/photos-metadata.csv")
    """
    from core import metadata_tools as _mt

    if (fmt or "").lower() not in _mt.EXPORT_FORMATS:
        raise ValueError(
            f"axross.export_metadata: fmt must be one of {_mt.EXPORT_FORMATS}, not {fmt!r}"
        )
    if _is_folder(backend, root):
        reports = _mt.scan_metadata(backend, root, recursive=recursive).reports
    else:
        reports = [_mt.read_metadata(backend, root)]
    text = _mt.export_reports(reports, fmt)
    if out is not None:
        import os as _os

        fd = _os.open(out, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        with _os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    return text


# ---------------------------------------------------------------------------
# File type identification (content, not name)
# ---------------------------------------------------------------------------


@_api(mutates=False)
def file_type(
    backend: FileBackend | str | os.PathLike[str],
    path: str | None = None,
    *,
    max_bytes: int = 64 * 1024,
    timeout: float = 15.0,
    use_file_command: bool = True,
) -> FileTypeInfo:
    """Identify a file's real type from its content (magic bytes), not its name.

    Returns a ``FileTypeInfo`` with ``kind`` (``file`` / ``directory`` /
    ``special`` / ``error`` / ``timeout`` / ``cancelled``), ``description``
    and ``mime`` (from the content), ``extension`` and ``extension_mime``
    (what the name claims), ``verdict`` (``match`` / ``mismatch`` /
    ``unknown``; ``mismatch`` is also the bool property ``mismatch``),
    ``size``, ``encoding`` and ``line_endings`` for text, ``engine`` (the
    detector that decided) and ``file_command`` (``file(1)``'s view of a
    local file, ``""`` without it). ``summary()`` gives one line.

    Pass a backend and a path, or just a local path. At most ``max_bytes``
    are read, on a helper thread: a remote that does not answer within
    ``timeout`` seconds gives ``kind == "timeout"`` instead of hanging, and
    an unreadable file gives ``kind == "error"`` with ``error`` set - this
    never raises for I/O failures. Detection uses Qt's MIME database, then
    puremagic, then a built-in signature table.

    Example::

        info = axross.file_type(b, "/upload/invoice.pdf")
        if info.mismatch:
            print(info.summary())   # ... MISMATCH: .pdf claims application/pdf
        print(axross.file_type("/home/me/notes.txt").encoding)
    """
    from core import file_type as _ft

    if path is None:
        if isinstance(backend, str) or hasattr(backend, "__fspath__"):
            import os as _os

            path, backend = _os.fspath(backend), localfs()
        else:
            raise TypeError("axross.file_type: pass (backend, path) or a local path")
    return _ft.identify(
        backend,
        path,
        max_bytes=max_bytes,
        timeout=timeout,
        use_file_command=use_file_command,
    )


# ---------------------------------------------------------------------------
# Cheat-sheet — auto-built from __all__ + each function's docstring
# ---------------------------------------------------------------------------

# Topical groupings so the cheat-sheet reads sensibly. The renderer
# falls back to "Other" for anything not listed here.
_HELP_GROUPS: list[tuple[str, list[str]]] = [
    (
        "Open / connect",
        [
            "open",
            "open_url",
            "localfs",
            "ramfs",
            "list_profiles",
            "get_profile",
            "save_profile",
            "delete_profile",
            "list_backends",
            "available_backends",
        ],
    ),
    (
        "File I/O",
        [
            "copy",
            "move",
            "remove",
            "trash",
            "read_bytes",
            "write_bytes",
            "read_text",
            "write_text",
            "checksum",
            "hash_bytes",
            "hash_file",
        ],
    ),
    (
        "Encryption + archives",
        [
            "encrypt",
            "decrypt",
            "extract_archive",
            "is_archive",
        ],
    ),
    (
        "Bookmarks + scripts",
        [
            "list_bookmarks",
            "add_bookmark",
            "remove_bookmark",
            "script_dir",
            "list_scripts",
            "save_script",
            "load_script",
            "delete_script",
            "run_script",
        ],
    ),
    (
        "Per-protocol",
        [
            "find_tftp_files",
            "slp_discover",
            "nntp_post",
            "git_push",
            "exec",
            "interactive_shell",
            "query",
            "tables",
            "imap_search",
            "imap_move",
            "imap_set_flags",
            "share",
            "ldap_search",
        ],
    ),
    (
        "Network helpers",
        [
            "dns_resolve",
            "dns_records",
            "dns_reverse",
            "port_open",
            "port_scan",
            "subnet_hosts",
            "tcp_banner",
            "tls_cert",
            "ssh_hostkey",
            "http_probe",
            "snmp_get",
            "snmp_walk",
            "snmp_set",
            "ping",
            "mac_lookup",
            "whois",
            "time_skew",
        ],
    ),
    (
        "Search across backends",
        [
            "find_files",
            "grep",
            "diff_files",
        ],
    ),
    (
        "Duplicate index",
        [
            "duplicate_scans",
            "duplicates",
            "dedupe",
        ],
    ),
    (
        "Content inspection",
        [
            "file_type",
            "magic_type",
            "text_encoding",
            "entropy",
            "archive_inspect",
        ],
    ),
    (
        "File metadata",
        [
            "metadata",
            "remove_metadata",
            "export_metadata",
        ],
    ),
    (
        "Safety + diagnostics",
        [
            "diagnose",
            "preview_delete",
            "preview_transfer",
            "recovery_scan",
            "recent_operations",
            "security_mode",
        ],
    ),
    (
        "Credential testing (authorised use only)",
        [
            "bruteforce",
            "spray",
            "enumerate_users",
        ],
    ),
    (
        "Multi-system workflow",
        [
            "where_was_i",
            "health_pulse",
            "summarize",
            "explain",
            "compare_file",
            "inspect_targets",
            "federated_search",
            "resumable_copy",
            "dashboard",
        ],
    ),
    (
        "Time-lapse / trail",
        [
            "snapshot_now",
            "start_trail",
            "stop_trail",
            "list_trails",
            "list_snapshots",
            "diff_snapshots",
        ],
    ),
    (
        "Reverse-serve (expose a backend over S3 / WebDAV)",
        [
            "serve_s3",
            "serve_webdav",
        ],
    ),
    (
        "Result types (dataclasses returned by helpers above)",
        [
            "TlsCert",
            "SshHostKey",
            "HttpProbe",
            "GrepHit",
            "SnmpVar",
            "ArchiveEntry",
            "PingResult",
            "OuiInfo",
            "WhoisInfo",
            "TimeSkew",
        ],
    ),
    (
        "UI helpers (REPL / scripts)",
        [
            "message",
            "confirm",
            "toast",
            "is_interactive",
            "NonInteractiveError",
        ],
    ),
    (
        "Misc",
        [
            "help",
            "docs",
            "api_schema",
        ],
    ),
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


@_api(mutates=False)
def help() -> None:
    """Print the curated cheat-sheet of the scripting surface."""
    print("Axross scripting cheat-sheet")
    print("=" * 60)
    for group, items in _help_entries():
        print(f"-- {group} --")
        for sig, summary in items:
            wrapped = _textwrap.fill(
                summary,
                width=58,
                initial_indent="    ",
                subsequent_indent="    ",
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


@_api(mutates=False)
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


#: Version of the api_schema() layout; raised when a field changes meaning.
#: 2: full docstrings, examples, raises, session-method traits and
#: parameters, the types the API returns, groups, rules, errors, legend.
API_SCHEMA_VERSION = 2

_PARAMETER_KINDS = {
    "POSITIONAL_ONLY": "positional_only",
    "POSITIONAL_OR_KEYWORD": "positional_or_keyword",
    "VAR_POSITIONAL": "var_positional",
    "KEYWORD_ONLY": "keyword_only",
    "VAR_KEYWORD": "var_keyword",
}

#: What each session method can change: True when it can change files or
#: remote state. A protocol method missing here is reported as ``None``
#: (unknown, not safe); tests/test_scripting_api_schema.py fails for it.
_SESSION_METHOD_MUTATES = {
    "name": False,
    "list_dir": False,
    "stat": False,
    "is_dir": False,
    "exists": False,
    "mkdir": True,
    "remove": True,
    "rename": True,
    "open_read": False,
    "open_write": True,
    "normalize": False,
    "separator": False,
    "join": False,
    "parent": False,
    "home": False,
    "chmod": True,
    "readlink": False,
    "symlink": True,
    "hardlink": True,
    "disk_usage": False,
    "list_versions": False,
    "open_version_read": False,
    "copy": True,
    "checksum": False,
    "close": False,
    "__enter__": False,
    "__exit__": False,
}

#: Protocol methods only some sessions have: callers test ``hasattr``
#: (core.backend.SessionLifecycle leaves them out on purpose).
_SESSION_OPTIONAL_METHODS = frozenset({"copy", "symlink", "hardlink"})

#: The data attributes of the protocol (core/backend.py), described here
#: because an attribute has no docstring.
_SESSION_ATTRIBUTES = {
    "supports_symlinks": (
        "True when this session can create symbolic links with symlink(); "
        "read it with getattr(b, 'supports_symlinks', False)."
    ),
    "supports_hardlinks": (
        "True when this session can create hard links with hardlink(); "
        "read it with getattr(b, 'supports_hardlinks', False)."
    ),
}

#: Capitalised names in annotations that are not described under
#: ``classes`` or ``types``: the stdlib and typing, and FileBackend, which
#: ``backend_protocol`` describes.
_NOT_DESCRIBED_TYPES = frozenset(
    {"Any", "Callable", "IO", "Iterable", "Iterator", "None", "FileBackend"}
)

#: Modules whose classes api_schema() describes; anything else (stdlib,
#: third party) is named by its annotation only.
_OWN_MODULE_PREFIXES = ("core.", "models.")

#: What every field of api_schema() means, for a reader without this file.
_LEGEND = {
    "functions": {
        "name": "Function name: call it as axross.<name>(...).",
        "group": "Topic the function belongs to (see groups).",
        "signature": "Python signature with type hints and defaults.",
        "parameters": (
            "One entry per parameter: name, kind (positional_or_keyword, keyword_only, "
            "var_positional, var_keyword, positional_only), annotation, required, and "
            "default (JSON value) or default_repr (Python repr) when it has one."
        ),
        "returns": "Return type as written in the code; types and classes describe the named ones.",
        "summary": "First paragraph of the docstring.",
        "doc": "The whole docstring: rules, return shape, caveats.",
        "examples": "The literal code blocks of the docstring (may be empty).",
        "raises": (
            "Exception classes raised by the axross scripting layer itself on some path "
            "(found in its source and the same-module helpers it calls). Not exhaustive: "
            "every call that touches a backend can raise OSError and its subclasses, and a "
            "function with prompts=true can raise NonInteractiveError (see errors)."
        ),
        "mutates": "True when the call can change files, remote state or saved settings.",
        "prompts": (
            "True when the call can need a human (a dialog, a terminal prompt, the "
            "production countdown); without one it raises NonInteractiveError."
        ),
    },
    "backend_protocol": {
        "name": "Method or attribute name on a session b (what open() and friends return).",
        "kind": "method, property or attribute.",
        "signature": "Python signature without self (methods only).",
        "parameters": "As for functions, without self (methods only).",
        "returns": "Return type as written in the code.",
        "annotation": "Type of an attribute.",
        "default": "Value of an attribute on a session that does not set it.",
        "summary": "First paragraph of the docstring.",
        "doc": "The whole docstring.",
        "mutates": "True when the method can change files or remote state.",
        "optional": "True when only some sessions have the method: test hasattr(b, name) first.",
        "fallback": "What a session without support for this method answers instead.",
    },
    "types": {
        "name": "Class name as the annotations use it.",
        "module": "Module that defines it (import it from there if you need the class itself).",
        "kind": "class, exception, enum or session (a class implementing backend_protocol).",
        "bases": "Base classes, nearest first.",
        "summary": "First paragraph of the class docstring.",
        "fields": "Dataclass fields: name and annotation.",
        "properties": "Read-only attributes computed on access: name, returns, summary.",
        "methods": "Public methods: name, signature without self, returns, summary.",
        "members": "Enum members.",
    },
}

#: Conventions a model writing a script needs, as (id, text). The comment
#: above each names the code that decides it; change both together.
_API_RULES = (
    (
        # core/script_runner.py (the namespace of a run); axross/__init__.py
        "namespace",
        "A script run by script_run, axross --script or the Scripts dock finds the API bound "
        "as axross; import axross gives the same names.",
    ),
    (
        # core/backend.py SessionLifecycle; tests/test_scripting_session_lifecycle.py
        "sessions",
        "open(profile_name), open_url(url), localfs() and ramfs() return a session b with the "
        "backend_protocol methods. Open it in a with block: leaving the block ends the "
        "connection, also after an exception; b.close() does the same by hand.",
    ),
    (
        # separator() of core/local_fs.py, core/winrm_client.py, core/wmi_client.py
        "paths",
        "Paths are absolute strings in the session's own syntax. Most sessions use '/'; "
        "localfs() uses the host's separator and WinRM and WMI sessions use '\\'. Build paths "
        "with b.join() and b.parent() rather than os.path, which follows the host.",
    ),
    (
        # models/file_item.py (the timestamp contract); core/net_helpers.py find_files
        "listing",
        "b.list_dir(path) returns a list of FileItem and b.stat(path) one FileItem (see "
        "types): name is the entry's name inside the directory, not a path - join it to the "
        "directory; modified is naive local time; is_dir and is_link give the kind. "
        "find_files(b, root, ...) walks a tree and yields the files as FileItem whose name "
        "is the full path; it skips folders it cannot read.",
    ),
    (
        # _refuse_existing_target_unless_overwrite, core/server_ops.py, remove/trash,
        # core/atomic_io.py; {gated} is derived from the code by _gated_functions
        "helpers-before-session-methods",
        "Change files with the axross.* helpers, not the raw session methods. copy, move, "
        "write_bytes, write_text and encrypt refuse an existing target unless "
        "overwrite=True (move across backends refuses it even then); remove and trash "
        "refuse without confirm=True; write_bytes writes "
        "atomically where the backend allows it; {gated} wait for the production countdown "
        "on a profile flagged production. b.remove(), b.rename(), b.open_write() and the "
        "other session methods do none of this.",
    ),
    (
        # core/mcp_server.py script_run sets AXROSS_NONINTERACTIVE=1;
        # core/safety_tarpit.py refuses an unwatched countdown
        "no-human",
        "Under script_run nobody can answer: stdin is empty and AXROSS_NONINTERACTIVE=1 is "
        "set. A function with prompts=true raises NonInteractiveError (a PermissionError) "
        "instead of asking: confirm() unless assume_yes=True is passed, and a change on a "
        "production profile unless the operator started axross with "
        "AXROSS_TARPIT_DISABLE=1. is_interactive() tells a script which case it is in. Pass "
        "assume_yes=True only for an action the operator asked for.",
    ),
    (
        # MAX_SCRIPT_READ_BYTES and _read_all_capped
        "bounded-reads",
        "read_bytes() and read_text() read at most {max_read} bytes unless max_bytes says "
        "otherwise, and raise OSError above it. Stream bigger files: with b.open_read(path) "
        "as fh: then fh.read(chunk_size) in a loop.",
    ),
    (
        # core/backend.py open_read/open_write ("Caller must close the returned handle")
        "handles",
        "b.open_read() and b.open_write() return file handles the caller must close: use "
        "them in a with block. b.open_write() has none of write_bytes()'s checks.",
    ),
    (
        # core/backend.py FileBackend.checksum; core/scripting.py checksum/hash_file
        "checksums",
        "checksum(b, path) returns the backend's fingerprint marked with its algorithm "
        "('sha256:<hex>', 'md5:<hex>', 's3-etag:<etag>', ...), which may not be the "
        "algorithm asked for: "
        "compare the prefix before the value. hash_file(b, path, algorithm) always streams "
        "and returns the bare hex digest of that algorithm - use it to compare files across "
        "backends.",
    ),
    (
        # the hasattr checks of the per-protocol helpers below
        "wrong-session-kind",
        "Per-protocol helpers (exec, interactive_shell, query, tables, imap_search, "
        "ldap_search, share, ...) raise TypeError on a session of another kind.",
    ),
    (
        # core/mcp_server.py script_run (the reply)
        "output",
        "print() goes to stdout, which script_run returns with stderr, the exit status and, "
        "after an uncaught exception, error_type, error and traceback. Print a result a "
        "machine reads as one JSON document; sys.exit(n) sets the exit status.",
    ),
)

#: Exceptions a script meets, what they mean and what to do. The base
#: class is taken from the class itself.
_API_ERRORS = (
    (
        "OSError",
        "An I/O operation failed or the session cannot do it: protocol error, connection "
        "lost, an operation the backend does not support, a read above max_bytes. The "
        "subclasses below say more.",
        "Read the message. Do not repeat the same call unchanged.",
    ),
    (
        "FileNotFoundError",
        "The path does not exist on that session.",
        "List the parent directory and check the path.",
    ),
    (
        "FileExistsError",
        "The target exists and overwrite=False (copy, move, write_bytes, write_text, encrypt).",
        "Choose another path, or pass overwrite=True only when replacing it is intended.",
    ),
    (
        "IsADirectoryError",
        "A file operation got a folder (for example metadata() on a directory).",
        "Use the folder variant the message names.",
    ),
    (
        "PermissionError",
        "A refusal: the server denied access, remove() or trash() was called without "
        "confirm=True, or the security mode blocks the feature.",
        "Do not route around it. confirm=True is for deletes the operator asked for.",
    ),
    (
        "NonInteractiveError",
        "The call needs a human and none can answer: confirm() without assume_yes=True, or "
        "a change on a production profile.",
        "Pass assume_yes=True only for what the operator asked for; production changes need "
        "the operator.",
    ),
    (
        "KeyError",
        "open() got a profile name that is not saved, or docs() an unknown topic.",
        "list_profiles() gives the saved names.",
    ),
    (
        "TypeError",
        "The session is the wrong kind for the helper (exec() on S3, query() on a session "
        "that is no database) or an argument has the wrong type.",
        "Check the session's protocol and the signature.",
    ),
    (
        "ValueError",
        "An argument value is invalid: an unknown URL scheme, a port out of range, a script "
        "name outside [A-Za-z0-9_-], an unknown mode or format.",
        "Fix the argument; the message names it.",
    ),
    (
        "KeyboardInterrupt",
        "Someone stopped the production countdown before a change.",
        "Do not repeat the change.",
    ),
)


def _annotation_text(annotation) -> str | None:
    """A hint as source text: hints are strings here (``from __future__
    import annotations``); others are formatted the way inspect does."""
    import inspect

    if annotation is inspect.Parameter.empty:
        return None
    if isinstance(annotation, str):
        return annotation
    return inspect.formatannotation(annotation)


def _annotation_names(text: str) -> set[str]:
    """The names an annotation text refers to: ``list[FileItem] | None``
    gives ``{"list", "FileItem", "None"}``; a dotted name stays dotted."""
    import ast

    if not text:
        return set()
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            names.add(ast.unparse(node))
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Constant) and node.value is None:
            names.add("None")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names |= _annotation_names(node.value)
    # A Name inside an Attribute (``os`` of ``os.PathLike``) is not a name of its own.
    return {n for n in names if not any(m.startswith(n + ".") for m in names)}


class _RawAnnotation:
    """Formats as its text, unquoted, inside ``str(inspect.Signature)``."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    def __repr__(self) -> str:
        return self.text


def _signature_text(name: str, sig, *, drop_self: bool = False) -> str:
    """``name(params) -> returns`` with hints as written and defaults as
    ``repr()``, the way Python prints a signature."""
    params = list(sig.parameters.values())
    if drop_self and params and params[0].name == "self":
        params = params[1:]
    params = [
        p.replace(annotation=_RawAnnotation(text))
        if (text := _annotation_text(p.annotation)) is not None
        else p
        for p in params
    ]
    bare = sig.replace(parameters=params, return_annotation=sig.empty)
    returns = _annotation_text(sig.return_annotation)
    return f"{name}{bare}" + (f" -> {returns}" if returns else "")


def _first_paragraph(obj) -> str:
    import inspect

    doc = inspect.getdoc(obj) or ""
    return " ".join(doc.split("\n\n", 1)[0].split())


def _docstring_examples(doc: str) -> list[str]:
    """The literal blocks of a docstring: the indented lines after a line
    ending in ``::`` (reStructuredText), dedented."""
    lines = (doc or "").splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.rstrip().endswith("::"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        j = i + 1
        block: list[str] = []
        while j < len(lines) and (
            not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent
        ):
            block.append(lines[j])
            j += 1
        text = _textwrap.dedent("\n".join(block)).strip("\n")
        if text:
            out.append(text)
        i = max(j, i + 1)
    return out


def _resolve_exception(node, namespace: dict):
    """The exception class a ``raise`` names, or None for a variable."""
    import ast
    import builtins

    if isinstance(node, ast.Call):
        node = node.func
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.insert(0, node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    obj = namespace.get(node.id, getattr(builtins, node.id, None))
    for part in parts:
        obj = getattr(obj, part, None)
    if isinstance(obj, type) and issubclass(obj, BaseException):
        return obj
    return None


def _raised_exceptions(fn, _seen: set | None = None) -> list[str]:
    """Names of the exception classes ``fn`` raises on some path: its own
    ``raise`` statements and those of the functions of its module it calls
    by name. A bare ``raise`` and a raised variable are left out."""
    import ast
    import inspect
    import sys as _sys

    seen = _seen if _seen is not None else set()
    if fn in seen:
        return []
    seen.add(fn)
    try:
        tree = ast.parse(_textwrap.dedent(inspect.getsource(fn)))
    except (OSError, TypeError, SyntaxError):
        return []
    module = _sys.modules.get(fn.__module__)
    namespace = vars(module) if module is not None else {}
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            cls = _resolve_exception(node.exc, namespace)
            if cls is not None:
                found.add(cls.__name__)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            callee = namespace.get(node.func.id)
            if inspect.isfunction(callee) and callee.__module__ == fn.__module__:
                found.update(_raised_exceptions(callee, seen))
    return sorted(found)


def _parameter_entries(sig, *, drop_self: bool = False) -> list[dict]:
    parameters = []
    for param in sig.parameters.values():
        if drop_self and param.name == "self":
            continue
        entry: dict = {"name": param.name, "kind": _PARAMETER_KINDS[param.kind.name]}
        annotation = _annotation_text(param.annotation)
        if annotation is not None:
            entry["annotation"] = annotation
        variadic = param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD)
        entry["required"] = param.default is param.empty and not variadic
        if param.default is not param.empty:
            default = param.default
            if default is None or isinstance(default, (bool, int, float, str)):
                entry["default"] = default
            else:
                entry["default_repr"] = repr(default)
        parameters.append(entry)
    return parameters


def _function_entry(name: str, fn) -> dict:
    """One function of :func:`api_schema`, built from the live object."""
    import inspect

    sig = inspect.signature(fn)
    traits = getattr(fn, _API_TRAITS_ATTR, None) or {}
    doc = inspect.getdoc(fn) or ""
    return {
        "name": name,
        "group": _help_group_of(name),
        "signature": _signature_text(name, sig),
        "parameters": _parameter_entries(sig),
        "returns": _annotation_text(sig.return_annotation),
        "summary": _first_paragraph(fn),
        "doc": doc,
        "examples": _docstring_examples(doc),
        "raises": _raised_exceptions(fn),
        "mutates": traits.get("mutates"),
        "prompts": traits.get("prompts"),
    }


def _help_group_of(name: str) -> str:
    for group, names in _HELP_GROUPS:
        if name in names:
            return group
    return "Other"


def _groups_entries() -> list[dict]:
    """The topics in ``_HELP_GROUPS`` order, every public name in one."""
    import inspect
    import sys as _sys

    me = _sys.modules[__name__]
    order = [group for group, _ in _HELP_GROUPS] + ["Other"]
    members: dict[str, dict[str, list[str]]] = {g: {"functions": [], "classes": []} for g in order}
    for group, names in _HELP_GROUPS:
        for name in names:
            if name in __all__:
                kind = "classes" if inspect.isclass(getattr(me, name)) else "functions"
                members[group][kind].append(name)
    listed = {n for group in members.values() for kind in group.values() for n in kind}
    for name in __all__:
        if name not in listed:
            kind = "classes" if inspect.isclass(getattr(me, name)) else "functions"
            members["Other"][kind].append(name)
    return [{"name": g, **members[g]} for g in order if any(members[g].values())]


def _type_checking_namespace(module) -> dict:
    """The names a module imports under ``if TYPE_CHECKING:``, imported for
    real one statement at a time; a statement that fails is skipped."""
    import ast
    import builtins
    import inspect

    namespace: dict = {}
    try:
        tree = ast.parse(inspect.getsource(module))
    except (OSError, TypeError, SyntaxError):
        return namespace
    for node in tree.body:
        if not (
            isinstance(node, ast.If)
            and getattr(node.test, "id", "") in {"TYPE_CHECKING", "_TYPE_CHECKING"}
        ):
            continue
        for stmt in node.body:
            if not isinstance(stmt, (ast.Import, ast.ImportFrom)):
                continue
            code = compile(ast.Module(body=[stmt], type_ignores=[]), module.__file__, "exec")
            try:
                builtins.exec(code, namespace)  # an import statement of axross' own source
            except Exception as exc:  # noqa: BLE001 - an optional dependency is missing
                log.debug("api_schema: %s: %s", ast.unparse(stmt), exc)
    namespace.pop("__builtins__", None)
    return namespace


class _TypeResolver:
    """Finds the classes an annotation names, in the module that wrote it."""

    def __init__(self) -> None:
        self._namespaces: dict[str, dict] = {}

    def namespace(self, module_name: str) -> dict:
        import sys as _sys

        if module_name not in self._namespaces:
            module = _sys.modules.get(module_name)
            ns = dict(vars(module)) if module is not None else {}
            if module is not None:
                ns.update(_type_checking_namespace(module))
            self._namespaces[module_name] = ns
        return self._namespaces[module_name]

    def classes(self, text: str | None, module_name: str) -> list[type]:
        import builtins

        found = []
        ns = self.namespace(module_name)
        for name in sorted(_annotation_names(text or "")):
            obj = ns.get(name.split(".")[0], getattr(builtins, name.split(".")[0], None))
            for part in name.split(".")[1:]:
                obj = getattr(obj, part, None)
            if isinstance(obj, type):
                found.append(obj)
        return found


def _is_own_class(cls) -> bool:
    return cls.__module__.startswith(_OWN_MODULE_PREFIXES)


def _is_session_class(cls) -> bool:
    return all(callable(getattr(cls, m, None)) for m in ("list_dir", "stat", "open_read"))


def _type_entry(name: str, cls) -> dict:
    """A class for :func:`api_schema`: what a script can read and call on it."""
    import dataclasses
    import enum
    import inspect

    from core.backend import FileBackend, SessionLifecycle

    if issubclass(cls, BaseException):
        kind = "exception"
    elif issubclass(cls, enum.Enum):
        kind = "enum"
    elif _is_session_class(cls):
        kind = "session"
    else:
        kind = "class"
    entry: dict = {
        "name": name,
        "module": cls.__module__,
        "kind": kind,
        "bases": [base.__name__ for base in cls.__mro__[1:] if base is not object],
        "summary": _first_paragraph(cls),
    }
    if kind == "enum":
        entry["members"] = [m.name for m in cls]
        return entry
    field_names: set[str] = set()
    if dataclasses.is_dataclass(cls):
        fields = dataclasses.fields(cls)
        field_names = {f.name for f in fields}
        entry["fields"] = [
            {"name": f.name, "annotation": _annotation_text(f.type) or ""} for f in fields
        ]
    # The session methods are described once, under backend_protocol.
    skip = set(vars(FileBackend)) | set(vars(SessionLifecycle)) if kind == "session" else set()
    properties: list[dict] = []
    methods: list[dict] = []
    own = [k for k in cls.__mro__ if k is not object and _is_own_class(k)]
    seen: set[str] = set()
    for klass in own:
        for attr, member in vars(klass).items():
            if attr.startswith("_") or attr in seen or attr in field_names or attr in skip:
                continue
            seen.add(attr)
            if isinstance(member, property) and member.fget is not None:
                sig = inspect.signature(member.fget)
                properties.append({
                    "name": attr,
                    "returns": _annotation_text(sig.return_annotation),
                    "summary": _first_paragraph(member),
                })
            elif inspect.isfunction(member):
                sig = inspect.signature(member)
                methods.append({
                    "name": attr,
                    "signature": _signature_text(attr, sig, drop_self=True),
                    "returns": _annotation_text(sig.return_annotation),
                    "summary": _first_paragraph(member),
                })
    if properties:
        entry["properties"] = sorted(properties, key=lambda p: p["name"])
    if methods:
        entry["methods"] = sorted(methods, key=lambda m: m["name"])
    return entry


def _referenced_types(seeds: list[tuple[str | None, str]], public: set[str]) -> list[dict]:
    """The axross classes reachable from the annotations ``seeds`` (text,
    module that wrote it), through their fields, properties and method
    returns. Public classes (``classes``) and FileBackend are left out."""
    from core.backend import FileBackend

    resolver = _TypeResolver()
    found: dict[str, type] = {}
    queue = list(seeds)
    while queue:
        text, module_name = queue.pop()
        for cls in resolver.classes(text, module_name):
            name = cls.__name__
            if not _is_own_class(cls) or cls is FileBackend or name in public:
                continue
            if name in found:
                if found[name] is not cls:
                    raise RuntimeError(f"api_schema: two classes named {name}")
                continue
            found[name] = cls
            entry = _type_entry(name, cls)
            for member in entry.get("fields", []):
                queue.append((member["annotation"], cls.__module__))
            for member in entry.get("properties", []) + entry.get("methods", []):
                queue.append((member["returns"], cls.__module__))
    return [_type_entry(name, found[name]) for name in sorted(found)]


def _session_method_mutates(name: str) -> bool | None:
    return _SESSION_METHOD_MUTATES.get(name)


def _backend_protocol_entries() -> list[dict]:
    """The members every session has: the FileBackend protocol plus
    ``close`` and the ``with`` statement (core.backend.SessionLifecycle)."""
    import inspect

    from core.backend import FileBackend, SessionLifecycle

    out: list[dict] = []
    members = [(n, getattr(FileBackend, n)) for n in sorted(vars(FileBackend))]
    members += [(n, getattr(SessionLifecycle, n)) for n in ("close", "__enter__", "__exit__")]
    lifecycle = {"close", "__enter__", "__exit__"}
    for name, member in members:
        if name.startswith("_") and name not in {"__enter__", "__exit__"}:
            continue
        if isinstance(member, property):
            sig = inspect.signature(member.fget)
            entry = {"name": name, "kind": "property"}
        elif callable(member):
            sig = inspect.signature(member)
            entry = {
                "name": name,
                "kind": "method",
                "signature": _signature_text(name, sig, drop_self=True),
                "parameters": _parameter_entries(sig, drop_self=True),
            }
        elif isinstance(member, bool):
            out.append({
                "name": name,
                "kind": "attribute",
                "annotation": "bool",
                "default": member,
                "summary": _SESSION_ATTRIBUTES.get(name, ""),
                "mutates": False,
                "optional": False,
            })
            continue
        else:
            continue
        doc = inspect.getdoc(member) or ""
        entry["returns"] = _annotation_text(sig.return_annotation)
        entry["summary"] = _first_paragraph(member)
        entry["doc"] = doc
        entry["mutates"] = _session_method_mutates(name)
        entry["optional"] = name in _SESSION_OPTIONAL_METHODS
        if name not in lifecycle and name in vars(SessionLifecycle):
            entry["fallback"] = _first_paragraph(vars(SessionLifecycle)[name])
        out.append(entry)
    return out


def _gated_functions() -> list[str]:
    """Public functions of this module that pass the production countdown:
    they enter ``_mutation_gate`` or call a public function that does."""
    import ast
    import inspect
    import sys as _sys

    me = _sys.modules[__name__]
    own = {
        n: getattr(me, n)
        for n in __all__
        if inspect.isfunction(getattr(me, n)) and getattr(me, n).__module__ == __name__
    }
    calls: dict[str, set[str]] = {}
    for name, fn in own.items():
        tree = ast.parse(_textwrap.dedent(inspect.getsource(fn)))
        calls[name] = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
    gated: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name in own:
            if name not in gated and ({"_mutation_gate"} | gated) & calls[name]:
                gated.add(name)
                changed = True
    return [n for n in __all__ if n in gated]


def _rules_entries() -> list[dict]:
    gated = _gated_functions()
    values = {
        "gated": ", ".join(gated[:-1]) + " and " + gated[-1] if len(gated) > 1 else "".join(gated),
        "max_read": f"{MAX_SCRIPT_READ_BYTES} ({MAX_SCRIPT_READ_BYTES // (1024 * 1024)} MiB)",
    }
    return [{"id": rule_id, "text": text.format(**values)} for rule_id, text in _API_RULES]


def _errors_entries() -> list[dict]:
    import builtins
    import sys as _sys

    me = _sys.modules[__name__]
    out = []
    for name, meaning, action in _API_ERRORS:
        cls = getattr(builtins, name, None) or getattr(me, name)
        out.append({
            "name": name,
            "base": cls.__mro__[1].__name__,
            "meaning": meaning,
            "action": action,
        })
    return out


@_api(mutates=False)
def api_schema(names: list[str] | None = None) -> dict:
    """Describe the scripting API as JSON-serialisable data, for a machine.

    Built from the live objects with :mod:`inspect` and :mod:`ast`, so it
    is never out of date. ``functions`` has one entry per public function:
    ``name``, ``group``, ``signature``, ``parameters`` (``name``, ``kind``,
    ``annotation``, ``required``, ``default`` or ``default_repr``),
    ``returns``, ``summary`` (the first docstring paragraph), ``doc`` (the
    whole docstring), ``examples`` (its literal code blocks), ``raises``
    (what the axross layer raises itself), ``mutates`` (can change files,
    remote state or settings) and ``prompts`` (can wait for a human, or
    raises :class:`NonInteractiveError` without one). ``classes`` lists the
    public classes, ``types`` the other classes the API takes or returns
    (``FileItem`` and the result types) with fields, properties and
    methods; ``backend_protocol`` lists what every session from
    :func:`open`, :func:`open_url`, :func:`localfs` or :func:`ramfs` has,
    with ``mutates``, ``optional`` and ``fallback``; ``groups`` orders the
    names by topic; ``rules`` and ``errors`` are the conventions and the
    exceptions a script meets; ``legend`` explains every field.

    ``names`` narrows ``functions``, ``classes`` and ``types`` to those
    names plus the types they and the session methods use; ``names=[]``
    gives the index alone (groups, rules, errors, session methods). An
    unknown name raises :class:`ValueError`.

    The MCP tool ``script_api_schema`` returns the same data, and
    ``docs/scripting-api.json`` is a copy of it. For prose, use
    :func:`docs`::

        import json
        print(json.dumps(axross.api_schema(["read_text"]), indent=2))
    """
    import inspect
    import json as _json
    import sys as _sys

    if names is not None and (
        isinstance(names, (str, bytes)) or not all(isinstance(n, str) for n in names)
    ):
        raise ValueError("axross.api_schema: names must be a list of names, e.g. ['copy']")
    me = _sys.modules[__name__]
    functions: list[dict] = []
    classes: list[dict] = []
    seeds_of: dict[str, list[tuple[str | None, str]]] = {}
    for name in __all__:
        obj = getattr(me, name)
        if inspect.isclass(obj):
            classes.append(_type_entry(name, obj))
            seeds_of[name] = [
                (f["annotation"], obj.__module__) for f in classes[-1].get("fields", [])
            ]
        elif callable(obj):
            entry = _function_entry(name, obj)
            functions.append(entry)
            texts = [entry["returns"]] + [p.get("annotation") for p in entry["parameters"]]
            seeds_of[name] = [(text, obj.__module__) for text in texts]
    protocol = _backend_protocol_entries()
    protocol_seeds = [
        (text, "core.backend")
        for entry in protocol
        for text in [entry.get("returns")]
        + [p.get("annotation") for p in entry.get("parameters", [])]
    ]
    public = {c["name"] for c in classes}
    types = _referenced_types(protocol_seeds + [s for v in seeds_of.values() for s in v], public)
    if names is not None:
        wanted = set(names)
        known = set(seeds_of) | {t["name"] for t in types}
        unknown = sorted(wanted - known)
        if unknown:
            raise ValueError(
                f"axross.api_schema: unknown names {unknown}; api_schema(names=[])['groups'] "
                "lists the functions and classes"
            )
        seeds = protocol_seeds + [s for n in wanted for s in seeds_of.get(n, [])]
        seeds += [(t["name"], t["module"]) for t in types if t["name"] in wanted]
        reached = {t["name"] for t in _referenced_types(seeds, public)}
        functions = [f for f in functions if f["name"] in wanted]
        classes = [c for c in classes if c["name"] in wanted]
        types = [t for t in types if t["name"] in reached]
    return {
        "schema_version": API_SCHEMA_VERSION,
        "module": "axross",
        "legend": _json.loads(_json.dumps(_LEGEND)),  # a copy the caller may change
        "rules": _rules_entries(),
        "errors": _errors_entries(),
        "groups": _groups_entries(),
        "functions": functions,
        "classes": classes,
        "backend_protocol": protocol,
        "types": types,
    }


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
        "namespace (refused in paranoid mode) |\n"
        "| `.delete <name>` | Remove a saved script |\n"
        "| `.open` | Print the script-directory path "
        "(`~/.config/axross/scripts/`) |\n"
    )


def _bundled_scripts_dir() -> str:
    """``resources/scripts/`` next to the ``core`` package — the same
    relative path in the source tree, a wheel and the frozen bundle."""
    import os

    me_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(me_dir, "resources", "scripts")


def _list_bundled_scripts() -> list[str]:
    """Names (without ``.py``) of the bundled example scripts."""
    import os

    directory = _bundled_scripts_dir()
    if not os.path.isdir(directory):
        return []
    return sorted(
        fname[:-3]
        for fname in os.listdir(directory)
        if fname.endswith(".py") and not fname.startswith("_")
    )


def _load_bundled_script(name: str) -> str:
    """Source of bundled example ``name``. The name passes the same
    allow-list as a saved script, so it cannot leave the directory."""
    import os

    safe = _validate_script_name(name)
    if safe.startswith("_"):
        raise ValueError(f"{name!r} is not a bundled example")
    path = os.path.join(_bundled_scripts_dir(), f"{safe}.py")
    with __import__("builtins").open(path, encoding="utf-8") as fh:
        source = fh.read(MAX_SCRIPT_SOURCE_BYTES + 1)
    if len(source.encode("utf-8", errors="replace")) > MAX_SCRIPT_SOURCE_BYTES:
        raise OSError(f"bundled example is too large: {path}")
    return source


def _render_scripts_reference() -> str:
    """Walk ``resources/scripts/*.py`` and render one block per script
    with the docstring's first paragraph."""
    import os

    scripts_dir = _bundled_scripts_dir()
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
                src = fh.read(MAX_SCRIPT_SOURCE_BYTES + 1)
        except OSError:
            continue
        if len(src.encode("utf-8", errors="replace")) > MAX_SCRIPT_SOURCE_BYTES:
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
    "open",
    "open_url",
    "localfs",
    "ramfs",
    "list_backends",
    "available_backends",
    "list_profiles",
    "get_profile",
    "save_profile",
    "delete_profile",
    # file I/O
    "copy",
    "move",
    "remove",
    "trash",
    "checksum",
    "read_bytes",
    "write_bytes",
    "read_text",
    "write_text",
    "hash_bytes",
    "hash_file",
    # encryption + archives
    "encrypt",
    "decrypt",
    "extract_archive",
    "is_archive",
    # bookmarks
    "list_bookmarks",
    "add_bookmark",
    "remove_bookmark",
    # script directory
    "script_dir",
    "list_scripts",
    "save_script",
    "load_script",
    "delete_script",
    "run_script",
    # per-protocol passthroughs
    "find_tftp_files",
    "slp_discover",
    "nntp_post",
    "git_push",
    "exec",
    "interactive_shell",
    "query",
    "tables",
    "imap_search",
    "imap_move",
    "imap_set_flags",
    "share",
    "ldap_search",
    # network helpers
    "dns_resolve",
    "dns_records",
    "dns_reverse",
    "port_open",
    "port_scan",
    "subnet_hosts",
    "ping",
    "PingResult",
    "mac_lookup",
    "OuiInfo",
    "whois",
    "WhoisInfo",
    "time_skew",
    "TimeSkew",
    "tcp_banner",
    "tls_cert",
    "TlsCert",
    "ssh_hostkey",
    "SshHostKey",
    "http_probe",
    "HttpProbe",
    "snmp_get",
    "snmp_walk",
    "snmp_set",
    "SnmpVar",
    # search across backends
    "find_files",
    "grep",
    "GrepHit",
    "diff_files",
    # duplicate index (Duplicate Finder)
    "duplicate_scans",
    "duplicates",
    "dedupe",
    # content inspection
    "file_type",
    "magic_type",
    "text_encoding",
    "entropy",
    "archive_inspect",
    "ArchiveEntry",
    # file metadata
    "metadata",
    "remove_metadata",
    "export_metadata",
    # safety + diagnostics
    "diagnose",
    "preview_delete",
    "preview_transfer",
    "recovery_scan",
    "recent_operations",
    "security_mode",
    # credential testing (authorised use only — see docs/CRED_ATTACK.md)
    "bruteforce",
    "spray",
    "enumerate_users",
    # multi-system / daily-driver verbs
    "where_was_i",
    "health_pulse",
    "summarize",
    "explain",
    "compare_file",
    "inspect_targets",
    "federated_search",
    "resumable_copy",
    "snapshot_now",
    "start_trail",
    "stop_trail",
    "list_trails",
    "list_snapshots",
    "diff_snapshots",
    "dashboard",
    "serve_s3",
    "serve_webdav",
    # ui helpers (REPL / scripts)
    "message",
    "confirm",
    "toast",
    "is_interactive",
    "NonInteractiveError",
    # cheat-sheet + machine-readable description
    "help",
    "docs",
    "api_schema",
]


# ---------------------------------------------------------------------------
# UI helpers (proxy through to core.ui_helpers so the import is lazy)
# ---------------------------------------------------------------------------


@_api(mutates=False)
def message(text: str, *, title: str = "axross", level: str = "info") -> None:
    """Show a modal informational dialog with the given message.

    ``level`` selects the state colour + icon: ``"info"`` (blue),
    ``"success"`` (green), ``"warning"`` (yellow), ``"error"`` (red).
    Other values fall back to ``"info"``.

    With a running Qt app, opens a :class:`QMessageBox` with a
    coloured state-icon and the bundled axross glyph as the window
    icon. Without Qt (headless ``--script`` / cron / CI), prints
    ``"[axross] LEVEL: TITLE — TEXT"`` to stdout so the same code
    works in both contexts.

    Example::

        axross.message("Backup completed (123 files copied)",
                       level="success")
    """
    from core.ui_helpers import message as _impl

    _impl(text, title=title, level=level)  # type: ignore[arg-type]


@_api(mutates=False, prompts=True)
def confirm(
    text: str, *, title: str = "axross", default_yes: bool = False, assume_yes: bool = False
) -> bool:
    """Show a Yes/No dialog. Returns True on Yes, False otherwise.

    Headless fallback (no Qt event loop): reads a single y/n from
    stdin when stdin is a terminal, so ``--script`` and
    REPL-without-GUI both work. Accepts ``y/yes/j/ja/s/si/sí`` as Yes;
    an empty answer is ``default_yes``.

    When no human can answer - no Qt window and no terminal (an MCP
    ``script_run``, the Scripts dock, cron, a pipe) or
    ``AXROSS_NONINTERACTIVE=1`` - it raises :class:`NonInteractiveError`
    instead of guessing, whatever ``default_yes`` says. Pass
    ``assume_yes=True`` to answer yes without asking in that case; a
    human who can be asked is still asked.

    Example::

        if axross.confirm("Delete 47 files? Cannot be undone.",
                          title="Confirm cleanup"):
            for p in doomed:
                backend.remove(p)
    """
    from core.ui_helpers import confirm as _impl

    return _impl(text, title=title, default_yes=default_yes, assume_yes=assume_yes)


@_api(mutates=False)
def is_interactive() -> bool:
    """True when a human can answer :func:`confirm` right now.

    False under ``AXROSS_NONINTERACTIVE=1`` (set for every MCP
    ``script_run``), off the GUI thread of a Qt window, and without a Qt
    window when stdin is not a terminal. Scripts that a machine may run
    can branch on it instead of catching :class:`NonInteractiveError`.
    """
    from core.ui_helpers import is_interactive as _impl

    return _impl()


from core.ui_helpers import NonInteractiveError  # noqa: E402 — part of the API


@_api(mutates=False)
def toast(text: str, *, level: str = "info", timeout: float = 4.0) -> None:
    """Non-modal toast in the bottom-right corner of the main window.

    Auto-dismisses after ``timeout`` seconds. Multiple toasts stack.
    Levels: same colour palette as :func:`message`.

    Example::

        axross.toast("Connection lost — retrying", level="error")
        axross.toast("Saved 1.2 MB to /tmp/dump.json",
                     level="success", timeout=2)
    """
    from core.ui_helpers import toast as _impl

    _impl(text, level=level, timeout=timeout)  # type: ignore[arg-type]
