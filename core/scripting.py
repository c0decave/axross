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
from typing import Any as _Any
from urllib.parse import unquote as _unquote
from urllib.parse import urlsplit as _urlsplit
from urllib.parse import urlunsplit as _urlunsplit

log = _logging.getLogger(__name__)

MAX_SCRIPT_READ_BYTES = 64 * 1024 * 1024
_SCRIPT_READ_CHUNK = 1024 * 1024


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


def open(profile_name: str, password: str | None = None, key_passphrase: str | None = None):
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
    log.info(
        "axross.open(%r) — protocol=%s host=%s user=%s",
        profile_name,
        profile.protocol,
        profile.host,
        profile.username,
    )
    # ConnectionManager owns the auth fallback chain (key, agent,
    # password); we only override when the caller hands us a value.
    return cm.connect(
        profile,
        password=password or "",
        key_passphrase=key_passphrase or "",
    )


_PROXY_KWARG_NAMES = (
    "proxy_type",
    "proxy_host",
    "proxy_port",
    "proxy_username",
    "proxy_password",
)


def open_url(url: str, **kwargs):
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
    if parts.port:
        init_kwargs.setdefault("port", parts.port)
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
    # otherwise silently drop proxy settings.
    if proxy_kwargs:
        import inspect

        try:
            sig = inspect.signature(load_backend_class(proto_id))
        except (TypeError, ValueError):
            sig = None
        accepted = False
        for k, v in proxy_kwargs.items():
            if sig is not None and k in sig.parameters:
                init_kwargs[k] = v
                accepted = True
        if not accepted:
            log.warning(
                "axross.open_url(%s://…) received proxy settings, but the "
                "%s backend has no SOCKS/HTTP proxy support. The proxy "
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
    return cm.connect(
        profile,
        password=password,
        key_passphrase=key_passphrase,
    )


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


def copy(
    src_backend,
    src_path: str,
    dst_backend,
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


def move(src_backend, src_path: str, dst_backend, dst_path: str, *, overwrite: bool = False) -> int:
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
        transferred = copy(
            src_backend,
            src_path,
            dst_backend,
            dst_path,
            overwrite=False,
        )
        try:
            src_backend.remove(src_path)
        except OSError as exc:
            log.warning(
                "axross.move: copied %s:%s -> %s:%s but source remove failed: %s; "
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
                    "axross.move: undo failed after source remove failure; "
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


def remove(backend, path: str, *, recursive: bool = False, confirm: bool = False) -> str:
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


def trash(backend, path: str, *, root: str | None = None, confirm: bool = False) -> str:
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


def checksum(backend, path: str, algorithm: str = "sha256") -> str:
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


def read_bytes(
    backend,
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


def write_bytes(backend, path: str, data: bytes, *, overwrite: bool = False) -> int:
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


def read_text(
    backend,
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


def write_text(
    backend, path: str, text: str, encoding: str = "utf-8", *, overwrite: bool = False
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


def encrypt(
    backend, path: str, passphrase: str, keep_original: bool = True, *, overwrite: bool = False
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


def decrypt(backend, path: str, passphrase: str) -> bytes:
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


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hex digest of ``data`` under ``algorithm`` (anything
    :mod:`hashlib.new` accepts: sha1, sha256, sha512, md5, …)."""
    import hashlib

    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file(backend, path: str, algorithm: str = "sha256", chunk_size: int = 1024 * 1024) -> str:
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


def save_profile(profile) -> None:
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


def extract_archive(local_path: str, dst_dir: str, progress=None) -> str:
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

    def _snmp_unavailable(*_a, **_kw):
        raise OSError(
            "SNMP support requires pysnmp — install with "
            "`pip install pysnmp` (or via the axross[snmp] extra)"
        )

    snmp_get = snmp_walk = snmp_set = _snmp_unavailable

# ---------------------------------------------------------------------------
# Network helpers (small + frequently useful in scripts)
# ---------------------------------------------------------------------------


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


def nntp_post(
    backend, group: str, subject: str, body: str, author: str = "axross <noreply@axross>"
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


def git_push(backend, branch: str | None = None) -> None:
    """Push committed work on ``backend`` (a :class:`GitFsSession`) to
    its origin. Raises :class:`GitForceRefused` on non-fast-forward.
    Pass ``branch=None`` to push every branch the session has touched."""
    log.info("axross.git_push: branch=%s", branch or "<all touched>")
    backend.flush_push(branch=branch)


def ldap_search(
    backend,
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


def imap_search(backend, criteria: str = "ALL", *, mailbox: str = "INBOX") -> list:
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


def imap_move(backend, uid: int, src_mailbox: str, dst_mailbox: str) -> None:
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


def imap_set_flags(
    backend, uid: int, flags: list[str], *, mailbox: str = "INBOX", mode: str = "set"
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
    raise TypeError(f"backend {type(backend).__name__} does not implement tables() / collections()")


def interactive_shell(
    backend,
    *,
    term: str = "xterm-256color",
    cols: int = 80,
    rows: int = 24,
    env: dict[str, str] | None = None,
):
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
# Safety, diagnostics and recovery
# ---------------------------------------------------------------------------


def diagnose(backend, *, root: str | None = None, write_test: bool = False) -> str:
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


def preview_delete(backend, paths: list[str], *, max_entries: int = 10_000) -> str:
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


def preview_transfer(
    source_backend,
    dest_backend,
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


def recovery_scan(backend, root: str | None = None) -> str:
    """Scan a backend location for recoverable temp/trash items and
    return a plain-text report."""
    from core.recovery import format_findings, scan_backend_recovery

    if root is None:
        try:
            root = backend.home()
        except Exception:  # noqa: BLE001
            root = "/"
    return format_findings(scan_backend_recovery(backend, root))


def recent_operations(limit: int = 20) -> list[dict]:
    """Return recent redacted operation-journal events."""
    from core.operation_journal import read_recent

    return read_recent(limit=limit)


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


def bruteforce(
    profile,
    *,
    users,
    passwords,
    rate_per_min: float = 30.0,
    timeout_per_attempt: float = 10.0,
    abort_on_lockout: bool = True,
    abort_after_n_lockouts: int = 1,
    abort_after_n_failures: int | None = None,
    max_attempts: int | None = None,
    stop_on_first_success_per_user: bool = True,
    progress=None,
    on_unknown_host=None,
    state_file=None,
    dry_run: bool = False,
    jitter_s: float = 0.0,
    authorized: bool = False,
):
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


def spray(
    profile,
    *,
    users,
    password: str | None = None,
    passwords=None,
    rate_per_min: float = 30.0,
    timeout_per_attempt: float = 10.0,
    abort_on_lockout: bool = True,
    abort_after_n_lockouts: int = 1,
    max_attempts: int | None = None,
    stop_on_first_success_per_user: bool = True,
    progress=None,
    on_unknown_host=None,
    state_file=None,
    dry_run: bool = False,
    jitter_s: float = 0.0,
    authorized: bool = False,
):
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


def enumerate_users(
    profile,
    candidates,
    *,
    method: str = "auto",
    timeout_per_probe: float = 10.0,
    timing_samples: int = 5,
    rate_per_min: float = 30.0,
    jitter_s: float = 0.0,
    progress=None,
    on_unknown_host=None,
    authorized: bool = False,
):
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


def where_was_i(host: str | None = None):
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


def health_pulse():
    """Snapshot the live connection-health pulse for every enrolled
    session — last-probe latency, median latency, staleness flag.

    Returns a list of :class:`core.conn_health.HealthRecord`. Empty
    when no sessions have been enrolled.
    """
    from core.conn_health import health_pulse as _impl

    return _impl()


def summarize(backend, path: str = "", *, max_entries: int = 2000):
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


def explain(backend, path: str = ""):
    """Heuristic best-guess "what IS this directory?" — git repo,
    PostgreSQL data dir, nginx config tree, k8s manifests, Maildir,
    web-server log dir, and friends. Returns the highest-confidence
    pattern match as a :class:`core.inspect.ExplainResult`, or an
    empty result if nothing scored above 0.2.
    """
    from core.inspect import explain as _impl

    return _impl(backend, path)


def compare_file(
    backends: list,
    path: str,
    *,
    content: bool = True,
    content_cap_bytes: int | None = None,
    parallelism: int = 8,
    per_target_timeout_s: float = 30.0,
):
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


def inspect_targets(
    targets: list,
    *,
    content: bool = True,
    content_cap_bytes: int | None = None,
    parallelism: int = 8,
    per_target_timeout_s: float = 30.0,
):
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


def federated_search(
    backends: list,
    query=None,
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
    progress=None,
):
    """Run one search query against many backends in parallel.

    The dispatcher picks the most efficient adapter per backend
    (IMAP SEARCH for IMAP, native ``find_by_query`` for DB-FS family,
    client-side walk for the rest). Pass either a pre-built
    :class:`core.search_federation.SearchQuery` (``query=…``) or the
    individual filter kwargs to construct one inline.

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


def resumable_copy(
    src_backend,
    src_path: str,
    dst_backend,
    dst_path: str,
    *,
    segment_size: int = 4 * 1024 * 1024,
    manifest_path=None,
    overwrite: bool = False,
    progress=None,
):
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


def snapshot_now(
    backend, path: str, *, name: str = "", head_hash: bool = False, max_files: int = 5000
):
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


def start_trail(
    backend,
    path: str,
    *,
    name: str = "",
    interval_s: float = 300.0,
    head_hash: bool = False,
    max_files: int = 5000,
    on_snapshot=None,
):
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


def stop_trail(name: str) -> bool:
    """Stop a named background trail. Returns True if one was found."""
    from core.trail import stop_trail as _impl

    return _impl(name)


def list_trails():
    """List every recorded trail with its metadata."""
    from core.trail import list_trails as _impl

    return _impl()


def list_snapshots(trail_name: str, *, limit: int = 100):
    """List the most recent snapshots of one trail (newest first).

    Returns a list of :class:`core.trail.Snapshot`.
    """
    from core.trail import list_snapshots as _impl

    return _impl(trail_name, limit=limit)


def diff_snapshots(snapshot_a: int, snapshot_b: int):
    """Compare snapshot A to snapshot B (B is the newer / target).

    Returns a :class:`core.trail.TrailDiff` with added / removed /
    modified path lists.
    """
    from core.trail import diff_snapshots as _impl

    return _impl(snapshot_a, snapshot_b)


def dashboard(
    *,
    with_capacity: bool = False,
    recent_ops_limit: int = 10,
    fmt: str = "text",
    backends: list | None = None,
):
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


def serve_s3(
    backend,
    *,
    bind: str = "127.0.0.1",
    port: int = 9000,
    read_only: bool = False,
    auth_token: str = "",
    root_path: str = "/",
):
    """Expose ``backend`` as a minimum-viable S3 endpoint so any
    existing S3 client (aws-cli / restic / rclone / terraform) can
    speak to it.

    Localhost-bound by default. Pass ``bind="0.0.0.0"`` only when you
    intentionally want LAN access; non-local binds without
    ``auth_token=…`` are refused. Returns a live
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


def serve_webdav(
    backend,
    *,
    bind: str = "127.0.0.1",
    port: int = 8080,
    read_only: bool = False,
    auth_token: str = "",
    root_path: str = "/",
):
    """Expose ``backend`` as a minimum-viable WebDAV endpoint —
    ``davfs2 mount``, gnome-files (``davs://``), macOS Finder, browser
    read-only listings all work. Same OPSEC rules as
    :func:`serve_s3`. Returns a :class:`core.reverse_serve.ReverseServer`.
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
        os.fchmod(fd, 0o600)
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
        "Content inspection",
        [
            "magic_type",
            "text_encoding",
            "entropy",
            "archive_inspect",
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
        ],
    ),
    (
        "Misc",
        [
            "help",
            "docs",
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
    # content inspection
    "magic_type",
    "text_encoding",
    "entropy",
    "archive_inspect",
    "ArchiveEntry",
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
    # cheat-sheet
    "help",
    "docs",
]


# ---------------------------------------------------------------------------
# UI helpers (proxy through to core.ui_helpers so the import is lazy)
# ---------------------------------------------------------------------------


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


def confirm(text: str, *, title: str = "axross", default_yes: bool = False) -> bool:
    """Show a Yes/No dialog. Returns True on Yes, False otherwise.

    Headless fallback (no Qt event loop): reads a single y/n from
    stdin so ``--script`` and REPL-without-GUI both work. Accepts
    ``y/yes/j/ja/s/si/sí`` as Yes; default answer is ``default_yes``.

    Example::

        if axross.confirm("Delete 47 files? Cannot be undone.",
                          title="Confirm cleanup"):
            for p in doomed:
                backend.remove(p)
    """
    from core.ui_helpers import confirm as _impl

    return _impl(text, title=title, default_yes=default_yes)


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
