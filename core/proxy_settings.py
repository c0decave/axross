"""Global default proxy, bypass list, PAC resolution and proxy probing.

Profiles choose one of three modes (``ConnectionProfile.proxy_mode``):

``custom``   the profile's own proxy fields (``proxy_type == "none"`` is a
             direct connection) — what every profile did before this
             module existed, so old profiles are unchanged;
``default``  the application-wide default configured here (Tools > Network
             & Proxy), subject to the bypass list and an optional PAC;
``none``     explicitly direct, whatever the default says.

The default's password lives in the keyring, never in ``proxy.json``.
A PAC script or a proxy that cannot be reached **never** turns into a
direct connection: failures raise :class:`ProxyResolutionError`.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from core.credentials import DEFAULT_PROXY_OWNER
from core.proxy import ProxyConfig, is_valid_proxy_type, parse_proxy_type
from core.secure_storage import keep_unreadable_copy

log = logging.getLogger(__name__)

SETTINGS_PATH = Path.home() / ".config" / "axross" / "proxy.json"
KEYRING_NAME = DEFAULT_PROXY_OWNER
DEFAULT_BYPASS = ("localhost", "127.0.0.0/8", "::1")
MAX_BYPASS_ENTRIES = 256
MAX_PAC_BYTES = 1 << 20
PAC_TTL_SECONDS = 300
PROXY_MODES = ("custom", "default", "none")

_LOCK = threading.Lock()


class ProxyResolutionError(ConnectionError):
    """No proxy decision could be made (PAC unreachable / unusable).

    Callers abort the connection; they must not fall back to direct."""


# ---------------------------------------------------------------------------
# Stored defaults
# ---------------------------------------------------------------------------
@dataclass
class ProxyDefaults:
    proxy_type: str = "none"
    host: str = ""
    port: int = 0
    username: str = ""
    store_password: bool = False
    bypass: list[str] = field(default_factory=lambda: list(DEFAULT_BYPASS))
    ca_file: str = ""
    pac_url: str = ""

    @property
    def configured(self) -> bool:
        return self.proxy_type != "none" or bool(self.pac_url)


def _clean(value: object, limit: int = 1024) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\x00-\x1f\x7f]", "", value).strip()[:limit]


def _from_dict(raw: dict) -> ProxyDefaults:
    ptype = _clean(raw.get("proxy_type"), 32).lower() or "none"
    if not is_valid_proxy_type(ptype):
        ptype = "none"
    port = raw.get("port")
    port = (
        port if isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535 else 0
    )
    bypass_raw = raw.get("bypass")
    if isinstance(bypass_raw, list):
        bypass = [e for e in (_clean(x, 253) for x in bypass_raw[:MAX_BYPASS_ENTRIES]) if e]
    else:
        bypass = list(DEFAULT_BYPASS)
    return ProxyDefaults(
        proxy_type=ptype,
        host=_clean(raw.get("host"), 253),
        port=port,
        username=_clean(raw.get("username"), 256),
        store_password=raw.get("store_password") is True,
        bypass=bypass,
        ca_file=_clean(raw.get("ca_file")),
        pac_url=_clean(raw.get("pac_url"), 2048),
    )


def _read(p: Path) -> tuple[ProxyDefaults, bool]:
    """The stored defaults and whether the file could be read. A missing
    file is readable: it means "no default proxy". A file that exists but
    cannot be read, is no JSON / UTF-8 or no object is not."""
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ProxyDefaults(), True
    except (OSError, ValueError):
        return ProxyDefaults(), False
    if not isinstance(raw, dict):
        return ProxyDefaults(), False
    return _from_dict(raw), True


def load(path: Path | None = None) -> ProxyDefaults:
    """Stored defaults; a missing / unreadable / hostile file gives the
    "no default proxy" state rather than an error. Connections do not use
    this: :func:`resolve` refuses to decide over an unreadable file."""
    return _read(path or SETTINGS_PATH)[0]


def validate(d: ProxyDefaults) -> None:
    """Raise ``ValueError`` for a configuration that cannot work."""
    if d.proxy_type != "none":
        if not is_valid_proxy_type(d.proxy_type):
            raise ValueError(f"Unknown proxy type: {d.proxy_type}")
        # With a PAC file the proxy endpoint comes from the script; the type
        # only contributes the authentication scheme.
        if not d.pac_url:
            if not d.host:
                raise ValueError("A proxy host is required when a proxy type is selected.")
            if not (1 <= int(d.port) <= 65535):
                raise ValueError("The proxy port must be 1..65535.")
    if d.pac_url:
        parts = urlsplit(d.pac_url)
        if parts.scheme.lower() not in ("", "file", "http", "https"):
            raise ValueError("The PAC location must be a file path or an http(s) URL.")
    if len(d.bypass) > MAX_BYPASS_ENTRIES:
        raise ValueError(f"At most {MAX_BYPASS_ENTRIES} bypass entries.")
    if d.ca_file and not Path(d.ca_file).expanduser().is_file():
        raise ValueError(f"The proxy CA file {d.ca_file!r} does not exist.")


def save(d: ProxyDefaults, path: Path | None = None) -> None:
    validate(d)
    p = path or SETTINGS_PATH
    payload = {
        "proxy_type": d.proxy_type,
        "host": d.host,
        "port": int(d.port),
        "username": d.username,
        "store_password": bool(d.store_password),
        "bypass": list(d.bypass),
        "ca_file": d.ca_file,
        "pac_url": d.pac_url,
    }
    with _LOCK:
        p.parent.mkdir(parents=True, exist_ok=True)
        # The dialog showed an unreadable file as "no proxy"; replacing it
        # would erase the proxy it held, so a copy of it is kept first.
        if not _read(p)[1] and not keep_unreadable_copy(p):
            raise OSError(f"Not saving: the unreadable {p} could not be kept as a copy")
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".proxy.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, indent=2) + "\n")
            os.replace(tmp, p)
            os.chmod(p, 0o600)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    _PAC_CACHE.clear()


def get_password() -> str:
    from core.credentials import get_proxy_password

    return get_proxy_password(KEYRING_NAME) or ""


# Password typed in the Network & Proxy dialog without "save in keyring":
# held for this process only, so real connections use what "Test proxy"
# used instead of silently connecting without it.
_session_password = ""


def set_session_password(password: str) -> None:
    global _session_password
    _session_password = password or ""


def session_password() -> str:
    """The password typed for this process only ("" when none)."""
    return _session_password


def set_password(password: str) -> bool:
    from core.credentials import delete_proxy_password, store_proxy_password

    if not password:
        delete_proxy_password(KEYRING_NAME)
        return True
    return store_proxy_password(KEYRING_NAME, password)


# ---------------------------------------------------------------------------
# Bypass list
# ---------------------------------------------------------------------------
def bypass_matches(host: str, patterns, port: int | None = None) -> bool:
    """Whether *host* (and optional *port*) matches the bypass list.

    Entries: ``*`` (everything), ``<local>`` (names without a dot), an IP
    literal, a CIDR block, ``host`` / ``.domain`` / ``*.domain`` (a
    domain matches itself and its subdomains), each optionally ``:port``.
    A hostname is never resolved to test a CIDR: that would be a DNS
    lookup outside the proxy.
    """
    host = host.strip().strip("[]").lower()
    if not host:
        return False
    host_ip = None
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    for raw in patterns:
        pat = raw.strip().lower()
        if not pat:
            continue
        want_port = None
        m = re.fullmatch(r"(.+):(\d{1,5})", pat)
        if m and not _is_ipv6(pat):
            pat, want_port = m.group(1), int(m.group(2))
        # An entry bound to a port only matches that port. With the port
        # unknown it cannot be shown to match, and a wrong match means
        # direct traffic — so it does not.
        if want_port is not None and want_port != port:
            continue
        pat = pat.strip("[]")
        if pat == "*":
            return True
        if pat == "<local>":
            if "." not in host and host_ip is None:
                return True
            continue
        if "/" in pat:
            try:
                if host_ip is not None and host_ip in ipaddress.ip_network(pat, strict=False):
                    return True
            except ValueError:
                pass
            continue
        pat_ip = None
        try:
            pat_ip = ipaddress.ip_address(pat)
        except ValueError:
            pass
        if pat_ip is not None:  # an address entry only ever matches that address
            if host_ip is not None and host_ip == pat_ip:
                return True
            continue
        domain = pat.removeprefix("*.").lstrip(".")
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _is_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# PAC
# ---------------------------------------------------------------------------
_PAC_CACHE: dict[str, tuple[float, object]] = {}


def _fetch_pac_source(location: str) -> str:
    parts = urlsplit(location)
    if parts.scheme.lower() in ("http", "https"):
        import requests

        sess = requests.Session()
        sess.trust_env = False  # the PAC is fetched directly, by design
        try:
            resp = sess.get(location, timeout=10, stream=True)
            resp.raise_for_status()
            data = b""
            for chunk in resp.iter_content(65536):
                data += chunk
                if len(data) > MAX_PAC_BYTES:
                    raise ProxyResolutionError("PAC file is larger than 1 MiB")
        except requests.RequestException as exc:
            raise ProxyResolutionError(f"Cannot fetch the PAC file: {exc}") from exc
        finally:
            sess.close()
        return data.decode("utf-8", errors="replace")
    path = Path(parts.path if parts.scheme.lower() == "file" else location).expanduser()
    try:
        if path.stat().st_size > MAX_PAC_BYTES:
            raise ProxyResolutionError("PAC file is larger than 1 MiB")
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ProxyResolutionError(f"Cannot read the PAC file: {exc}") from exc


def pac_script(location: str, *, now: float | None = None):
    """Parsed script for *location* (cached for :data:`PAC_TTL_SECONDS`;
    a failed refresh keeps serving the last good copy)."""
    from core.pac import PacError, load_pac

    t = now if now is not None else time.monotonic()
    cached = _PAC_CACHE.get(location)
    if cached is not None and t - cached[0] < PAC_TTL_SECONDS:
        return cached[1]
    try:
        script = load_pac(_fetch_pac_source(location))
    except (PacError, ProxyResolutionError) as exc:
        if cached is not None:
            log.warning("PAC refresh failed (%s); using the previous copy", exc)
            return cached[1]
        if isinstance(exc, ProxyResolutionError):
            raise
        raise ProxyResolutionError(f"The PAC file is unusable: {exc}") from exc
    _PAC_CACHE[location] = (t, script)
    return script


def _with_auth(kind: str, defaults: ProxyDefaults) -> str:
    """PAC names the proxy kind; the authentication scheme comes from the
    default's own type (``http+ntlm`` -> an ``http`` entry becomes
    ``http+ntlm``)."""
    if defaults.proxy_type == "none" or kind.startswith("socks"):
        return kind
    try:
        _transport, auth = parse_proxy_type(defaults.proxy_type)
    except ValueError:
        return kind
    return f"{kind}+{auth}" if auth else kind


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Resolution:
    """Outcome of choosing a proxy for one connection."""

    config: ProxyConfig | None  # None = connect directly
    source: str  # none | custom | default | bypass | pac | default-none
    detail: str = ""

    @property
    def description(self) -> str:
        """One line for tooltips / logs (never contains a password)."""
        if self.config is None:
            reason = {
                "none": "profile is set to connect directly",
                "custom": "no proxy configured on the profile",
                "bypass": "target matches the bypass list",
                "default-none": "no default proxy configured",
                "pac": "PAC says DIRECT",
            }.get(self.source, self.source)
            return f"Direct ({reason})"
        c = self.config
        origin = {"pac": "PAC", "default": "default proxy", "custom": "profile proxy"}.get(
            self.source, self.source
        )
        return f"{c.proxy_type.upper()} {c.host}:{c.port} ({origin})"


def target_of(profile) -> tuple[str, int | None]:
    """Host and port the profile's traffic is going to (for bypass / PAC)."""
    proto = getattr(profile, "protocol", "")
    url = ""
    if proto == "webdav":
        url = getattr(profile, "webdav_url", "") or ""
    elif proto == "sharepoint":
        url = getattr(profile, "sharepoint_site_url", "") or ""
    elif proto == "s3":
        url = getattr(profile, "s3_endpoint", "") or ""
        if not url:
            return "s3.amazonaws.com", 443
    if url:
        parts = urlsplit(url if "://" in url else f"https://{url}")
        if parts.hostname:
            return parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    port = getattr(profile, "port", 0) or _default_port(proto)
    return getattr(profile, "host", "") or "", port


def _default_port(protocol: str) -> int | None:
    """The port a profile without one really connects to, so a port-bound
    bypass entry can be judged."""
    from core import backend_registry

    backend_registry.ensure_initialized()
    info = backend_registry.get(protocol)
    return (info.default_port or None) if info is not None else None


_PROTO_SCHEME = {"webdav": "https", "s3": "https", "sharepoint": "https", "ftps": "ftp"}


def resolve(
    mode: str,
    own: ProxyConfig | None,
    host: str,
    port: int | None,
    protocol: str = "",
    defaults: ProxyDefaults | None = None,
) -> Resolution:
    """Choose the proxy for a connection to ``host:port``."""
    if mode == "none":
        return Resolution(None, "none")
    if mode != "default":
        return Resolution(own, "custom") if own is not None else Resolution(None, "custom")
    if defaults is not None:
        d = defaults
    else:
        d, readable = _read(SETTINGS_PATH)
        if not readable:
            # "No default proxy" would connect directly: fail closed.
            raise ProxyResolutionError(
                f"The default proxy settings in {SETTINGS_PATH} cannot be read; "
                "not connecting without them"
            )
    if not d.configured:
        return Resolution(None, "default-none")
    if host and bypass_matches(host, d.bypass, port):
        return Resolution(None, "bypass", host)
    if d.pac_url:
        return _resolve_pac(d, host, port, protocol)
    return Resolution(_default_config(d, d.proxy_type, d.host, d.port), "default")


def _default_config(d: ProxyDefaults, ptype: str, host: str, port: int) -> ProxyConfig:
    password = ""
    if d.username:
        password = get_password() if d.store_password else _session_password
    return ProxyConfig(ptype, host, port, d.username, password, d.ca_file)


def _same_host(a: str, b: str) -> bool:
    return a.strip().rstrip(".").lower() == b.strip().rstrip(".").lower()


def _pac_is_authentic(location: str) -> bool:
    """A PAC fetched over plain http can be rewritten by anyone on the path."""
    return urlsplit(location).scheme.lower() != "http"


def _resolve_pac(d: ProxyDefaults, host: str, port: int | None, protocol: str) -> Resolution:
    from core.pac import PacError

    script = pac_script(d.pac_url)
    scheme = _PROTO_SCHEME.get(protocol, protocol or "tcp")
    url = f"{scheme}://{host}{':' + str(port) if port else ''}/"
    try:
        directives = script.find(url, host)  # type: ignore[attr-defined]
    except PacError as exc:
        raise ProxyResolutionError(f"The PAC file could not decide for {host}: {exc}") from exc
    first = directives[0]
    if first.kind == "direct":
        return Resolution(None, "pac", url)
    cfg = _default_config(d, _with_auth(first.kind, d), first.host, first.port)
    if cfg.username and not _pac_is_authentic(d.pac_url) and not _same_host(first.host, d.host):
        # Whoever can rewrite a plain-http PAC could otherwise name their
        # own proxy and collect the credentials. The configured proxy
        # itself is still trusted with them.
        log.warning(
            "PAC (plain http) names %s, not the configured proxy; connecting "
            "without the default proxy credentials",
            first.host,
        )
        cfg = ProxyConfig(cfg.proxy_type, cfg.host, cfg.port, "", "", cfg.ca_file)
    return Resolution(cfg, "pac", url)


def resolve_for_profile(profile, defaults: ProxyDefaults | None = None) -> Resolution:
    """:func:`resolve` for a :class:`core.profiles.ConnectionProfile`."""
    mode = getattr(profile, "proxy_mode", "custom") or "custom"
    own = None
    ptype = (getattr(profile, "proxy_type", "none") or "none").lower()
    if mode == "custom" and ptype != "none":
        password = ""
        if hasattr(profile, "get_proxy_password"):
            try:
                password = profile.get_proxy_password() or ""
            except Exception:  # noqa: BLE001 - keyring trouble must not block the lookup
                password = ""
        own = ProxyConfig(
            ptype,
            profile.proxy_host,
            int(profile.proxy_port or 0),
            profile.proxy_username,
            password,
        )
    host, port = target_of(profile)
    return resolve(mode, own, host, port, getattr(profile, "protocol", ""), defaults)


def adopt_default_proxy(profiles) -> list[str]:
    """Switch every profile whose protocol can use a proxy to the default
    one (``proxy_mode = "default"``). Returns the names that changed; the
    caller persists the profile store. Profiles that already follow the
    default, protocols a proxy cannot carry and profiles routed through a
    ProxyCommand are left alone."""
    from core.connection_manager import proxy_unavailable_reason

    changed: list[str] = []
    for profile in profiles:
        if proxy_unavailable_reason(profile.protocol):
            continue
        if getattr(profile, "proxy_mode", "custom") == "default":
            continue
        # A ProxyCommand (jump host) is deliberate per-host routing; the
        # default proxy would replace it, and the host may only be
        # reachable through that jump.
        if getattr(profile, "proxy_command", ""):
            continue
        profile.proxy_mode = "default"
        changed.append(profile.name)
    return changed


def default_proxy_kwargs(host: str, port: int | None, protocol: str = "") -> dict:
    """The five ``proxy_*`` kwargs for a connection that names no proxy
    (scripts, ``open_url``): the default if one applies, else ``{}``."""
    res = resolve("default", None, host, port, protocol)
    cfg = res.config
    if cfg is None:
        return {}
    return {
        "proxy_type": cfg.proxy_type,
        "proxy_host": cfg.host,
        "proxy_port": cfg.port,
        "proxy_username": cfg.username,
        "proxy_password": cfg.password,
    }


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    stage: str  # config | proxy | tls | auth | tunnel | ok
    message: str
    seconds: float = 0.0


def probe(cfg: ProxyConfig, host: str, port: int, timeout: float = 10.0) -> ProbeResult:
    """Open a tunnel through *cfg* to ``host:port`` and report where it
    fails. Used by the "Test proxy" button; closes the socket at once."""
    from core.proxy import create_proxy_socket
    from core.proxy_http import ProxyAuthError

    start = time.monotonic()

    def done(ok: bool, stage: str, message: str) -> ProbeResult:
        return ProbeResult(ok, stage, message, time.monotonic() - start)

    try:
        if not cfg.enabled:
            return done(False, "config", "No proxy is configured.")
        sock = create_proxy_socket(cfg, host, port, timeout=timeout)
    except ValueError as exc:
        return done(False, "config", str(exc))
    except ProxyAuthError as exc:
        return done(False, "auth", str(exc))
    except ConnectionError as exc:
        text = str(exc)
        stage = "tls" if "TLS to proxy" in text else "proxy"
        if "refused" in text.lower() and (
            "tunnel" in text.lower() or "connect failed" in text.lower()
        ):
            stage = "tunnel"
        return done(False, stage, text)
    except OSError as exc:
        return done(False, "proxy", str(exc))
    try:
        sock.close()
    except OSError:
        pass
    return done(True, "ok", f"Tunnel to {host}:{port} established through {cfg.host}:{cfg.port}.")
