"""The shares an SMB host publishes, through impacket (no external binary).

``list_shares`` asks the server's SRVSVC pipe for NetShareEnum level 1 over
IPC$ - what ``smbclient -L`` did before, without running a program, so the
password never reaches a child process and the list works where the samba
client tools are not installed (Windows, macOS, the frozen builds).

impacket is an optional dependency (``pip install axross[wmi]``; axross-full
bundles it).
"""

from __future__ import annotations

import logging

from core.net_helpers import TargetError, parse_targets

log = logging.getLogger(__name__)

#: shi1_type: the low bits are the kind, 0x80000000 marks a special (admin,
#: hidden "$") share ([MS-SRVS] 2.2.2.4).
_STYPE_MASK = 0x0FFFFFFF
STYPE_SPECIAL = 0x80000000
_SHARE_TYPES = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}

#: NT statuses that mean "this account cannot log on" - wrong password,
#: locked, disabled, expired. A caller that tries one credential on many
#: hosts stops at the first of them (core.remote_sweep).
LOGON_FAILURES = frozenset({
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_WRONG_PASSWORD",
    "STATUS_NO_SUCH_USER",
})
_DENIED = frozenset({"STATUS_ACCESS_DENIED", "STATUS_BAD_NETWORK_NAME", "STATUS_NETWORK_ACCESS_DENIED"})


def _connection_class():
    """impacket's SMBConnection; a seam for the tests."""
    try:
        from impacket.smbconnection import SMBConnection  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise OSError(
            "SMB share listing needs impacket: pip install axross[wmi], or use the axross-full build"
        ) from exc
    return SMBConnection


def status_name(exc: BaseException) -> str:
    """The NT status name of an impacket SessionError (``STATUS_...``), or ""."""
    get_code = getattr(exc, "getErrorCode", None)
    if get_code is None:
        return ""
    try:
        from impacket import nt_errors  # type: ignore[import-not-found]

        entry = nt_errors.ERROR_MESSAGES.get(get_code())
    except Exception:  # noqa: BLE001 - a status we cannot name is just unnamed
        return ""
    return entry[0] if entry else ""


def as_os_error(host: str, exc: BaseException) -> OSError:
    """An impacket error as the OSError axross reports: PermissionError for
    a refused logon or access, OSError otherwise. The text names the host
    and the NT status; it never repeats the credentials."""
    name = status_name(exc)
    if name in LOGON_FAILURES or name in _DENIED:
        return PermissionError(f"{host}: {name}")
    if name:
        return OSError(f"{host}: {name}")
    if isinstance(exc, OSError):
        return exc
    return OSError(f"{host}: {type(exc).__name__}: {exc}")


def check_host(host: str) -> str:
    """*host* if it is one host name or address, else ValueError."""
    # One entry, nothing parse_targets would read as a list, a block or a
    # range: no separators, no "/", no all-numeric "a-b".
    if (
        not isinstance(host, str)
        or host != host.strip()
        or any(ord(c) < 32 for c in host)
        or any(c in host for c in " ,;#/")
        or ("-" in host and host.replace(".", "").replace("-", "").isdigit())
    ):
        raise ValueError(f"not a single SMB host: {host!r}")
    try:
        hosts = parse_targets(host, max_hosts=1)
    except TargetError as exc:
        raise ValueError(f"not a single SMB host: {host!r} ({exc})") from exc
    return hosts[0]


def connect(host: str, *, username: str = "", password: str = "", domain: str = "",
            port: int = 445, timeout: float = 10.0):
    """A logged-on impacket SMBConnection to *host*. The caller closes it."""
    host = check_host(host)
    conn_class = _connection_class()
    try:
        conn = conn_class(host, host, sess_port=int(port), timeout=float(timeout))
    except Exception as exc:  # noqa: BLE001 - socket and protocol errors alike
        raise as_os_error(host, exc) from None
    try:
        conn.login(username or "", password or "", domain or "")
    except Exception as exc:  # noqa: BLE001
        _close(conn)
        raise as_os_error(host, exc) from None
    return conn


def _close(conn) -> None:
    try:
        conn.close()
    except Exception as exc:  # noqa: BLE001 - closing a dead session
        log.debug("SMB close failed: %s", exc)


def _text(value) -> str:
    text = value if isinstance(value, str) else str(value)
    return text.rstrip("\x00")


def shares_of(conn) -> list[dict]:
    """``{name, type, comment, special}`` per share of a logged-on connection."""
    out = []
    for share in conn.listShares():
        raw_type = int(share["shi1_type"])
        out.append({
            "name": _text(share["shi1_netname"]),
            "type": _SHARE_TYPES.get(raw_type & _STYPE_MASK, f"Type {raw_type & _STYPE_MASK}"),
            "comment": _text(share["shi1_remark"]),
            "special": bool(raw_type & STYPE_SPECIAL),
        })
    return out


def list_shares(host: str, *, username: str = "", password: str = "", domain: str = "",
                port: int = 445, timeout: float = 10.0) -> list[dict]:
    """The shares *host* publishes: ``{name, type, comment, special}`` each,
    ``type`` one of Disk, Printer, Device, IPC. Anonymous without a user.

    Raises ValueError for a bad host, PermissionError for a refused logon
    (the NT status in the text), OSError when the host cannot be reached.
    """
    conn = connect(host, username=username, password=password, domain=domain,
                   port=port, timeout=timeout)
    try:
        return shares_of(conn)
    except Exception as exc:  # noqa: BLE001
        raise as_os_error(host, exc) from None
    finally:
        _close(conn)
