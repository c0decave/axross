"""Find your own files on many SMB hosts with one login - read only.

Operator: *„das hier ist die range, das ist mein
login, bitte suche mir alle meine files dort raus"*. Decided: impacket;
targets are host names, addresses, CIDR blocks and ranges
(:func:`core.net_helpers.parse_targets`, bounded); read only; 4 hosts in
parallel by default, a setting (``remote_sweep_parallel`` in settings.json).

One credential against many hosts can lock a domain account when it is
wrong: lockout policies count failures across the domain. So:

1. The first reachable host is the **canary**: it is logged on to and
   searched alone. A refused logon there ends the run before any other
   host sees the credential. A host that fails before it has judged the
   credential (a reset, a refused dialect) is no canary: the next one is.
2. Then the other hosts, at most ``parallel`` at a time. The first refused
   logon (any status in :data:`core.smb_shares.LOGON_FAILURES`) stops every
   host that has not started yet.

There is one credential per run, never a list. Nothing here writes:
:class:`ReadOnlySmb` has no method that could.
"""

from __future__ import annotations

import fnmatch
import logging
import socket
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from core import open_limits as OL
from core.net_helpers import MAX_TARGET_HOSTS, parse_targets
from core.smb_shares import LOGON_FAILURES, as_os_error, connect, shares_of, status_name

log = logging.getLogger(__name__)

PARALLEL_SETTING = "remote_sweep_parallel"
DEFAULT_PARALLEL = 4
MAX_PARALLEL = 64


def parallel_hosts() -> int:
    """Hosts searched at the same time (settings.json, default 4)."""
    value = OL.read_setting(PARALLEL_SETTING, DEFAULT_PARALLEL)
    if type(value) is int and 1 <= value <= MAX_PARALLEL:
        return value
    return DEFAULT_PARALLEL


def set_parallel_hosts(value: int) -> None:
    if type(value) is not int or not 1 <= value <= MAX_PARALLEL:
        raise ValueError(f"parallel hosts must be a whole number from 1 to {MAX_PARALLEL}, not {value!r}")
    OL.write_setting(PARALLEL_SETTING, value)


@dataclass
class SweepConfig:
    targets: str
    username: str
    password: str = field(repr=False)
    domain: str = ""
    #: None: the setting (parallel_hosts()).
    parallel: int | None = None
    #: Glob on the file name, case-insensitive; "" matches every file.
    name: str = ""
    #: Only files whose owner is the logged-on account.
    owner_only: bool = False
    #: Also the hidden admin shares (C$, ADMIN$ ...). IPC$ never.
    include_special: bool = False
    max_depth: int = 12
    max_files_per_host: int = 10_000
    #: Folder entries listed per host before its walk stops (a huge or
    #: hostile share with endless folders).
    max_entries_per_host: int = 1_000_000
    max_hosts: int = MAX_TARGET_HOSTS
    port: int = 445
    timeout: float = 15.0
    reachable_timeout: float = 1.0

    def __post_init__(self) -> None:
        if self.parallel is None:
            self.parallel = parallel_hosts()
        if type(self.parallel) is not int or not 1 <= self.parallel <= MAX_PARALLEL:
            raise ValueError(f"parallel must be 1..{MAX_PARALLEL}, not {self.parallel!r}")
        if type(self.max_entries_per_host) is not int or self.max_entries_per_host < 1:
            raise ValueError(f"max_entries_per_host must be a positive whole number, "
                             f"not {self.max_entries_per_host!r}")


@dataclass(frozen=True)
class SweepHit:
    host: str
    share: str
    path: str  # "/" separated, from the share root
    size: int
    mtime: float
    owner_sid: str = ""

    @property
    def unc(self) -> str:
        return "\\\\" + self.host + "\\" + self.share + self.path.replace("/", "\\")


@dataclass
class SweepResult:
    hosts_total: int = 0
    hosts_searched: int = 0
    hosts_unreachable: int = 0
    hosts_failed: int = 0
    hits: int = 0
    truncated: bool = False
    aborted: bool = False
    abort_reason: str = ""
    cancelled: bool = False


#: A junction or symlink ([MS-FSCC] 2.6).
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class LogonRefused(PermissionError):
    """The credential was refused: the run must stop."""


class ReadOnlySmb:
    """The few read operations a sweep needs on one host, over impacket.
    There is deliberately no write, delete, rename or upload here."""

    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._conn = None

    def login(self, username: str, password: str, domain: str) -> None:
        self._conn = connect(self.host, username=username, password=password, domain=domain,
                             port=self.port, timeout=self.timeout)
        self._username, self._domain = username, domain

    def disk_shares(self, include_special: bool = False) -> list[str]:
        return [
            s["name"] for s in shares_of(self._conn)
            if s["type"] == "Disk" and (include_special or not s["special"])
        ]

    def list_dir(self, share: str, path: str) -> list[tuple[str, bool, int, float]]:
        pattern = path.rstrip("/").replace("/", "\\") + "\\*"
        out = []
        for entry in self._conn.listPath(share, pattern):
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            if entry.is_directory() and int(entry.get_attributes()) & FILE_ATTRIBUTE_REPARSE_POINT:
                continue  # a junction or folder symlink: never followed (no loops)
            out.append((name, bool(entry.is_directory()), int(entry.get_filesize()),
                        float(entry.get_mtime_epoch())))
        return out

    def owner_sid(self, share: str, path: str) -> str:
        """The owner SID of *path* (SMB2/3 QUERY_INFO SECURITY on a
        READ_CONTROL handle)."""
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR  # type: ignore[import-not-found]
        from impacket.smb3structs import (  # type: ignore[import-not-found]
            FILE_OPEN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SMB2_0_INFO_SECURITY,
        )

        READ_CONTROL = 0x00020000
        OWNER_SECURITY_INFORMATION = 0x00000001
        conn = self._conn
        tree = conn.connectTree(share)
        try:
            fid = conn.openFile(
                tree, path.lstrip("/").replace("/", "\\"), desiredAccess=READ_CONTROL,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationDisposition=FILE_OPEN,
            )
            try:
                raw = conn.getSMBServer().queryInfo(
                    tree, fid, infoType=SMB2_0_INFO_SECURITY, fileInfoClass=0,
                    additionalInformation=OWNER_SECURITY_INFORMATION,
                )
            finally:
                conn.closeFile(tree, fid)
        finally:
            conn.disconnectTree(tree)
        sd = SR_SECURITY_DESCRIPTOR(data=raw)
        return sd["OwnerSid"].formatCanonical() if sd["OwnerSid"] else ""

    def user_sid(self) -> str:
        """The logged-on account's SID, looked up on this host (LSARPC)."""
        from impacket.dcerpc.v5 import lsad, lsat, transport  # type: ignore[import-not-found]
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED  # type: ignore[import-not-found]

        rpc = transport.SMBTransport(self.host, self.port, r"\lsarpc", smb_connection=self._conn)
        dce = rpc.get_dce_rpc()
        dce.connect()
        try:
            dce.bind(lsat.MSRPC_UUID_LSAT)
            policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)["PolicyHandle"]
            name = f"{self._domain}\\{self._username}" if self._domain else self._username
            resp = lsat.hLsarLookupNames(dce, policy, (name,))
            sid = resp["TranslatedSids"]["Sids"][0]
            domain_sid = resp["ReferencedDomains"]["Domains"][sid["DomainIndex"]]["Sid"].formatCanonical()
            return f"{domain_sid}-{sid['RelativeId']}"
        finally:
            dce.disconnect()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception as exc:  # noqa: BLE001 - closing a dead session
                log.debug("sweep: close %s failed: %s", self.host, exc)
            self._conn = None


def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _is_logon_failure(exc: BaseException) -> bool:
    if isinstance(exc, LogonRefused):
        return True
    text = str(exc)
    return status_name(exc) in LOGON_FAILURES or any(s in text for s in LOGON_FAILURES)


def _safe_detail(exc: BaseException, config: SweepConfig) -> str:
    """An error for the status line, with the password cut out should a
    library ever put it into its text."""
    text = str(exc) or type(exc).__name__
    if config.password:
        text = text.replace(config.password, "***")
    return text


def sweep(
    config: SweepConfig,
    *,
    on_hit: Callable[[SweepHit], None],
    on_status: Callable[..., None],
    connect: Callable | None = None,
    reachable: Callable[[str, int, float], bool] | None = None,
    cancel: threading.Event | None = None,
) -> SweepResult:
    """Search every target of *config*; calls *on_hit* per file found and
    ``on_status(host, state, detail)`` with state one of ``unreachable``,
    ``searching``, ``done``, ``error``, ``skipped``. Returns the summary.

    Raises :class:`core.net_helpers.TargetError` for a bad target list and
    PermissionError in paranoid security mode, before any connection.
    """
    from core import security_mode as SM

    SM.require("network sweeps (one login against many hosts)", SM.current_policy().allow_network_sweep)
    hosts = parse_targets(config.targets, max_hosts=config.max_hosts)
    connect = connect or (lambda h, port, timeout: ReadOnlySmb(h, port, timeout))
    reachable = reachable or port_open
    cancel = cancel or threading.Event()
    stop = threading.Event()  # set on a logon failure
    result = SweepResult(hosts_total=len(hosts))
    lock = threading.Lock()
    name_glob = config.name.lower()
    logged_on: set[str] = set()  # hosts that accepted the credential

    def emit(hit: SweepHit) -> None:
        with lock:
            result.hits += 1
        on_hit(hit)

    def search_host(host: str) -> None:
        """One host from logon to the last directory. Raises LogonRefused."""
        session = connect(host, config.port, config.timeout)
        try:
            try:
                session.login(config.username, config.password, config.domain)
            except Exception as exc:  # noqa: BLE001
                if _is_logon_failure(exc):
                    raise LogonRefused(f"{host}: {status_name(exc) or _safe_detail(exc, config)}") from None
                raise
            with lock:
                logged_on.add(host)
            on_status(host, "searching", "")
            mine = session.user_sid() if config.owner_only else ""
            found = 0
            listed = 0
            for share in session.disk_shares(config.include_special):
                stack = [("/", 0)]
                while stack:
                    if cancel.is_set() or stop.is_set():
                        return
                    path, depth = stack.pop()
                    try:
                        entries = session.list_dir(share, path)
                    except Exception as exc:  # noqa: BLE001 - one folder, not the host
                        on_status(host, "error", f"{share}{path}: {_safe_detail(as_os_error(host, exc), config)}")
                        continue
                    listed += len(entries)
                    if listed > config.max_entries_per_host:
                        with lock:
                            result.truncated = True
                        on_status(host, "error",
                                  f"stopped after {config.max_entries_per_host} entries")
                        return
                    for name, is_dir, size, mtime in sorted(entries):
                        full = path.rstrip("/") + "/" + name
                        if is_dir:
                            if depth + 1 < config.max_depth:
                                stack.append((full, depth + 1))
                            continue
                        if name_glob and not fnmatch.fnmatch(name.lower(), name_glob):
                            continue
                        owner = ""
                        if config.owner_only:
                            try:
                                owner = session.owner_sid(share, full)
                            except Exception as exc:  # noqa: BLE001
                                log.debug("sweep: owner of %s%s on %s: %s", share, full, host, exc)
                                continue
                            if owner != mine:
                                continue
                        if found >= config.max_files_per_host:
                            with lock:
                                result.truncated = True
                            return
                        found += 1
                        emit(SweepHit(host, share, full, int(size), float(mtime), owner))
        finally:
            session.close()

    def unreachable(host: str) -> bool:
        if reachable(host, config.port, config.reachable_timeout):
            return False
        with lock:
            result.hosts_unreachable += 1
        on_status(host, "unreachable", "")
        return True

    def search_counted(host: str) -> None:
        """search_host with the bookkeeping; a refused logon stops the run."""
        try:
            search_host(host)
        except LogonRefused as exc:
            with lock:
                if not result.aborted:
                    result.aborted = True
                    result.abort_reason = str(exc)
            stop.set()
            on_status(host, "error", str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - one host, not the run
            with lock:
                result.hosts_failed += 1
            on_status(host, "error", _safe_detail(as_os_error(host, exc), config))
            return
        with lock:
            result.hosts_searched += 1
        on_status(host, "done", "")

    def run_one(host: str) -> None:
        if cancel.is_set() or stop.is_set():
            on_status(host, "skipped", "")
            return
        if not unreachable(host):
            search_counted(host)

    # The canary: hosts in order, searched alone, until one has judged the
    # credential - accepted it, or refused it (which stops the run). A host
    # that failed before the logon (a reset, a dialect it refuses) said
    # nothing about the credential, so the next host is the canary.
    rest = list(hosts)
    while rest and not cancel.is_set() and not stop.is_set():
        host = rest.pop(0)
        if unreachable(host):
            continue
        search_counted(host)
        if host in logged_on:
            break
    if rest and not stop.is_set() and not cancel.is_set():
        with ThreadPoolExecutor(max_workers=config.parallel, thread_name_prefix="axross-sweep") as pool:
            for future in [pool.submit(run_one, host) for host in rest]:
                future.result()
    else:
        for host in rest:
            on_status(host, "skipped", "")
    result.cancelled = cancel.is_set()
    return result

