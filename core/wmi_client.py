"""WMI/DCOM backend — metadata-only enumeration of Windows file systems.

Uses impacket's DCOM client to query ``Win32_Directory`` and
``CIM_DataFile`` over MS-RPC. Useful when a Windows host has SMB
AND WinRM disabled but leaves DCOM open — common in hardened lab /
pentest scenarios.

Scope (V1)
----------
**Metadata-only.** ``list_dir`` / ``stat`` / ``exists`` work; every
content / mutation entry point raises :class:`OSError` with a clear
"use WinRM or SMB" hint. Reading file bytes via WMI requires
``Win32_Process.Create`` to spawn ``powershell.exe`` and pipe the
content back, which is just WinRM with extra steps; we don't
half-implement it.

Path semantics
--------------
WMI splits a path into three properties:
  * ``Drive``     — ``"C:"``
  * ``Path``      — backslash-bracketed dir, e.g. ``"\\Users\\Marco\\"``
  * ``FileName``  — base name without extension
  * ``Extension`` — extension without dot

The translator ``_split_wmi`` and reassembler ``_compose`` keep the
FileBackend protocol's single-string view consistent with what WMI
expects.

Optional dependency: ``impacket``. Falls back to an explicit
ImportError when missing — there's no graceful degradation since the
DCOM stack is the whole point.
"""

from __future__ import annotations

import errno
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import IO

from core.answer_fields import as_size, as_str
from core.backend import SessionLifecycle
from core.i18n import tr
from models.file_item import FileItem

log = logging.getLogger(__name__)


try:  # pragma: no cover — optional dep
    from impacket.dcerpc.v5.dcom.wmi import (  # type: ignore[import-not-found]
        CLSID_WbemLevel1Login,
        IID_IWbemLevel1Login,
        IWbemLevel1Login,
    )
    from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore[import-not-found]
    from impacket.dcerpc.v5.dtypes import NULL  # type: ignore[import-not-found]

    IMPACKET_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    DCOMConnection = None  # type: ignore[assignment]
    CLSID_WbemLevel1Login = None  # type: ignore[assignment]
    IID_IWbemLevel1Login = None  # type: ignore[assignment]
    IWbemLevel1Login = None  # type: ignore[assignment]
    NULL = None  # type: ignore[assignment]
    IMPACKET_AVAILABLE = False


# DMTF datetime format: YYYYMMDDhhmmss.uuuuuu±UUU (e.g. 20260419103000.000000+000);
# UUU is the offset from UTC in minutes.
_DMTF_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d+)([+-])(\d+)$")


class WmiValueError(OSError, ValueError):
    """A path or WQL value WMI cannot take. An OSError - what every
    caller of a backend handles (a ValueError escaped the pane) - and
    still a ValueError for callers that caught that."""


class WmiLoginRefused(PermissionError):
    """The host refused the DCOM / WMI login. Its text is written for the
    user (core.user_errors shows a ``*Refused`` text unchanged): impacket's
    "rpc_s_access_denied" or "STATUS_LOGON_FAILURE" said nothing about
    what to check."""


#: impacket's words for a refused login (DCE/RPC bind, NTLM, DCOM
#: activation); lower case.
_LOGIN_REFUSED_TEXTS = (
    "rpc_s_access_denied",
    "access_denied",
    "accessdenied",
    "logon_failure",
    "status_account_",
    "password_expired",
    "password_must_change",
)


def _is_wbem_error(exc: BaseException) -> bool:
    """A WMI answer (WBEM_E_*, 0x8004xxxx: an invalid query, a denied
    class) - the connection itself is fine. Anything else (a reset socket,
    RPC_E_DISCONNECTED, a timeout) means the DCOM connection is gone."""
    code = getattr(exc, "error_code", None)
    return isinstance(code, int) and (code & 0xFFFF0000) == 0x80040000


def _parse_dmtf(value: str) -> datetime:
    """Decode a WMI DMTF datetime into an aware datetime.

    The value is the wall clock of the zone its ``±UUU`` suffix names
    (minutes from UTC); dropping the offset handed out that wall clock
    as a naive time, which FileItem reads as the CLIENT's local time.

    Returns ``datetime.fromtimestamp(0)`` when the value is missing
    or malformed — matches the rest of axross's "missing mtime"
    convention.
    """
    if not value:
        return datetime.fromtimestamp(0)
    m = _DMTF_RE.match(value.strip())
    if not m:
        return datetime.fromtimestamp(0)
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    micro = int((m.group(7) + "000000")[:6])
    offset = int(m.group(9)) * (-1 if m.group(8) == "-" else 1)
    try:
        return datetime(y, mo, d, h, mi, s, micro, tzinfo=timezone(timedelta(minutes=offset)))
    except (ValueError, OverflowError):
        return datetime.fromtimestamp(0)


# --------------------------------------------------------------------------
# Path split helpers — pure functions so the tests don't need DCOM
# --------------------------------------------------------------------------


def _normalise(path: str) -> str:
    """Backslash everything, collapse doubled separators, strip
    trailing backslash unless it's a drive root."""
    p = (path or "").replace("/", "\\")
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    if len(p) > 3 and p.endswith("\\"):
        p = p.rstrip("\\")
    return p


def _split_wmi(path: str) -> tuple[str, str, str, str]:
    """Translate a normalised path into WMI's (Drive, Path, FileName,
    Extension). Drive is "C:"; Path is bracketed with backslashes.

    Examples:
      C:\\                       -> ("C:", "\\",                "",     "")
      C:\\Users\\Marco           -> ("C:", "\\Users\\",         "Marco", "")
      C:\\Users\\Marco\\f.txt    -> ("C:", "\\Users\\Marco\\",  "f",    "txt")
    """
    norm = _normalise(path)
    if not norm:
        raise WmiValueError("empty path")
    # Drive prefix.
    if len(norm) < 2 or norm[1] != ":":
        raise WmiValueError(f"WMI path must begin with a drive letter: {path!r}")
    drive = norm[:2].upper()
    rest = norm[2:]  # everything after "C:"
    if not rest or rest == "\\":
        return drive, "\\", "", ""
    # rest begins with "\".  Last component is filename; the rest is path.
    if rest.endswith("\\"):
        rest = rest[:-1]
    head, _, tail = rest.rpartition("\\")
    head = head + "\\" if head else "\\"
    if not tail:
        # Path was just "\\", already handled above; defensive fallback.
        return drive, head, "", ""
    name, _, ext = tail.rpartition(".")
    if name:
        return drive, head, name, ext
    return drive, head, tail, ""


def _wql_escape(value: str) -> str:
    """Escape a value for inlining into a WQL WHERE clause.

    WQL strings are delimited by single quotes; the canonical escape
    is to double a literal quote. We also strip NUL bytes — they're
    invalid in DCOM strings and would either corrupt the query or
    get stripped silently by the runtime.

    Anything that cannot survive escaping (control chars below 0x20
    other than tab/newline/CR) raises ValueError so a hostile
    filename can't pivot the WHERE clause.
    """
    if "\x00" in value:
        raise WmiValueError("WQL value contains NUL byte")
    for ch in value:
        if ord(ch) < 0x20 and ch not in ("\t", "\r", "\n"):
            raise WmiValueError(f"WQL value contains forbidden control char {ch!r}")
    return value.replace("'", "''")


def _wql_literal(value: str) -> str:
    """*value* as a WQL string literal: in double quotes, backslashes
    doubled.

    WQL escapes with a backslash (``\\``, ``\'``); a doubled single
    quote is SQL, not WQL, so ``'C:\\O''Brien'`` was an invalid query and
    a folder with an apostrophe in its name (``Bob's files``) could not be
    listed or opened. A Windows name can never hold a double quote, so a
    double-quoted literal needs no quote escape at all; a value that holds
    one is refused (no such file can exist).
    """
    if '"' in value:
        raise WmiValueError(f"WQL value contains a double quote: {value!r}")
    _wql_escape(value)  # NUL and control characters are refused
    return '"' + value.replace("\\", "\\\\") + '"'


def _compose(drive: str, path: str, name: str, ext: str) -> str:
    """Reverse of :func:`_split_wmi`. Useful for translating WMI
    enumeration rows back into single-string paths."""
    base = f"{drive}{path}"
    if not name:
        return base.rstrip("\\") if base != f"{drive}\\" else base
    file_name = f"{name}.{ext}" if ext else name
    if base.endswith("\\"):
        return base + file_name
    return f"{base}\\{file_name}"


# --------------------------------------------------------------------------
# WMI session
# --------------------------------------------------------------------------


# WBEM_S_FALSE: IEnumWbemClassObject::Next returned fewer objects than
# asked for - the enumeration is over ([MS-WMI] IEnumWbemClassObject::Next). impacket's
# DCE/RPC layer raises it like an error (rpcrt.py: any non-zero status).
_WBEM_S_FALSE = 0x1


def _is_enum_end(exc: Exception) -> bool:
    return getattr(exc, "error_code", None) == _WBEM_S_FALSE or "WBEM_S_FALSE" in str(exc)


class WMISession(SessionLifecycle):
    """DCOM-WMI backend (FileBackend). Metadata-only.

    Construct one per (host, credentials). Lazy-connects on first
    query so unit tests can build a session and patch around the
    DCOM call without standing up a real connection; :meth:`home`
    connects, so Test Connection and a new pane find a refused login.

    One DCOM connection is not safe for two threads at once (a pane's
    listing and a transfer's stat): every connect and query holds the
    session's lock. A connection that broke (not a WMI error answer) is
    torn down, and the next call connects again - a dropped connection
    used to stay cached and fail every call until axross restarted.
    """

    #: Windows keeps "README.txt" and "Readme.txt" as one name
    #: (core.transfer_conflicts.case_insensitive_names).
    case_insensitive_names = True

    _closed = False
    _wbem = None
    _dcom = None

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        *,
        domain: str = "",
        lmhash: str = "",
        nthash: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        from core.proxy import refuse_unsupported_proxy

        refuse_unsupported_proxy(
            "WMI",
            proxy_type,
            proxy_host,
            "WMI/DCOM negotiates dynamic RPC ports after the endpoint mapper, so a single "
            "proxied connection is not enough.",
        )
        if not IMPACKET_AVAILABLE:
            raise ImportError(
                "WMI support requires impacket. Install with: pip install axross[wmi]"
            )
        if not domain and "\\" in username:
            # "DOMAIN\\user" typed into the one user name field.
            domain, username = username.split("\\", 1)
        self._host = host
        self._username = username
        self._password = password
        self._domain = domain
        self._lock = threading.RLock()
        self._lmhash = lmhash
        self._nthash = nthash
        self._dcom = None
        self._wbem = None
        log.info("WMISession created for %s as %s", host, username)

    # ------------------------------------------------------------------
    # FileBackend protocol — required surface
    # ------------------------------------------------------------------
    @property
    def name(self) -> str:
        return f"{self._username}@{self._host} (WMI)"

    @property
    def connected(self) -> bool:
        """False once closed; a broken DCOM connection reconnects on the
        next call by itself."""
        return not self._closed

    def _session_lock(self) -> threading.RLock:
        # Sessions made with __new__ (tests) have no lock from __init__.
        return self.__dict__.setdefault("_lock", threading.RLock())

    def separator(self) -> str:
        return "\\"

    def join(self, *parts: str) -> str:
        cleaned: list[str] = []
        for p in parts:
            s = (p or "").replace("/", "\\")
            if s.endswith("\\") and len(s) > 1:
                s = s.rstrip("\\")
            if s:
                cleaned.append(s)
        if not cleaned:
            return ""
        first = cleaned[0]
        if len(cleaned) == 1:
            return first
        rest = "\\".join(cleaned[1:])
        return first + ("" if first.endswith("\\") else "\\") + rest

    def normalize(self, path: str) -> str:
        return _normalise(path)

    def parent(self, path: str) -> str:
        norm = _normalise(path)
        if len(norm) <= 3 and norm.endswith(":\\"):
            return norm
        if "\\" not in norm[2:]:
            return norm[:2] + "\\"
        return norm.rsplit("\\", 1)[0] or "\\"

    def home(self) -> str:
        """A best guess matching the convention WinRM uses (WMI has no
        $HOME without a query) - after connecting: the guess alone made
        Test Connection succeed with a wrong password or an unreachable
        host, and the pane failed only at its first listing."""
        self._connect()
        user = self._username.split("@", 1)[0] if self._username else ""
        return f"C:\\Users\\{user}" if user else "C:\\"

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------
    def list_dir(self, path: str) -> list[FileItem]:
        norm = _normalise(path)
        try:
            drive = _split_wmi(norm)[0]
        except ValueError as exc:
            raise OSError(f"WMI list_dir({path}): {exc}") from exc
        # WMI's Path of a folder's entries is the folder itself, bracketed
        # with backslashes ("\\Windows\\" for C:\Windows, "\\" for the
        # root). A folder used to be taken for a file here and its PARENT
        # listed (review B1, 2026-10-17); a file or a missing folder is
        # an error, not some other listing.
        rest = norm[2:].rstrip("\\")
        if rest and not self.stat(norm).is_dir:
            raise NotADirectoryError(f"WMI list_dir({path}): not a folder")
        dir_path = rest + "\\" if rest else "\\"
        wbem = self._connect()
        results: list[FileItem] = []
        # Escape every user-derived value before inlining into WQL.
        # WQL has no parameter binding (impacket / WMI), so single-quote
        # doubling is the canonical defence. Doing this server-side
        # would defeat the purpose; doing it here keeps a hostile
        # directory name from pivoting the WHERE clause.
        drive_q = _wql_literal(drive)
        # Backslashes doubled as in stat: WQL string literals escape them.
        dir_q = _wql_literal(dir_path)
        for cls, is_dir in (("Win32_Directory", True), ("CIM_DataFile", False)):
            query = (
                f"SELECT Name, FileName, Extension, FileSize, "
                f"LastModified, Drive, Path FROM {cls} "
                f"WHERE Drive = {drive_q} AND Path = {dir_q}"
            )
            for row in self._exec_query(wbem, query):
                results.append(self._row_to_item(row, is_dir=is_dir))
        return results

    def stat(self, path: str) -> FileItem:
        norm = _normalise(path)
        drive, dir_path, name, ext = _split_wmi(norm)
        # Try CIM_DataFile first; fall back to Win32_Directory.
        wbem = self._connect()
        # WMI Name property uses doubled backslashes in WQL string
        # literals. Escape single quotes too — same WQL-injection
        # mitigation as in list_dir.
        full_name = _wql_literal(norm)
        for cls, is_dir in (("CIM_DataFile", False), ("Win32_Directory", True)):
            query = (
                f"SELECT Name, FileName, Extension, FileSize, "
                f"LastModified, Drive, Path FROM {cls} "
                f"WHERE Name = {full_name}"
            )
            # A row that cannot be read is not "no row": strict.
            rows = list(self._exec_query(wbem, query, strict=True))
            if rows:
                return self._row_to_item(rows[0], is_dir=is_dir)
        raise FileNotFoundError(errno.ENOENT, f"WMI stat({path}): not found", path)

    def is_dir(self, path: str) -> bool:
        """False only when neither WQL class has the path; a failed
        connect or query is an OSError (transfer_manager recurses on
        True)."""
        try:
            return self.stat(path).is_dir
        except FileNotFoundError:
            return False

    def exists(self, path: str) -> bool:
        """False only when both WQL classes answer with no row. A failed
        DCOM connect, a refused or dropped query is an OSError:
        server_side_copy(overwrite=False) takes False as its go-ahead."""
        try:
            self.stat(path)
            return True
        except FileNotFoundError:
            return False

    # ------------------------------------------------------------------
    # Mutation / IO — refused, with pointer to alternatives
    # ------------------------------------------------------------------
    _METADATA_ONLY = (
        "WMI backend is metadata-only — use the WinRM or SMB backend for content read/write."
    )

    def mkdir(self, path: str) -> None:
        raise OSError(self._METADATA_ONLY)

    def remove(self, path: str, recursive: bool = False) -> None:
        raise OSError(self._METADATA_ONLY)

    def rename(self, src: str, dst: str) -> None:
        raise OSError(self._METADATA_ONLY)

    def open_read(self, path: str) -> IO[bytes]:
        raise OSError(self._METADATA_ONLY)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        raise OSError(self._METADATA_ONLY)

    def chmod(self, path: str, mode: int) -> None:
        raise OSError(self._METADATA_ONLY)

    def readlink(self, path: str) -> str:
        raise OSError(self._METADATA_ONLY)

    def copy(self, src: str, dst: str) -> None:
        raise OSError(self._METADATA_ONLY)

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        # Win32_LogicalDisk.FreeSpace and .Size — cheap query.
        norm = _normalise(path)
        if len(norm) < 2 or norm[1] != ":":
            return (0, 0, 0)
        drive = norm[:2].upper()
        try:
            wbem = self._connect()
            query = (
                "SELECT FreeSpace, Size FROM Win32_LogicalDisk "
                f"WHERE DeviceID = {_wql_literal(drive)}"
            )
            rows = list(self._exec_query(wbem, query))
        except OSError:
            return (0, 0, 0)
        if not rows:
            return (0, 0, 0)
        try:
            free = int(rows[0].get("FreeSpace") or 0)
            total = int(rows[0].get("Size") or 0)
            return (total, max(total - free, 0), free)
        except (TypeError, ValueError):
            return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        # Computing a checksum requires reading the file, which we
        # don't do over WMI by design.
        return ""

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("WMI backend has no version history")

    # ------------------------------------------------------------------
    # DCOM plumbing
    # ------------------------------------------------------------------
    def _connect(self):
        with self._session_lock():
            return self._connect_locked()

    def _connect_locked(self):
        if self._wbem is not None:
            return self._wbem
        self._closed = False
        try:
            self._dcom = DCOMConnection(  # type: ignore[misc]
                self._host,
                self._username,
                self._password,
                self._domain,
                self._lmhash,
                self._nthash,
                oxidResolver=True,
            )
            iface = self._dcom.CoCreateInstanceEx(
                CLSID_WbemLevel1Login,
                IID_IWbemLevel1Login,
            )
            login = IWbemLevel1Login(iface)  # type: ignore[misc]
            self._wbem = login.NTLMLogin("//./root/cimv2", NULL, NULL)
            login.RemRelease()
        except Exception as exc:  # noqa: BLE001 — surface to user
            self._teardown()
            if any(t in str(exc).lower() for t in _LOGIN_REFUSED_TEXTS):
                raise WmiLoginRefused(
                    tr("{host} refused the WMI login. Check the user name (DOMAIN\\user), "
                       "the password, and that the account may use WMI remotely (members "
                       "of Administrators can).").format(host=self._host),
                ) from exc
            raise OSError(f"WMI DCOM connect to {self._host}: {exc}") from exc
        return self._wbem

    # ------------------------------------------------------------------
    # WMI-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def cim_query(self, wql: str, *, namespace: str | None = None, limit: int = 1000) -> list[dict]:
        """Run a WQL (WMI Query Language) query and return the
        result rows as dicts ``{property_name: value}``.

        ``namespace`` overrides the default ``//./root/cimv2`` —
        pass e.g. ``"//./root/StandardCimv2"`` for the newer
        CIM-style namespace. Uses impacket's DCOM client.

        Refuses CR/LF in ``wql`` so a tainted argument can't
        smuggle a second WBEM call. There IS no parameter
        binding in WQL (it's a query language without prepared
        statements) — caller is responsible for escaping any
        single-quotes in spliced values.

        ``limit`` caps the row count so a stray
        ``SELECT * FROM Win32_PerfRawData_*`` doesn't drag
        thousands of rows back over DCOM.
        """
        if "\r" in wql or "\n" in wql:
            raise WmiValueError("WMI cim_query: WQL must not contain CR/LF")
        if namespace is not None and ("\r" in namespace or "\n" in namespace):
            raise WmiValueError("WMI cim_query: invalid namespace")
        # Connect using the requested namespace (or fall back to the
        # session's default ``//./root/cimv2``).
        if namespace is None:
            wbem = self._connect()
        else:
            # _connect caches a single namespace; for an off-cimv2
            # namespace we open a fresh login and remember to release.
            wbem = self._connect_namespace(namespace)
        try:
            out = list(self._exec_query(wbem, wql, limit=int(limit)))
        finally:
            if namespace is not None and wbem is not None:
                try:
                    wbem.RemRelease()
                except Exception:  # noqa: BLE001
                    pass
        return out

    def _connect_namespace(self, namespace: str):
        """Open a one-shot WBEM login at ``namespace``. Caller is
        responsible for ``wbem.RemRelease()``."""
        if self._dcom is None:
            self._connect()  # ensures _dcom is up
        try:
            iInterface = self._dcom.CoCreateInstanceEx(
                "8BC3F05E-D86B-11D0-A075-00C04FB68820",
                "9556DC99-828C-11CF-A37E-00AA003240C7",
            )
            login = IWbemLevel1Login(iInterface)
            wbem = login.NTLMLogin(namespace, NULL, NULL)
            login.RemRelease()
            return wbem
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"WMI namespace switch to {namespace}: {exc}") from exc

    def _exec_query(
        self, wbem, query: str, *, strict: bool = False, limit: int | None = None
    ) -> list[dict]:
        """The row dicts {prop_name: value} until the enumerator signals
        end (at most *limit*). Wraps the impacket Next() pattern; read
        whole under the session's lock, so no other thread's call runs on
        the connection in between.

        The end is an empty batch or WBEM_S_FALSE, which impacket raises
        as an error with code 0x1 once fewer objects than asked for are
        left. Any other error of Next() - a dropped connection, an access
        denied - is an OSError: it used to end the rows silently, so a
        cut query read as "no such file". A row whose properties cannot
        be read is skipped, or with *strict* an OSError.

        A failure that is no WMI answer (the connection broke) tears the
        connection down: the next call connects again.
        """
        with self._session_lock():
            try:
                return self._read_rows(wbem, query, strict, limit)
            except OSError as exc:
                cause = exc.__cause__
                if cause is not None and not _is_wbem_error(cause) and wbem is self._wbem:
                    log.info("WMI connection to %s broke (%s); reconnecting on the next call",
                             self._host, cause)
                    self._teardown()
                raise

    @staticmethod
    def _read_rows(wbem, query: str, strict: bool, limit: int | None) -> list[dict]:
        rows: list[dict] = []
        try:
            enumer = wbem.ExecQuery(query)
        except Exception as exc:  # noqa: BLE001
            raise OSError(f"WMI query failed: {exc}") from exc
        try:
            while limit is None or len(rows) < limit:
                try:
                    pairs = enumer.Next(0xFFFFFFFF, 1)
                except Exception as exc:  # noqa: BLE001
                    if _is_enum_end(exc):
                        break
                    raise OSError(f"WMI query failed while reading rows: {exc}") from exc
                if not pairs:
                    break
                obj = pairs[0]
                try:
                    props = obj.getProperties()
                except Exception as exc:  # noqa: BLE001
                    if strict:
                        raise OSError(f"WMI query: unreadable row: {exc}") from exc
                    continue
                # impacket's getProperties returns
                # {prop_name: {'value': ..., ...}}
                rows.append(
                    {k: v.get("value") if isinstance(v, dict) else v for k, v in props.items()}
                )
        finally:
            try:
                enumer.RemRelease()
            except Exception:
                pass
        return rows

    def _teardown(self) -> None:
        try:
            if self._wbem is not None:
                self._wbem.RemRelease()
        except Exception:
            pass
        try:
            if self._dcom is not None:
                self._dcom.disconnect()
        except Exception:
            pass
        self._wbem = None
        self._dcom = None

    def close(self) -> None:
        with self._session_lock():
            self._teardown()
            self._closed = True

    # ------------------------------------------------------------------
    # Row → FileItem
    # ------------------------------------------------------------------
    @staticmethod
    def _row_to_item(row: dict, *, is_dir: bool) -> FileItem:
        # Win32_Directory rows don't have FileName/Extension columns,
        # so we fall back to the basename of Name (the full path).
        # Properties are read with the type they should have: a value of
        # another type (a hostile or broken WMI provider) must not raise
        # AttributeError / ValueError in the pane. FileSize is a CIM
        # uint64, which WMI hands over as a decimal string.
        name = as_str(row.get("FileName"))
        ext = as_str(row.get("Extension"))
        if name:
            display = f"{name}.{ext}" if ext else name
        else:
            full = as_str(row.get("Name"))
            display = full.rsplit("\\", 1)[-1] or full
        return FileItem(
            name=display,
            size=as_size(row.get("FileSize"), digit_strings=True),
            modified=_parse_dmtf(as_str(row.get("LastModified"))),
            is_dir=is_dir,
        )


__all__ = [
    "IMPACKET_AVAILABLE",
    "WMISession",
    "_compose",
    "_normalise",
    "_parse_dmtf",
    "_split_wmi",
    "_wql_escape",
]
