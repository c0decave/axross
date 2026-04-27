"""WinRM (PowerShell-Remoting) backend implementing FileBackend.

Uses ``pywinrm`` to talk to a Windows host's WSMan endpoint
(default HTTPS:5986, HTTP:5985). Every file operation is a small
PowerShell snippet executed via Invoke-Command/Run; binary IO is
base64-framed inside the script so the SOAP envelope stays text-clean.

Why this matters: many production Windows hosts disable SMB inbound
but keep WinRM open for management, especially in cloud / hardened
environments. Without a backend here the user has to drop into a
real PowerShell session.

Security
--------
PowerShell is a code-execution channel. Every path / argument that
crosses into a script is passed via base64-encoded UTF-8 so a
filename like ``C:\\foo'; rm -rf C:\\``  cannot break out of its
quoting context — the script decodes the base64 INSIDE the runner
and only the decoded bytes ever land in a PowerShell variable.

Not implemented in V1
---------------------
* checksums via Get-FileHash work but the implementation favours
  the cheap-native path; we expose it as ``sha256:<hex>``.
* ``readlink`` returns the path itself (Windows symlinks are rare
  in user-land and need elevated PowerShell to follow reliably).
* ``chmod`` is a no-op — Windows ACLs don't map to POSIX bits and
  applying SetAcl from here would be a footgun.
"""
from __future__ import annotations

import base64
import io
import logging
import posixpath
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


try:
    import winrm  # type: ignore[import-not-found]
    from winrm.exceptions import (  # type: ignore[import-not-found]
        InvalidCredentialsError,
        WinRMTransportError,
    )
except ImportError:  # pragma: no cover — optional dep
    winrm = None  # type: ignore[assignment]
    InvalidCredentialsError = OSError  # type: ignore[assignment,misc]
    WinRMTransportError = OSError  # type: ignore[assignment,misc]


# Cap on a single read_file call. Larger files transit fine through
# WinRM but the base64 round-trip eats RAM on both ends; 32 MiB is
# generous for config / log files and small enough to not OOM the
# remote PS host.
MAX_READ_BYTES = 32 * 1024 * 1024
MAX_WRITE_BYTES = 32 * 1024 * 1024


# --------------------------------------------------------------------------
# PowerShell quoting helper — base64 safety
# --------------------------------------------------------------------------

def _ps_decode(b64: str) -> str:
    """Inline PS expression that decodes a base64 string to UTF-8 text.

    Used inside script bodies so an attacker-controlled path can never
    inject quoting / command-separator characters into the running
    PowerShell — the bytes only ever exist as a variable assignment
    once the snippet is on the remote side.
    """
    return (
        f"[System.Text.Encoding]::UTF8.GetString("
        f"[Convert]::FromBase64String('{b64}'))"
    )


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


# --------------------------------------------------------------------------
# WinRM session
# --------------------------------------------------------------------------

class WinRMSession:
    """PowerShell-Remoting backend (FileBackend protocol).

    Construct one per (host, credentials) tuple. The pywinrm
    Session object is reused across all operations.
    """

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        *,
        port: int = 5986,
        use_https: bool = True,
        transport: str = "ntlm",
        verify_ssl: bool = True,
        operation_timeout_sec: int = 60,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        if winrm is None:
            raise ImportError(
                "WinRM support requires pywinrm. "
                "Install with: pip install axross[winrm]"
            )
        scheme = "https" if use_https else "http"
        self._host = host
        self._username = username
        self._endpoint = f"{scheme}://{host}:{port}/wsman"
        try:
            self._session = winrm.Session(  # type: ignore[union-attr]
                self._endpoint,
                auth=(username, password),
                transport=transport,
                server_cert_validation=("validate" if verify_ssl else "ignore"),
                operation_timeout_sec=operation_timeout_sec,
            )
        except (InvalidCredentialsError, WinRMTransportError, OSError) as exc:
            raise OSError(f"WinRM connect to {host}: {exc}") from exc
        from core.proxy import build_requests_proxies
        proxies = build_requests_proxies(
            proxy_type, proxy_host, int(proxy_port or 0),
            proxy_username, proxy_password,
        )
        self._apply_session_overrides(self._session, proxies)
        # Endpoint goes to INFO (operational); the username is PII —
        # keep it at DEBUG so it doesn't ship to centralised logs by
        # default. Anyone debugging an auth issue can flip the level.
        log.info("WinRM session opened to %s", self._endpoint)
        log.debug("WinRM session user: %s", username)

    @staticmethod
    def _apply_session_overrides(session, proxies: dict | None = None) -> None:
        """Walk pywinrm's ``Session → Protocol → Transport → session``
        chain and override the underlying :class:`requests.Session`:
        uniform ``User-Agent`` (per docs/OPSEC.md #4) and per-profile
        proxy dict if any. Best-effort: silently skipped when pywinrm's
        internal layout changes.
        """
        from core.client_identity import HTTP_USER_AGENT
        try:
            req_session = session.protocol.transport.session
        except AttributeError:
            return
        if req_session is None or not hasattr(req_session, "headers"):
            return
        req_session.headers["User-Agent"] = HTTP_USER_AGENT
        if proxies:
            req_session.proxies = dict(proxies)

    # ------------------------------------------------------------------
    # FileBackend protocol — required surface
    # ------------------------------------------------------------------
    @property
    def name(self) -> str:
        return f"{self._username}@{self._host} (WinRM)"

    def separator(self) -> str:
        return "\\"

    def join(self, *parts: str) -> str:
        if not parts:
            return ""
        # Normalise: forward-slashes → backslashes; drop empty
        # segments so join("C:\\", "", "x") == "C:\\x".
        cleaned: list[str] = []
        for p in parts:
            s = p.replace("/", "\\")
            if s.endswith("\\") and len(s) > 1:
                s = s.rstrip("\\")
            if s:
                cleaned.append(s)
        if not cleaned:
            return ""
        first = cleaned[0]
        rest = "\\".join(cleaned[1:])
        if not rest:
            return first
        return f"{first}\\{rest}" if not first.endswith("\\") else first + rest

    def normalize(self, path: str) -> str:
        return path.replace("/", "\\") if path else path

    def parent(self, path: str) -> str:
        norm = self.normalize(path)
        # ``C:\\`` and ``\\\\server\\share`` are roots — parent of root is itself.
        if len(norm) <= 3 and norm.endswith(":\\"):
            return norm
        norm = norm.rstrip("\\")
        if "\\" not in norm:
            return norm
        return norm.rsplit("\\", 1)[0] or "\\"

    def home(self) -> str:
        # Best effort: ask PS for $HOME. Falls back to C:\Users\<user>.
        try:
            out = self._run_ps("Write-Output $HOME")
            home = out.strip()
            if home:
                return home
        except OSError as exc:
            log.debug("WinRM home(): falling back (%s)", exc)
        return f"C:\\Users\\{self._username}" if self._username else "C:\\"

    # ------------------------------------------------------------------
    # Listing / stat
    # ------------------------------------------------------------------
    def list_dir(self, path: str) -> list[FileItem]:
        path_b64 = _b64(self.normalize(path))
        script = f"""
            $p = {_ps_decode(path_b64)}
            $items = Get-ChildItem -Force -LiteralPath $p -ErrorAction Stop
            $items | ForEach-Object {{
              [PSCustomObject]@{{
                Name = $_.Name
                IsDir = $_.PSIsContainer
                Size = if ($_.PSIsContainer) {{ 0 }} else {{ $_.Length }}
                Mtime = $_.LastWriteTimeUtc.ToString('o')
                IsLink = ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
              }}
            }} | ConvertTo-Json -Compress -Depth 2
        """
        out = self._run_ps(script)
        return [self._parse_listing_row(row) for row in self._parse_json_array(out)]

    def stat(self, path: str) -> FileItem:
        path_b64 = _b64(self.normalize(path))
        script = f"""
            $p = {_ps_decode(path_b64)}
            $item = Get-Item -Force -LiteralPath $p -ErrorAction Stop
            [PSCustomObject]@{{
              Name = $item.Name
              IsDir = $item.PSIsContainer
              Size = if ($item.PSIsContainer) {{ 0 }} else {{ $item.Length }}
              Mtime = $item.LastWriteTimeUtc.ToString('o')
              IsLink = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            }} | ConvertTo-Json -Compress -Depth 2
        """
        out = self._run_ps(script)
        rows = self._parse_json_array(out)
        if not rows:
            raise OSError(f"WinRM stat({path}) returned no data")
        return self._parse_listing_row(rows[0])

    def is_dir(self, path: str) -> bool:
        try:
            return self.stat(path).is_dir
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        path_b64 = _b64(self.normalize(path))
        script = (
            f"if (Test-Path -LiteralPath {_ps_decode(path_b64)}) "
            f"{{ Write-Output 'YES' }} else {{ Write-Output 'NO' }}"
        )
        try:
            out = self._run_ps(script).strip()
        except OSError:
            return False
        return out == "YES"

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    def mkdir(self, path: str) -> None:
        path_b64 = _b64(self.normalize(path))
        script = (
            f"New-Item -ItemType Directory -Force -Path "
            f"{_ps_decode(path_b64)} | Out-Null"
        )
        self._run_ps(script)

    def remove(self, path: str, recursive: bool = False) -> None:
        path_b64 = _b64(self.normalize(path))
        flag = "-Recurse" if recursive else ""
        script = (
            f"Remove-Item -Force {flag} -LiteralPath "
            f"{_ps_decode(path_b64)} -ErrorAction Stop"
        )
        self._run_ps(script)

    def rename(self, src: str, dst: str) -> None:
        # Move-Item handles cross-directory moves on Windows — same
        # contract as our other backends' rename().
        src_b64 = _b64(self.normalize(src))
        dst_b64 = _b64(self.normalize(dst))
        script = (
            f"Move-Item -Force -LiteralPath {_ps_decode(src_b64)} "
            f"-Destination {_ps_decode(dst_b64)} -ErrorAction Stop"
        )
        self._run_ps(script)

    def chmod(self, path: str, mode: int) -> None:
        # Windows ACLs don't map to POSIX bits cleanly; refuse rather
        # than silently no-op so callers know.
        raise OSError("chmod not supported on WinRM backend")

    def readlink(self, path: str) -> str:
        # Reading a NTFS reparse point requires SeBackupPrivilege in
        # the runner; rather than half-implement it, we degrade to
        # "the path itself" when stat says it isn't a link, and
        # OSError when it is. Saves callers from following bogus data.
        item = self.stat(path)
        if not item.is_link:
            raise OSError(f"{path}: not a symlink")
        raise OSError("readlink not implemented for WinRM")

    # ------------------------------------------------------------------
    # IO
    # ------------------------------------------------------------------
    def open_read(self, path: str) -> IO[bytes]:
        path_b64 = _b64(self.normalize(path))
        script = f"""
            $p = {_ps_decode(path_b64)}
            $bytes = [IO.File]::ReadAllBytes($p)
            if ($bytes.Length -gt {MAX_READ_BYTES}) {{
              throw "WinRM open_read: file too large ($($bytes.Length) bytes)"
            }}
            [Convert]::ToBase64String($bytes)
        """
        out = self._run_ps(script).strip()
        try:
            data = base64.b64decode(out, validate=True)
        except Exception as exc:
            raise OSError(f"WinRM open_read({path}): bad base64: {exc}") from exc
        return io.BytesIO(data)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        # Buffer in memory; flush on close. Append semantics are rare
        # in the GUI flow; if the caller asks, we fetch the existing
        # bytes first so the file ends up as old + new.
        backend = self
        buffer = io.BytesIO()
        if append:
            try:
                with self.open_read(path) as fh:
                    buffer.write(fh.read())
            except OSError:
                # File doesn't exist yet — append from empty is fine.
                pass

        class _WinRMWriteHandle(io.BytesIO):
            def close(self_inner) -> None:  # noqa: N805
                if self_inner.closed:
                    return
                data = self_inner.getvalue()
                if len(data) > MAX_WRITE_BYTES:
                    raise OSError(
                        f"WinRM open_write({path}): payload too large "
                        f"({len(data)} > {MAX_WRITE_BYTES})"
                    )
                backend._write_bytes(path, data)
                super().close()

        h = _WinRMWriteHandle(buffer.getvalue())
        h.seek(0, io.SEEK_END)
        return h

    def _write_bytes(self, path: str, data: bytes) -> None:
        path_b64 = _b64(self.normalize(path))
        data_b64 = base64.b64encode(data).decode("ascii")
        # Two-stage: decode the base64 inside PS, then ReadAllBytes-style
        # write. Path goes through _ps_decode for the same anti-injection
        # reason as the other ops.
        script = f"""
            $p = {_ps_decode(path_b64)}
            $bytes = [Convert]::FromBase64String('{data_b64}')
            [IO.File]::WriteAllBytes($p, $bytes)
        """
        self._run_ps(script)

    # ------------------------------------------------------------------
    # Server-side helpers
    # ------------------------------------------------------------------
    def copy(self, src: str, dst: str) -> None:
        src_b64 = _b64(self.normalize(src))
        dst_b64 = _b64(self.normalize(dst))
        script = (
            f"Copy-Item -Force -LiteralPath {_ps_decode(src_b64)} "
            f"-Destination {_ps_decode(dst_b64)} -ErrorAction Stop"
        )
        self._run_ps(script)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        algo = (algorithm or "sha256").upper()
        if algo not in ("SHA1", "SHA256", "SHA384", "SHA512", "MD5"):
            return ""
        path_b64 = _b64(self.normalize(path))
        script = (
            f"(Get-FileHash -Algorithm {algo} -LiteralPath "
            f"{_ps_decode(path_b64)}).Hash"
        )
        try:
            out = self._run_ps(script).strip().lower()
        except OSError:
            return ""
        if not out:
            return ""
        return f"{algo.lower()}:{out}"

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        # Drive-letter lookup via CIM_LogicalDisk. Falls back to
        # (0,0,0) on UNC paths or odd locations — same contract as
        # other backends.
        norm = self.normalize(path)
        if len(norm) < 2 or norm[1] != ":":
            return (0, 0, 0)
        drive = norm[0].upper()
        script = (
            f"$d = Get-PSDrive -Name '{drive}' -ErrorAction Stop;"
            f" Write-Output (\"$($d.Used) $($d.Free)\")"
        )
        try:
            out = self._run_ps(script).strip()
            used_str, free_str = out.split(None, 1)
            used = int(used_str)
            free = int(free_str)
            return (used + free, used, free)
        except (OSError, ValueError):
            return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        # Windows does have Volume Shadow Copy / Previous Versions
        # but exposing them programmatically requires admin VSS calls
        # — out of scope for V1.
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("WinRM backend has no version history")

    # ------------------------------------------------------------------
    # WinRM-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def ps(self, script: str, *,
           stdout_cap: int = 1024 * 1024,
           stderr_cap: int = 64 * 1024) -> "ExecResult":
        """Public PowerShell runner. Returns
        :class:`models.exec_result.ExecResult` (rc/stdout/stderr/
        truncated_*) — same shape as ``axross.exec()`` for SSH.

        ``script`` is the PS body (not a one-liner — multi-line is
        supported and goes through ``run_ps`` directly). Caps clip
        each stream after the byte count; the corresponding
        ``truncated_*`` flag is set when a clip happens.

        Raises ``OSError`` on transport failure; non-zero remote
        rc surfaces as ``ok=False`` on the result (use ``.check()``
        to raise instead)."""
        from models.exec_result import ExecResult
        try:
            result = self._session.run_ps(script)
        except (InvalidCredentialsError, WinRMTransportError) as exc:
            raise OSError(f"WinRM ps transport error: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 — pywinrm raises various
            raise OSError(f"WinRM ps failed: {exc}") from exc
        out = result.std_out or b""
        err = result.std_err or b""
        return ExecResult(
            returncode=int(result.status_code),
            stdout=bytes(out[:stdout_cap]),
            stderr=bytes(err[:stderr_cap]),
            truncated_stdout=len(out) > stdout_cap,
            truncated_stderr=len(err) > stderr_cap,
        )

    def cim_query(self, wql: str, *,
                  namespace: str = "root\\cimv2") -> list[dict]:
        """Run a WQL (WMI Query Language) query via PowerShell's
        ``Get-CimInstance -Query`` and return the result rows as
        dicts (one row per object).

        Refuses single-quote characters in ``wql`` because the query
        is interpolated into a PowerShell single-quoted string and
        a tainted ``'`` would close the string + run arbitrary PS
        cmdlets. Use parameterised values via the WMI metadata
        catalog if you need user input in the query.

        Default namespace is ``root\\cimv2`` (the standard WMI
        namespace); override for ``root\\StandardCimv2`` etc.
        """
        if "'" in wql:
            raise ValueError(
                "WinRM cim_query: single-quote in WQL is refused "
                "(would break out of the PS interpolated string). "
                "Filter clauses with %s placeholders are a follow-up."
            )
        if "\r" in wql or "\n" in wql:
            raise ValueError(
                "WinRM cim_query: WQL must not contain CR/LF"
            )
        if "'" in namespace or "\r" in namespace or "\n" in namespace:
            raise ValueError(
                "WinRM cim_query: invalid characters in namespace"
            )
        # ``ConvertTo-Json -Compress -Depth 4`` so we get parseable
        # output for any nested object. -Depth 4 is enough for the
        # vast majority of CIM classes.
        script = (
            f"$r = Get-CimInstance -Namespace '{namespace}' -Query '{wql}' "
            f"-ErrorAction Stop | ConvertTo-Json -Compress -Depth 4; "
            f"if ($r -is [string]) {{ $r }} else {{ $r -join \"\" }}"
        )
        out = self._run_ps(script)
        if not out.strip():
            return []
        import json as _json
        try:
            data = _json.loads(out)
        except _json.JSONDecodeError as exc:
            raise OSError(
                f"WinRM cim_query: malformed JSON from server: "
                f"{out[:200]!r}"
            ) from exc
        # ConvertTo-Json returns a single object for 1 row, list for N.
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return []

    # ------------------------------------------------------------------
    # PowerShell runner
    # ------------------------------------------------------------------
    def _run_ps(self, script: str) -> str:
        try:
            result = self._session.run_ps(script)
        except (InvalidCredentialsError, WinRMTransportError) as exc:
            raise OSError(f"WinRM transport error: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 — pywinrm raises various
            raise OSError(f"WinRM run_ps failed: {exc}") from exc
        if result.status_code != 0:
            stderr = (result.std_err or b"").decode("utf-8", errors="replace").strip()
            stdout = (result.std_out or b"").decode("utf-8", errors="replace").strip()
            raise OSError(
                f"WinRM ps rc={result.status_code}: "
                f"{stderr or stdout or '<no output>'}"
            )
        return (result.std_out or b"").decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_json_array(raw: str) -> list[dict]:
        """ConvertTo-Json on a single object yields an object, not an
        array. Normalise both shapes to a list."""
        import json
        text = raw.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise OSError(f"WinRM: malformed JSON: {exc}") from exc
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        raise OSError(f"WinRM: unexpected JSON shape: {type(data).__name__}")

    @staticmethod
    def _parse_listing_row(row: dict) -> FileItem:
        mtime_iso = row.get("Mtime") or ""
        try:
            mtime = datetime.fromisoformat(mtime_iso.rstrip("Z"))
        except (ValueError, AttributeError):
            mtime = datetime.fromtimestamp(0)
        return FileItem(
            name=row.get("Name") or "",
            size=int(row.get("Size") or 0),
            modified=mtime,
            is_dir=bool(row.get("IsDir")),
            is_link=bool(row.get("IsLink")),
        )


__all__ = [
    "MAX_READ_BYTES",
    "MAX_WRITE_BYTES",
    "WinRMSession",
]
