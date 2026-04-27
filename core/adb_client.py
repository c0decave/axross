"""ADB (Android Debug Bridge) backend over pure Python.

Talks the ADB wire protocol directly via the ``adb-shell`` library —
no external ``adb`` binary needed. Two transport modes:

* **TCP** (preferred): the device has ``adb tcpip 5555`` enabled
  and we connect to ``host:port``. Works over Wi-Fi, USB-over-IP,
  etc. Primary mode; the connection dialog defaults to this.
* **USB**: direct libusb transport with an optional serial filter.
  Works for a USB-cable-attached device without a running adb
  daemon. Requires udev rules allowing the current user raw USB
  access on the phone's vendor/product id — on Linux this usually
  means the ``plugdev`` group plus a ``51-android.rules`` file.

Auth
----
ADB uses RSA-based auth. The phone's first connection prompts the
user to "Allow USB debugging from this computer?". The keypair lives
at ``~/.android/adbkey`` (private) + ``~/.android/adbkey.pub``; the
backend generates one on first use when missing. Once the phone has
recorded the fingerprint the subsequent connects are non-interactive.

FileBackend surface
-------------------
Every operation flows through ``shell()`` (for metadata / mutations)
or ``push`` / ``pull`` (for content transfer). The protocol doesn't
expose a random-access IO primitive — ``open_read`` / ``open_write``
therefore go through a per-call local tempfile that the transfer is
streamed into. Good enough for transfer-manager workflows; editors
that write byte-ranges on the remote file should use buffer mode
semantics (a full write replaces the remote file).

Not supported on V1
-------------------
* symlinks / hardlinks — ADB shell on most Android images doesn't
  expose ``ln``; the backend flags ``supports_*=False`` so the UI
  hides the menu entries.
* ``list_versions`` — no version history concept.
* ``disk_usage`` — returns (0, 0, 0). ``df`` is available on Android
  shells but the output format varies wildly; skip until asked.
"""
from __future__ import annotations

import io
import logging
import os
import shlex
import stat as stat_module
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import IO

from models.file_item import FileItem

log = logging.getLogger("core.adb_client")


try:  # pragma: no cover — optional dep
    from adb_shell.adb_device import AdbDeviceTcp, AdbDeviceUsb  # type: ignore[import-not-found]
    from adb_shell.auth.sign_pythonrsa import PythonRSASigner  # type: ignore[import-not-found]
    from adb_shell.auth.keygen import keygen  # type: ignore[import-not-found]
    ADB_SHELL_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    AdbDeviceTcp = None  # type: ignore[assignment]
    AdbDeviceUsb = None  # type: ignore[assignment]
    PythonRSASigner = None  # type: ignore[assignment]
    keygen = None  # type: ignore[assignment]
    ADB_SHELL_AVAILABLE = False


# Default path for the ADB RSA keypair. Matches what the system
# ``adb`` binary uses so the user doesn't get a second "allow
# debugging" prompt from our backend after having already approved
# the CLI tool.
DEFAULT_ADB_KEY_PATH = os.path.expanduser("~/.android/adbkey")

# Wall-clock ceiling for connect(). Phones sometimes take a few
# seconds to accept the authentication prompt; 15s is generous
# without being painful on a dead endpoint.
DEFAULT_CONNECT_TIMEOUT = 15.0

# Default transport timeout per primitive (list_dir, push/pull
# chunk). 30 s covers slow WAN links; lower defaults are unfriendly
# to over-the-air connections.
DEFAULT_TRANSPORT_TIMEOUT = 30.0


def is_available() -> bool:
    """True iff ``adb-shell`` is importable AND a reasonable auth
    keypair exists / can be generated."""
    return ADB_SHELL_AVAILABLE


def ensure_adb_key(path: str = DEFAULT_ADB_KEY_PATH) -> str:
    """Ensure an ADB RSA keypair exists at *path*. Creates one with
    ``adb_shell.auth.keygen.keygen`` if missing. Returns the path
    (useful for downstream logging). Refuses to overwrite an
    existing key — the ADB fingerprint on the phone ties to the
    specific public key, and rotating it silently would force the
    user to re-accept debugging from scratch.

    Security details:

    * The enclosing ``~/.android`` directory is created mode 0o700.
    * ``keygen`` is called inside an ``os.umask(0o077)`` bracket so
      the private key file is never briefly world-readable between
      write and chmod. (The previous flow relied on a follow-up
      chmod, which left a TOCTOU window for another local process
      to race the read.)
    * An explicit ``os.chmod(path, 0o600)`` runs after keygen and
      re-raises on failure — better to refuse to return the key
      than return one with unsafe perms a caller might sign with.
    * An EXISTING key with unsafe perms (e.g. copied in from a
      git checkout) is flagged loudly rather than silently trusted.
    """
    if not ADB_SHELL_AVAILABLE:
        raise RuntimeError(
            "adb-shell not installed — pip install adb-shell",
        )
    if os.path.exists(path):
        # Defensive: reject pre-existing keys with world/group
        # readable bits. Adversary could have planted a key they
        # control, forcing a MITM on every subsequent ADB session.
        try:
            st = os.stat(path)
        except OSError as exc:
            raise OSError(
                f"ADB key at {path!r}: cannot stat: {exc}",
            ) from exc
        if st.st_mode & 0o077:
            raise PermissionError(
                f"ADB key {path!r} has unsafe permissions "
                f"(mode={oct(st.st_mode & 0o777)}); "
                f"run `chmod 0600 {path}` before continuing",
            )
        return path
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True, mode=0o700)
    # Tighten umask BEFORE keygen so the private half is never
    # briefly readable between write and chmod. Restore in finally
    # so we don't accidentally leak the restricted umask to
    # unrelated code paths elsewhere in the process.
    old_umask = os.umask(0o077)
    try:
        keygen(path)  # type: ignore[misc]
    finally:
        os.umask(old_umask)
    # Explicit chmod — let OSError propagate. A key with 0o644
    # perms on a shared filesystem is strictly worse than no key
    # at all; refuse rather than silently continue.
    os.chmod(path, 0o600)
    # Identity hygiene: adb_shell.auth.keygen writes the .pub file
    # with a trailing comment that can include ``user@hostname`` (or
    # an upstream-chosen default like ``unknown@unknown``). The
    # comment is shipped to the phone verbatim on first pairing and
    # persists in /data/misc/adb/adb_keys. Strip it to the canonical
    # two-token form so the workstation identity doesn't leak.
    # See docs/OPSEC.md finding #8.
    pub_path = path + ".pub"
    try:
        with open(pub_path, "rb") as fh:
            pub_raw = fh.read().strip()
        tokens = pub_raw.split(None, 2)
        if len(tokens) >= 2:
            scrubbed = b" ".join(tokens[:2]) + b"\n"
            if scrubbed != pub_raw + b"\n":
                with open(pub_path, "wb") as fh:
                    fh.write(scrubbed)
                os.chmod(pub_path, 0o644)
    except OSError as exc:
        log.warning("Could not scrub ADB pub-key comment at %r: %s", pub_path, exc)
    return path


def _load_signer(path: str = DEFAULT_ADB_KEY_PATH) -> "PythonRSASigner":
    """Load the RSA signer for an existing keypair. Raises OSError
    when the pub key is missing — callers should call
    :func:`ensure_adb_key` first.
    """
    pub_path = path + ".pub"
    try:
        with open(path, "r", encoding="utf-8") as f:
            priv = f.read()
        with open(pub_path, "r", encoding="utf-8") as f:
            pub = f.read()
    except OSError as exc:
        raise OSError(
            f"ADB keypair unreadable at {path!r} (+.pub): {exc}",
        ) from exc
    return PythonRSASigner(pub, priv)  # type: ignore[misc]


# --------------------------------------------------------------------------
# Listing parser — ``ls -la`` shell output
# --------------------------------------------------------------------------


# ``ls -la`` on Android's toybox emits lines like:
#   drwxrwx--x 5 system system 3452 2026-04-20 14:02 Download
#   -rw-rw---- 1 u0_a123 u0_a123 98765 2025-12-01 03:11 photo.jpg
#   lrwxrwxrwx 1 root root 11 1971-01-01 00:00 sdcard -> /storage/self/primary
# The leading "total N" line is skipped. Other quirks:
#   * toybox emits 7 fixed columns + name; the name may contain spaces
#   * some Android builds use ``-h`` for bigger sizes (rare)
# Regex captures the whole mode + numeric size + "YYYY-MM-DD HH:MM"
# + the remainder (name, possibly containing " -> target" for links).
_LS_LINE_RE = None  # lazily compiled — import-time re isn't hot enough
# to matter AND keeps the module's import surface small.


def _compile_ls_re():
    global _LS_LINE_RE
    if _LS_LINE_RE is None:
        import re
        _LS_LINE_RE = re.compile(
            r"^(?P<mode>[bcdlps-][rwxstST-]{9})\s+"
            r"(?P<links>\d+)\s+"
            r"(?P<user>\S+)\s+"
            r"(?P<group>\S+)\s+"
            r"(?P<size>\d+)\s+"
            r"(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+"
            r"(?P<name>.+?)$"
        )
    return _LS_LINE_RE


def _parse_ls_line(line: str) -> FileItem | None:
    """Parse one ``ls -la`` output line into a FileItem. Returns
    None for ``total N`` or otherwise unparseable lines so the
    caller can skip silently rather than crash on a weird format.
    """
    line = line.rstrip()
    if not line or line.startswith("total "):
        return None
    m = _compile_ls_re().match(line)
    if m is None:
        log.debug("ADB ls: unparseable line %r", line)
        return None
    mode = m.group("mode")
    is_dir = mode.startswith("d")
    is_link = mode.startswith("l")
    name = m.group("name")
    link_target = ""
    if is_link and " -> " in name:
        name, _, link_target = name.partition(" -> ")
    # Android's ``ls -la`` without --full-time omits seconds.
    try:
        modified = datetime.strptime(m.group("date"), "%Y-%m-%d %H:%M")
    except ValueError:
        modified = datetime.fromtimestamp(0)
    return FileItem(
        name=name,
        size=int(m.group("size")),
        modified=modified,
        is_dir=is_dir,
        is_link=is_link,
        link_target=link_target,
    )


# --------------------------------------------------------------------------
# Writer wrapper — buffers writes to a local tempfile, push on close
# --------------------------------------------------------------------------


class _AdbPushOnClose:
    """File-like writer that buffers to a local temp file and pushes
    to the device on ``close()``. Supports the same cancel /
    discard / seekable=False shape as the other backends' spool
    writers."""

    def __init__(self, session: "AdbSession", remote_path: str):
        self._session = session
        self._remote_path = remote_path
        import tempfile
        self._tmp = tempfile.NamedTemporaryFile(
            prefix="axross-adb-", delete=False, mode="w+b",
        )
        self._tmp_path = self._tmp.name
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("ADB writer already closed")
        return self._tmp.write(data)

    def flush(self) -> None:
        self._tmp.flush()

    def tell(self) -> int:
        return self._tmp.tell()

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._tmp.flush()
        finally:
            self._tmp.close()
        try:
            self._session._push_file(self._tmp_path, self._remote_path)
        finally:
            try:
                os.unlink(self._tmp_path)
            except OSError:
                pass

    def discard(self) -> None:
        """Drop buffered bytes without pushing (transfer cancel)."""
        if self._closed:
            return
        self._closed = True
        try:
            self._tmp.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            os.unlink(self._tmp_path)
        except OSError:
            pass

    def __enter__(self) -> "_AdbPushOnClose":
        return self

    def __exit__(self, *exc_info) -> bool:
        self.close()
        return False


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------


class AdbSession:
    """Android device exposed as a FileBackend via ADB.

    Construct with TCP args (host + port) OR USB args
    (usb=True, usb_serial=... optional). One or the other.
    """

    # ADB shell on most Android images doesn't ship with ln / ln -s
    # as a first-class utility. Rather than pretending and failing
    # at action time, flag False so the UI hides the menu entries.
    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str = "",
        port: int = 5555,
        *,
        usb: bool = False,
        usb_serial: str = "",
        adb_key_path: str = DEFAULT_ADB_KEY_PATH,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        transport_timeout: float = DEFAULT_TRANSPORT_TIMEOUT,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ) -> None:
        if not ADB_SHELL_AVAILABLE:
            raise ImportError(
                "ADB support requires adb-shell. Install with: "
                "pip install adb-shell",
            )
        if not usb and not host:
            raise ValueError(
                "AdbSession: one of (usb=True, host=…) must be given",
            )
        self._usb = bool(usb)
        self._usb_serial = usb_serial
        self._host = host
        self._port = port
        self._transport_timeout = transport_timeout
        self._conn_lock = threading.Lock()
        ensure_adb_key(adb_key_path)
        self._signer = _load_signer(adb_key_path)
        from core.proxy import ProxyConfig, patched_create_connection
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )
        if self._usb:
            if self._proxy.enabled:
                raise OSError(
                    "ADB USB mode does not use TCP — proxy_* fields are "
                    "incompatible with usb=True; remove the proxy or "
                    "switch to TCP mode.",
                )
            self._device = AdbDeviceUsb(  # type: ignore[misc]
                serial=usb_serial or None,
                default_transport_timeout_s=transport_timeout,
            )
            self._label = f"USB {usb_serial or 'first'}"
        else:
            self._device = AdbDeviceTcp(  # type: ignore[misc]
                host, port,
                default_transport_timeout_s=transport_timeout,
            )
            self._label = f"{host}:{port}"
        try:
            # adb_shell.transport.tcp_transport.TcpTransport.connect()
            # uses ``socket.create_connection`` under the hood. The
            # patched_create_connection scope routes that through the
            # SOCKS / HTTP proxy. After connect returns, the socket is
            # owned by adb_shell and stays patched — but the patch
            # reverts here, which is fine because subsequent IO
            # reuses the existing socket directly.
            with patched_create_connection(self._proxy):
                self._device.connect(
                    rsa_keys=[self._signer],
                    auth_timeout_s=connect_timeout,
                )
        except Exception as exc:
            raise OSError(
                f"ADB connect to {self._label} failed: {exc}",
            ) from exc
        log.info("AdbSession opened: %s", self._label)

    # ------------------------------------------------------------------
    # FileBackend identity / traversal
    # ------------------------------------------------------------------
    @property
    def name(self) -> str:
        return f"ADB: {self._label}"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [str(p).strip("/") for p in parts if p is not None]
        cleaned = [p for p in cleaned if p]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        norm = path.replace("\\", "/")
        # Preserve a leading slash; strip duplicate separators and
        # trailing slashes (except when the whole path IS "/").
        out = "/" + "/".join(p for p in norm.split("/") if p)
        return out or "/"

    def parent(self, path: str) -> str:
        norm = self.normalize(path)
        if norm == "/":
            return "/"
        return norm.rsplit("/", 1)[0] or "/"

    def home(self) -> str:
        # /sdcard is the canonical landing for user-accessible data
        # on every Android version since the API 4 release. Apps
        # don't see it directly but the shell bind-mounts it to
        # /storage/self/primary — /sdcard is the friendlier UX.
        return "/sdcard"

    # ------------------------------------------------------------------
    # Shell helpers
    # ------------------------------------------------------------------
    def _shell(self, cmd: str) -> str:
        """Run *cmd* on the device and return stdout. Raises OSError
        on transport failure. Non-zero shell exit does NOT raise —
        Android's adb shell doesn't reliably propagate exit codes
        through the wire; callers distinguish empty results from
        failures by content."""
        try:
            with self._conn_lock:
                return self._device.shell(
                    cmd,
                    transport_timeout_s=self._transport_timeout,
                )
        except Exception as exc:
            raise OSError(
                f"ADB shell({cmd[:60]!r}) on {self._label}: {exc}",
            ) from exc

    def _shell_q(self, path: str) -> str:
        """Shell-quote *path* for embedding in a shell command. We
        use shlex.quote which is safe against filename metachars
        AND against path traversal at the wire layer (the quoted
        form prevents glob / eval expansion).
        """
        return shlex.quote(path)

    # ------------------------------------------------------------------
    # Listing / stat
    # ------------------------------------------------------------------
    def list_dir(self, path: str) -> list[FileItem]:
        out = self._shell(f"ls -la {self._shell_q(path)}")
        items: list[FileItem] = []
        for line in out.splitlines():
            fi = _parse_ls_line(line)
            if fi is None:
                continue
            if fi.name in (".", ".."):
                continue
            items.append(fi)
        return items

    def stat(self, path: str) -> FileItem:
        # Use ``ls -la -d <path>`` — -d prevents directories from
        # expanding their contents.
        out = self._shell(f"ls -la -d {self._shell_q(path)}")
        for line in out.splitlines():
            fi = _parse_ls_line(line)
            if fi is None:
                continue
            # ls -d echoes the path as the name; reduce to basename
            # so callers comparing against FileItem.name aren't
            # surprised by a leading slash. FileItem is frozen — we
            # can't mutate, so rebuild with the name replaced.
            from dataclasses import replace
            return replace(
                fi,
                name=os.path.basename(path.rstrip("/")) or path,
            )
        raise OSError(f"ADB stat({path}): not found")

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

    # ------------------------------------------------------------------
    # IO
    # ------------------------------------------------------------------
    def open_read(self, path: str) -> IO[bytes]:
        """Pull *path* to a tempfile and return an open handle to
        it. The caller is responsible for closing — we clean the
        tempfile via a small wrapper that unlinks on close.
        """
        import tempfile as _tf

        local = _tf.NamedTemporaryFile(
            prefix="axross-adb-", delete=False, mode="w+b",
        )
        local_path = local.name
        local.close()
        try:
            with self._conn_lock:
                self._device.pull(path, local_path)
        except Exception as exc:
            try:
                os.unlink(local_path)
            except OSError:
                pass
            raise OSError(
                f"ADB pull({path}) from {self._label}: {exc}",
            ) from exc
        return _CleanupOnClose(open(local_path, "rb"), local_path)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            raise OSError(
                "ADB open_write: append mode is not supported — "
                "Android shell has no wire-level append primitive; "
                "writes are full-file replacements",
            )
        return _AdbPushOnClose(self, path)

    def _push_file(self, local_path: str, remote_path: str) -> None:
        """Push *local_path* to *remote_path* on the device. Used by
        :class:`_AdbPushOnClose` on flush/close."""
        try:
            with self._conn_lock:
                self._device.push(local_path, remote_path)
        except Exception as exc:
            raise OSError(
                f"ADB push({remote_path}) to {self._label}: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    def remove(self, path: str, recursive: bool = False) -> None:
        flag = "-rf" if recursive else "-f"
        out = self._shell(f"rm {flag} {self._shell_q(path)}")
        if out.strip():
            # rm on Android's toybox is quiet on success; any output
            # indicates a refusal.
            raise OSError(f"ADB rm({path}): {out.strip()}")

    def mkdir(self, path: str) -> None:
        out = self._shell(f"mkdir {self._shell_q(path)}")
        if out.strip():
            raise OSError(f"ADB mkdir({path}): {out.strip()}")

    def rename(self, src: str, dst: str) -> None:
        out = self._shell(
            f"mv {self._shell_q(src)} {self._shell_q(dst)}",
        )
        if out.strip():
            raise OSError(f"ADB mv({src}→{dst}): {out.strip()}")

    def chmod(self, path: str, mode: int) -> None:
        # Android's shell ``chmod`` accepts symbolic AND octal; stick
        # to octal for predictability.
        out = self._shell(
            f"chmod {oct(mode)[2:]} {self._shell_q(path)}",
        )
        if out.strip():
            raise OSError(f"ADB chmod({path}): {out.strip()}")

    def readlink(self, path: str) -> str:
        out = self._shell(f"readlink {self._shell_q(path)}").strip()
        if not out:
            raise OSError(f"ADB readlink({path}): not a symlink or missing")
        return out

    def copy(self, src: str, dst: str) -> None:
        out = self._shell(
            f"cp {self._shell_q(src)} {self._shell_q(dst)}",
        )
        if out.strip():
            raise OSError(f"ADB cp({src}→{dst}): {out.strip()}")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        # df output format on Android varies; return zeros rather
        # than lying about the numbers.
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        tool = {
            "sha256": "sha256sum",
            "sha1": "sha1sum",
            "md5": "md5sum",
        }.get(algorithm)
        if tool is None:
            return ""
        out = self._shell(
            f"{tool} {self._shell_q(path)}",
        ).strip()
        if not out:
            return ""
        # `sha256sum` prints "<hex>  <path>" — keep just the hex.
        first = out.split()[0]
        # Sanity: hex only, correct length for the algorithm.
        expected_len = {"sha256": 64, "sha1": 40, "md5": 32}[algorithm]
        if len(first) != expected_len:
            return ""
        return first

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("ADB backend has no version history")

    # ------------------------------------------------------------------
    # ADB-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def shell(self, cmd: str) -> str:
        """Run an arbitrary shell command on the connected device and
        return its stdout. Caller is responsible for shlex-quoting any
        substituted path.

        Note: Android's adb-shell wire protocol does NOT reliably
        propagate non-zero exit codes back to the client (the
        ``adb shell`` CLI shells over a stream that mixes stdout +
        stderr without a clean status). Callers branch on the
        content of the returned string instead of expecting an
        OSError on remote-side failure.
        """
        if "\r" in cmd or "\n" in cmd:
            raise ValueError(
                "ADB shell(cmd): refusing CR/LF (would smuggle a second "
                "shell line)"
            )
        return self._shell(cmd)

    def install_apk(self, local_apk_path: str, *,
                    replace: bool = True,
                    grant_permissions: bool = False) -> str:
        """Install an APK on the device.

        Pushes the APK to a temp path on the device (``/data/local/tmp/
        axross-install-<pid>.apk``), runs ``pm install`` against it,
        then deletes the temp file. ``replace`` adds ``-r`` (replace
        existing app); ``grant_permissions`` adds ``-g`` (grant runtime
        perms at install time).

        Returns the ``pm install`` stdout — typical success line is
        ``Success`` or ``Success: streamed install`` depending on
        Android version.
        """
        import os as _os
        if not _os.path.isfile(local_apk_path):
            raise OSError(f"install_apk: not a file: {local_apk_path!r}")
        # F35: PID alone collides when two threads inside the SAME
        # process call install_apk() concurrently (the REPL + the
        # GUI's transfer worker, for example). Add a per-call uuid4
        # suffix; the remote tmp dir is sticky-bit'd on Android so
        # collisions overwrite each other's APK before the second
        # ``pm install`` runs.
        import uuid as _uuid
        remote = (
            f"/data/local/tmp/axross-install-{_os.getpid()}-"
            f"{_uuid.uuid4().hex[:12]}.apk"
        )
        self._push_file(local_apk_path, remote)
        flags = []
        if replace:
            flags.append("-r")
        if grant_permissions:
            flags.append("-g")
        cmd = f"pm install {' '.join(flags)} {self._shell_q(remote)}"
        try:
            return self._shell(cmd)
        finally:
            # Best-effort cleanup; ignore errors so a failed install
            # still surfaces its real reason instead of a cleanup IOError.
            try:
                self._shell(f"rm -f {self._shell_q(remote)}")
            except OSError:
                pass

    def screencap(self, *, quality: int = 100) -> bytes:
        """Capture the screen as PNG bytes via ``screencap -p``.
        Returns the raw PNG data — caller can write it to a file or
        pass to PIL/cv2."""
        # screencap -p writes PNG to stdout. adb-shell returns this
        # as a UTF-8 string by default (which corrupts binary). Use
        # the raw shell that returns bytes.
        try:
            with self._conn_lock:
                return self._device.shell(
                    "screencap -p",
                    transport_timeout_s=self._transport_timeout,
                    decode=False,
                )
        except Exception as exc:
            raise OSError(
                f"ADB screencap on {self._label}: {exc}",
            ) from exc

    def logcat_tail(self, *, lines: int = 200,
                    filter_spec: str = "*:V") -> str:
        """Read recent logcat entries and return them as text.

        ``lines`` caps the output count via ``logcat -d -t <n>`` —
        ``-d`` dumps the buffer and exits (no streaming), ``-t``
        keeps the result bounded.

        ``filter_spec`` is the standard logcat filter format,
        e.g. ``"AxrossTag:D *:S"`` for tag-filtering. Default
        ``"*:V"`` captures everything down to verbose.
        """
        if "\r" in filter_spec or "\n" in filter_spec:
            raise ValueError(
                "logcat_tail: filter_spec must not contain CR/LF"
            )
        n = max(1, int(lines))
        return self._shell(f"logcat -d -t {n} {self._shell_q(filter_spec)}")

    def pm_list(self, *, system: bool = True,
                user: bool = True) -> list[str]:
        """List installed package names via ``pm list packages``.
        ``system=False`` excludes pre-installed system apps,
        ``user=False`` excludes user-installed ones (almost never
        useful but the flag exists for symmetry).

        Returns a sorted list of package names (e.g.
        ``["com.android.chrome", "com.android.settings", ...]``).
        """
        flags = []
        if not system:
            flags.append("-3")   # third-party only (excludes system)
        if not user and not system:
            return []
        if not user and system:
            flags.append("-s")   # system only
        out = self._shell(f"pm list packages {' '.join(flags)}".strip())
        # Each line is "package:com.foo.bar".
        return sorted(
            line.partition(":")[2].strip()
            for line in out.splitlines()
            if line.startswith("package:")
        )

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------
    def close(self) -> None:
        try:
            self._device.close()
        except Exception as exc:  # noqa: BLE001
            log.debug("ADB close(%s) raised: %s", self._label, exc)

    def disconnect(self) -> None:
        self.close()


class _CleanupOnClose:
    """File-like wrapper that forwards to the underlying handle and
    unlinks a backing tempfile when closed. Used by
    :meth:`AdbSession.open_read` so the caller's ``close()`` also
    drops the materialised pull temp file.
    """

    def __init__(self, handle: IO[bytes], tmp_path: str):
        self._handle = handle
        self._tmp_path = tmp_path
        self._closed = False

    def read(self, n: int = -1) -> bytes:
        return self._handle.read(n) if n >= 0 else self._handle.read()

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return self._handle.seekable()

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._handle.seek(offset, whence)

    def tell(self) -> int:
        return self._handle.tell()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._handle.close()
        finally:
            try:
                os.unlink(self._tmp_path)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


__all__ = [
    "ADB_SHELL_AVAILABLE",
    "AdbSession",
    "DEFAULT_ADB_KEY_PATH",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_TRANSPORT_TIMEOUT",
    "_AdbPushOnClose",
    "_parse_ls_line",
    "ensure_adb_key",
    "is_available",
]
