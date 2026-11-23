"""ADB (Android Debug Bridge) backend over pure Python.

Talks the ADB wire protocol directly via the ``adb-shell`` library —
no external ``adb`` binary needed. Two transport modes:

* **TCP** (preferred): the device has ``adb tcpip 5555`` enabled
  and we connect to ``host:port``. Works over Wi-Fi, USB-over-IP,
  etc. Primary mode; the connection dialog defaults to this.
* **USB**: through the adb server of this computer when one answers on
  127.0.0.1:5037 (core.adb_server: the platform tools' ``adb`` holds the
  phone, axross shares it as the console's ``adb`` does), else a direct
  libusb transport with an optional serial filter. libusb works for a
  USB-cable-attached device without a running adb server. Requires udev
  rules allowing the current user raw USB access on the phone's
  vendor/product id — on Linux this usually means the ``plugdev`` group
  plus a ``51-android.rules`` file. TCP mode pointed at the server's port
  (localhost:5037) uses the server too.

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

import contextlib
import contextvars
import errno
import io
import logging
import os
import posixpath
import secrets
import shlex
import threading
import time
from datetime import datetime, timezone
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from models.exec_result import ExecResult

from core import transfer_hooks
from core.backend import SessionLifecycle
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

log = logging.getLogger(__name__)


try:  # pragma: no cover — optional dep
    from adb_shell.adb_device import AdbDevice, AdbDeviceUsb  # type: ignore[import-not-found]
    from adb_shell.auth.keygen import keygen  # type: ignore[import-not-found]
    from adb_shell.auth.sign_pythonrsa import PythonRSASigner  # type: ignore[import-not-found]
    from adb_shell.transport.tcp_transport import TcpTransport  # type: ignore[import-not-found]

    ADB_SHELL_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    AdbDevice = None  # type: ignore[assignment]
    AdbDeviceUsb = None  # type: ignore[assignment]
    PythonRSASigner = None  # type: ignore[assignment]
    TcpTransport = None  # type: ignore[assignment]
    keygen = None  # type: ignore[assignment]
    ADB_SHELL_AVAILABLE = False


def _adb_tcp_module(proxy):
    """The adb_shell module whose ``socket.create_connection`` an ADB TCP
    connect calls (core.proxy.routed_create_connection routes it); None
    without a proxy. A proxy that cannot be honoured is refused: never
    a direct connection instead."""
    if not getattr(proxy, "enabled", False):
        return None
    try:
        import adb_shell.transport.tcp_transport as tcp_transport  # type: ignore[import-not-found]
    except ImportError as exc:
        raise OSError(
            "ADB over a proxy needs the adb-shell package (pip install adb-shell)"
        ) from exc
    return tcp_transport


# Default path for the ADB RSA keypair. Matches what the system
# ``adb`` binary uses so the user doesn't get a second "allow
# debugging" prompt from our backend after having already approved
# the CLI tool. Read when a session is made (tests point it elsewhere).
DEFAULT_ADB_KEY_PATH = os.path.expanduser("~/.android/adbkey")

#: Seconds for the TCP connect and the device's first answer.
DEFAULT_CONNECT_TIMEOUT = 10.0

#: Seconds the phone may take to answer "Allow USB debugging?" on a first
#: connect: the user has to notice it, unlock the phone and tap Allow.
DEFAULT_AUTH_TIMEOUT = 60.0

# Default transport timeout per primitive (list_dir, push/pull
# chunk). 30 s covers slow WAN links; lower defaults are unfriendly
# to over-the-air connections.
DEFAULT_TRANSPORT_TIMEOUT = 30.0

#: Seconds a command that works without printing may take: a checksum of a
#: big video, ``cp`` / ``mv`` of a big file on the device, ``rm -rf`` of a
#: big folder, ``pm install``.
DEFAULT_LONG_COMMAND_TIMEOUT = 3600.0

#: The banner of the CNXN message. adb_shell sends the workstation's host
#: name ("host::<hostname>") and the phone keeps it; the adb tool sends its
#: features there, never a name (docs/OPSEC.md).
_BANNER = b"features="

#: The comment after the public key the phone stores in
#: /data/misc/adb/adb_keys: a fixed neutral one, never ``user@hostname``
#: (docs/OPSEC.md).
NEUTRAL_KEY_COMMENT = "unknown@unknown"

#: The mode an upload gets: rw-r--r-- like a file the shell makes. adb_shell's
#: default (S_IFREG | 0o770) made every upload executable and group-writable.
_PUSH_MODE = 0o100644


class _RawCommand(str):
    """A command or device path that adb_shell sends as the bytes it names.

    adb_shell encodes with ``.encode("utf8")``: a name that is not UTF-8,
    listed as surrogate escapes (as the local file system does, see
    os.fsdecode), could not be sent back. Here such a name goes back as
    its original bytes."""

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:  # noqa: ARG002
        return str.encode(self, "utf-8", "surrogateescape")


def _as_text(raw) -> str:
    """adb_shell's answer (bytes with ``decode=False``) as text; a byte
    that is no UTF-8 stays a surrogate escape (as os.fsdecode)."""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "surrogateescape")
    return raw


#: The time-out of the commands run in the body of :func:`_command_timeout`
#: (None: the session's transport time-out).
_COMMAND_TIMEOUT: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "axross_adb_command_timeout", default=None
)


class _ShellDeadline(TimeoutError):
    """A shell answer still coming at its deadline (_shell)."""


class _ShellTooLarge(OSError):
    """A shell answer over SHELL_OUTPUT_CAP (_shell)."""


#: The most one shell answer may hold (a listing of ~500 000 entries):
#: adb_shell joined every packet, so an endless answer filled the memory.
SHELL_OUTPUT_CAP = 64 * 1024 * 1024
#: Seconds one ordinary command may take in all (each packet has the
#: transport time-out); a long one (_command_timeout) has its own.
SHELL_DEADLINE = 600.0
#: exec(): how much of the head of an answer is kept (its stdout_cap);
#: the rest is read and dropped but for the tail with the status trailer.
_SHELL_KEEP_HEAD: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "adb_shell_keep_head", default=None)


@contextlib.contextmanager
def _command_timeout(seconds: float | None):
    """Commands of the body may run *seconds* without an answer."""
    token = _COMMAND_TIMEOUT.set(seconds)
    try:
        yield
    finally:
        _COMMAND_TIMEOUT.reset(token)


class AdbAuthTimeout(OSError):
    """The phone asked "Allow USB debugging?" and did not allow the
    connection in time (no answer, or Deny)."""


class AdbNeedsApproval(OSError):
    """A connection made without asking (a reconnect) would have made the
    phone ask "Allow USB debugging?" again."""


class AdbConnectionLost(ConnectionResetError):
    """The device closed the connection."""


class AdbTlsPortError(OSError):
    """The port answered with STLS: Android 11+'s "Wireless debugging"
    port, which wants pairing and TLS (adb_shell speaks neither)."""


class AdbNotAdbError(OSError):
    """Something answered on the port, but not as an ADB device."""


class AdbUsbError(OSError):
    """ADB over USB failed; :attr:`kind` says why: ``missing-package``
    (libusb1 not installed), ``missing-library`` (no libusb-1.0 on the
    system), ``not-found`` (no phone with USB debugging on the cable),
    ``busy`` (another program - an adb server - holds it), ``access``
    (no permission for the USB device: udev rules). :attr:`server_note`:
    why no adb server was used instead (core.adb_server), for ``busy``:
    ``none`` (none answers on :attr:`server_address`), ``refused`` (the
    setting :attr:`server_detail` names another computer), ``not-adb``."""

    def __init__(self, kind: str, message: str, serial: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.serial = serial
        self.server_note = ""
        self.server_address = ""
        self.server_detail = ""


def _usb_missing_kind() -> str:
    """Why adb_shell has no USB transport: the package or the library."""
    try:
        import usb1  # type: ignore[import-not-found]  # noqa: F401
        import adb_shell.transport.usb_transport  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return "missing-package"
    except OSError:
        return "missing-library"
    return "missing-package"


def _usb_error(exc: BaseException, serial: str) -> AdbUsbError | None:
    """The :class:`AdbUsbError` for a libusb / adb_shell USB failure."""
    names, text = _names(exc), str(exc)
    which = f"USB {serial or 'device'}"
    if "InvalidTransportError" in names:
        kind = _usb_missing_kind()
        return AdbUsbError(kind, f"ADB over USB needs libusb ({kind}): {text}", serial)
    if names & {"UsbDeviceNotFoundError", "DeviceNotFoundError", "USBErrorNoDevice",
                "USBErrorNotFound"}:
        return AdbUsbError("not-found", f"ADB: no Android device found on {which}", serial)
    if "USBErrorBusy" in names or "LIBUSB_ERROR_BUSY" in text:
        return AdbUsbError("busy", f"ADB: {which} is held by another program ({text})", serial)
    if "USBErrorAccess" in names or "LIBUSB_ERROR_ACCESS" in text:
        return AdbUsbError("access", f"ADB: no permission to open {which} ({text})", serial)
    return None


#: adb_shell errors that are the device's answer to one command: the
#: connection itself is fine.
_COMMAND_ERRORS = frozenset({
    "AdbCommandFailureException", "PushFailedError", "DevicePathInvalidError",
    "UnicodeError", "AdbServerCommandFailed",
})
#: adb_shell / socket time-outs.
_TIMEOUT_ERRORS = frozenset({"TcpTimeoutException", "AdbTimeoutError", "TimeoutError", "timeout"})


def _names(exc: BaseException) -> set[str]:
    return {cls.__name__ for cls in type(exc).__mro__}


def _breaks_connection(exc: BaseException) -> bool:
    """Whether *exc* leaves the connection unusable (a lost socket, a
    time-out in the middle of a stream, a cancelled transfer) rather than
    being the device's answer to one command."""
    return not (_names(exc) & _COMMAND_ERRORS)


def _closed_aware_transport(host: str, port: int, address_family: str | None = None):
    """adb_shell's TcpTransport, except that a connection the device
    closed is an :class:`AdbConnectionLost` at once: ``recv()`` returning
    b"" made adb_shell loop until its read time-out (10 s at full CPU) and
    report "Timeout: read 0 of 24 bytes". *address_family* ``ipv4`` /
    ``ipv6`` connects over that IP version only (not through a proxy:
    the proxy resolves the name)."""
    import socket

    class _Transport(TcpTransport):  # type: ignore[misc, valid-type]
        def connect(self, transport_timeout_s):
            family = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}.get(address_family or "")
            if family is None:
                return super().connect(transport_timeout_s)
            import adb_shell.transport.tcp_transport as module  # type: ignore[import-not-found]

            last: OSError | None = None
            for *_rest, address in socket.getaddrinfo(host, port, family, socket.SOCK_STREAM):
                try:
                    self._connection = module.socket.create_connection(
                        address[:2], timeout=transport_timeout_s)
                    break
                except OSError as exc:
                    last = exc
            else:
                raise last or OSError(f"no {address_family} address for {host}")
            if transport_timeout_s:
                self._connection.setblocking(False)
            return None

        def bulk_read(self, numbytes, transport_timeout_s):
            if self._connection is None:
                raise AdbConnectionLost(f"the connection to {host}:{port} is closed")
            data = super().bulk_read(numbytes, transport_timeout_s)
            if numbytes and not data:
                raise AdbConnectionLost(f"the device {host}:{port} closed the connection")
            return data

        def bulk_write(self, data, transport_timeout_s):
            if self._connection is None:
                raise AdbConnectionLost(f"the connection to {host}:{port} is closed")
            return super().bulk_write(data, transport_timeout_s)

    return _Transport(host, port)


if ADB_SHELL_AVAILABLE:

    class AdbDeviceTcp(AdbDevice):  # type: ignore[misc, valid-type]
        """adb_shell's AdbDeviceTcp over :func:`_closed_aware_transport`."""

        def __init__(self, host, port=5555, default_transport_timeout_s=None, banner=None,
                     address_family=None):
            super().__init__(_closed_aware_transport(host, port, address_family),
                             default_transport_timeout_s, banner)

else:  # pragma: no cover — optional dep
    AdbDeviceTcp = None  # type: ignore[assignment, misc]


def _close_quietly(device) -> None:
    """Close an adb_shell device; whatever it raises is logged."""
    close = getattr(device, "close", None)
    if close is None:
        return
    try:
        close()
    except Exception as exc:  # noqa: BLE001 - a dead socket may refuse its close
        log.debug("ADB close raised: %s", exc)


def is_available() -> bool:
    """True iff ``adb-shell`` is importable AND a reasonable auth
    keypair exists / can be generated."""
    return ADB_SHELL_AVAILABLE


_KEYGEN_LOCK = threading.Lock()


def ensure_adb_key(path: str | None = None) -> str:
    """Ensure an ADB RSA keypair exists at *path* (default
    :data:`DEFAULT_ADB_KEY_PATH`). Creates one with
    ``adb_shell.auth.keygen.keygen`` if missing. Returns the path
    (useful for downstream logging). Refuses to overwrite an
    existing key — the ADB fingerprint on the phone ties to the
    specific public key, and rotating it silently would force the
    user to re-accept debugging from scratch.

    Security details:

    * The enclosing ``~/.android`` directory is created mode 0o700.
    * ``keygen`` writes into a fresh 0o700 folder next to the key, so
      the private key is never readable by anyone else, whatever mode
      keygen gives it - without ``os.umask``, which is process-wide (the
      old bracket changed the mode of files other threads made meanwhile).
    * The key is put in place with ``O_CREAT | O_EXCL``, mode 0o600: two
      connects at once (two panes, or two axross processes) make ONE key -
      the second keygen replaced the key the phone had just been asked to
      trust. A thread lock keeps keygen to one run per process.
    * An EXISTING key with unsafe perms (e.g. copied in from a
      git checkout) is flagged loudly rather than silently trusted.
    """
    if not ADB_SHELL_AVAILABLE:
        raise RuntimeError(
            "adb-shell not installed — pip install adb-shell",
        )
    path = path or DEFAULT_ADB_KEY_PATH
    with _KEYGEN_LOCK:
        if os.path.exists(path):
            _check_existing_key(path)
            return path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True, mode=0o700)
        import shutil
        import tempfile

        workdir = tempfile.mkdtemp(prefix=".axross-adbkey-", dir=parent or None)  # 0o700
        try:
            draft = os.path.join(workdir, "adbkey")
            keygen(draft)  # type: ignore[misc]
            with open(draft, "rb") as fh:
                private = fh.read()
            with open(draft + ".pub", "rb") as fh:
                tokens = fh.read().split()
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                return path  # another process made it meanwhile: that one counts
            with os.fdopen(fd, "wb") as fh:
                fh.write(private)
            os.chmod(path, 0o600)
            # Identity hygiene: adb_shell.auth.keygen writes the .pub file
            # as "<base64> user@hostname". The comment is shipped to the
            # phone on first pairing and persists in /data/misc/adb/adb_keys:
            # keep the key (the first token) with a fixed neutral comment.
            # (Keeping "two tokens" kept exactly that comment.) See
            # docs/OPSEC.md finding #8.
            if tokens:
                pub_draft = draft + ".pub"
                with open(pub_draft, "wb") as fh:
                    fh.write(tokens[0] + b" " + NEUTRAL_KEY_COMMENT.encode() + b"\n")
                os.chmod(pub_draft, 0o644)
                os.replace(pub_draft, path + ".pub")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    return path


def _check_existing_key(path: str) -> None:
    """Defensive: reject a pre-existing key with world/group readable
    bits. An adversary could have planted a key they control, forcing a
    MITM on every subsequent ADB session."""
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


def _load_signer(path: str) -> "PythonRSASigner":
    """Load the RSA signer for an existing key (callers call
    :func:`ensure_adb_key` first). A missing ``.pub`` is derived from the
    private key."""
    pub_path = path + ".pub"
    try:
        with open(path, "r", encoding="utf-8") as f:
            priv = f.read()
    except OSError as exc:
        raise OSError(f"ADB key unreadable at {path!r}: {exc}") from exc
    try:
        with open(pub_path, "r", encoding="utf-8") as f:
            pub = f.read()
    except FileNotFoundError:
        # The adb tool needs only the private key; a key copied without
        # its .pub is complete. The public half follows from it.
        import base64

        from adb_shell.auth.keygen import encode_pubkey  # type: ignore[import-not-found]

        pub = base64.b64encode(encode_pubkey(path)).decode("ascii")
    except OSError as exc:
        raise OSError(f"ADB public key unreadable at {pub_path!r}: {exc}") from exc
    # What the phone gets on the first pairing: the key with a neutral
    # comment, also when an older adbkey.pub carries user@hostname.
    tokens = pub.split()
    if tokens:
        pub = f"{tokens[0]} {NEUTRAL_KEY_COMMENT}"
    return PythonRSASigner(pub, priv)  # type: ignore[misc]


# --------------------------------------------------------------------------
# Listing parser — ``ls -la`` shell output
# --------------------------------------------------------------------------


# ``ls -la`` on Android's toybox (Android 6 and newer) emits lines like:
#   drwxrwx--x 5 system system 3452 2026-04-20 14:02 Download
#   -rw-rw---- 1 u0_a123 u0_a123 98765 2025-12-01 03:11 photo.jpg
#   lrwxrwxrwx 1 root root 11 1971-01-01 00:00 sdcard -> /storage/self/primary
#   crw-rw-rw- 1 root root 10, 229 2024-03-28 10:40 fuse
#   d?????????   ? ?      ?             ?                ? postinstall
# The last one is an entry ls could not stat (EACCES in / of a phone):
# every field but the type and the name is a "?". The old toolbox ``ls``
# (Android 5 and older) has no link-count column, and no size for a folder
# or a link:
#   drwxrwx--x root     sdcard_r          2014-03-28 10:40 Alarms
#   -rw-rw---- root     sdcard_r   123456 2014-03-28 10:41 photo.jpg
#   crw-rw---- system   audio     14,   3 2014-03-28 10:40 dsp
# A busybox or GNU ls prints the date as "Jan  2 03:04" / "Jan  2  2023";
# ``ls -lZ`` puts the SELinux context (u:object_r:system_file:s0) between
# the group and the size. The "total N" line is skipped. The name is what
# follows the ONE blank after the date: blanks around it belong to it.
#
# AdbSession lists with ``ls -lab`` where ls takes -b (toybox, GNU,
# busybox builds with it): a line feed, a tab, a backslash, a blank or any
# other unprintable byte of a name comes escaped (``\n``, ``\ ``,
# ``\303``), so one physical line is one entry and its name is decoded
# (core.telnet_client.ls_unescape). The toolbox ls of Android 5 and older
# refuses -b ("Unknown option"): it is listed without, and an entry whose
# name went on over a line break is left out with a warning (its first
# line names ANOTHER file, which a delete would remove) - two lines are
# never joined into one name.
_LS_LINE_RES = None  # lazily compiled — import-time re isn't hot enough
# to matter AND keeps the module's import surface small.

#: The file-type characters of an ``ls`` mode that name no file content.
_SPECIAL_NAMES = {
    "b": "block device",
    "c": "character device",
    "p": "FIFO (named pipe)",
    "s": "socket",
}
_SPECIAL_TYPES = frozenset(_SPECIAL_NAMES)
#: Guards each session's ``_special_paths`` (a listing and a stat of two
#: threads changed it at once: "dictionary changed size during iteration").
_SPECIAL_LOCK = threading.Lock()
#: An ls that does not take -b says so in one of these ways (toolbox:
#: "ls: Unknown option '-b'. Aborting.", busybox / GNU: "invalid option").
_LS_NO_ESCAPE = None
#: What an entry ls could not stat says instead of its size and date.
NOT_STATTABLE = "ls could not read its attributes (permission denied)"


def _checked(path: str) -> str:
    """*path*, or OSError when it holds a control character: no
    quoting is safe for those on every line a command passes through
    (see :func:`core.path_policy.refuse_control_chars`)."""
    from core.path_policy import refuse_control_chars

    return refuse_control_chars(path, "ADB")


def _compile_ls_res():
    global _LS_LINE_RES, _LS_NO_ESCAPE
    if _LS_LINE_RES is None:
        import re

        mode = r"^(?P<mode>[bcdlps-][rwxstST-]{9})[.+@]?\s+"
        owner = r"(?P<user>\S+)\s+(?P<group>\S+)\s+"
        # ls -Z: the SELinux context between the group and the size.
        context = r"(?:(?P<context>[^\s:]*:[^\s:]*:[^\s:]*:\S+)\s+)?"
        date = (r"(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?"
                r"|[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}|\d{4}))")
        # The name is exactly what follows the ONE space after the date.
        tail = date + r" (?P<name>.+)"
        device = r"(?P<major>\d+),\s*(?P<minor>\d+)\s+"
        unknown = r"^(?P<mode>[bcdlps?-]\?{9})[.+@]?"
        _LS_LINE_RES = (
            # toybox / GNU / busybox: link count, and a size (or major, minor) always
            re.compile(
                mode + r"(?P<links>\d+)\s+" + owner + context
                + r"(?:(?P<size>\d+)\s+|" + device + ")" + tail
            ),
            # toolbox: no link count; no size for a folder or a link
            re.compile(mode + owner + context + r"(?:(?P<size>\d+)\s+|" + device + ")?" + tail),
            # an entry ls could not stat: links, owner, group, size, date all "?"
            re.compile(unknown + r"(?:\s+\?){5} (?P<name>.+)"),
            re.compile(unknown + r"(?:\s+\?){4} (?P<name>.+)"),
        )
        _LS_NO_ESCAPE = re.compile(
            r"(?im)^(?:ls: )?(?:unknown|invalid|illegal|unrecognized) option"
            r"|^ls: (?:unknown|invalid|illegal|unrecognized) option|^usage: ls|invalid option -- '?b")
    return _LS_LINE_RES


def _is_ls_entry(line: str) -> bool:
    return any(regex.fullmatch(line) for regex in _compile_ls_res())


_LS_ESCAPES = {"n": 10, "t": 9, "r": 13, "a": 7, "b": 8, "f": 12, "v": 11, "e": 27}


def ls_unescape(text: str) -> str:
    """A name as ``ls -b`` prints it, back to the name: ``\\ `` is a blank,
    ``\\n`` a line feed, ``\\NNN`` an octal byte. Bytes that are no UTF-8
    stay surrogate escapes, as every other name of this backend
    (:func:`_as_text`), so the name can be sent back as it is."""
    if "\\" not in text:
        return text
    import re

    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "\\" or i + 1 >= len(text):
            out += ch.encode("utf-8", "surrogateescape")
            i += 1
            continue
        nxt = text[i + 1]
        octal = re.match(r"[0-7]{1,3}", text[i + 1:i + 4])
        if octal:
            out.append(int(octal.group(0), 8) & 0xFF)
            i += 1 + len(octal.group(0))
        elif nxt in _LS_ESCAPES:
            out.append(_LS_ESCAPES[nxt])
            i += 2
        else:  # \\ \  \" \' ...: the character itself
            out += nxt.encode("utf-8", "surrogateescape")
            i += 2
    return out.decode("utf-8", "surrogateescape")


def _ls_lines(out: str) -> list[str]:
    """The physical lines of an ``ls`` answer (LF only; a CR before each LF
    of a CRLF answer dropped). Each is a record of its own: no line ever
    continues another's name."""
    lines = split_lf_only_stream(out)
    if lines and lines[-1] == "":
        lines.pop()  # the final line feed ends the last line, it is no name
    if lines and all(line.endswith("\r") for line in lines):
        lines = [line[:-1] for line in lines]
    return lines


def _ls_entries(out: str) -> list[tuple[str, str]]:
    """``ls -la`` output as ``(line, "")`` records, one per physical line
    (kept in this shape for its callers; two lines are never joined)."""
    return [(line, "") for line in _ls_lines(out)]


def ls_refuses_escape(out: str) -> bool:
    """Whether *out* is an ls refusing the -b option (and listing nothing)."""
    _compile_ls_res()
    return bool(_LS_NO_ESCAPE.search(out)) and not any(
        _is_ls_entry(line) for line in _ls_lines(out))


def _parse_ls_entry(line: str, rest: str = "", *,
                    escaped: bool = False) -> tuple[FileItem, str] | None:
    """One ``ls -la`` output line (toybox, toolbox, busybox, GNU) as
    ``(FileItem, file-type character)``; None for ``total N`` or an
    unparseable line.

    A device node, FIFO or socket is an entry like any other, with size
    0 ("major, minor" is no size); its type character (``c``, ``b``,
    ``p``, ``s``) tells the caller it holds no file content. An entry ls
    could not stat (``d????????? ? ? ? ? ? name``) is listed with its name
    and type, unknown size, time and mode, and ``stat_error`` set.

    The line is not stripped: blanks around a name belong to it ("report "
    cut to "report" named another file, which a delete then removed).
    *escaped*: the line came from ``ls -b`` (name and link target are
    decoded). *rest* is no longer used (two lines are never one name);
    a non-empty one is refused.
    """
    if not line or line.startswith("total ") or rest:
        return None
    m = None
    for regex in _compile_ls_res():
        m = regex.fullmatch(line)
        if m is not None:
            break
    if m is None:
        log.debug("ADB ls: unparseable line %r", line)
        return None
    mode = m.group("mode")
    kind = mode[0]
    is_dir = kind == "d"
    is_link = kind == "l"
    name = m.group("name")
    if "?" in mode:  # not stattable: every field but type and name unknown
        if escaped:
            name = ls_unescape(name)
        return FileItem(name=name, is_dir=is_dir, is_link=is_link,
                        stat_error=NOT_STATTABLE), kind
    link_target = ""
    size = m.group("size")
    if is_link and " -> " in name:
        from core.telnet_client import split_link_field

        # ls -b escapes the blanks: only one " -> " is left, the arrow.
        # toolbox prints no size for a link: an ambiguous name is kept whole.
        name, link_target = split_link_field(name, int(size) if size is not None else None)
    if escaped:
        name, link_target = ls_unescape(name), ls_unescape(link_target)
    # ls runs under TZ=UTC0 (AdbSession._LS): the date is UTC, returned
    # aware (FileItem converts it); the device's wall clock was handed out
    # as local time.
    date = m.group("date")
    if date[:1].isdigit():
        try:
            modified = datetime.strptime(date[:16].replace("  ", " "), "%Y-%m-%d %H:%M").replace(
                tzinfo=timezone.utc)
        except ValueError:
            modified = datetime.fromtimestamp(0, timezone.utc)
    else:
        from core.telnet_client import _parse_ls_date

        modified = _parse_ls_date(date, utc=True)
    item = FileItem(
        name=name,
        size=int(size) if size is not None else 0,
        modified=modified,
        is_dir=is_dir,
        is_link=is_link,
        link_target=link_target,
    )
    return item, kind


def _parse_ls_line(line: str, *, escaped: bool = False) -> FileItem | None:
    """Parse one ``ls -la`` output line into a FileItem. Returns None
    for ``total N`` or otherwise unparseable lines; whether an answer
    without a single parsed line is an error is the caller's to say
    (it is: see :meth:`AdbSession.list_dir`)."""
    entry = _parse_ls_entry(line, escaped=escaped)
    return entry[0] if entry is not None else None


def parse_ls_listing(out: str, *, escaped: bool) -> tuple[list[tuple[FileItem, str]], list[str],
                                                         list[str], list[str]]:
    """An ``ls -la`` answer as ``(entries, errors, unparsed, dropped)``:
    the ``(FileItem, type char)`` of each entry line ("." and ".." kept),
    the ``ls:`` messages, the lines no pattern reads, and the names left
    out because they went on over a line break (an unescaped listing
    only: its first line names another file)."""
    entries: list[tuple[FileItem, str]] = []
    errors: list[str] = []
    unparsed: list[str] = []
    dropped: list[str] = []
    after_entry = False
    for line in _ls_lines(out):
        entry = _parse_ls_entry(line, escaped=escaped)
        if entry is not None:
            entries.append(entry)
            after_entry = True
            continue
        if line.startswith("ls:") or line.startswith("ls "):
            errors.append(line.strip())
        elif line.startswith("total ") or not line.strip() and not after_entry:
            pass
        elif after_entry and not escaped and entries:
            # A name with a line break, from an ls without -b: its first
            # line is not its name. Never joined, never listed under a
            # name that is another file's.
            dropped.append(entries.pop()[0].name)
            unparsed.append(line)
            after_entry = False
            continue
        else:
            unparsed.append(line)
        after_entry = False
    return entries, errors, unparsed, dropped


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
        import weakref

        from core.read_spool import new_named_spool, remove_quietly

        # In the spool folder (not /tmp, a tmpfs), and removed even when
        # the writer is dropped without close() or discard().
        self._tmp = new_named_spool(tag="adb", delete=False)
        self._tmp_path = self._tmp.name
        self._cleanup = weakref.finalize(self, remove_quietly, self._tmp_path)
        self._closed = False
        # The running transfer's Cancel and progress (core.transfer_hooks):
        # the upload happens in close(), after the copy loop.
        self._hooks = transfer_hooks.current()
        if self._hooks is not None:
            self._hooks.expect_upload()

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
            try:
                self._tmp.flush()  # a full disk fails here: removed all the same
            finally:
                self._tmp.close()
            self._session._push_file(self._tmp_path, self._remote_path, hooks=self._hooks)
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
        if exc_info and exc_info[0] is not None:
            self.discard()
        else:
            self.close()
        return False


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------


class AdbSession(SessionLifecycle):
    """Android device exposed as a FileBackend via ADB.

    Construct with TCP args (host + port) OR USB args
    (usb=True, usb_serial=... optional). One or the other.

    The connection is watched: an operation that finds it lost (the
    device closed it, a time-out in the middle of an answer) fails with
    that, :attr:`connected` turns False - ConnectionManager then makes a
    new session instead of handing out this one - and the next operation
    connects again, without asking the phone: a key the phone no longer
    accepts is :class:`AdbNeedsApproval`, not a prompt nobody waits for.
    """

    # ADB shell on most Android images doesn't ship with ln / ln -s
    # as a first-class utility. Rather than pretending and failing
    # at action time, flag False so the UI hides the menu entries.
    supports_symlinks = False
    supports_hardlinks = False

    #: The listing command: under TZ=UTC0 (every Android shell, mksh and
    #: the older toolbox sh, takes a variable prefix), so its dates are UTC
    #: and the parser returns them aware. Without it they were the device's
    #: wall clock, handed out as the client's local time (as Telnet / SCP).
    _LS = "TZ=UTC0 ls -la"

    # Defaults of a session (also of one a test builds without __init__).
    _label = "ADB"
    _transport_timeout = DEFAULT_TRANSPORT_TIMEOUT
    _long_timeout = DEFAULT_LONG_COMMAND_TIMEOUT
    #: The command connection was lost; the next operation reconnects.
    _dead = False
    #: close() was called: nothing reconnects.
    _closed = False
    #: Made by __init__ (the parameters to connect again are known).
    _can_reconnect = False
    #: The current device goes through the adb server (core.adb_server).
    _server_mode = False
    #: Why the adb server was not used (AdbUsbError.server_note).
    _server_note = ""
    _server_address = ""
    _server_detail = ""

    def __init__(
        self,
        host: str = "",
        port: int = 5555,
        *,
        usb: bool = False,
        usb_serial: str = "",
        adb_key_path: str | None = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        auth_timeout: float = DEFAULT_AUTH_TIMEOUT,
        transport_timeout: float = DEFAULT_TRANSPORT_TIMEOUT,
        long_command_timeout: float = DEFAULT_LONG_COMMAND_TIMEOUT,
        address_family: str = "auto",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ) -> None:
        if not ADB_SHELL_AVAILABLE:
            raise ImportError(
                "ADB support requires adb-shell. Install with: pip install adb-shell",
            )
        if not usb and not host:
            raise ValueError(
                "AdbSession: one of (usb=True, host=…) must be given",
            )
        self._usb = bool(usb)
        self._usb_serial = usb_serial
        self._host = host
        self._port = port
        self._connect_timeout = connect_timeout
        self._auth_timeout = auth_timeout
        self._transport_timeout = transport_timeout
        self._long_timeout = long_command_timeout
        self._address_family = address_family
        self._conn_lock = threading.Lock()
        # The transfer connection (see _transfer_channel): made on the
        # first pull / push; off for USB (one program per USB device).
        self._xfer_lock = threading.Lock()
        self._xfer_device = None
        self._xfer_off = self._usb
        key_path = adb_key_path or DEFAULT_ADB_KEY_PATH
        ensure_adb_key(key_path)
        self._signer = _load_signer(key_path)
        from core.proxy import ProxyConfig

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
            self._label = f"USB {usb_serial or 'first'}"
        else:
            self._label = f"{host}:{port}"
        self._device = self._open_device(interactive=True)
        self._mode_opened()
        self._can_reconnect = True
        log.info("AdbSession opened: %s%s", self._label,
                 " (through the adb server)" if self._server_mode else "")

    # ------------------------------------------------------------------
    # Connections
    # ------------------------------------------------------------------
    def _new_device(self):
        """An unconnected adb_shell device for this session's transport:
        for USB (and TCP to the adb server's port) the phone through the
        adb server when one answers, else libusb / TCP."""
        server = self._server_device()
        self._server_mode = server is not None
        if server is not None:
            return server
        if self._usb:
            try:
                return AdbDeviceUsb(  # type: ignore[misc]
                    serial=self._usb_serial or None,
                    default_transport_timeout_s=self._transport_timeout,
                    banner=_BANNER,
                )
            except Exception as exc:
                usb = _usb_error(exc, self._usb_serial)
                if usb is not None:
                    raise usb from exc
                raise
        return AdbDeviceTcp(  # type: ignore[misc]
            self._host,
            self._port,
            default_transport_timeout_s=self._transport_timeout,
            banner=_BANNER,
            # A proxy resolves the name itself.
            address_family=None if self._proxy.enabled else self._address_family,
        )

    def _server_device(self):
        """The phone through the adb server (core.adb_server), or None to
        use libusb / TCP (no server answers: :attr:`_server_note` says
        so). A server that answers but cannot give the phone raises
        :class:`core.adb_server.AdbServerError`."""
        from core import adb_server

        via_port = (not self._usb and not self._proxy.enabled
                    and adb_server.is_server_port(self._host, self._port))
        if not (self._usb or via_port):
            return None
        address = adb_server.server_address()
        self._server_address = str(address)
        if address.refused:
            self._server_note, self._server_detail = "refused", address.setting
            log.info("ADB %s: %s", self._label, address.refused)
            return None
        try:
            devices = adb_server.list_devices(
                address, timeout=min(self._connect_timeout, adb_server.PROBE_TIMEOUT))
        except adb_server.AdbServerError as exc:
            if exc.kind != "protocol":
                raise
            self._server_note = "not-adb"
            log.info("ADB %s: %s answers, but not as an adb server", self._label, address)
            return None
        except OSError as exc:
            self._server_note = "none"
            log.debug("ADB %s: no adb server answers on %s (%s); libusb / TCP",
                      self._label, address, exc)
            return None
        try:
            chosen = adb_server.choose_device(devices, self._usb_serial if self._usb else "",
                                              usb_only=self._usb, address=address)
        except adb_server.AdbServerError as exc:
            exc.via_port = via_port
            raise
        return adb_server.AdbServerDevice(address, chosen.serial,
                                          default_transport_timeout_s=self._transport_timeout)

    def _note_server(self, exc: AdbUsbError) -> None:
        """Tell *exc* why the adb server was not used (core.user_errors)."""
        exc.server_note = self._server_note
        exc.server_address = self._server_address
        exc.server_detail = self._server_detail

    def _mode_opened(self) -> None:
        """After a connect: through the adb server a second connection for
        transfers is free (the server multiplexes); libusb has one."""
        if self._usb:
            self._xfer_off = not self._server_mode

    def _open_device(self, *, interactive: bool):
        """A connected device. *interactive*: a key the phone does not
        know yet makes it ask "Allow USB debugging?" (the user is told,
        core.connect_notice) and the answer is waited for; otherwise
        :class:`AdbNeedsApproval` instead of a prompt."""
        from core.proxy import routed_create_connection

        from core.adb_server import AdbServerError

        try:
            device = self._new_device()
        except AdbUsbError as exc:
            self._note_server(exc)
            raise
        except AdbServerError:
            raise
        except Exception as exc:
            raise OSError(f"ADB connect to {self._label} failed: {exc}") from exc
        prompted: list[bool] = []

        def on_prompt(_io_manager) -> None:
            if not interactive:
                raise AdbNeedsApproval(
                    f"ADB {self._label}: the phone no longer accepts this computer's key; "
                    "connect again and allow USB debugging",
                )
            prompted.append(True)
            from core import connect_notice
            from core.i18n import tr

            connect_notice.notify(tr(
                "Check the phone: unlock it and allow USB debugging for this computer "
                "(tick \"Always allow from this computer\")."))

        try:
            # adb_shell.transport.tcp_transport.TcpTransport.connect()
            # calls ``socket.create_connection`` of its own module. It is
            # routed through the SOCKS / HTTP proxy for THIS thread only
            # (core.proxy.routed_create_connection): the old process-wide
            # patch sent every other thread's connection (ftplib,
            # imaplib, ...) to the ADB proxy for as long as the connect
            # waited - up to the "Allow USB debugging?" tap on the phone.
            # The socket it made stays adb_shell's; later I/O reuses it.
            with routed_create_connection(_adb_tcp_module(self._proxy), self._proxy):
                device.connect(
                    rsa_keys=[self._signer],
                    transport_timeout_s=self._connect_timeout,
                    read_timeout_s=self._connect_timeout,
                    auth_timeout_s=self._auth_timeout,
                    auth_callback=on_prompt,
                )
        except Exception as exc:
            _close_quietly(device)
            if isinstance(exc, AdbNeedsApproval):
                raise
            raise self._connect_error(exc, prompted=bool(prompted)) from exc
        return device

    def _connect_error(self, exc: BaseException, *, prompted: bool) -> OSError:
        """The OSError for a failed connect: the phone's prompt not
        answered is :class:`AdbAuthTimeout`, a time-out a TimeoutError."""
        from core.adb_server import AdbServerError

        names = _names(exc)
        if isinstance(exc, AdbServerError):
            if prompted and exc.kind == "unauthorized":
                return AdbAuthTimeout(
                    f"ADB connect to {self._label}: the phone did not allow USB debugging "
                    f"for the adb server within {self._auth_timeout:.0f} s",
                )
            return exc
        if self._usb:
            usb = _usb_error(exc, self._usb_serial)
            if usb is not None:
                self._note_server(usb)
                return usb
        if "STLS" in str(exc):
            return AdbTlsPortError(
                f"ADB connect to {self._label}: this is a Wireless debugging (TLS) port; "
                "use the port of \"adb tcpip\" (5555)",
            )
        if names & {"InvalidCommandError", "InvalidChecksumError", "InvalidResponseError"}:
            return AdbNotAdbError(
                f"ADB connect to {self._label}: the answer is not ADB ({str(exc)[:80]})",
            )
        if prompted and (names & _TIMEOUT_ERRORS or isinstance(exc, ConnectionError)):
            return AdbAuthTimeout(
                f"ADB connect to {self._label}: the phone did not allow USB debugging "
                f"within {self._auth_timeout:.0f} s",
            )
        if names & _TIMEOUT_ERRORS:
            return TimeoutError(
                f"ADB connect to {self._label}: no answer within {self._connect_timeout:.0f} s",
            )
        return OSError(f"ADB connect to {self._label} failed: {exc}")

    @property
    def connected(self) -> bool:
        """False once the connection was found lost or the session closed
        (the next operation of a lost one connects again)."""
        if self._closed or self._dead:
            return False
        return bool(getattr(self.__dict__.get("_device"), "available", True))

    def _main(self):
        """The command connection (``_conn_lock`` held), connected again
        first when it was lost."""
        if self._closed:
            raise OSError(f"ADB {self._label}: the session is closed")
        if self._dead and self._can_reconnect:
            _close_quietly(self._device)
            self._device = self._open_device(interactive=False)
            self._mode_opened()
            self._dead = False
            log.info("AdbSession reconnected: %s", self._label)
        return self._device

    def _lost(self, exc: BaseException) -> None:
        """Note that *exc* broke the command connection. A connection the
        device closed takes an idle transfer connection with it (it went
        the same way: adbd restarted, the Wi-Fi dropped)."""
        if not _breaks_connection(exc):
            return
        self._dead = True
        _close_quietly(self.__dict__.get("_device"))
        xlock = self.__dict__.get("_xfer_lock")
        if isinstance(exc, ConnectionError) and xlock is not None and xlock.acquire(blocking=False):
            try:
                _close_quietly(self._xfer_device)
                self._xfer_device = None
            finally:
                xlock.release()

    @contextlib.contextmanager
    def _transfer_channel(self):
        """The device for a transfer or a long command: the transfer
        connection when there is one, so a listing in another pane does
        not wait for it; else (USB, a second connection would need the
        phone's approval, a session built without __init__) the command
        connection. A connection the body breaks is dropped."""
        xlock = self.__dict__.get("_xfer_lock")
        if xlock is not None and not self.__dict__.get("_xfer_off", True):
            with xlock:
                device = self._xfer_device or self._open_transfer_connection()
                if device is not None:
                    try:
                        yield device
                    except BaseException as exc:
                        if _breaks_connection(exc):
                            self._xfer_device = None
                            _close_quietly(device)
                            if isinstance(exc, ConnectionError):
                                self._dead = True  # the command connection went too
                        raise
                    return
        with self._conn_lock:
            device = self._main()
            try:
                yield device
            except BaseException as exc:
                self._lost(exc)
                raise

    def _open_transfer_connection(self):
        """A second connection for transfers (``_xfer_lock`` held), or None
        to use the command connection: it would need the phone's approval
        ("Always allow" was not ticked), or it cannot be made now."""
        if self._closed:
            raise OSError(f"ADB {self._label}: the session is closed")
        try:
            device = self._open_device(interactive=False)
        except AdbNeedsApproval:
            log.info("ADB %s: no second connection without the phone's approval; "
                     "transfers share the command connection", self._label)
            self._xfer_off = True
            return None
        except OSError as exc:
            log.info("ADB %s: no transfer connection (%s); using the command one",
                     self._label, exc)
            return None
        self._xfer_device = device
        return device

    def _error(self, what: str, exc: BaseException, timeout: float) -> OSError:
        """The OSError for a failed command: a time-out is a TimeoutError,
        a lost connection keeps its cause (core.user_errors reads it)."""
        if _names(exc) & _TIMEOUT_ERRORS:
            return TimeoutError(f"{what} on {self._label}: no answer within {timeout:.0f} s")
        return OSError(f"{what} on {self._label}: {exc}")

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
        failures by content.

        It may run silent for the transport time-out, in the body of
        :func:`_command_timeout` for that one (adb_shell's own read
        time-out of 10 s, which also capped the transport time-out, failed
        every checksum of a big file)."""
        long_timeout = _COMMAND_TIMEOUT.get()
        timeout = long_timeout or self._transport_timeout
        # The whole command, not only each packet: SHELL_DEADLINE, or the
        # long command's own time-out.
        deadline = time.monotonic() + (long_timeout or max(SHELL_DEADLINE, timeout))
        keep_head = _SHELL_KEEP_HEAD.get()
        # A long command runs beside the listings, as a transfer does.
        channel = self._transfer_channel() if long_timeout else self._command_channel()
        try:
            with channel as device:
                # Read as a stream: device.shell() joined every packet, so
                # an endless answer filled the memory and never returned.
                # Leaving it early leaves its rest unread: the exception
                # out of this body drops the connection (_lost).
                head = bytearray()
                tail = b""
                size = 0
                kwargs = dict(transport_timeout_s=timeout, read_timeout_s=timeout, decode=False)
                stream = getattr(device, "streaming_shell", None)
                chunks = (stream(_RawCommand(cmd), **kwargs) if stream is not None
                          else [device.shell(_RawCommand(cmd), **kwargs)])  # a stand-in
                for chunk in chunks:
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8", "surrogateescape")
                    size += len(chunk)
                    if keep_head is None:
                        if size > SHELL_OUTPUT_CAP:
                            raise _ShellTooLarge(
                                errno.EFBIG,
                                f"ADB shell({cmd[:60]!r}): the answer holds more than "
                                f"{SHELL_OUTPUT_CAP // (1024 * 1024)} MiB",
                            )
                        head += chunk
                    else:
                        room = keep_head + 1 - len(head)
                        if room > 0:
                            head += chunk[:room]
                        tail = (tail + chunk)[-4096:]
                    if time.monotonic() > deadline:
                        raise _ShellDeadline(
                            errno.ETIMEDOUT,
                            f"ADB shell({cmd[:60]!r}) on {self._label}: still answering after "
                            f"{(long_timeout or max(SHELL_DEADLINE, timeout)):.0f} s; stopped",
                        )
                if keep_head is not None and size > len(head):
                    # The head (stdout_cap and one byte more) and the tail
                    # that holds exec's status trailer.
                    return _as_text(bytes(head)) + "\n" + _as_text(tail)
                return _as_text(bytes(head))
        except (_ShellDeadline, _ShellTooLarge):
            raise
        except Exception as exc:
            raise self._error(f"ADB shell({cmd[:60]!r})", exc, timeout) from exc

    @contextlib.contextmanager
    def _command_channel(self):
        """The command connection (locked); a connection the body breaks
        is noted (:meth:`_lost`)."""
        with self._conn_lock:
            device = self._main()
            try:
                yield device
            except BaseException as exc:
                self._lost(exc)
                raise

    def _shell_q(self, path: str) -> str:
        """Shell-quote *path* for embedding in a shell command. We
        use shlex.quote which is safe against filename metachars
        AND against path traversal at the wire layer (the quoted
        form prevents glob / eval expansion). A relative path that starts
        with ``-`` gets ``./`` first (exec_util.shell_path): ``readlink -f``
        answered its own error text as the link target.
        """
        from core.exec_util import shell_path

        return shell_path(_checked(path))

    # ------------------------------------------------------------------
    # Listing / stat
    # ------------------------------------------------------------------
    def _ls(self, flags: str, operand: str) -> tuple[str, bool]:
        """``(answer, escaped)`` of ``ls -la<flags> OPERAND``: with -b where
        this device's ls takes it (asked once per session: toolbox ls of
        Android 5 and older refuses it), else without."""
        q = self._shell_q(operand)
        if self.__dict__.get("_ls_escape") is not False:
            out = self._shell(f"{self._LS} -b{flags} {q}")
            if not ls_refuses_escape(out):
                self._ls_escape = True
                return out, True
            log.info("ADB %s: ls takes no -b; names with a line break cannot be listed",
                     self._label)
            self._ls_escape = False
        return self._shell(f"{self._LS}{flags} {q}"), False

    def list_dir(self, path: str) -> list[FileItem]:
        from core.exec_util import ls_dir_operand, ls_error

        # /sdcard itself is a symlink on Android: list through it.
        out, escaped = self._ls("", ls_dir_operand(path))
        entries, errors, unparsed, dropped = parse_ls_listing(out, escaped=escaped)
        items: list[FileItem] = []
        special: dict[str, str] = {}
        # "." and ".." too, and a name left out: the folder is there.
        listed = bool(entries) or bool(dropped)
        for fi, kind in entries:
            if fi.name in (".", ".."):
                continue
            if kind in _SPECIAL_TYPES:
                special[posixpath.normpath(posixpath.join(path, fi.name))] = kind
            items.append(fi)
        if errors and not listed:
            # ls refused the folder itself; an unparsable answer used to
            # be an empty listing (review B13, 2026-10-17). An entry ls
            # could not stat beside a listing stays a partial listing.
            raise ls_error(f"ADB list_dir({path})", errors[0])
        if unparsed and not listed and not dropped:
            # An ls whose lines this parser cannot read at all (another
            # ls build) is no empty folder: a copy would take it as one.
            raise OSError(
                f"ADB list_dir({path}): unreadable answer from ls: {unparsed[0][:200]!r}"
            )
        if dropped:
            log.warning(
                "ADB list_dir(%s): %d name(s) with a line break left out (this ls cannot "
                "escape them), first starting %r", path, len(dropped), dropped[0][:200])
        elif unparsed:
            log.warning(
                "ADB list_dir(%s): %d ls line(s) not understood, first %r",
                path, len(unparsed), unparsed[0][:200],
            )
        self._remember_special(path, special)
        return items

    def _remember_special(self, folder: str, special: dict[str, str]) -> None:
        """Note the device nodes, FIFOs and sockets a listing of *folder*
        named: open_read refuses them (a pull of /dev/zero never ends)."""
        prefix = posixpath.normpath(folder).rstrip("/") + "/"
        with _SPECIAL_LOCK:  # stat() in another thread adds to the map
            known = self.__dict__.setdefault("_special_paths", {})
            for old in [p for p in known if p.startswith(prefix) and "/" not in p[len(prefix):]]:
                del known[old]
            known.update(special)

    def stat(self, path: str) -> FileItem:
        """The entry at *path*. FileNotFoundError only when ``ls`` says
        "No such file or directory"; a dropped transport, a refused
        permission or an answer without a listing line is another
        OSError - exists() and is_dir() answer False from the first
        alone."""
        from core.exec_util import ls_error

        # Use ``ls -la -d <path>`` — -d prevents directories from
        # expanding their contents.
        out, escaped = self._ls(" -d", path)
        entries, errors, _unparsed, dropped = parse_ls_listing(out, escaped=escaped)
        if dropped and not entries:
            raise OSError(f"ADB stat({path}): ls answered a name with a line break")
        for fi, kind in entries:
            with _SPECIAL_LOCK:
                known = self.__dict__.setdefault("_special_paths", {})
                if kind in _SPECIAL_TYPES:
                    known[posixpath.normpath(path)] = kind
                else:
                    known.pop(posixpath.normpath(path), None)
            # ls -d echoes the path as the name; reduce to basename
            # so callers comparing against FileItem.name aren't
            # surprised by a leading slash. FileItem is frozen — we
            # can't mutate, so rebuild with the name replaced.
            from dataclasses import replace

            return replace(
                fi,
                name=os.path.basename(path.rstrip("/")) or path,
            )
        if errors:
            raise ls_error(f"ADB stat({path})", errors[0])
        # adb shell carries no exit status: an answer with neither a
        # listing line nor an ls error says nothing about the path.
        raise OSError(f"ADB stat({path}): unreadable answer from ls: {out[:200]!r}")

    def is_dir(self, path: str) -> bool:
        """False for a missing path or one below a file; any other
        failure is an OSError (transfer_manager recurses on True)."""
        try:
            return self.stat(path).is_dir
        except (FileNotFoundError, NotADirectoryError):
            return False

    def exists(self, path: str) -> bool:
        """False only when ``ls`` reports the path missing. A dropped
        connection, a refused permission or an unreadable answer is an
        OSError: server_side_copy(overwrite=False) and the transfer
        worker take False as the go-ahead to write."""
        try:
            self.stat(path)
            return True
        except (FileNotFoundError, NotADirectoryError):
            return False

    # ------------------------------------------------------------------
    # IO
    # ------------------------------------------------------------------
    def open_read(self, path: str) -> IO[bytes]:
        """Pull *path* to a tempfile and return an open handle to
        it. The caller is responsible for closing — we clean the
        tempfile via a small wrapper that unlinks on close.
        """
        from core.read_spool import new_named_spool, remove_quietly

        _checked(path)
        with _SPECIAL_LOCK:
            kind = self.__dict__.get("_special_paths", {}).get(posixpath.normpath(path))
        if kind is not None:
            # A device node, FIFO or socket the listing named: no file
            # content to pull, and a pull of /dev/zero never ends.
            raise OSError(
                errno.EINVAL,
                f"ADB: {path} is not a regular file ({_SPECIAL_NAMES[kind]}); not read",
                path,
            )
        hooks = transfer_hooks.current()
        total = None
        if hooks is not None:
            hooks.check()
            try:
                total = self.stat(path).size  # for the progress bar
            except OSError:
                total = None
        # In the spool folder (not /tmp, a tmpfs), removed on every path.
        local = new_named_spool(tag="adb", delete=False)
        local_path = local.name
        try:
            with local:
                self._pull_into(path, local, hooks, total)
        except BaseException as exc:
            remove_quietly(local_path)
            if isinstance(exc, InterruptedError):
                raise
            if isinstance(exc, Exception):
                raise self._pull_refused(path, exc) from exc
            raise
        try:
            handle = open(local_path, "rb")
        except BaseException:
            remove_quietly(local_path)
            raise
        if os.name == "posix":
            # The open handle keeps the bytes: no name left behind should
            # the caller never close it.
            remove_quietly(local_path)
        return _CleanupOnClose(handle, local_path)

    def _pull_into(self, path: str, local, hooks, total: int | None) -> None:
        """Pull *path* into the open file *local* on the transfer channel:
        each chunk reports progress and checks Cancel (*hooks*); Cancel
        closes the connection, which also wakes a read that waits."""
        timeout = self._transport_timeout
        with self._transfer_channel() as device:
            sink = _PullSink(local, hooks, total, abort=lambda: _close_quietly(device))
            with _closed_on_cancel(device, hooks, sink):
                device.pull(_RawCommand(path), sink,
                            transport_timeout_s=timeout, read_timeout_s=timeout)
        if hooks is not None and sink.done == 0:
            hooks.received(0, total)

    def _pull_refused(self, path: str, exc: BaseException) -> OSError:
        """A failed pull typed by what *path* is (adb's sync error text
        is not stable across versions): missing is FileNotFoundError, a
        folder IsADirectoryError; a dropped connection stays an OSError
        (the probe fails too)."""
        from core.exec_util import refused_as

        def kind():
            item = self.stat(path)
            return "dir" if item.is_dir else "other"

        def probe():
            try:
                return kind()
            except (FileNotFoundError, NotADirectoryError):
                return None

        return refused_as(f"ADB pull({path}) from {self._label}", path, str(exc), probe,
                          wanted="file")

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            raise OSError(
                "ADB open_write: append mode is not supported — "
                "Android shell has no wire-level append primitive; "
                "writes are full-file replacements",
            )
        return _AdbPushOnClose(self, _checked(path))

    def _push_file(self, local_path: str, remote_path: str, hooks=None, *,
                   atomic: bool = True) -> None:
        """Push *local_path* to *remote_path* on the device. Used by
        :class:`_AdbPushOnClose` on flush/close.

        Atomic, as the other backends' writes: the bytes go to a temporary
        name beside the target (``.<name>.axross-part-<pid>-<random>``),
        which a rename makes the target when it is complete - a broken or
        cancelled upload leaves the old file as it was. A folder that takes
        no new file (the target alone is writable) gets the bytes in
        place, as before; so does a push to a fresh private name of
        axross's own (*atomic* False: install_apk's package)."""
        try:
            remote_path.encode("utf-8")
        except UnicodeEncodeError:
            # adb_shell builds the SEND request with str.format + utf-8.
            raise OSError(
                errno.EINVAL,
                f"ADB push({remote_path!r}): an upload to a name that is not UTF-8 is "
                "not possible",
                remote_path,
            ) from None
        if hooks is not None and hooks.cancelled():
            # Nothing sent yet: the destination is as it was.
            raise transfer_hooks.UploadCancelled(transfer_hooks.CANCELLED)
        if not atomic:
            self._send_file(local_path, remote_path, hooks)
            return
        folder = posixpath.dirname(remote_path) or "/"
        temp = posixpath.join(folder, f".{posixpath.basename(remote_path)[:80]}"
                                      f".axross-part-{os.getpid()}-{secrets.token_hex(4)}")
        try:
            self._send_file(local_path, temp, hooks)
        except InterruptedError:
            self._drop_temp(temp)
            raise
        except OSError as exc:
            self._drop_temp(temp)
            if not (_names(exc.__cause__ or exc) & _COMMAND_ERRORS):
                raise
            # The folder refused the new name: the target itself may be
            # writable (an app's folder, a file shared by another app).
            log.info("ADB push(%s): the folder takes no temporary file (%s); written in place",
                     remote_path, exc)
            self._send_file(local_path, remote_path, hooks)
            return
        try:
            self._commit_push(temp, remote_path)
        except BaseException:
            self._drop_temp(temp)
            raise

    def _send_file(self, local_path: str, remote_path: str, hooks) -> None:
        """One sync SEND of *local_path* to *remote_path*."""
        timeout = self._transport_timeout
        try:
            with self._transfer_channel() as device:
                if hooks is None:
                    device.push(local_path, remote_path, st_mode=_PUSH_MODE,
                                transport_timeout_s=timeout, read_timeout_s=timeout)
                    return
                size = os.path.getsize(local_path)
                with open(local_path, "rb") as fh:
                    source = _PushSource(fh, hooks, size, abort=lambda: _close_quietly(device))
                    with _closed_on_cancel(device, hooks, source):
                        device.push(source, remote_path, st_mode=_PUSH_MODE,
                                    transport_timeout_s=timeout, read_timeout_s=timeout)
                hooks.sent(size, size, check=False)
        except InterruptedError:
            raise  # a part of the file may be there: the engine rolls back
        except Exception as exc:
            raise self._error(f"ADB push({remote_path})", exc, timeout) from exc

    def push_stream(self, source, remote_path: str) -> None:
        """Send the open binary file *source* to *remote_path* (mode 0644)
        as it is: no temporary name - for a fresh private name of the
        caller's (core.adb_device's APK upload). An exception out of
        *source* (its Cancel, its size check) drops the connection that
        carried the half transfer."""
        _checked(remote_path)
        timeout = self._transport_timeout
        try:
            with self._transfer_channel() as device:
                device.push(_StreamSource(source), _RawCommand(remote_path), st_mode=_PUSH_MODE,
                            transport_timeout_s=timeout, read_timeout_s=timeout)
        except (InterruptedError, ValueError):
            raise
        except Exception as exc:
            raise self._error(f"ADB push({remote_path})", exc, timeout) from exc

    def pull_stream(self, remote_path: str, sink, max_bytes: int) -> None:
        """Write the device file *remote_path* into the open binary file
        *sink*; OSError (EFBIG) once more than *max_bytes* arrive - the
        connection is closed then, so the rest of the file is not read."""
        _checked(remote_path)
        timeout = self._transport_timeout
        try:
            with self._transfer_channel() as device:
                device.pull(_RawCommand(remote_path),
                            _CappedSink(sink, max_bytes, remote_path,
                                        abort=lambda: _close_quietly(device)),
                            transport_timeout_s=timeout, read_timeout_s=timeout)
        except Exception as exc:
            if isinstance(exc, OSError) and exc.errno == errno.EFBIG:
                raise
            raise self._pull_refused(remote_path, exc) from exc

    def _commit_push(self, temp: str, remote_path: str) -> None:
        """The complete *temp* becomes *remote_path* (a rename in one
        folder); a folder in the target's place is refused."""
        p, t = shlex.quote(remote_path), shlex.quote(temp)
        out = self._shell(
            f"( p={p}; t={t}; "
            'if [ -d "$p" ]; then echo "$p: Is a directory"; exit 1; fi; '
            'mv -f -- "$t" "$p" ) 2>&1'
        )
        if out.strip():
            from core.exec_util import ls_error

            raise ls_error(f"ADB push({remote_path})", out.strip()[:500])

    def _drop_temp(self, temp: str) -> None:
        """Remove an upload's temporary file; a failure is logged."""
        try:
            self._shell(f"rm -f -- {shlex.quote(temp)}")
        except Exception as exc:  # noqa: BLE001 - the upload's own error counts
            log.warning("ADB: could not remove the temporary file %s: %s", temp, exc)

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    def remove(self, path: str, recursive: bool = False) -> None:
        from core.telnet_client import remove_command

        with _command_timeout(self._long_timeout):  # rm -rf of a big folder
            out = self._shell(remove_command(path, recursive=recursive, quote=self._shell_q))
        if out.strip():
            # rm on Android's toybox is quiet on success; any output
            # indicates a refusal - ls's "No such file or directory" for a
            # path that is not there (rm -f alone said nothing for it).
            from core.exec_util import ls_error

            raise ls_error(f"ADB rm({path})", out.strip()[:500])

    def mkdir(self, path: str) -> None:
        out = self._shell(f"mkdir {self._shell_q(path)}")
        if out.strip():
            # Typed by mkdir's wording: "File exists" for an existing
            # folder was a plain OSError (core.exec_util.ls_error).
            from core.exec_util import ls_error

            raise ls_error(f"ADB mkdir({path})", out.strip()[:500])

    def rename(self, src: str, dst: str) -> None:
        # Plain mv moves src INTO an existing folder dst and says nothing
        # (review B6, 2026-10-17); the guard's message is the error.
        from core.telnet_client import rename_command

        with _command_timeout(self._long_timeout):  # mv to another file system copies
            out = self._shell(rename_command(_checked(src), _checked(dst)))
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

    def set_modified(self, path: str, mtime: float) -> None:
        """Give *path* the modification time *mtime* (whole seconds), so an
        upload keeps its source's time (core.transfer_worker); a push
        stamps the time of the upload. ``touch -t`` under UTC, which
        toybox and busybox take."""
        stamp = datetime.fromtimestamp(int(mtime), tz=timezone.utc).strftime("%Y%m%d%H%M.%S")
        out = self._shell(f"TZ=UTC0 touch -c -m -t {stamp} {self._shell_q(path)}")
        if out.strip():
            raise OSError(f"ADB touch({path}): {out.strip()[:500]}")
        # -c makes no file: a missing one said nothing.
        self.stat(path)

    def readlink(self, path: str) -> str:
        out = self._shell(f"readlink {self._shell_q(path)}").strip()
        if not out:
            raise OSError(f"ADB readlink({path}): not a symlink or missing")
        return out

    def copy(self, src: str, dst: str) -> None:
        from core.telnet_client import copy_command

        with _command_timeout(self._long_timeout):  # cp of a big file
            out = self._shell(copy_command(_checked(src), _checked(dst)))
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
        with _command_timeout(self._long_timeout):  # a big file takes a while
            out = self._shell(f"{tool} {self._shell_q(path)}").strip()
        if not out:
            return ""
        from core.exec_util import digest_from_sum_output

        # `sha256sum` prints "<hex>  <path>" (a leading backslash when the
        # name is escaped) — keep just the hex, of the algorithm's length.
        first = digest_from_sum_output(out, algorithm)
        if not first:
            return ""
        # "<algo>:<hex>" like every other backend: the transfer worker
        # compares the algorithm part before it compares digests.
        return f"{algorithm}:{first}"

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
            raise ValueError("ADB shell(cmd): refusing CR/LF (would smuggle a second shell line)")
        return self._shell(cmd)

    def exec(
        self,
        cmd: str,
        *,
        timeout: float | None = 30.0,
        stdin: bytes | None = None,
        stdout_cap: int = 1024 * 1024,
        stderr_cap: int = 64 * 1024,
        env: dict[str, str] | None = None,
    ) -> "ExecResult":
        """Run *cmd* on the device - same shape as ``SSHSession.exec``.

        The adb shell stream carries no exit status, so the command
        reports it in a trailer line with a per-call tag; stdout and
        stderr arrive mixed in ``stdout``. *stdin* goes to a temporary
        file under /data/local/tmp that the command reads.
        """
        import secrets

        from core.exec_util import capped, sh_env_prefix

        if "\r" in cmd or "\n" in cmd:
            raise OSError("ADB exec: refusing CR/LF in the command (run a script file instead)")
        prefix = sh_env_prefix(env, "ADB exec")
        if "\r" in prefix or "\n" in prefix:
            raise OSError("ADB exec: refusing CR/LF in an env value")
        tag = f"__AXROSS_RC_{secrets.token_hex(8)}__"
        # Its own sh: 'exit' must not skip the status trailer, and a
        # trailing comment must not swallow it.
        line = f"sh -c {shlex.quote(prefix + cmd)}"
        tmp = None
        if stdin is not None:
            tmp = f"/data/local/tmp/.axross-stdin-{secrets.token_hex(6)}"
            with self.open_write(tmp) as fh:
                fh.write(stdin)
            line = f"{line} < {shlex.quote(tmp)}"
        try:
            keep = _SHELL_KEEP_HEAD.set(max(0, int(stdout_cap)))
            try:
                with _command_timeout(timeout or self._long_timeout):
                    raw = self._shell(f"{line}; echo {tag} $?")
            finally:
                _SHELL_KEEP_HEAD.reset(keep)
        finally:
            if tmp is not None:
                try:
                    self.remove(tmp)
                except OSError as exc:
                    log.warning("ADB exec: could not remove %s: %s", tmp, exc)
        marker = raw.rfind(tag + " ")
        status = raw[marker + len(tag) + 1 :].strip() if marker >= 0 else ""
        if marker < 0 or not status.isdigit():
            raise OSError("ADB exec: output ended without the exit status (connection cut?)")
        out = raw[:marker].encode("utf-8", "surrogateescape")
        return capped(int(status), out, b"", stdout_cap, stderr_cap)

    def install_apk(
        self, local_apk_path: str, *, replace: bool = True, grant_permissions: bool = False
    ) -> str:
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

        remote = f"/data/local/tmp/axross-install-{_os.getpid()}-{_uuid.uuid4().hex[:12]}.apk"
        self._push_file(local_apk_path, remote, atomic=False)  # a fresh name already
        flags = []
        if replace:
            flags.append("-r")
        if grant_permissions:
            flags.append("-g")
        cmd = f"pm install {' '.join(flags)} {self._shell_q(remote)}"
        log.info(
            "ADB install_apk on %s: %s -> %s (flags=%s)",
            self._label,
            local_apk_path,
            remote,
            " ".join(flags) or "(none)",
        )
        try:
            with _command_timeout(self._long_timeout):  # a big app takes a minute
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
                device = self._main()
                try:
                    return device.shell(
                        "screencap -p",
                        transport_timeout_s=self._transport_timeout,
                        read_timeout_s=self._transport_timeout,
                        decode=False,
                    )
                except Exception as exc:
                    self._lost(exc)
                    raise
        except Exception as exc:
            raise OSError(
                f"ADB screencap on {self._label}: {exc}",
            ) from exc

    def logcat_tail(self, *, lines: int = 200, filter_spec: str = "*:V") -> str:
        """Read recent logcat entries and return them as text.

        ``lines`` caps the output count via ``logcat -d -t <n>`` —
        ``-d`` dumps the buffer and exits (no streaming), ``-t``
        keeps the result bounded.

        ``filter_spec`` is the standard logcat filter format,
        e.g. ``"AxrossTag:D *:S"`` for tag-filtering. Default
        ``"*:V"`` captures everything down to verbose.
        """
        if "\r" in filter_spec or "\n" in filter_spec:
            raise ValueError("logcat_tail: filter_spec must not contain CR/LF")
        n = max(1, int(lines))
        return self._shell(f"logcat -d -t {n} {self._shell_q(filter_spec)}")

    def pm_list(self, *, system: bool = True, user: bool = True) -> list[str]:
        """List installed package names via ``pm list packages``.
        ``system=False`` excludes pre-installed system apps,
        ``user=False`` excludes user-installed ones (almost never
        useful but the flag exists for symmetry).

        Returns a sorted list of package names (e.g.
        ``["com.android.chrome", "com.android.settings", ...]``).
        """
        flags = []
        if not system:
            flags.append("-3")  # third-party only (excludes system)
        if not user and not system:
            return []
        if not user and system:
            flags.append("-s")  # system only
        out = self._shell(f"pm list packages {' '.join(flags)}".strip())
        # Each line is "package:com.foo.bar".
        return sorted(
            line.partition(":")[2].strip()
            for line in split_lf_only_stream(out)
            if line.startswith("package:")
        )

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------
    def close(self) -> None:
        self._closed = True
        _close_quietly(self.__dict__.get("_device"))
        _close_quietly(self.__dict__.get("_xfer_device"))

    def disconnect(self) -> None:
        self.close()


class _PullSink(io.BytesIO):
    """Where adb_shell's pull writes (it takes a BytesIO for a stream):
    the spool file, with progress and Cancel per chunk. Cancel closes the
    connection first (*abort*), so the pull's own clean-up (a CLSE it
    waits for) ends at once."""

    def __init__(self, fh, hooks, total: int | None, abort) -> None:
        super().__init__()
        self._fh = fh
        self._hooks = hooks
        self._total = total
        self._abort = abort
        self.done = 0
        self.cancelled = False

    def write(self, data) -> int:  # type: ignore[override]
        hooks = self._hooks
        if hooks is not None and hooks.cancelled():
            self.cancelled = True
            self._abort()
            raise InterruptedError(transfer_hooks.CANCELLED)
        written = self._fh.write(data)
        self.done += len(data)
        if hooks is not None:
            hooks.received(self.done, self._total)
        return written


class _PushSource(io.BytesIO):
    """What adb_shell's push reads (it takes a BytesIO for a stream): the
    spool file, with progress and Cancel per chunk."""

    def __init__(self, fh, hooks, total: int, abort) -> None:
        super().__init__()
        self._fh = fh
        self._hooks = hooks
        self._total = total
        self._abort = abort
        self.done = 0
        self.cancelled = False

    def read(self, n: int | None = -1) -> bytes:  # type: ignore[override]
        if self._hooks.cancelled():
            self.cancelled = True
            self._abort()
            raise InterruptedError(transfer_hooks.CANCELLED)
        data = self._fh.read(n)
        self.done += len(data)
        if data:
            self._hooks.sent(self.done, self._total, check=False)
        return data


class _StreamSource(io.BytesIO):
    """An open binary file in the shape adb_shell's push reads (a BytesIO;
    the adb server's push reads any file object)."""

    def __init__(self, fh) -> None:
        super().__init__()
        self._fh = fh

    def read(self, n: int | None = -1) -> bytes:  # type: ignore[override]
        return self._fh.read(n)


class _CappedSink(io.BytesIO):
    """Where adb_shell's pull writes for :meth:`AdbSession.pull_stream`:
    *fh*, refusing more than *limit* bytes (the connection is closed
    first, *abort*, so the pull's own clean-up ends at once)."""

    def __init__(self, fh, limit: int, path: str, abort) -> None:
        super().__init__()
        self._fh = fh
        self._limit = int(limit)
        self._path = path
        self._abort = abort
        self.done = 0

    def write(self, data) -> int:  # type: ignore[override]
        if self.done + len(data) > self._limit:
            self._abort()
            raise OSError(errno.EFBIG, f"ADB pull({self._path}): larger than {self._limit} bytes")
        self._fh.write(data)
        self.done += len(data)
        return len(data)


@contextlib.contextmanager
def _closed_on_cancel(device, hooks, stream):
    """In a running transfer: close *device* the moment Cancel is pressed
    (core.transfer_hooks.CancelWatch) - a read that waits on a silent
    network wakes at once - and raise InterruptedError for whatever the
    closed connection caused."""
    watch = transfer_hooks.watch_cancel(lambda: _close_quietly(device), hooks) \
        if hooks is not None else None
    try:
        yield
    except BaseException as exc:
        cancelled = stream.cancelled or (watch is not None and watch.fired)
        if cancelled and not isinstance(exc, InterruptedError):
            raise InterruptedError(transfer_hooks.CANCELLED) from exc
        raise
    finally:
        if watch is not None:
            watch.stop()


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
