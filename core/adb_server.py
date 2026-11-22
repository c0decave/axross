"""ADB through the adb server of this computer (platform-tools' ``adb``).

A phone on the USB cable belongs to one program: libusb hands its
interface to whoever claims it first. When the adb server of the Android
platform tools runs (``adb start-server``, Android Studio, any ``adb``
command), it holds every phone it sees, and the console's ``adb`` - as many
sessions as you like - talks to the phones through it. axross does the
same here: it speaks the server's host protocol on 127.0.0.1:5037 and
reaches the phone through the server instead of claiming the USB device
itself (core.adb_client falls back to libusb when no server answers).

The server is a program on this computer; its answers are still read as
untrusted input:

* only a server on the loopback address is used (127.0.0.1:5037, or
  ``ADB_SERVER_SOCKET`` / ``ANDROID_ADB_SERVER_PORT`` when they name a
  loopback address); never a remote host;
* every read has a time-out, a host answer a deadline as a whole;
* lengths are four strict hex digits (at most 65535), a FAIL text is cut
  and stripped of control characters, ``host:devices-l`` lines are
  counted and bounded and each serial is checked (:func:`valid_serial`)
  before it goes into ``host:transport:``;
* a sync DATA block is at most 64 KiB, as the protocol says.

The protocols (platform-tools' ``SERVICES.TXT`` and ``SYNC.TXT``): a host
request is four hex digits of length and the request; the answer
``OKAY`` or ``FAIL`` + length + message. ``host:transport:<serial>``
switches the connection to that phone, the next request is a service on
it: ``shell:<command>`` (its output until the connection closes) or
``sync:`` (STAT / RECV / SEND / DONE / QUIT, each an id, a little-endian
32-bit length and data).
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import os
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5037
#: Seconds to wait for the server to take the connection and to answer a
#: host request as a whole (a server trickling its answer is cut off).
PROBE_TIMEOUT = 2.0
#: The longest FAIL text kept (it is read in full, up to 65535 bytes).
FAIL_TEXT_CAP = 300
#: ``host:devices-l``: the most lines read, the longest line kept.
MAX_DEVICES = 256
MAX_LINE = 1024
#: A sync DATA block (SYNC.TXT: "at most 64k").
SYNC_DATA_MAX = 64 * 1024
#: A sync FAIL text (also length-prefixed, 32 bits).
SYNC_FAIL_MAX = 64 * 1024
#: The shell answer read by AdbServerDevice.shell() (core.adb_client's cap).
SHELL_OUTPUT_CAP = 64 * 1024 * 1024

#: A serial the server may name and axross may send back: letters, digits
#: and ``. _ : % @ -`` (USB serials, ``emulator-5554``, ``192.168.1.5:5555``,
#: mDNS names ``adb-XXXX._adb-tls-connect._tcp``). Nothing that could end
#: the request or reach a terminal.
_SERIAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:%@\-]{0,127}")
_HEX4_RE = re.compile(rb"[0-9A-Fa-f]{4}")
_FIELD_RE = re.compile(r"(usb|product|model|device|transport_id):(\S*)")
_FIELD_VALUE_RE = re.compile(r"[A-Za-z0-9._\-]{0,64}")
#: C0 / C1 controls, the blanks and the invisible and bidirectional formatting
#: characters (U+061C, U+180E, U+2060-U+206F, the tag characters among them):
#: a FAIL text or a USB name with one of them read in another order.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u00a0\u00ad\u034f\u061c\u115f\u1160\u180b-\u180f"
                         r"\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\u3164\ufe00-\ufe0f"
                         r"\ufeff\uffa0\ufff9-\ufffb\U000e0000-\U000e007f\U000e0100-\U000e01ef]")

#: The states adb prints; anything else is shown as "unknown".
STATES = frozenset({
    "device", "unauthorized", "offline", "no permissions", "authorizing", "connecting",
    "bootloader", "recovery", "rescue", "sideload", "host", "detached",
})


def valid_serial(serial: str) -> bool:
    """Whether *serial* may go into a ``host:transport:`` request."""
    return bool(serial) and _SERIAL_RE.fullmatch(serial) is not None


def clean_text(raw: bytes | str, cap: int = FAIL_TEXT_CAP) -> str:
    """Text from the server for a message: decoded, control and bidi
    characters dropped, at most *cap* characters."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    text = _CONTROL_RE.sub(" ", text).strip()
    return text[:cap] + ("..." if len(text) > cap else "")


class AdbServerError(OSError):
    """The adb server could not give the phone; :attr:`kind` says why:
    ``unauthorized`` (the phone has not allowed the server's key yet),
    ``offline``, ``no-permissions`` (the server may not open the USB
    device: udev), ``not-found`` (no such phone, or none on USB),
    ``several`` (more than one phone and no serial chosen), ``protocol``
    (the answer is not the adb protocol), ``failed`` (the server said no:
    :attr:`detail`)."""

    def __init__(self, kind: str, message: str, serial: str = "", detail: str = "",
                 address: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.serial = serial
        self.detail = detail
        self.address = address


class AdbServerProtocolError(AdbServerError):
    """The server's answer broke the protocol (a bad length, a wrong id)."""

    def __init__(self, message: str, address: str = "") -> None:
        super().__init__("protocol", message, address=address)


class AdbServerCommandFailed(OSError):
    """The phone refused one sync request (a pull of a missing file, a
    push into a read-only folder): the connection itself is fine."""


@dataclass(frozen=True)
class ServerAddress:
    """Where the adb server is, or why none is used (:attr:`refused`)."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    refused: str = ""
    #: The setting that named the refused address (``NAME=value``).
    setting: str = ""

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def _loopback(host: str) -> str | None:
    """The loopback address *host* names (``localhost`` is 127.0.0.1, not
    asked of the resolver), else None."""
    host = host.strip().strip("[]")
    if host.lower() == "localhost":
        return DEFAULT_HOST
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    return str(address) if address.is_loopback else None


def _port(text: str) -> int | None:
    if not text.isdigit() or len(text) > 5:
        return None
    port = int(text)
    return port if 0 < port < 65536 else None


def server_address(environ=None) -> ServerAddress:
    """The adb server's address: 127.0.0.1:5037, or what
    ``ADB_SERVER_SOCKET`` (``tcp:HOST:PORT`` / ``tcp:PORT``) or
    ``ANDROID_ADB_SERVER_PORT`` set - only a loopback address; another one
    is :attr:`ServerAddress.refused` with the reason."""
    env = os.environ if environ is None else environ
    spec = (env.get("ADB_SERVER_SOCKET") or "").strip()
    if spec:
        setting = f"ADB_SERVER_SOCKET={clean_text(spec, 80)}"
        if not spec.startswith("tcp:"):
            return ServerAddress(refused=f"{setting} is not a TCP address on this computer",
                                 setting=setting)
        rest = spec[4:]
        host, sep, port_text = rest.rpartition(":")
        port = _port(port_text)
        loop = _loopback(host) if sep else DEFAULT_HOST
        if port is None or loop is None:
            return ServerAddress(refused=f"{setting} is not the loopback address; axross uses "
                                         "an adb server on this computer only",
                                 setting=setting)
        return ServerAddress(loop, port)
    port_text = (env.get("ANDROID_ADB_SERVER_PORT") or "").strip()
    if port_text:
        port = _port(port_text)
        if port is None:
            setting = f"ANDROID_ADB_SERVER_PORT={clean_text(port_text, 20)}"
            return ServerAddress(refused=f"{setting} is not a port", setting=setting)
        return ServerAddress(DEFAULT_HOST, port)
    return ServerAddress()


def is_server_port(host: str, port: int, environ=None) -> bool:
    """Whether *host*:*port* is where the adb server listens (TCP mode
    pointed at it, the dialog's "localhost:5037")."""
    address = server_address(environ)
    loop = _loopback(host or "")
    return loop is not None and int(port or 0) == address.port and not address.refused


# --------------------------------------------------------------------------
# One connection to the server
# --------------------------------------------------------------------------
class _Conn:
    """A socket to the server; every read has a time-out, a host answer a
    deadline (:meth:`deadline`)."""

    def __init__(self, address: ServerAddress, timeout: float) -> None:
        self.address = address
        self.timeout = max(0.05, float(timeout or PROBE_TIMEOUT))
        self._deadline: float | None = None
        self.sock = socket.create_connection((address.host, address.port),
                                             timeout=min(self.timeout, PROBE_TIMEOUT * 2))
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        sock, self.sock = self.sock, None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def deadline(self, seconds: float | None) -> None:
        """The reads that follow end by *seconds* from now (None: each
        read has the time-out only)."""
        self._deadline = None if seconds is None else time.monotonic() + seconds

    def _sock(self) -> socket.socket:
        if self.sock is None:
            raise ConnectionResetError(f"the connection to the adb server {self.address} is closed")
        return self.sock

    def _arm(self) -> None:
        wait = self.timeout
        if self._deadline is not None:
            wait = min(wait, self._deadline - time.monotonic())
            if wait <= 0:
                raise TimeoutError(f"the adb server {self.address} did not answer in time")
        self._sock().settimeout(wait)

    def send(self, data: bytes) -> None:
        self._sock().settimeout(self.timeout)
        self._sock().sendall(data)

    def recv_some(self, limit: int) -> bytes:
        """Up to *limit* bytes; b"" at the end of the stream."""
        self._arm()
        try:
            return self._sock().recv(limit)
        except socket.timeout as exc:
            raise TimeoutError(f"the adb server {self.address} did not answer in time") from exc

    def recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.recv_some(n - len(buf))
            if not chunk:
                raise ConnectionResetError(
                    f"the adb server {self.address} closed the connection "
                    f"({len(buf)} of {n} bytes)")
            buf += chunk
        return bytes(buf)

    # -- host protocol ---------------------------------------------------
    def request(self, text: bytes) -> None:
        if len(text) > 0xFFFF:
            raise ValueError("adb server request too long")
        self.send(b"%04x" % len(text) + text)

    def hex4(self) -> int:
        raw = self.recv_exact(4)
        if not _HEX4_RE.fullmatch(raw):
            raise AdbServerProtocolError(
                f"the adb server {self.address} sent no length ({raw[:4]!r})", str(self.address))
        return int(raw, 16)

    def status(self) -> None:
        """Read OKAY, or raise :class:`AdbServerError` for a FAIL."""
        word = self.recv_exact(4)
        if word == b"OKAY":
            return
        if word == b"FAIL":
            detail = clean_text(self.recv_exact(self.hex4()))
            raise AdbServerError("failed", f"adb server: {detail}", detail=detail,
                                 address=str(self.address))
        raise AdbServerProtocolError(
            f"{self.address} did not answer as an adb server ({word!r})", str(self.address))

    def prefixed(self) -> bytes:
        return self.recv_exact(self.hex4())


def _open(address: ServerAddress, timeout: float) -> _Conn:
    if address.refused:
        raise AdbServerError("refused", address.refused, address=str(address))
    return _Conn(address, timeout)


def _host_query(address: ServerAddress, request: bytes, timeout: float) -> bytes:
    conn = _open(address, timeout)
    try:
        conn.deadline(timeout)
        conn.request(request)
        conn.status()
        return conn.prefixed()
    finally:
        conn.close()


def server_version(address: ServerAddress | None = None,
                   timeout: float = PROBE_TIMEOUT) -> int | None:
    """The version of the adb server that answers at *address*, None when
    none does (nothing listens, a refused address, not the protocol)."""
    address = address or server_address()
    if address.refused:
        return None
    try:
        raw = _host_query(address, b"host:version", timeout)
    except (OSError, ValueError) as exc:
        log.debug("adb server %s: %s", address, exc)
        return None
    if not _HEX4_RE.fullmatch(raw):
        log.info("adb server %s: version answer %r is not the protocol", address, raw[:8])
        return None
    return int(raw, 16)


@dataclass(frozen=True)
class ServerDevice:
    """One line of ``host:devices-l``."""

    serial: str
    state: str
    usb: str = ""
    product: str = ""
    model: str = ""
    device: str = ""
    transport_id: str = ""

    @property
    def on_usb(self) -> bool:
        return bool(self.usb)

    @property
    def ready(self) -> bool:
        return self.state == "device"

    def label(self) -> str:
        """``serial - model`` (the model with blanks for underscores)."""
        model = self.model.replace("_", " ")
        return f"{self.serial} - {model}" if model else self.serial


def parse_devices(text: bytes | str) -> list[ServerDevice]:
    """The devices of a ``host:devices-l`` answer; a line whose serial is
    not :func:`valid_serial` is left out, a state adb does not print is
    ``unknown``, a field value that is not plain is dropped."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    found: list[ServerDevice] = []
    seen: set[str] = set()
    for number, line in enumerate(text.split("\n")):
        if number >= MAX_DEVICES or len(found) >= MAX_DEVICES:
            log.info("adb server: more than %d device lines; the rest is not read", MAX_DEVICES)
            break
        line = line.rstrip("\r")
        if not line.strip() or len(line) > MAX_LINE:
            continue
        parts = line.split()
        serial = parts[0]
        if not valid_serial(serial) or serial in seen:
            log.info("adb server: device line with an unusable serial left out")
            continue
        fields: dict[str, str] = {}
        rest = parts[1:]
        while rest:
            match = _FIELD_RE.fullmatch(rest[-1])
            if match is None:
                break
            if _FIELD_VALUE_RE.fullmatch(match.group(2)):
                fields.setdefault(match.group(1), match.group(2))
            rest.pop()
        words = " ".join(rest)
        if words.startswith("no permissions"):
            state = "no permissions"
        else:
            state = rest[0] if rest else ""
            if state not in STATES:
                state = "unknown"
        seen.add(serial)
        found.append(ServerDevice(serial, state, **fields))
    return found


def list_devices(address: ServerAddress | None = None,
                 timeout: float = PROBE_TIMEOUT) -> list[ServerDevice]:
    """The phones the adb server sees (all states). Raises OSError when
    no server answers."""
    address = address or server_address()
    return parse_devices(_host_query(address, b"host:devices-l", timeout))


# --------------------------------------------------------------------------
# A phone through the server, in the shape core.adb_client uses
# --------------------------------------------------------------------------
class AdbServerDevice:
    """The phone *serial* through the adb server, with the methods of
    adb_shell's AdbDevice that core.adb_client calls (connect, shell,
    streaming_shell, pull, push, close, available). Each command opens its
    own connection to the server (the server multiplexes them), so a
    transfer never waits for a listing."""

    def __init__(self, address: ServerAddress, serial: str, *,
                 default_transport_timeout_s: float = 30.0) -> None:
        if not valid_serial(serial):
            raise AdbServerError("not-found", "adb server: an unusable serial", address=str(address))
        self.address = address
        self.serial = serial
        self._timeout = float(default_transport_timeout_s or 30.0)
        self._lock = threading.Lock()
        self._open_conns: set[_Conn] = set()
        self._available = False

    @property
    def available(self) -> bool:
        return self._available

    # -- life cycle ------------------------------------------------------
    def connect(self, rsa_keys=None, transport_timeout_s=None, read_timeout_s=None,  # noqa: ARG002
                auth_timeout_s=60.0, auth_callback=None) -> bool:
        """Check that the server has the phone ready; an unauthorized one
        calls *auth_callback* (it may raise) and is waited for until
        *auth_timeout_s* (the phone's "Allow USB debugging?")."""
        timeout = float(transport_timeout_s or PROBE_TIMEOUT)
        waited_since = None
        while True:
            device = self._find(list_devices(self.address, timeout))
            if device is not None and device.ready:
                self._available = True
                return True
            state = device.state if device is not None else ""
            if state in ("unauthorized", "authorizing", "connecting"):
                if waited_since is None:
                    waited_since = time.monotonic()
                    if auth_callback is not None:
                        auth_callback(self)
                if time.monotonic() - waited_since > float(auth_timeout_s or 0):
                    raise AdbServerError(
                        "unauthorized",
                        f"adb server: the phone {self.serial} has not allowed USB debugging "
                        f"for this computer's adb server within {float(auth_timeout_s or 0):.0f} s",
                        serial=self.serial, address=str(self.address))
                time.sleep(0.5)
                continue
            raise state_error(self.serial, state, self.address)

    def _find(self, devices: list[ServerDevice]) -> ServerDevice | None:
        return next((d for d in devices if d.serial == self.serial), None)

    def close(self) -> None:
        self._available = False
        with self._lock:
            conns, self._open_conns = list(self._open_conns), set()
        for conn in conns:
            conn.close()

    # -- one service on the phone -----------------------------------------
    def _service(self, service: bytes, timeout: float | None) -> _Conn:
        if not self._available:
            raise ConnectionResetError(f"adb server: the connection to {self.serial} is closed")
        conn = _open(self.address, float(timeout or self._timeout))
        with self._lock:
            self._open_conns.add(conn)
        try:
            conn.deadline(float(timeout or self._timeout))
            conn.request(b"host:transport:" + self.serial.encode("ascii"))
            try:
                conn.status()
            except AdbServerError as exc:
                if exc.kind == "failed":
                    raise transport_error(self.serial, exc.detail, self.address) from exc
                raise
            conn.request(service)
            conn.status()
            conn.deadline(None)
        except BaseException:
            self._release(conn)
            raise
        return conn

    def _release(self, conn: _Conn) -> None:
        with self._lock:
            self._open_conns.discard(conn)
        conn.close()

    @staticmethod
    def _command(command) -> bytes:
        if isinstance(command, (bytes, bytearray)):
            return bytes(command)
        return str.encode(command, "utf-8", "surrogateescape")

    def streaming_shell(self, command, transport_timeout_s=None, read_timeout_s=None,
                        decode=True):
        """The output of *command*, chunk by chunk, until the phone ends it."""
        timeout = read_timeout_s or transport_timeout_s or self._timeout
        conn = self._service(b"shell:" + self._command(command), timeout)
        try:
            while True:
                chunk = conn.recv_some(64 * 1024)
                if not chunk:
                    return
                yield chunk.decode("utf-8", "replace") if decode else chunk
        finally:
            self._release(conn)

    def shell(self, command, transport_timeout_s=None, read_timeout_s=None, timeout_s=None,
              decode=True):
        """The whole output of *command* (at most SHELL_OUTPUT_CAP)."""
        deadline = time.monotonic() + timeout_s if timeout_s else None
        out = bytearray()
        for chunk in self.streaming_shell(command, transport_timeout_s, read_timeout_s,
                                          decode=False):
            out += chunk
            if len(out) > SHELL_OUTPUT_CAP:
                raise OSError(errno.EFBIG, f"adb server shell: the answer holds more than "
                                           f"{SHELL_OUTPUT_CAP // (1024 * 1024)} MiB")
            if deadline is not None and time.monotonic() > deadline:
                raise TimeoutError("adb server shell: still answering at its time-out")
        return bytes(out).decode("utf-8", "replace") if decode else bytes(out)

    # -- sync --------------------------------------------------------------
    @staticmethod
    def _sync_request(conn: _Conn, sid: bytes, data: bytes) -> None:
        conn.send(sid + struct.pack("<I", len(data)) + data)

    def _sync_header(self, conn: _Conn) -> tuple[bytes, int]:
        sid, length = struct.unpack("<4sI", conn.recv_exact(8))
        return sid, length

    def _sync_fail(self, conn: _Conn, length: int, what: str) -> AdbServerCommandFailed:
        if length > SYNC_FAIL_MAX:
            raise AdbServerProtocolError(
                f"adb server {what}: a FAIL of {length} bytes", str(self.address))
        return AdbServerCommandFailed(f"{what}: {clean_text(conn.recv_exact(length))}")

    def pull(self, device_path, local_path, progress_callback=None, transport_timeout_s=None,
             read_timeout_s=None):
        """Write the file *device_path* into *local_path* (a path or a
        writable file object)."""
        timeout = read_timeout_s or transport_timeout_s or self._timeout
        path = self._command(device_path)
        if not path:
            raise AdbServerCommandFailed("pull: no device path")
        own = isinstance(local_path, (str, bytes, os.PathLike))
        sink = open(local_path, "wb") if own else local_path  # noqa: SIM115
        conn = self._service(b"sync:", timeout)
        try:
            self._sync_request(conn, b"RECV", path)
            done = 0
            while True:
                sid, length = self._sync_header(conn)
                if sid == b"DATA":
                    if length > SYNC_DATA_MAX:
                        raise AdbServerProtocolError(
                            f"adb server pull: a DATA block of {length} bytes "
                            f"(at most {SYNC_DATA_MAX})", str(self.address))
                    data = conn.recv_exact(length)
                    sink.write(data)
                    done += length
                    if progress_callback is not None:
                        progress_callback(device_path, done, None)
                elif sid == b"DONE":
                    self._quit(conn)
                    return
                elif sid == b"FAIL":
                    raise self._sync_fail(conn, length, f"pull({clean_text(path, 200)})")
                else:
                    raise AdbServerProtocolError(
                        f"adb server pull: an unknown answer {sid!r}", str(self.address))
        finally:
            self._release(conn)
            if own:
                sink.close()

    def push(self, local_path, device_path, st_mode=0o100644, mtime=0, progress_callback=None,
             transport_timeout_s=None, read_timeout_s=None):
        """Send *local_path* (a path or a readable file object) to
        *device_path* with the mode *st_mode*."""
        timeout = read_timeout_s or transport_timeout_s or self._timeout
        path = self._command(device_path)
        if not path:
            raise AdbServerCommandFailed("push: no device path")
        own = isinstance(local_path, (str, bytes, os.PathLike))
        source = open(local_path, "rb") if own else local_path  # noqa: SIM115
        conn = self._service(b"sync:", timeout)
        try:
            self._sync_request(conn, b"SEND", path + b",%d" % int(st_mode))
            done = 0
            while True:
                data = source.read(SYNC_DATA_MAX)
                if not data:
                    break
                self._sync_request(conn, b"DATA", data)
                done += len(data)
                if progress_callback is not None:
                    progress_callback(device_path, done, None)
            stamp = int(mtime or time.time()) & 0xFFFFFFFF
            conn.send(b"DONE" + struct.pack("<I", stamp))
            sid, length = self._sync_header(conn)
            if sid == b"OKAY":
                self._quit(conn)
                return
            if sid == b"FAIL":
                raise self._sync_fail(conn, length, f"push({clean_text(path, 200)})")
            raise AdbServerProtocolError(
                f"adb server push: an unknown answer {sid!r}", str(self.address))
        finally:
            self._release(conn)
            if own:
                source.close()

    def _quit(self, conn: _Conn) -> None:
        try:
            self._sync_request(conn, b"QUIT", b"")
        except OSError:
            pass


def state_error(serial: str, state: str, address: ServerAddress) -> AdbServerError:
    """The error for a phone the server lists as *state* (not "device")."""
    where = str(address)
    if state in ("unauthorized", "authorizing"):
        return AdbServerError("unauthorized", f"adb server: the phone {serial} is unauthorized",
                              serial=serial, address=where)
    if state == "offline":
        return AdbServerError("offline", f"adb server: the phone {serial} is offline",
                              serial=serial, address=where)
    if state == "no permissions":
        return AdbServerError("no-permissions",
                              f"adb server: no permissions for the USB device {serial}",
                              serial=serial, address=where)
    if not state:
        return AdbServerError("not-found", f"adb server {where}: no phone {serial}",
                              serial=serial, address=where)
    return AdbServerError("failed", f"adb server: the phone {serial} is in the state {state}",
                          serial=serial, detail=state, address=where)


def transport_error(serial: str, detail: str, address: ServerAddress) -> AdbServerError:
    """The error for a FAIL of ``host:transport:`` (*detail*: its text)."""
    lowered = detail.lower()
    for word, state in (("unauthorized", "unauthorized"), ("offline", "offline"),
                        ("no permissions", "no permissions"), ("not found", "")):
        if word in lowered:
            return state_error(serial, state, address)
    return AdbServerError("failed", f"adb server: {detail}", serial=serial, detail=detail,
                          address=str(address))


def choose_device(devices: list[ServerDevice], serial: str, *, usb_only: bool,
                  address: ServerAddress) -> ServerDevice:
    """The phone to use: the one with *serial*, else the only ready one
    (on USB when *usb_only*). Raises :class:`AdbServerError` naming why
    there is none."""
    if serial:
        found = next((d for d in devices if d.serial == serial), None)
        if found is None:
            raise AdbServerError(
                "not-found", f"adb server {address}: no phone {serial}", serial=serial,
                detail=", ".join(d.serial for d in devices[:8]), address=str(address))
        return found
    pool = [d for d in devices if d.on_usb] if usb_only else list(devices)
    ready = [d for d in pool if d.ready]
    if len(ready) == 1:
        return ready[0]
    if len(ready) > 1:
        raise AdbServerError(
            "several", f"adb server: {len(ready)} phones are connected; choose one by its serial",
            detail=", ".join(d.serial for d in ready[:8]), address=str(address))
    if pool:
        # None ready: the first one's state says why (unauthorized, ...).
        return pool[0]
    raise AdbServerError("not-found", f"adb server {address}: no phone"
                         + (" on USB" if usb_only else ""), address=str(address))


# --------------------------------------------------------------------------
# What is connected (the connection dialog's device list)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Discovery:
    """The phones found: :attr:`source` ``server`` (the adb server's
    list, all states), ``usb`` (no server answers: the USB descriptors of
    phones with USB debugging, read with libusb) or ``none`` (neither
    could be read: :attr:`note`)."""

    source: str
    devices: tuple[ServerDevice, ...] = ()
    address: str = ""
    note: str = ""


#: The USB interface of adbd: vendor class, subclass 0x42, protocol 1.
_ADB_INTERFACE = (0xFF, 0x42, 0x01)


def usb_descriptors() -> list[ServerDevice]:
    """The phones with USB debugging on the cable, from their USB
    descriptors (libusb; nothing is claimed). A serial that cannot be read
    (no permission for the device) is the ``no permissions`` state with
    the vendor:product id as the name."""
    try:
        import usb1  # type: ignore[import-not-found]
    except ImportError as exc:  # the adb extra brings libusb1
        raise OSError(f"no libusb1 to list the USB devices: {exc}") from exc

    found: list[ServerDevice] = []
    with usb1.USBContext() as context:
        for dev in context.getDeviceIterator(skip_on_error=True):
            try:
                is_adb = any(
                    (s.getClass(), s.getSubClass(), s.getProtocol()) == _ADB_INTERFACE
                    for c in dev.iterConfigurations() for i in c for s in i)
            except Exception:  # noqa: BLE001 - an odd device is skipped
                continue
            if not is_adb:
                continue
            ids = f"{dev.getVendorID():04x}:{dev.getProductID():04x}"
            where = f"{dev.getBusNumber()}-{dev.getPortNumber()}"
            serial = model = ""
            try:
                serial = clean_text(dev.getSerialNumber() or "", 128)
                model = clean_text(dev.getProduct() or "", 64)
            except Exception:  # noqa: BLE001 - no permission to open it
                serial = ""
            model = "_".join(model.split())
            if not _FIELD_VALUE_RE.fullmatch(model):
                model = ""
            if valid_serial(serial):
                found.append(ServerDevice(serial, "device", usb=where, product=ids, model=model))
            else:
                found.append(ServerDevice(ids, "no permissions", usb=where, product=ids))
            if len(found) >= MAX_DEVICES:
                break
    return found


def discover(timeout: float = PROBE_TIMEOUT, environ=None) -> Discovery:
    """The phones the adb server sees, or - when no server answers - the
    phones on USB (:func:`usb_descriptors`)."""
    address = server_address(environ)
    if not address.refused:
        try:
            return Discovery("server", tuple(list_devices(address, timeout)), str(address))
        except AdbServerError as exc:
            if exc.kind != "protocol":
                return Discovery("none", (), str(address), str(exc))
        except OSError as exc:
            log.debug("adb server %s: %s", address, exc)
    try:
        return Discovery("usb", tuple(usb_descriptors()), str(address), address.refused)
    except Exception as exc:  # noqa: BLE001 - no libusb1 / libusb-1.0
        log.info("ADB device list: no adb server on %s and no libusb (%s)", address, exc)
        return Discovery("none", (), str(address), address.refused or str(exc))
