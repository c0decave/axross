"""PJL (Printer Job Language) FileBackend over port 9100.

HP / Brother / Canon / Ricoh / Lexmark MFPs commonly listen on TCP
9100 ("JetDirect" / RAW print). On supported devices PJL exposes a
filesystem on the printer's flash / mass storage:

* ``@PJL FSDIRLIST`` — list a directory
* ``@PJL FSUPLOAD``  — read a file from printer → client
* ``@PJL FSDOWNLOAD`` — write a file from client → printer
* ``@PJL FSDELETE``  — delete

Many MFPs hold scan jobs, address books, fax logs, embedded LDAP
credentials, or firmware staging in the FS — interesting for
security audits.

**Critical safety**: most printers DO NOT speak PJL. Sending raw
PJL bytes to a non-PJL printer prints them, page after page. The
``__init__`` therefore opens a session-validation socket and sends
``@PJL INFO STATUS``; only a *sane PJL response* progresses the
session. If the response is empty / non-PJL / a print job is
already in progress, the constructor refuses to operate.

Every subsequent operation re-checks via the session's cached
device-ID before issuing FS commands. The check is cheap and
guarantees a misconfigured profile cannot accidentally print
gigabytes.
"""
from __future__ import annotations

import io
import logging
import posixpath
import re
import socket
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

PJL_PORT = 9100
DEFAULT_TIMEOUT = 15.0

# PJL frames are bracketed by Universal Exit Language (UEL) bytes
# (ESC ``%-12345X``) so the printer drops out of any prior emulation.
UEL = b"\x1b%-12345X"

# Cap on a single response. Printer FS files are usually small but
# someone could exfil firmware images — 64 MiB ceiling protects the
# UI without rejecting realistic content.
MAX_FILE_BYTES = 64 * 1024 * 1024

# Allow-list for the SAFETY probe response. We accept anything that
# looks like a valid ``@PJL`` reply (case-insensitive, optionally
# preceded by status-code prefix). Rejects responses that start with
# raw text the printer is about to lay down on a page.
_PJL_RESPONSE_RE = re.compile(
    rb"@PJL\s+(INFO|FSDIRLIST|FSUPLOAD|FSDOWNLOAD|FSQUERY|FSDELETE|RDYMSG|USTATUS)",
    re.IGNORECASE,
)

# Filename allow-list. PJL filesystems are usually 8.3 / volume:path
# style on HP devices (e.g. ``0:/PJL/USTATUS.TXT``) — allow that
# plus generic POSIX-y paths. ``:`` is deliberately EXCLUDED so a
# path can't masquerade as a second volume specifier and trick a
# greedy server-side parser into redirecting the op (e.g. /foo:/etc).
# The volume specifier itself goes through _VOLUME_RE separately.
_PATH_RE = re.compile(r"^[0-9A-Za-z._/\-]+$")
# Volume specifier (e.g. ``0:``, ``1:``). Must not embed quotes or
# whitespace — it goes into the NAME="…" frame verbatim and would
# otherwise let a hostile profile.json break out of the quoted field.
_VOLUME_RE = re.compile(r"^[0-9A-Za-z]:?$")


class PjlNotSupported(OSError):
    """Raised when the device on the wire does not respond to PJL.
    The session refuses to send any further commands."""


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _open_socket(host: str, port: int, proxy_config, timeout: float) -> socket.socket:
    if proxy_config is not None and getattr(proxy_config, "enabled", False):
        from core.proxy import create_proxy_socket
        sock = create_proxy_socket(proxy_config, host, port, timeout=timeout)
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _send_pjl(sock: socket.socket, body: bytes) -> None:
    """Frame ``body`` (one or more PJL commands) with UEL guards and
    send it. Each command line MUST end with a newline before the
    closing UEL."""
    if not body.endswith(b"\n"):
        body = body + b"\n"
    sock.sendall(UEL + body + UEL)


def _recv_until(sock: socket.socket, terminator: bytes, max_bytes: int) -> bytes:
    """Read until ``terminator`` appears in the buffer, or EOF, or
    ``max_bytes`` would be exceeded. Returns the bytes received
    (excluding the closing UEL frame)."""
    buf = bytearray()
    while terminator not in buf and len(buf) < max_bytes:
        try:
            chunk = sock.recv(64 * 1024)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Public session
# ---------------------------------------------------------------------------

class PjlSession:
    """PJL backend implementing the FileBackend protocol.

    Construction fails with :class:`PjlNotSupported` when the device
    on the wire does NOT respond to ``@PJL INFO STATUS`` with a
    well-formed PJL reply — the safety guarantee that no axross
    operation can accidentally print bytes.
    """

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str,
        port: int = PJL_PORT,
        username: str = "",
        password: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        volume: str = "0:",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        self._host = host
        self._port = int(port)
        self._timeout = float(timeout)
        # On HP devices "0:" is the default PJL filesystem volume;
        # Lexmark uses "1:", Brother varies. Profile picks one.
        # Hard-validate the volume against a tight allow-list so a
        # hostile profile cannot smuggle a quote / metachar into the
        # NAME="…" envelope of every subsequent FS command.
        cleaned_volume = volume.rstrip("/")
        if not _VOLUME_RE.match(cleaned_volume):
            raise OSError(
                f"PJL volume {volume!r} is outside the safe set "
                "[0-9A-Za-z][:]"
            )
        self._volume = cleaned_volume
        self._device_id = ""
        self._safety_probed = False
        from core.proxy import ProxyConfig
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host, port=int(proxy_port or 0),
            username=proxy_username, password=proxy_password,
        )
        self._safety_probe()
        log.info(
            "PJL session ready: %s:%d (volume=%s, device-id=%r)",
            host, self._port, self._volume, self._device_id[:80],
        )

    # ------------------------------------------------------------------
    # SAFETY probe
    # ------------------------------------------------------------------

    def _safety_probe(self) -> None:
        """Open one socket, send ``@PJL INFO ID`` + ``@PJL INFO STATUS``,
        and refuse to mark the session usable unless the response is a
        recognisable PJL reply.

        This is the mandatory gate that prevents axross from blasting
        bytes at a printer that does not speak PJL — we'd otherwise
        print them.
        """
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            _send_pjl(sock, b"@PJL INFO ID\n@PJL INFO STATUS\n")
            response = _recv_until(sock, UEL, max_bytes=4096)
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        if not response.strip():
            raise PjlNotSupported(
                f"PJL safety probe: {self._host}:{self._port} returned "
                "no data — refusing to send PJL commands (could be a "
                "non-PJL printer that would print the bytes)."
            )
        if not _PJL_RESPONSE_RE.search(response):
            # Show the first 200 bytes verbatim (escaped) so the
            # operator can see what the wire actually said.
            preview = response[:200].decode("latin-1", "replace")
            raise PjlNotSupported(
                f"PJL safety probe: {self._host}:{self._port} did not "
                f"return a recognised PJL reply. Preview: {preview!r}. "
                "Refusing to mount."
            )
        self._device_id = response.decode("latin-1", "replace").strip()
        self._safety_probed = True

    def _ensure_safe(self) -> None:
        if not self._safety_probed:
            raise PjlNotSupported("PJL session not safety-probed; refusing")

    def _per_op_revalidate(self, response: bytes) -> None:
        """Per-op MITM check: every FS op now prepends ``@PJL INFO STATUS``
        to its frame and the response is required to contain a
        well-formed PJL reply. If a MITM swapped the device for a
        non-PJL host between the initial probe and now, this catches
        it on the very first op and refuses."""
        if not _PJL_RESPONSE_RE.search(response):
            preview = response[:200].decode("latin-1", "replace")
            raise PjlNotSupported(
                f"PJL per-op revalidation failed for {self._host}:{self._port}: "
                f"response did not contain a recognised PJL reply. "
                f"Preview: {preview!r}. Refusing further ops."
            )

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"PJL: {self._host}:{self._port} ({self._volume})"

    @property
    def connected(self) -> bool:
        return self._safety_probed

    def close(self) -> None:
        # PJL is connectionless from our perspective — every op opens
        # its own socket. Nothing to close.
        pass

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path) or "/"

    def _to_pjl_path(self, path: str) -> str:
        """Translate ``/foo/bar`` → ``0:/foo/bar`` for the configured
        volume. Validates every byte against the safe character set."""
        path = self.normalize(path)
        if not _PATH_RE.match(path):
            raise OSError(
                f"PJL path contains characters outside [0-9A-Za-z._/:-]: {path!r}"
            )
        if path == "/":
            return f"{self._volume}/"
        return f"{self._volume}{path}"

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        self._ensure_safe()
        target = self._to_pjl_path(path)
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            # Prepend INFO STATUS so the response carries a per-op
            # PJL signature; without it a MITM-substituted non-PJL
            # device would only be caught on parse failure (silent
            # corruption otherwise).
            cmd = (
                b'@PJL INFO STATUS\n'
                + f'@PJL FSDIRLIST NAME="{target}" ENTRY=1 COUNT=65535\n'.encode()
            )
            _send_pjl(sock, cmd)
            blob = _recv_until(sock, UEL, max_bytes=4 * 1024 * 1024)
        finally:
            sock.close()
        self._per_op_revalidate(blob)
        return self._parse_fsdirlist(blob)

    @staticmethod
    def _parse_fsdirlist(blob: bytes) -> list[FileItem]:
        """Parse a FSDIRLIST response. Lines look like::

            "filename" TYPE=FILE SIZE=12345
            "subdir"   TYPE=DIR

        Real printers vary; we be tolerant. The parser drops anything
        we can't interpret.
        """
        items: list[FileItem] = []
        text = blob.decode("latin-1", "replace")
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("@PJL") or line.startswith("ESC"):
                continue
            # Two common forms: ``NAME TYPE=DIR`` or ``NAME TYPE=FILE SIZE=N``
            parts = line.split()
            if len(parts) < 2:
                continue
            # Strip surrounding quotes if present.
            name = parts[0].strip('"')
            type_field = ""
            size = 0
            for token in parts[1:]:
                if token.upper().startswith("TYPE="):
                    type_field = token[5:].upper()
                elif token.upper().startswith("SIZE="):
                    try:
                        size = int(token[5:])
                    except ValueError:
                        size = 0
            is_dir = type_field == "DIR"
            items.append(FileItem(
                name=name, is_dir=is_dir, is_link=False,
                size=size, modified=datetime.fromtimestamp(0),
                permissions=0o555 if is_dir else 0o444,
            ))
        return items

    def stat(self, path: str) -> FileItem:
        self._ensure_safe()
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o555,
            )
        # PJL has no single-entry stat — list the parent and find us.
        parent = self.parent(path)
        leaf = posixpath.basename(path)
        for item in self.list_dir(parent):
            if item.name == leaf:
                return item
        raise OSError(f"PJL stat({path}): not found")

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

    def open_read(self, path: str) -> IO[bytes]:
        self._ensure_safe()
        target = self._to_pjl_path(path)
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            cmd = (
                b'@PJL INFO STATUS\n'
                + f'@PJL FSUPLOAD NAME="{target}" OFFSET=0 SIZE={MAX_FILE_BYTES}\n'.encode()
            )
            _send_pjl(sock, cmd)
            blob = _recv_until(sock, UEL, max_bytes=MAX_FILE_BYTES + 4096)
        finally:
            sock.close()
        self._per_op_revalidate(blob)
        # The response carries an "@PJL FSUPLOAD ..." header line then
        # the bytes; isolate the content after the first blank line.
        marker = b"\r\n\r\n"
        idx = blob.find(marker)
        if idx == -1:
            marker = b"\n\n"
            idx = blob.find(marker)
        body = blob if idx == -1 else blob[idx + len(marker):]
        # ``rstrip(UEL)`` would treat UEL as a SET of byte values and
        # strip any of {0x1B, 0x25, 0x2D, 0x31..0x35, 0x58} from the
        # tail — silently corrupting binaries that happen to end in
        # those bytes. Use ``removesuffix`` so we strip only the exact
        # frame terminator (and only once).
        return io.BytesIO(body.removesuffix(UEL))

    def readlink(self, path: str) -> str:
        raise OSError("PJL has no symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("PJL has no version history")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return ""

    # ------------------------------------------------------------------
    # PJL-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    # Categories that ``@PJL INFO <CAT>`` accepts on most HP devices.
    # Whitelisted so a tainted category can't smuggle a second PJL
    # command (categories are otherwise interpolated into the wire
    # frame).
    _INFO_CATEGORIES = {
        "ID", "STATUS", "CONFIG", "FILESYS", "MEMORY", "PAGECOUNT",
        "VARIABLES", "PRODINFO", "USTATUS", "SUPPLIES", "TONER",
    }

    def info(self, category: str = "ID") -> str:
        """``@PJL INFO <CATEGORY>`` — request informational text from
        the printer. Returns the body of the response (UEL frames
        stripped).

        Categories restricted to the well-known ``_INFO_CATEGORIES``
        whitelist; anything else raises ``ValueError`` BEFORE the
        device connect, so a tainted user input can't smuggle a
        second PJL command via the category slot.
        """
        cat = category.strip().upper()
        if cat not in self._INFO_CATEGORIES:
            raise ValueError(
                f"PJL info() category {category!r} not in allow-list "
                f"({sorted(self._INFO_CATEGORIES)})"
            )
        self._ensure_safe()
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            _send_pjl(sock, f"@PJL INFO {cat}\n".encode("ascii"))
            response = _recv_until(sock, UEL, max_bytes=256 * 1024)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        self._per_op_revalidate(response)
        # Strip the leading UEL + the @PJL header line; return the body
        # (everything between the first newline after @PJL and the
        # closing UEL).
        text = response.decode("latin-1", errors="replace")
        # Find and strip from the @PJL INFO header onward.
        marker = f"@PJL INFO {cat}"
        idx = text.find(marker)
        if idx >= 0:
            # Skip past the line that contains the marker.
            nl = text.find("\n", idx)
            if nl >= 0:
                text = text[nl + 1:]
        # Strip a trailing FF / form-feed which printers append.
        return text.replace("\x0c", "").rstrip()

    def status(self) -> str:
        """Convenience wrapper — ``self.info("STATUS")`` (the most
        useful query for triage: paper/toner/jam/ready). Identical
        return shape."""
        return self.info("STATUS")

    def eject_paper(self) -> None:
        """``@PJL EJECT`` — force a form-feed of the current page.
        Useful when a partial print job has stranded a sheet in the
        engine. No response data; we still do the per-op revalidation
        on whatever the device returns to defend against MITM."""
        self._ensure_safe()
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            _send_pjl(sock, b"@PJL INFO STATUS\n@PJL EJECT\n")
            response = _recv_until(sock, UEL, max_bytes=4096)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        self._per_op_revalidate(response)

    # ------------------------------------------------------------------
    # FileBackend — write surface
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            raise OSError("PJL has no append primitive")
        self._ensure_safe()
        return _PjlWriter(self, path)

    def remove(self, path: str, recursive: bool = False) -> None:
        self._ensure_safe()
        target = self._to_pjl_path(path)
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            cmd = (
                b'@PJL INFO STATUS\n'
                + f'@PJL FSDELETE NAME="{target}"\n'.encode()
            )
            _send_pjl(sock, cmd)
            blob = _recv_until(sock, UEL, max_bytes=4096)
        finally:
            sock.close()
        self._per_op_revalidate(blob)

    def mkdir(self, path: str) -> None:
        # FSMKDIR is supported by some PJL stacks (HP's mainline,
        # Lexmark's MarkVision) but absent from many others. PJL is
        # fire-and-forget, so we send the command then probe via a
        # follow-up ``stat()`` to confirm; if the directory still
        # doesn't exist afterwards we log a warning so the operator
        # knows the firmware silently dropped the request.
        self._ensure_safe()
        target = self._to_pjl_path(path)
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            cmd = (
                b'@PJL INFO STATUS\n'
                + f'@PJL FSMKDIR NAME="{target}"\n'.encode()
            )
            _send_pjl(sock, cmd)
            blob = _recv_until(sock, UEL, max_bytes=4096)
        finally:
            sock.close()
        self._per_op_revalidate(blob)
        # Post-op verification: most printers don't surface an error
        # code for unsupported FSMKDIR, they just no-op. A follow-up
        # stat catches that without breaking the caller.
        try:
            if not self.is_dir(path):
                log.warning(
                    "PJL FSMKDIR(%s) on %s appears to have been ignored "
                    "(no directory entry visible after the op). The "
                    "firmware on this device may not implement FSMKDIR.",
                    path, self._host,
                )
        except Exception:  # noqa: BLE001 — verification is best-effort
            pass

    def rename(self, src: str, dst: str) -> None:
        # PJL has no native rename — emulate via upload + delete only
        # if the caller really wants it. For v1 refuse cleanly so the
        # operator picks the right tool.
        raise OSError("PJL: rename not supported (no native primitive)")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("PJL carries no POSIX permissions")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("PJL has no server-side copy")

    # ------------------------------------------------------------------
    # Internal: actual upload (called by writer.close)
    # ------------------------------------------------------------------

    def _upload(self, path: str, data: bytes) -> None:
        target = self._to_pjl_path(path)
        size = len(data)
        # FSDOWNLOAD does not return an OK status, so the per-op
        # revalidation runs as a SEPARATE prior probe — we hold off on
        # the actual write until the device confirms it's still PJL.
        probe = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            _send_pjl(probe, b"@PJL INFO STATUS\n")
            self._per_op_revalidate(_recv_until(probe, UEL, max_bytes=4096))
        finally:
            probe.close()
        sock = _open_socket(self._host, self._port, self._proxy, self._timeout)
        try:
            header = (
                f'@PJL FSDOWNLOAD FORMAT:BINARY SIZE={size} NAME="{target}"\n'
            ).encode()
            sock.sendall(UEL + header + data + b"\n" + UEL)
        finally:
            sock.close()


class _PjlWriter:
    def __init__(self, session: PjlSession, path: str):
        self._session = session
        self._path = path
        self._buf = io.BytesIO()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("writer closed")
        return self._buf.write(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._session._upload(self._path, self._buf.getvalue())
        self._buf.close()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
