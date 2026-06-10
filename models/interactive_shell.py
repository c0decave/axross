"""Interactive remote shell channel — a thin wrapper around a paramiko
``Channel`` that has been put into shell + PTY mode.

Both :class:`core.ssh_client.SSHSession` and
:class:`core.scp_client.SCPSession` expose ``interactive_shell()`` that
returns one of these. The point is **transport multiplexing**: the
existing paramiko Transport is reused, a NEW SSH channel is opened on
it, a PTY is allocated, and the user's login shell is invoked. File
operations on the same session continue to work because they use a
SEPARATE channel on the same transport.

The wrapper is a deliberately tight surface — paramiko's Channel is
quirky (blocking semantics flip between recv/recv_ready/timeout) and
the interactive-shell use case wants:

* ``read(n)`` — non-blocking read up to ``n`` bytes (falls through to
  blocking read with a deadline when ``timeout`` is set).
* ``read_until(needle, timeout)`` — wait for a marker.
* ``write(data)`` — push bytes to the remote.
* ``resize_pty(cols, rows)`` — propagate terminal-resize so e.g.
  ``htop`` / ``vim`` re-render correctly.
* ``close()`` — close THIS channel; the underlying transport stays
  alive so the parent session keeps working.
* ``interact(stdin, stdout)`` — optional convenience: bidirectional
  copy until either side closes.

The wrapper is iter-able for line-based reads — ``for line in shell:``
yields lines as bytes, terminated by LF.
"""

from __future__ import annotations

import logging
import socket
import time
from typing import IO

log = logging.getLogger(__name__)


class InteractiveShell:
    """Thin wrapper around a paramiko ``Channel`` in shell+PTY mode.

    Closing the wrapper closes only the channel — the parent session's
    transport (and any other channels: SFTP, SCP, etc.) keep running.
    That's the multiplexing property: one TCP connection + auth
    handshake serves both file ops and an interactive shell.
    """

    def __init__(self, channel, *, label: str = "") -> None:
        self._chan = channel
        self._label = label
        self._closed = False
        # Default to non-blocking; per-call ``timeout`` overrides.
        try:
            self._chan.settimeout(0.0)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Identity / state
    # ------------------------------------------------------------------

    @property
    def label(self) -> str:
        return self._label

    @property
    def closed(self) -> bool:
        if self._closed:
            return True
        try:
            return (
                bool(self._chan.exit_status_ready())
                and not bool(self._chan.recv_ready())
                and not bool(self._chan.recv_stderr_ready())
            )
        except Exception:  # noqa: BLE001
            return True

    def fileno(self) -> int:
        """Underlying file descriptor — useful for select() loops."""
        return self._chan.fileno()

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    def write(self, data: bytes) -> int:
        """Send ``data`` to the remote shell. Returns bytes written.

        Raises ``OSError`` if the channel was closed by the peer.
        """
        if self._closed:
            raise OSError("InteractiveShell.write: channel closed")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("InteractiveShell.write expects bytes")
        try:
            return int(self._chan.send(bytes(data)))
        except (OSError, socket.error) as exc:
            raise OSError(
                f"InteractiveShell.write: {exc}",
            ) from exc

    def read(self, n: int = 4096, *, timeout: float | None = None) -> bytes:
        """Read up to ``n`` bytes from the remote. With ``timeout=None``
        the call returns immediately with whatever's buffered (may be
        empty); with a numeric ``timeout`` it blocks up to that many
        seconds for the first byte.

        Returns ``b""`` on EOF (peer closed) or at the timeout.
        """
        if self._closed:
            return b""
        if timeout is None:
            deadline: float = 0.0
        else:
            deadline = time.monotonic() + float(timeout)
        # Wait until either (a) data available, (b) channel closed,
        # (c) deadline elapsed.
        while True:
            if self._chan.recv_ready():
                try:
                    return bytes(self._chan.recv(int(n)))
                except (OSError, socket.error) as exc:
                    raise OSError(
                        f"InteractiveShell.read: {exc}",
                    ) from exc
            if self._chan.exit_status_ready() and not self._chan.recv_ready():
                # Peer closed cleanly; surface as EOF.
                return b""
            if timeout is None:
                return b""
            if time.monotonic() >= deadline:
                return b""
            time.sleep(0.01)

    def read_stderr(self, n: int = 4096, *, timeout: float | None = None) -> bytes:
        """Same shape as :meth:`read` but for the channel's stderr
        sub-stream. Most interactive shells merge stderr into stdout,
        so this is rarely useful — included for symmetry."""
        if self._closed:
            return b""
        if timeout is None:
            deadline: float = 0.0
        else:
            deadline = time.monotonic() + float(timeout)
        while True:
            if self._chan.recv_stderr_ready():
                return bytes(self._chan.recv_stderr(int(n)))
            if self._chan.exit_status_ready() and not self._chan.recv_stderr_ready():
                return b""
            if timeout is None:
                return b""
            if time.monotonic() >= deadline:
                return b""
            time.sleep(0.01)

    def read_until(
        self, needle: bytes, *, timeout: float = 30.0, max_bytes: int = 1024 * 1024
    ) -> bytes:
        """Read until ``needle`` appears in the accumulated stream
        OR ``timeout`` elapses OR ``max_bytes`` is buffered. Returns
        the buffered bytes (which include the needle on success;
        the partial buffer on timeout/cap)."""
        if not isinstance(needle, (bytes, bytearray)):
            raise TypeError("read_until needle must be bytes")
        deadline = time.monotonic() + float(timeout)
        buf = bytearray()
        while time.monotonic() < deadline and len(buf) < max_bytes:
            chunk = self.read(min(4096, max_bytes - len(buf)), timeout=0.1)
            if chunk:
                buf.extend(chunk)
                if needle in buf:
                    return bytes(buf)
            elif self.closed:
                break
        return bytes(buf)

    # ------------------------------------------------------------------
    # PTY size + lifecycle
    # ------------------------------------------------------------------

    def resize_pty(self, cols: int, rows: int) -> None:
        """Tell the remote side our terminal grew/shrank. Programs
        that listen to SIGWINCH (vim, less, htop, tmux) re-render."""
        try:
            self._chan.resize_pty(width=int(cols), height=int(rows))
        except Exception as exc:  # noqa: BLE001
            log.debug("resize_pty(%d, %d) failed: %s", cols, rows, exc)

    def close(self) -> None:
        """Close THIS channel only. The underlying transport (and any
        other channels: SFTP, SCP, file ops) keep working. Idempotent.
        """
        if self._closed:
            return
        self._closed = True
        log.info(
            "InteractiveShell %s closed (transport stays alive for any remaining channels)",
            self._label or "<unlabelled>",
        )
        try:
            self._chan.close()
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "InteractiveShell.close: chan.close() ignored: %s",
                exc,
            )

    def __enter__(self) -> "InteractiveShell":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Iteration — line-based for ``for line in shell``
    # ------------------------------------------------------------------

    def __iter__(self):
        # Use bytearray.find + del so we don't pay an O(n²) re-allocation
        # cost when the remote streams a continuous log without
        # newlines for a while (an earlier draft re-wrapped the buffer
        # via ``bytearray(bytes(buf).partition(...)[2])`` per yield —
        # killed throughput on a chatty journalctl tail).
        buf = bytearray()
        while not self.closed:
            chunk = self.read(4096, timeout=0.5)
            if not chunk:
                if self.closed:
                    break
                continue
            buf.extend(chunk)
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    break
                yield bytes(buf[:nl])
                del buf[: nl + 1]
        if buf:
            yield bytes(buf)

    # ------------------------------------------------------------------
    # Convenience: bidirectional copy
    # ------------------------------------------------------------------

    def interact(self, stdin: IO[bytes], stdout: IO[bytes], *, idle_poll: float = 0.05) -> None:
        """Pump bytes between ``stdin`` (peer-to-our-end) and
        ``stdout`` (our-end-to-peer). Returns when the channel
        closes. Useful for "axross.exec but interactive" scripts;
        most callers will roll their own loop with select() against
        ``self.fileno()``."""
        import select as _select

        sources = [stdin.fileno(), self.fileno()]
        try:
            while not self.closed:
                rlist, _, _ = _select.select(sources, [], [], idle_poll)
                if stdin.fileno() in rlist:
                    data = stdin.read(4096)
                    if not data:
                        # EOF on our stdin — close write side, let the
                        # remote drain its pending output, then exit.
                        try:
                            self._chan.shutdown_write()
                        except Exception:  # noqa: BLE001
                            pass
                        sources = [self.fileno()]
                    else:
                        self.write(data)
                if self.fileno() in rlist:
                    data = self.read(8192)
                    if data:
                        stdout.write(data)
                        try:
                            stdout.flush()
                        except Exception:  # noqa: BLE001
                            pass
        except (OSError, KeyboardInterrupt):
            pass
        finally:
            self.close()
