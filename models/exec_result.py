"""Result of a remote ``exec`` call (SSH/SFTP/SCP/rsh/winrm/cisco/...).

Modelled as an immutable dataclass so callers can pattern-match on the
return code and inspect stdout/stderr separately. ``check()`` raises
``OSError`` with a structured message when the remote exited non-zero —
the common one-liner pattern is::

    out = session.exec("uname -a").check().stdout.decode()

Per-backend implementations cap stdout/stderr at the size limits the
caller passes (default 1 MiB / 64 KiB). When a cap fires, the
corresponding ``truncated_*`` flag is set so a downstream consumer can
tell ``empty body`` from ``cap-clipped body``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    truncated_stdout: bool = False
    truncated_stderr: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self) -> "ExecResult":
        """Return self if returncode == 0; otherwise raise OSError with
        a tail-of-stderr in the message so the failure mode is visible
        without needing to print stderr separately."""
        if self.returncode == 0:
            return self
        # Last 4 KiB of stderr is enough to recognise the failure
        # without flooding the caller's logs.
        tail = self.stderr[-4096:].decode("utf-8", errors="replace").strip()
        raise OSError(f"remote command exited rc={self.returncode}; stderr-tail: {tail!r}")
