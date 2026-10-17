"""Append never replaces a file it could not read (telnet, WinRM).

Both backends emulate append as read-old + write-old-plus-new. They
caught EVERY OSError from the read and carried on with an empty buffer,
so a file that exists but could not be read (permission denied, a
decode failure, WinRM's 32 MiB read cap) was overwritten by the new
bytes alone. Only a file that does not exist may start empty now.

Telnet runs against a fake shell that executes each command with
``/bin/sh -c`` in a temp directory; WinRM against a fake PowerShell
runner at the ``run_ps`` boundary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as TC  # noqa: E402
from core import winrm_client as WC  # noqa: E402


class _LocalShell:
    """``_ShellSession`` stand-in: the remote shell is the local /bin/sh."""

    def __init__(self, cwd: str) -> None:
        self.cwd = cwd

    def execute(self, cmd: str, timeout: float = 30.0) -> tuple[str, int]:
        p = subprocess.run(
            ["/bin/sh", "-c", cmd], cwd=self.cwd, capture_output=True, text=True, timeout=timeout
        )
        return p.stdout + p.stderr, p.returncode

    def execute_checked(self, cmd: str, timeout: float = 30.0) -> str:
        out, code = self.execute(cmd, timeout)
        if code != 0:
            raise OSError(f"exit {code}: {out}")
        return out


@unittest.skipUnless(shutil.which("base64"), "needs base64")
@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads mode-000 files")
class TelnetAppendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="axross-telnet-")
        self.addCleanup(shutil.rmtree, self.root, True)
        s = TC.TelnetSession.__new__(TC.TelnetSession)
        s._shell = _LocalShell(self.root)
        s._connected = True
        s._transport = SimpleNamespace(closed=False)
        s._caps = TC._Capabilities(has_base64=True, transfer_method="base64")
        self.s = s

    def _path(self, name: str) -> str:
        return os.path.join(self.root, name)

    def _append(self, name: str, data: bytes) -> None:
        with self.s.open_write(self._path(name), append=True) as fh:
            fh.write(data)

    def test_happy_append_keeps_the_old_bytes(self) -> None:
        Path(self._path("log")).write_bytes(b"old;")
        self._append("log", b"new")
        self.assertEqual(Path(self._path("log")).read_bytes(), b"old;new")

    def test_sad_unreadable_existing_file_is_not_overwritten(self) -> None:
        p = Path(self._path("secret"))
        p.write_bytes(b"precious")
        p.chmod(0o200)  # write-only: the read fails, a write would succeed
        self.addCleanup(p.chmod, 0o600)
        with self.assertRaises(OSError):
            self._append("secret", b"new")
        p.chmod(0o600)
        self.assertEqual(p.read_bytes(), b"precious")

    def test_edge_missing_file_starts_empty(self) -> None:
        self._append("fresh", b"new")
        self.assertEqual(Path(self._path("fresh")).read_bytes(), b"new")


class _FakePowerShell:
    """Answers the three scripts the append path sends."""

    def __init__(self, *, exists: bool, read_error: str | None, content: bytes = b"") -> None:
        self.exists = exists
        self.read_error = read_error
        self.content = content
        self.written: list[bytes] = []

    def run_ps(self, script: str):
        import base64
        import re

        if "Write-Output 'YES'" in script:  # the exists() probe
            return SimpleNamespace(
                status_code=0, std_out=b"YES" if self.exists else b"NO", std_err=b""
            )
        if "ReadAllBytes" in script:
            if self.read_error:
                return SimpleNamespace(status_code=1, std_out=b"", std_err=self.read_error.encode())
            return SimpleNamespace(
                status_code=0, std_out=base64.b64encode(self.content), std_err=b""
            )
        if "WriteAllBytes" in script:
            data = re.findall(r"FromBase64String\('([^']*)'\)", script)[-1]
            self.written.append(base64.b64decode(data))
            return SimpleNamespace(status_code=0, std_out=b"", std_err=b"")
        raise AssertionError(f"unexpected script: {script[:80]}")


class WinRmAppendTest(unittest.TestCase):
    def _session(self, ps: _FakePowerShell) -> WC.WinRMSession:
        s = WC.WinRMSession.__new__(WC.WinRMSession)
        s._session = ps
        s._host = "win"
        return s

    def test_happy_append_keeps_the_old_bytes(self) -> None:
        ps = _FakePowerShell(exists=True, read_error=None, content=b"old;")
        with self._session(ps).open_write("C:/log.txt", append=True) as fh:
            fh.write(b"new")
        self.assertEqual(ps.written, [b"old;new"])

    def test_sad_too_large_existing_file_is_not_overwritten(self) -> None:
        ps = _FakePowerShell(exists=True, read_error="WinRM open_read: file too large")
        with self.assertRaises(OSError):
            self._session(ps).open_write("C:/big.bin", append=True)
        self.assertEqual(ps.written, [])

    def test_edge_missing_file_starts_empty(self) -> None:
        ps = _FakePowerShell(exists=False, read_error="Cannot find path")
        with self._session(ps).open_write("C:/fresh.txt", append=True) as fh:
            fh.write(b"new")
        self.assertEqual(ps.written, [b"new"])


if __name__ == "__main__":
    unittest.main()
