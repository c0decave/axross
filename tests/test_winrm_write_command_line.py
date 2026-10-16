"""WinRM writes fit the Windows command line, whatever the file size.

pywinrm's ``Session.run_ps`` puts the whole script, UTF-16LE + base64
encoded, on a ``powershell -encodedcommand <...>`` command line
(winrm/__init__.py ``run_ps``). ``_write_bytes`` embedded the file's own
base64 in that script, so the command grew by ~3.6 characters per payload
byte: past the 8,190-character command line of the WinRM cmd shell at
~2 KB, past CreateProcess's 32,767 at ~9 KB. Any larger upload failed.

Driven through the real pywinrm ``Session.run_ps``; ``run_cmd`` - the
call that would go on the wire - is replaced by a recorder that checks
the command length and applies the decoded script to an in-memory file
table.
"""

from __future__ import annotations

import base64
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

winrm = pytest.importorskip("winrm")
from core import winrm_client as WC  # noqa: E402

#: The WinRM cmd shell's command line limit (CreateProcess allows 32,767).
LIMIT = 8190
PREFIX = "powershell -encodedcommand "


class _FakeHost:
    """Applies the scripts _write_bytes generates to a dict of files."""

    def __init__(self, fail_at: int | None = None) -> None:
        self.files: dict[str, bytes] = {}
        self.lengths: list[int] = []
        self.fail_at = fail_at

    @staticmethod
    def _strings(script: str) -> list[str]:
        return re.findall(r"FromBase64String\('([^']*)'\)", script)

    def run_cmd(self, command, args=()):
        assert command.startswith(PREFIX)
        self.lengths.append(len(command))
        if len(command) > LIMIT:
            return winrm.Response((b"", b"The command line is too long.", 1))
        if self.fail_at is not None and len(self.lengths) == self.fail_at:
            return winrm.Response((b"", b"disk full", 1))
        script = base64.b64decode(command[len(PREFIX) :]).decode("utf_16_le")
        strings = self._strings(script)

        def text(i: int) -> str:
            return base64.b64decode(strings[i]).decode()

        if "Move-Item" in script:
            self.files[text(1)] = self.files.pop(text(0))
        elif "Remove-Item" in script:
            self.files.pop(text(0), None)
        elif "WriteAllBytes" in script:
            self.files[text(0)] = base64.b64decode(strings[1])
        elif "FileMode]::Append" in script:
            self.files[text(0)] += base64.b64decode(strings[1])
        else:
            raise AssertionError(f"unexpected script: {script[:200]}")
        return winrm.Response((b"", b"", 0))


def _session(host: _FakeHost) -> WC.WinRMSession:
    s = WC.WinRMSession("127.0.0.1", "u", "p", port=5985, use_https=False)
    s._session.run_cmd = host.run_cmd
    return s


def _write(s, path, data):
    with s.open_write(path) as fh:
        fh.write(data)


@pytest.mark.parametrize("size", [0, 1, 1500, 2300, 9 * 1024, 64 * 1024 + 3])
def test_happy_every_command_fits_and_the_file_is_reassembled(size):
    host = _FakeHost()
    data = bytes((i * 7) % 256 for i in range(size))
    _write(_session(host), "C:\\Users\\u\\f.bin", data)
    assert max(host.lengths) <= LIMIT
    assert host.files == {"C:\\Users\\u\\f.bin": data}


def test_sad_a_failed_chunk_leaves_no_partial_file_and_raises():
    host = _FakeHost(fail_at=3)
    host.files["C:\\d\\f.bin"] = b"old content"
    with pytest.raises(OSError):
        _write(_session(host), "C:\\d\\f.bin", b"x" * 20000)
    # The previous file is untouched and no part file is left behind.
    assert host.files == {"C:\\d\\f.bin": b"old content"}


def test_edge_long_path_still_fits():
    host = _FakeHost()
    path = "C:\\" + "\\".join(["deep-directory-name"] * 12) + "\\f.bin"
    _write(_session(host), path, b"y" * 12000)
    assert max(host.lengths) <= LIMIT
    assert host.files == {path: b"y" * 12000}
