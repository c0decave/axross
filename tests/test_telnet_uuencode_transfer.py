"""Telnet's uuencode transfer works without the ``uu`` module.

``uu`` was removed from the standard library in Python 3.13. On a host
whose only binary-safe encoder is uuencode, every telnet read and write
did ``import uu`` and raised ModuleNotFoundError - not an OSError, so it
escaped every caller that handles backend failures.

The shell is a recording stand-in; uuencoded text is checked against
the standard encoding of known bytes (``Cat`` -> ``#0V%T``).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as TC  # noqa: E402

# What GNU sharutils prints for ``printf Cat | uuencode -``.
_CAT_UU = "begin 644 -\n#0V%T\n`\nend\n"


class _Shell:
    def __init__(self, reply: str = "", code: int = 0) -> None:
        self.reply, self.code = reply, code
        self.commands: list[str] = []

    def execute(self, cmd: str, timeout: float = 30.0) -> tuple[str, int]:
        self.commands.append(cmd)
        return self.reply, self.code

    def execute_checked(self, cmd: str, timeout: float = 30.0) -> str:
        self.commands.append(cmd)
        return ""


def _session(shell: _Shell) -> TC.TelnetSession:
    s = TC.TelnetSession.__new__(TC.TelnetSession)
    s._shell = shell
    s._connected = True
    s._transport = SimpleNamespace(closed=False)
    s._caps = TC._Capabilities(has_uuencode=True, transfer_method="uuencode")
    return s


class TelnetUuencodeTest(unittest.TestCase):
    def test_happy_read_decodes_uuencode_output(self) -> None:
        s = _session(_Shell(_CAT_UU))
        self.assertEqual(s.open_read("/tmp/cat").read(), b"Cat")

    def test_happy_write_sends_standard_uuencode(self) -> None:
        shell = _Shell()
        with _session(shell).open_write("/tmp/cat") as fh:
            fh.write(b"Cat")
        self.assertIn("uudecode -o /tmp/cat", shell.commands[-1])
        self.assertIn("\n#0V%T\n", shell.commands[-1])
        self.assertIn("begin ", shell.commands[-1])

    def test_sad_garbage_output_is_an_oserror(self) -> None:
        s = _session(_Shell("this is not uuencoded\n"))
        with self.assertRaises(OSError):
            s.open_read("/tmp/x")

    def test_edge_binary_roundtrip_across_line_boundaries(self) -> None:
        data = bytes(range(256)) * 3  # 768 bytes: 17 full 45-byte lines + rest
        shell = _Shell()
        with _session(shell).open_write("/tmp/bin") as fh:
            fh.write(data)
        cmd = shell.commands[-1]
        body = cmd.split("\n", 1)[1].rsplit("\n", 1)[0]  # strip heredoc framing
        self.assertEqual(_session(_Shell(body + "\n")).open_read("/tmp/bin").read(), data)
        empty = _Shell()
        with _session(empty).open_write("/tmp/empty") as fh:
            fh.write(b"")
        body = empty.commands[-1].split("\n", 1)[1].rsplit("\n", 1)[0]
        self.assertEqual(_session(_Shell(body + "\n")).open_read("/tmp/empty").read(), b"")


if __name__ == "__main__":
    unittest.main()
