"""A shell command that ran and failed is not a broken connection.

Before: ``execute_checked`` reported a non-zero exit as ``OSError`` and
``_exec`` treated every ``OSError`` as a dropped link: full reconnect
(login, capability probe, ``echo $HOME``) and the SAME command a second
time - ``mv``/``rm`` included. Only transport failures reconnect now.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as TC  # noqa: E402


class _FakeShell(TC._ShellSession):
    def __init__(self, results) -> None:  # no network
        self.results = list(results)
        self.commands: list[str] = []

    def execute(self, cmd, timeout=TC.CMD_TIMEOUT):
        self.commands.append(cmd)
        res = self.results.pop(0)
        if isinstance(res, BaseException):
            raise res
        return res


def _session(shell, fresh=None) -> TC.TelnetSession:
    s = object.__new__(TC.TelnetSession)
    s._connected = True
    s._shell = shell
    s._transport = mock.Mock(closed=False)
    s.reconnects = 0

    def reconnect():
        s.reconnects += 1
        s._shell = fresh
        return fresh

    s._force_reconnect = reconnect
    return s


class FailedCommandTest(unittest.TestCase):
    def test_happy_a_successful_command_runs_once(self) -> None:
        shell = _FakeShell([("out", 0)])
        s = _session(shell)
        self.assertEqual(s._exec("true"), "out")
        self.assertEqual((shell.commands, s.reconnects), (["true"], 0))

    def test_sad_a_non_zero_exit_raises_without_reconnect_or_rerun(self) -> None:
        shell = _FakeShell([("mv: cannot move", 1)])
        s = _session(shell, fresh=_FakeShell([("", 0)]))
        with self.assertRaises(OSError) as cm:
            s._exec("mv a b")
        self.assertIn("exit 1", str(cm.exception))
        self.assertEqual((shell.commands, s.reconnects), (["mv a b"], 0))

    def test_sad_a_transport_failure_still_reconnects_and_retries_once(self) -> None:
        fresh = _FakeShell([("ok", 0)])
        s = _session(_FakeShell([OSError("connection reset")]), fresh=fresh)
        self.assertEqual(s._exec("ls"), "ok")
        self.assertEqual((s.reconnects, fresh.commands), (1, ["ls"]))

    def test_edge_timeout_still_reconnects(self) -> None:
        fresh = _FakeShell([("ok", 0)])
        s = _session(_FakeShell([TimeoutError("slow")]), fresh=fresh)
        self.assertEqual(s._exec("ls"), "ok")
        self.assertEqual(s.reconnects, 1)

    def test_edge_the_failure_is_still_an_oserror_for_callers(self) -> None:
        self.assertTrue(issubclass(TC.CommandFailed, OSError))
        shell = _FakeShell([("", 2)])
        with self.assertRaises(TC.CommandFailed):
            shell.execute_checked("false")


if __name__ == "__main__":
    unittest.main()
