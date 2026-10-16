"""A failed iscsiadm call never carries the CHAP secret in its error.

Before: when the CHAP secret could not be written to the node file,
``_set_chap_if_needed`` fell back to ``iscsiadm ... -n
node.session.auth.password -v <secret>`` through ``_run_privileged``
(``check=True``). A non-zero exit raised ``CalledProcessError`` whose
message is ``Command '[..., '-v', '<secret>']' returned non-zero exit
status N`` - out of ``connect()`` into the "Connection Failed" dialog and
the log. ``_redact_command`` masked only the debug line and the timeout
error.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.iscsi_client import IscsiSession  # noqa: E402

SECRET = "chap-secret-0123456789"


def _client() -> IscsiSession:
    client = object.__new__(IscsiSession)  # no discovery / login in __init__
    client._target_iqn = "iqn.2026-10.example:disk1"
    client._portal_ip, client._portal_port = "192.0.2.10", 3260
    client._username, client._password = "initiator", SECRET
    return client


class ChapErrorTest(unittest.TestCase):
    def _run(self, fail_on: str | None, returncode: int = 1):
        calls: list[list[str]] = []

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            if fail_on is not None and fail_on in cmd:
                err = "iscsiadm: no records found"
                raise subprocess.CalledProcessError(returncode, cmd, "", err)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        client = _client()
        with (
            mock.patch.object(IscsiSession, "_is_root", return_value=True),
            mock.patch.object(IscsiSession, "_write_chap_secrets_to_node_file", return_value=False),
            mock.patch("core.iscsi_client.subprocess.run", side_effect=fake_run),
        ):
            client._set_chap_if_needed()
        return calls

    def test_sad_the_password_update_error_hides_the_secret(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError) as ctx:
            self._run("node.session.auth.password")
        exc = ctx.exception
        self.assertNotIn(SECRET, str(exc))
        self.assertNotIn(SECRET, repr(exc.cmd))
        self.assertIn("node.session.auth.password", str(exc))  # still says what failed
        self.assertEqual(exc.returncode, 1)

    def test_happy_a_successful_update_is_unchanged(self) -> None:
        calls = self._run(None)
        self.assertIn(SECRET, calls[-1])  # the fallback still sends it (documented)

    def test_edge_a_failure_without_a_secret_keeps_its_command_and_code(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError) as ctx:
            self._run("node.session.auth.authmethod", returncode=15)
        self.assertEqual(ctx.exception.returncode, 15)  # _login branches on it
        self.assertIn("CHAP", ctx.exception.cmd)


if __name__ == "__main__":
    unittest.main()
