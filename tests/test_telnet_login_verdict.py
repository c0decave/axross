"""Telnet login: success and failure are read from what the server shows
LAST, not from words anywhere in the answer.

RHEL, CentOS and Fedora greet a successful login with "Last failed login:
... There were 3 failed login attempts since the last successful login."
The client looked for "failed" / "bad" / "invalid" in the whole answer and
refused that login as "invalid credentials". A wrong password ends in a
new ``login:`` prompt, and that is what tells a refusal; the refusal is a
login failure the message layer knows (core.user_errors), not a bare
PermissionError text.

Against a real shell on a pty (tests/telnet_pty_server.py).
"""

from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")

from tests.telnet_pty_server import PtyTelnetServer  # noqa: E402

from core.telnet_client import TelnetSession  # noqa: E402


RHEL_MOTD = (
    "Last failed login: Mon Nov 17 09:12:44 UTC 2026 from 10.0.0.9 on ssh:notty\n"
    "There were 3 failed login attempts since the last successful login.\n"
    "Last login: Sun Nov 16 18:01:02 2026 from 10.0.0.2\n"
)


def test_a_motd_that_mentions_failed_logins_is_a_successful_login(tmp_path):
    with PtyTelnetServer(cwd=str(tmp_path), motd=RHEL_MOTD) as srv:
        session = TelnetSession("127.0.0.1", srv.port, "u", "pw")
        try:
            assert session.home() == str(tmp_path)
            assert session.list_dir(str(tmp_path)) == []
        finally:
            session.close()


def test_a_wrong_password_is_a_login_failure_with_a_helpful_message(tmp_path):
    from core.user_errors import describe

    with PtyTelnetServer(cwd=str(tmp_path)) as srv:
        with pytest.raises(PermissionError) as info:
            TelnetSession("127.0.0.1", srv.port, "u", "wrong")
        assert srv.failed_logins == 1
    text = describe(info.value)
    assert "refused the login" in text, text
