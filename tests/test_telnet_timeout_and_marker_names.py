"""Telnet: a timed-out command leaves no half-parsed shell behind, and
the prompt marker is taken out of an answer only as a whole line.

Protocol review (round 1):

* ``exec("echo 'it''s")`` - an unbalanced quote - timed out, and the
  login shell stayed inside the open quote: the next command was parsed
  inside it, its quoting flipped, and a listing of a folder named
  ``x; touch PWNED; ) #`` ran ``touch PWNED``. A time-out now ends the
  connection; the next call logs in again.
* ``output.replace(PROMPT_MARKER, "")`` edited every answer: a file
  ``a__AXX_PROMPT__b`` was listed as ``ab``, and deleting the listed
  ``ab`` deleted another file.

Against a real shell on a pty (tests/telnet_pty_server.py).
"""

from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")

from tests.telnet_pty_server import PtyTelnetServer  # noqa: E402

import core.telnet_client as tc  # noqa: E402


def test_sad_a_timed_out_command_does_not_turn_names_into_code(tmp_path):
    evil = tmp_path / "x; touch PWNED; ) #"
    evil.mkdir()
    (evil / "inside").write_text("1")
    with PtyTelnetServer(cwd=str(tmp_path)) as srv:
        s = tc.TelnetSession("127.0.0.1", srv.port, "u", "pw")
        try:
            with pytest.raises(TimeoutError):
                s.exec("echo 'it''s", timeout=2)
            names = [i.name for i in s.list_dir(str(evil))]
        finally:
            s.close()
    assert not (tmp_path / "PWNED").exists()
    assert names == ["inside"]


def test_edge_a_name_holding_the_prompt_marker_is_listed_as_it_is(tmp_path):
    marker = tc._PROMPT_MARKER
    (tmp_path / f"a{marker}b").write_text("x")
    (tmp_path / "ab").write_text("y")
    with PtyTelnetServer(cwd=str(tmp_path)) as srv:
        s = tc.TelnetSession("127.0.0.1", srv.port, "u", "pw")
        try:
            names = sorted(i.name for i in s.list_dir(str(tmp_path)))
            out = s.exec(f"echo 'Q{marker}Q'").stdout
        finally:
            s.close()
    assert names == sorted(["ab", f"a{marker}b"])
    assert out.strip() == f"Q{marker}Q".encode()
