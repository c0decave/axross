"""FTP: a file renamed to a path ending in "/" is refused.

The server canonicalizes the target name, so ``rename("/f.txt", "/x/")``
made a FILE ``/x`` - the other backends refuse that (EISDIR) through
core.path_policy.refuse_folder_path, as the backend conformance suite
checks; FTP is not in that suite (no FTP server in the test env), so here
against the scripted fake server.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402


@pytest.fixture
def ftp():
    srv = FakeFtpServer(replies={"FEAT": b"211 end\r\n", "RNFR": b"350 ready\r\n",
                                 "RNTO": b"250 renamed\r\n"})
    session = FC.FtpSession(srv.host, srv.port, "u", "p")
    yield session, srv
    srv.close()


def _kind(session, monkeypatch, *, exists: bool, folder: bool):
    monkeypatch.setattr(session, "exists", lambda p: exists)
    monkeypatch.setattr(session, "is_dir", lambda p: folder)


def test_sad_a_file_renamed_to_a_slash_path_is_refused(ftp, monkeypatch):
    session, srv = ftp
    _kind(session, monkeypatch, exists=True, folder=False)
    with pytest.raises(IsADirectoryError) as caught:
        session.rename("/f.txt", "/x/")
    assert caught.value.errno == errno.EISDIR
    assert not any(c.startswith("RNFR") for c in srv.commands)  # nothing was renamed


def test_happy_a_folder_may_be_renamed_to_a_slash_path(ftp, monkeypatch):
    session, srv = ftp
    _kind(session, monkeypatch, exists=True, folder=True)
    session.rename("/d", "/e/")
    assert "RNTO /e/" in srv.commands


def test_edge_a_missing_source_is_the_servers_answer(ftp, monkeypatch):
    session, srv = ftp
    srv.replies["RNFR"] = b"550 no such file\r\n"
    _kind(session, monkeypatch, exists=False, folder=False)
    with pytest.raises(OSError) as caught:
        session.rename("/gone", "/x/")
    assert not isinstance(caught.value, IsADirectoryError)


def test_happy_a_plain_rename_asks_nothing_first(ftp, monkeypatch):
    session, srv = ftp
    monkeypatch.setattr(session, "exists", lambda p: pytest.fail("asked"))
    session.rename("/f.txt", "/g.txt")
    assert "RNTO /g.txt" in srv.commands
