"""SSHSession: what a server said about hashing is remembered; mode and time
go in one SETSTAT.

Measured before (lab, 20 ms relay, 500-file SFTP upload): the checksum exec
was 35 s of 147 s - on a server that refuses to run commands at all, so it
verified nothing and paid two round trips per file to hear "no" again.
chmod and the time were a SETSTAT each.

Remembered for the session: a command refused after its channel opened,
and a hash tool that is not installed (exit 127). Not remembered: a channel
the server would not open - that can be a passing limit (OpenSSH
MaxSessions), and remembering it would end verification for good.
"""

from __future__ import annotations

import collections
import os
import shutil
import stat
import time
from unittest import mock

import paramiko
import pytest

from core.profiles import ConnectionProfile
from core.ssh_client import SSHSession
from tests import ssh_exec_testkit
from tests.ssh_exec_testkit import ExecServer


def _session(**server_kw):
    server = ExecServer(**server_kw)
    prof = ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1", port=server.port,
                             username="u")
    sess = SSHSession(prof)
    sess._transport = server.client_transport()
    return server, sess


def _count_sessions(sess) -> collections.Counter:
    counts: collections.Counter = collections.Counter()
    real = sess._transport.open_session

    def counted(*a, **k):
        counts["open_session"] += 1
        return real(*a, **k)

    sess._transport.open_session = counted
    return counts


@pytest.fixture
def close_after():
    opened = []
    yield opened.append
    for server, sess in opened:
        sess._transport.close()
        server.close()


# -- happy ---------------------------------------------------------------------------------


@pytest.mark.skipif(not shutil.which("sha256sum"), reason="GNU coreutils needed")
def test_happy_a_working_tool_is_asked_every_time(tmp_path, close_after):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
    server, sess = _session(shell=True, env=env, cwd=str(tmp_path))
    close_after((server, sess))
    (tmp_path / "a").write_bytes(b"one")
    counts = _count_sessions(sess)
    for _ in range(3):
        assert sess.checksum(str(tmp_path / "a")).startswith("sha256:")
    assert counts["open_session"] == 3
    assert sess.checksum_kinds("x") is None


def test_happy_a_refused_command_is_not_asked_again(tmp_path, close_after, monkeypatch):
    monkeypatch.setattr(ssh_exec_testkit._Server, "check_channel_exec_request",
                        lambda self, channel, command: False)
    server, sess = _session(shell=True, cwd=str(tmp_path))
    close_after((server, sess))
    counts = _count_sessions(sess)
    for _ in range(3):
        with pytest.raises(OSError, match="checksum failed"):
            sess.checksum("/x")
    assert counts["open_session"] == 1
    assert sess.checksum_kinds("x") == frozenset()


def test_happy_a_missing_tool_is_not_asked_again(tmp_path, close_after):
    server, sess = _session(shell=True, env={"PATH": str(tmp_path / "none")}, cwd=str(tmp_path))
    close_after((server, sess))
    counts = _count_sessions(sess)
    assert [sess.checksum("/x") for _ in range(3)] == ["", "", ""]
    assert counts["open_session"] == 1
    assert sess.checksum_kinds("x") == frozenset()


# -- sad -----------------------------------------------------------------------------------


def test_sad_a_channel_the_server_would_not_open_is_asked_again(tmp_path, close_after,
                                                                  monkeypatch):
    monkeypatch.setattr(ssh_exec_testkit._Server, "check_channel_request",
                        lambda self, kind, chanid:
                        paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)
    server, sess = _session(shell=True, cwd=str(tmp_path))
    close_after((server, sess))
    counts = _count_sessions(sess)
    for _ in range(2):
        with pytest.raises(OSError):
            sess.checksum("/x")
    assert counts["open_session"] == 2
    assert sess.checksum_kinds("x") is None


def test_sad_a_dead_connection_is_not_taken_for_a_refusal(tmp_path, close_after):
    server, sess = _session(shell=True, cwd=str(tmp_path))
    close_after((server, sess))
    sess._transport.close()
    with pytest.raises((OSError, ConnectionError)):
        sess.checksum("/x")
    assert sess._checksum_unavailable == {}


# -- set_attributes ----------------------------------------------------------------------


@pytest.fixture
def sftp(tmp_path):
    from tests import sftp_testkit
    from tests.sftp_testkit import SftpServer

    requests: collections.Counter = collections.Counter()

    class _Chattr(sftp_testkit._Sftp):
        def chattr(self, path, attr):
            requests["setstat"] += 1
            if requests["refuse"]:
                return paramiko.SFTP_PERMISSION_DENIED
            real = self._real(path)
            if attr.st_mode is not None:
                os.chmod(real, stat.S_IMODE(attr.st_mode))
            if attr.st_mtime is not None:
                os.utime(real, (attr.st_atime, attr.st_mtime))
            return paramiko.SFTP_OK

    root = tmp_path / "root"
    root.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    with mock.patch("pathlib.Path.home", return_value=home), \
            mock.patch.object(sftp_testkit, "_Sftp", _Chattr):
        server = SftpServer(str(root))
        sess = SSHSession(ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                            port=server.port, username="u"))
        sess.connect(password="x", on_unknown_host=lambda _e: True)
        try:
            yield sess, root, requests
        finally:
            sess.disconnect()
            server.close()


def test_happy_mode_and_time_in_one_setstat(sftp):
    sess, root, requests = sftp
    (root / "f").write_bytes(b"x")
    sess.set_attributes("/f", mode=0o640, mtime=1_600_000_000.0)
    assert requests["setstat"] == 1
    st = os.stat(root / "f")
    assert stat.S_IMODE(st.st_mode) == 0o640
    assert int(st.st_mtime) == 1_600_000_000
    assert abs(st.st_atime - time.time()) < 60  # as set_modified: now


def test_edge_only_the_time_leaves_the_mode(sftp):
    sess, root, requests = sftp
    (root / "f").write_bytes(b"x")
    os.chmod(root / "f", 0o604)
    sess.set_attributes("/f", mtime=1_600_000_000.0)
    st = os.stat(root / "f")
    assert stat.S_IMODE(st.st_mode) == 0o604
    assert int(st.st_mtime) == 1_600_000_000


def test_sad_a_missing_file_is_an_oserror(sftp):
    sess, _root, _requests = sftp
    with pytest.raises(OSError):
        sess.set_attributes("/nope", mode=0o600, mtime=1.0)


# -- rename_with_attributes ----------------------------------------------------------------


def test_happy_setstat_and_rename_go_out_together(sftp):
    sess, root, requests = sftp
    (root / ".f.part-1").write_bytes(b"x")
    (root / "f").write_bytes(b"old")  # posix-rename replaces it
    sent = []
    client = sess.sftp
    real = client._async_request
    client._async_request = lambda *a, **k: sent.append(a[1]) or real(*a, **k)
    real_sync = client._request
    synced = []
    client._request = lambda *a, **k: synced.append(a[0]) or real_sync(*a, **k)
    try:
        assert sess.rename_with_attributes("/.f.part-1", "/f", mode=0o640, mtime=1_600_000_000.0)
    finally:
        client._async_request, client._request = real, real_sync
    from paramiko.sftp import CMD_EXTENDED, CMD_SETSTAT

    assert sent == [CMD_SETSTAT, CMD_EXTENDED] and synced == []
    assert not (root / ".f.part-1").exists()
    assert (root / "f").read_bytes() == b"x"
    st = os.stat(root / "f")
    assert stat.S_IMODE(st.st_mode) == 0o640 and int(st.st_mtime) == 1_600_000_000


def test_sad_a_refused_setstat_still_renames_and_says_so(sftp):
    sess, root, requests = sftp
    (root / "t").write_bytes(b"x")
    requests["refuse"] = 1
    assert sess.rename_with_attributes("/t", "/u", mode=0o600, mtime=1.0) is False
    assert (root / "u").read_bytes() == b"x" and not (root / "t").exists()


def test_sad_a_missing_source_raises_like_rename(sftp):
    sess, _root, _requests = sftp
    with pytest.raises(OSError):
        sess.rename_with_attributes("/none", "/u", mode=0o600, mtime=1.0)
