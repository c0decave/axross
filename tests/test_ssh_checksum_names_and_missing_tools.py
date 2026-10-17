"""SSHSession.checksum: names with a backslash, and hosts without the tool.

GNU sha256sum / md5sum escape a file name that holds a backslash or a
newline and mark the line with a leading backslash: ``\\<hex>  a\\\\b``.
The first word was taken as the digest, so such a file got the checksum
``sha256:\\<hex>`` - never equal to the same bytes elsewhere. And on a
host without the tool the shell's "command not found" (exit 127) became
an OSError, while the method promises "" so callers hash the stream
themselves (the MCP checksum tool and the duplicate index did not).

The remote is the local /bin/sh behind a loopback paramiko server.
"""

from __future__ import annotations

import hashlib
import os
import shutil

import pytest

from core.profiles import ConnectionProfile
from core.ssh_client import SSHSession
from tests.ssh_exec_testkit import ExecServer

pytestmark = pytest.mark.skipif(
    not (shutil.which("sha256sum") and shutil.which("md5sum")), reason="GNU coreutils needed"
)

BODY = b"checksum body\n"


def _session(env=None, cwd=None):
    server = ExecServer(shell=True, env=env, cwd=cwd)
    prof = ConnectionProfile(
        name="t", protocol="sftp", host="127.0.0.1", port=server.port, username="u"
    )
    sess = SSHSession(prof)
    sess._transport = server.client_transport()
    return server, sess


@pytest.fixture
def remote(tmp_path):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
    server, sess = _session(env=env, cwd=str(tmp_path))
    try:
        yield sess, tmp_path
    finally:
        sess._transport.close()
        server.close()


@pytest.fixture
def remote_without_tools(tmp_path):
    server, sess = _session(env={"PATH": str(tmp_path / "nothing-here")}, cwd=str(tmp_path))
    try:
        yield sess, tmp_path
    finally:
        sess._transport.close()
        server.close()


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("name", ["plain.txt", "a\\b.txt", "two\nlines.txt", "back\\\\slash"])
def test_happy_the_digest_is_the_content_hash_whatever_the_name(remote, name):
    sess, tmp = remote
    (tmp / name).write_bytes(BODY)
    assert sess.checksum(str(tmp / name)) == "sha256:" + hashlib.sha256(BODY).hexdigest()


def test_happy_md5_of_a_backslash_name(remote):
    sess, tmp = remote
    (tmp / "x\\y").write_bytes(BODY)
    assert sess.checksum(str(tmp / "x\\y"), "md5") == "md5:" + hashlib.md5(BODY).hexdigest()


def _local_sh(cmd: str):
    import subprocess

    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
    return subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, env=env, timeout=30)


def _twin(kind: str):
    """The other shell backends, their remote shell being the local sh."""
    from core.adb_client import AdbSession
    from core.rsh_client import RshError, RshSession
    from core.scp_client import SCPSession
    from core.telnet_client import TelnetSession

    def exec_raw(cmd, timeout=30.0, **kw):
        p = _local_sh(cmd)
        return p.stdout.decode(), p.returncode

    if kind == "rsh":
        s = object.__new__(RshSession)

        def run_remote(cmd, *, stdin=None):
            p = _local_sh(cmd)
            if p.returncode:
                raise RshError(p.stderr.decode())
            return p.stdout

        s._run_remote = run_remote
    elif kind == "adb":
        s = object.__new__(AdbSession)
        s._shell = lambda cmd: _local_sh(cmd).stdout.decode()
    else:
        s = object.__new__(SCPSession if kind == "scp" else TelnetSession)
        s._exec_raw = exec_raw
    return s


@pytest.mark.parametrize("kind", ["rsh", "scp", "telnet", "adb"])
@pytest.mark.parametrize("name", ["plain.txt", "a\\b.txt"])
def test_happy_the_shell_twins_give_the_content_hash(tmp_path, kind, name):
    (tmp_path / name).write_bytes(BODY)
    got = _twin(kind).checksum(str(tmp_path / name))
    assert got == "sha256:" + hashlib.sha256(BODY).hexdigest()


# -- sad ---------------------------------------------------------------------


def test_sad_a_host_without_the_tool_answers_empty(remote_without_tools):
    sess, tmp = remote_without_tools
    (tmp / "f").write_bytes(BODY)
    assert sess.checksum(str(tmp / "f")) == ""


def test_sad_a_missing_file_is_still_an_error(remote):
    sess, tmp = remote
    with pytest.raises(OSError):
        sess.checksum(str(tmp / "missing"))


# -- edge --------------------------------------------------------------------


def test_edge_an_unsupported_algorithm_answers_empty(remote):
    sess, tmp = remote
    (tmp / "f").write_bytes(BODY)
    assert sess.checksum(str(tmp / "f"), "blake2b") == ""


def test_edge_a_tool_that_prints_no_digest_answers_empty(remote, tmp_path):
    sess, tmp = remote
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    tool = fake_bin / "sha256sum"
    tool.write_text("#!/bin/sh\necho 'not-a-digest  x'\n")
    tool.chmod(0o755)
    server, other = _session(env={"PATH": f"{fake_bin}:/usr/bin:/bin"}, cwd=str(tmp))
    try:
        (tmp / "f").write_bytes(BODY)
        assert other.checksum(str(tmp / "f")) == ""
    finally:
        other._transport.close()
        server.close()
