"""SCP: a file whose name is not UTF-8 is listed by its bytes and can be
read, written, renamed and removed - as over SFTP.

The listing was decoded with ``errors="replace"``: a latin-1 name such as
``lat\\xe9.txt`` became ``lat\\ufffd.txt``, a name no file has, so every
action on it failed ("No such file"). Asked with the name as Python
decodes it (``surrogateescape``, how SFTP lists it), paramiko encoded the
command strictly as UTF-8 and raised UnicodeEncodeError - not even an
OSError.

End to end against tests/ssh_shell_testkit.py (commands run in /bin/sh).
"""

from __future__ import annotations

import os
import shutil

import pytest

from core.scp_client import SCPSession
from tests.ssh_shell_testkit import SshShellServer, connect, profile

pytestmark = pytest.mark.skipif(not shutil.which("base64"), reason="needs base64")

RAW = b"lat\xe9 \xff.txt"
NAME = os.fsdecode(RAW)  # 'lat\udce9 \udcff.txt'


@pytest.fixture
def scp(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    srv = SshShellServer(str(root))
    s = connect(SCPSession(profile(srv, "scp")), known_hosts=tmp_path / "known_hosts")
    yield s, root
    s.disconnect()
    srv.close()


def test_happy_listed_by_its_bytes_and_read(scp):
    s, root = scp
    with open(os.fsencode(root) + b"/" + RAW, "wb") as fh:
        fh.write(b"latin")
    assert NAME in [i.name for i in s.list_dir(str(root))]
    path = f"{root}/{NAME}"
    assert s.stat(path).size == 5
    assert s.exists(path)
    assert s.open_read(path).read() == b"latin"


def test_sad_written_renamed_and_removed(scp):
    s, root = scp
    path = f"{root}/{NAME}"
    with s.open_write(path) as fh:
        fh.write(b"new")
    with open(os.fsencode(root) + b"/" + RAW, "rb") as fh:
        assert fh.read() == b"new"
    other = f"{root}/{NAME}.bak"
    s.rename(path, other)
    assert os.path.exists(os.fsencode(root) + b"/" + RAW + b".bak")
    s.remove(other)
    assert os.listdir(os.fsencode(root)) == []


def test_edge_scp_protocol_upload_of_such_a_name(scp):
    s, root = scp
    s._caps = type(s._caps)(transfer_method="scp", has_stat_gnu=True)
    if not shutil.which("scp"):
        pytest.skip("needs scp")
    path = f"{root}/{NAME}"
    with s.open_write(path) as fh:
        fh.write(b"via scp -t")
    with open(os.fsencode(root) + b"/" + RAW, "rb") as fh:
        assert fh.read() == b"via scp -t"
    assert s.open_read(path).read() == b"via scp -t"
