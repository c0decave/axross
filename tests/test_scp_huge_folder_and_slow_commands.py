"""SCP: a huge folder lists, and a slow checksum is waited for.

* ``ls -la`` of a folder was read with the 4 MiB cap meant for command
  output: a folder of some 20 000 files with long names (or 50 000 with
  short ones) failed with "SCP command stdout exceeds 4194304 byte cap".
  SFTP lists up to 300 000 entries; a listing gets room for as many.
* ``sha256sum`` of a big file prints nothing until it is done; after
  30 s (CMD_TIMEOUT) the checksum after an upload was given up as
  "unavailable". Hashing takes as long as reading the file does.

End to end against tests/ssh_shell_testkit.py (commands run in /bin/sh).
"""

from __future__ import annotations

import os
import shutil
import stat

import pytest

from core import scp_client
from core.scp_client import SCPSession
from tests.ssh_shell_testkit import SshShellServer, connect, profile

pytestmark = pytest.mark.skipif(
    not shutil.which("base64") or not shutil.which("sha256sum"), reason="needs coreutils"
)


def _tool(bindir, name: str, body: str) -> None:
    path = bindir / name
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def server(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    env = {"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(root)}
    srv = SshShellServer(str(root), env=env)
    sessions = []

    def open_session():
        s = connect(SCPSession(profile(srv, "scp")), known_hosts=tmp_path / "known_hosts")
        sessions.append(s)
        return s

    yield open_session, root, bindir
    for s in sessions:
        s.disconnect()
    srv.close()


def test_happy_a_folder_with_more_than_4_mib_of_listing(server):
    open_session, root, _ = server
    big = root / "big"
    big.mkdir()
    names = [f"{n:05d}_" + "x" * 200 for n in range(20_000)]
    for name in names:
        (big / name).touch()
    s = open_session()
    listed = {i.name for i in s.list_dir(str(big))}
    assert set(names) <= listed


def test_sad_a_checksum_slower_than_the_command_time_out(server, monkeypatch):
    open_session, root, bindir = server
    (root / "f.bin").write_bytes(b"abc")
    s = open_session()
    monkeypatch.setattr(scp_client, "CMD_TIMEOUT", 0.5)
    _tool(bindir, "sha256sum", 'sleep 1.5; exec /usr/bin/env -i PATH=/usr/bin:/bin sha256sum "$@"')
    assert s.checksum(str(root / "f.bin")) == (
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

