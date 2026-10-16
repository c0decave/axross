"""Telnet/SCP rename onto an existing directory fails like rename(2).

``rename`` ran ``mv SRC DST``. When DST is an existing directory, ``mv``
moves SRC *into* it - silently replacing a same-named file in there -
while the caller believes SRC now sits at DST. ``mv -T`` is GNU only
(BSD/macOS ``mv`` have no such option), so the backends test for a
directory first and keep plain POSIX ``mv``.

Both backends are driven with the real ``/bin/sh`` and ``mv``: Telnet
through a shell session that runs each command with ``sh -c``, SCP end
to end through an in-process paramiko server.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from unittest import mock

import paramiko
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as TC  # noqa: E402
from core.scp_client import SCPSession, _Capabilities  # noqa: E402
from tests.test_scp_large_upload import _ShellServer  # noqa: E402

pytestmark = pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs /bin/sh")


class _ShShell(TC._ShellSession):
    """Runs each command with ``/bin/sh -c``, the way the remote shell would."""

    def __init__(self, cwd: str) -> None:  # no network
        self.cwd = cwd

    def execute(self, cmd, timeout=TC.CMD_TIMEOUT):
        proc = subprocess.run(
            ["/bin/sh", "-c", f"{cmd} 2>&1"],
            cwd=self.cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.returncode


def _telnet(root: str) -> TC.TelnetSession:
    s = object.__new__(TC.TelnetSession)
    s._connected = True
    s._shell = _ShShell(root)
    s._transport = mock.Mock(closed=False)
    s._force_reconnect = mock.Mock(side_effect=AssertionError("no reconnect"))
    return s


@pytest.fixture(params=["telnet", "scp"])
def backend(request, tmp_path):
    root = str(tmp_path)
    if request.param == "telnet":
        yield _telnet(root), tmp_path
        return
    srv = _ShellServer(root)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1",
        port=srv.port,
        username="u",
        password="p",
        allow_agent=False,
        look_for_keys=False,
    )
    s = SCPSession.__new__(SCPSession)
    s._client = client
    s._lock = threading.Lock()
    s._caps = _Capabilities(has_base64=bool(shutil.which("base64")), transfer_method="cat")
    try:
        yield s, tmp_path
    finally:
        client.close()
        srv.close()


def test_happy_rename_to_a_free_name(backend) -> None:
    s, root = backend
    (root / "a.txt").write_text("A")
    s.rename(str(root / "a.txt"), str(root / "b.txt"))
    assert (root / "b.txt").read_text() == "A"
    assert not (root / "a.txt").exists()


def test_sad_rename_onto_an_existing_directory_fails_and_moves_nothing(backend) -> None:
    s, root = backend
    (root / "a.txt").write_text("new")
    (root / "dir").mkdir()
    (root / "dir" / "a.txt").write_text("precious")
    with pytest.raises(OSError):
        s.rename(str(root / "a.txt"), str(root / "dir"))
    assert (root / "a.txt").read_text() == "new"
    assert (root / "dir" / "a.txt").read_text() == "precious"


def test_sad_directory_onto_an_existing_directory_is_not_nested(backend) -> None:
    s, root = backend
    (root / "src").mkdir()
    (root / "src" / "f").write_text("x")
    (root / "dst").mkdir()
    with pytest.raises(OSError):
        s.rename(str(root / "src"), str(root / "dst"))
    assert (root / "src" / "f").is_file()
    assert not (root / "dst" / "src").exists()


def test_edge_symlink_to_a_directory_counts_as_a_directory(backend) -> None:
    s, root = backend
    (root / "a.txt").write_text("A")
    (root / "real").mkdir()
    os.symlink("real", root / "link")
    with pytest.raises(OSError):
        s.rename(str(root / "a.txt"), str(root / "link"))
    assert not (root / "real" / "a.txt").exists()
    assert (root / "a.txt").is_file()


def test_edge_existing_file_is_replaced_like_rename2(backend) -> None:
    s, root = backend
    (root / "a.txt").write_text("A")
    (root / "b.txt").write_text("old")
    s.rename(str(root / "a.txt"), str(root / "b.txt"))
    assert (root / "b.txt").read_text() == "A"


def test_edge_names_with_spaces_quotes_and_leading_dash(backend) -> None:
    s, root = backend
    (root / "-it's a file").write_text("A")
    s.rename("-it's a file", "-new name")  # relative: resolved in the shell's cwd
    assert (root / "-new name").read_text() == "A"
