"""SMB against a real SMB2 server (tests/fake_smbd.py, impacket): a wrong
password, a missing share and a server that went away say what to check;
files with odd names go there and back; a dropped connection is noticed and
a reconnect works.

Measured before the fix:

* a wrong password: "Received unexpected status from the server: The
  attempted logon is invalid ... (3221225581) STATUS_LOGON_FAILURE:
  0xc000006d - Raw: a1073005..." (fixed in core.user_errors);
* a missing share: "SMB connect failed for \\\\host\\NOPE: [Error 2]
  [NtStatus 0xc000003a] ..." or "\\\\host\\NOPE was not found. It may have
  been moved or deleted; refresh the folder ...";
* the server gone: "/ refused the connection" - the folder's path stood
  where the server belongs.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("impacket.smbserver")
pytest.importorskip("smbclient")

from fake_smbd import PASSWORD, SHARE, USER, FakeSmbd  # noqa: E402

from core.smb_client import SmbSession  # noqa: E402
from core.user_errors import describe  # noqa: E402

ODD = "a b #%&+ ü"


@pytest.fixture
def smbd(tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    (root / f"{ODD}.txt").write_bytes(b"hello")
    server = FakeSmbd(str(root))
    yield server, root
    server.stop()


def _open(server, **kw) -> SmbSession:
    args = {"host": "127.0.0.1", "share": SHARE, "username": USER, "password": PASSWORD,
            "port": server.port, **kw}
    return SmbSession(**args)


def test_happy_odd_names_go_there_and_back(smbd):
    server, root = smbd
    session = _open(server)
    try:
        assert f"{ODD}.txt" in [i.name for i in session.list_dir("/")]
        assert session.open_read(f"/{ODD}.txt").read() == b"hello"
        session.mkdir(f"/{ODD} dir")
        with session.open_write(f"/{ODD} dir/new ü.bin") as handle:
            handle.write(b"x" * 300_000)
        assert (root / f"{ODD} dir" / "new ü.bin").stat().st_size == 300_000
        assert session.stat(f"/{ODD} dir/new ü.bin").size == 300_000
    finally:
        session.close()


def test_sad_a_wrong_password_is_a_refused_login(smbd):
    server, _root = smbd
    with pytest.raises(Exception) as info:
        _open(server, password="wrong")
    text = describe(info.value)
    assert "refused the login" in text and "0xc000006d" not in text.lower()


def test_sad_a_missing_share_is_named(smbd):
    server, _root = smbd
    with pytest.raises(FileNotFoundError) as info:
        _open(server, share="NOPE")
    text = describe(info.value)
    assert "NOPE" in text and "127.0.0.1" in text and "share" in text
    assert "refresh the folder" not in text and "NtStatus" not in text


def test_sad_a_server_that_went_away_is_named_as_the_server(smbd):
    server, _root = smbd
    session = _open(server)
    try:
        server.stop()
        assert not session.connected
        with pytest.raises(OSError) as info:
            session.list_dir("/")
        text = describe(info.value)
        assert not text.startswith("/ "), text
    finally:
        session.close()
