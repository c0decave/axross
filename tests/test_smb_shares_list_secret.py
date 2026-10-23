"""``SmbSession.shares_list`` keeps the password away from any child process.

docs/SECURITY-REVIEW-2026-10.md C-5: the share listing ran
``smbclient -L //host -g -U user%password``; argv is world readable. The fix
of that review moved the password into the child's ``PASSWD`` variable.
Since 2026-10-21 (operator: *„ersetze alles was smb/cifs/wmi betrifft wo wir
BINARIES benutzen, mit impacket"*) there is no child at all: the list comes
from NetShareEnum through impacket in-process (core/smb_shares.py).

A stand-in ``smbclient`` on PATH records whether anything still runs it.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SC = pytest.importorskip("core.smb_client")

SECRET = "s3cr%t pass"


class _Conn:
    seen: list = []

    def __init__(self, remote_name, remote_host, sess_port=445, timeout=60, **kw):
        pass

    def login(self, user, password, domain="", lmhash="", nthash=""):
        _Conn.seen.append((user, password, domain))

    def listShares(self):
        return [
            {"shi1_netname": "public\x00", "shi1_type": 0, "shi1_remark": "Public share\x00"},
            {"shi1_netname": "IPC$\x00", "shi1_type": 0x80000003, "shi1_remark": "IPC Service\x00"},
        ]

    def close(self):
        pass


@pytest.fixture
def fake_smbclient(tmp_path, monkeypatch):
    from core import smb_shares

    record = tmp_path / "record.json"
    script = tmp_path / "bin" / "smbclient"
    script.parent.mkdir()
    script.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json, sys
            with open({str(record)!r}, "w") as fh:
                json.dump({{"argv": sys.argv[1:]}}, fh)
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{script.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    _Conn.seen = []
    monkeypatch.setattr(smb_shares, "_connection_class", lambda: _Conn)
    return record


def test_happy_no_child_process_sees_the_password(fake_smbclient):
    shares = SC.SmbSession.shares_list("fileserver", username="alice", password=SECRET)
    assert [s["name"] for s in shares] == ["public", "IPC$"]
    assert not fake_smbclient.exists(), "the smbclient binary still ran"
    assert _Conn.seen == [("alice", SECRET, "")]


def test_sad_a_percent_in_the_user_name_is_just_a_character_now(fake_smbclient):
    # smbclient split "-U user%pass" itself; impacket takes the name as is.
    SC.SmbSession.shares_list("fileserver", username="al%ice", password=SECRET)
    assert _Conn.seen == [("al%ice", SECRET, "")]
    assert not fake_smbclient.exists()


def test_edge_anonymous_listing_sends_an_empty_login(fake_smbclient):
    SC.SmbSession.shares_list("fileserver")
    assert _Conn.seen == [("", "", "")]
    assert not fake_smbclient.exists()
