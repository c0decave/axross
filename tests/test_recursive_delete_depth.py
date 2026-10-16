"""A recursive delete stops at a depth bound instead of RecursionError.

Twins of the SMB case (tests/test_smb_recursive_delete_links.py): the
SFTP (SSHSession._rmtree) and FTP (FtpSession._rmdir_recursive) tree
walks recursed once per level with no bound, so a server whose every
directory holds another directory (a loop on the server, or a hostile
server) drove them into RecursionError - not an OSError - after
hundreds of round trips. The bound is core.path_policy's
MAX_RECURSIVE_DELETE_DEPTH; the tests lower it to keep the walk short.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fuzz_server import FakeFtpServer  # noqa: E402
from fuzz_testkit import check_contract  # noqa: E402
from paramiko import SFTPAttributes  # noqa: E402
from sftp_hostile_kit import attr, hostile_session  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core import path_policy  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402

_FTP_REPLIES = {
    "MLSD": b"500 unknown\r\n",
    "FEAT": b"211 end\r\n",
    "DELE": b"250 ok\r\n",
    "RMD": b"250 ok\r\n",
}
_FTP_ENDLESS = {"LIST": b"drwxr-xr-x 1 u g 0 Jan  1 00:00 d\r\n", "NLST": b"d\r\n"}


def _dir_stat() -> SFTPAttributes:
    a = SFTPAttributes()
    a.st_mode, a.st_size = 0o040755, 0
    return a


def test_happy_bound_is_far_beyond_real_trees():
    assert path_policy.MAX_RECURSIVE_DELETE_DEPTH >= 128
    with pytest.raises(OSError, match="deeper than 3 levels"):
        path_policy.check_tree_depth("/x", 4, 3)
    path_policy.check_tree_depth("/x", 3, 3)


def test_happy_sftp_tree_is_removed():
    with hostile_session() as (script, s):
        script.stat = _dir_stat()
        script.listing = [attr("a.txt")]
        s.remove("/sub", recursive=True)


def test_edge_sftp_endless_tree_stops_with_oserror(monkeypatch):
    monkeypatch.setattr(SSHSession, "_MAX_TREE_DEPTH", 5)
    with hostile_session() as (script, s):
        script.stat = _dir_stat()
        script.listing = [attr("d", mode=0o040755)]
        result = check_contract(lambda: s.remove("/sub", recursive=True), (OSError,), timeout=60.0)
        assert isinstance(result, OSError) and "deeper than 5 levels" in str(result)


def test_edge_ftp_endless_tree_stops_with_oserror(monkeypatch):
    monkeypatch.setattr(FC.FtpSession, "_MAX_TREE_DEPTH", 3)
    with FakeFtpServer(replies=_FTP_REPLIES, data=_FTP_ENDLESS) as srv:
        s = FC.FtpSession(srv.host, srv.port, "u", "p")
        result = check_contract(lambda: s.remove("/d", recursive=True), (OSError,), timeout=60.0)
        assert isinstance(result, OSError) and "deeper than 3 levels" in str(result)
