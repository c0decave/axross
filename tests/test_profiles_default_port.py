"""A profile without a port gets its protocol's port, not SSH's 22.

ConnectionProfile.from_dict defaulted every missing "port" to 22: an
imported or hand-written SMB, DFS-N, NFS or iSCSI profile then dialled
port 22 ("SMB: cannot connect to host:22"), and DFS-N's ``port or 445``
never saw the 0 it relies on.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.profiles import ConnectionProfile, password_needed  # noqa: E402


@pytest.mark.parametrize(
    "protocol, port",
    [("smb", 445), ("dfsn", 445), ("nfs", 2049), ("iscsi", 3260), ("sftp", 22), ("ftp", 21)],
)
def test_sad_an_imported_profile_without_a_port_gets_its_protocol_s_port(protocol, port):
    profile = ConnectionProfile.from_dict({"name": "x", "protocol": protocol, "host": "h"})
    assert profile.port == port


def test_happy_a_profile_s_own_port_is_kept():
    profile = ConnectionProfile.from_dict(
        {"name": "x", "protocol": "smb", "host": "h", "port": 4445})
    assert profile.port == 4445


def test_sad_an_out_of_range_port_falls_back_to_the_protocol_s_port():
    profile = ConnectionProfile.from_dict(
        {"name": "x", "protocol": "nfs", "host": "h", "port": 70000})
    assert profile.port == 2049


def test_sad_an_iscsi_target_without_chap_asks_for_no_password():
    """CHAP needs a user name; without one there is nothing to send - Quick
    Connect asked for a password the target never wanted."""
    assert not password_needed(ConnectionProfile(name="t", protocol="iscsi", host="h"))
    assert password_needed(ConnectionProfile(name="t", protocol="iscsi", host="h",
                                             username="chapuser"))
