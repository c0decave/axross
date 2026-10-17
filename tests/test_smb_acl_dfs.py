"""SMB acl_get (the security descriptor of a file or folder) and
dfs_referrals (where a DFS path leads). Both raised NotImplementedError
("a follow-up") before.

The descriptor comes from an SMB2 QUERY_INFO of type SECURITY (owner,
group, DACL), the referrals from FSCTL_DFS_GET_REFERRALS on IPC$. The
unit tests build real descriptors with smbprotocol's structures; the
live tests run against the lab's Samba (tests/docker, 10.99.0.31) and
skip without it.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from smbprotocol.security_descriptor import (  # noqa: E402
    AccessAllowedAce,
    AccessDeniedAce,
    AclPacket,
    SDControl,
    SIDPacket,
    SMB2CreateSDBuffer,
)

from core import smb_client as M  # noqa: E402

OWNER = "S-1-5-21-1533048046-1227877506-1103788458-1000"
GROUP = "S-1-22-2-1000"


def _sid(text: str) -> SIDPacket:
    sid = SIDPacket()
    sid.from_string(text)
    return sid


def _ace(kind, sid: str, mask: int, flags: int = 0):
    ace = kind()
    ace["sid"] = _sid(sid)
    ace["mask"] = mask
    ace["ace_flags"] = flags
    return ace


def _descriptor(aces=None) -> bytes:
    sd = SMB2CreateSDBuffer()
    sd["control"].set_flag(SDControl.SELF_RELATIVE)
    sd.set_owner(_sid(OWNER))
    sd.set_group(_sid(GROUP))
    if aces is not None:
        acl = AclPacket()
        acl["aces"] = aces
        sd.set_dacl(acl)
    return sd.pack()


def _session(**seams):
    s = M.SmbSession.__new__(M.SmbSession)
    s._host, s._share, s._port = "files.example", "share", 445
    s._prefix = r"\\files.example\share"
    for name, value in seams.items():
        setattr(s, name, value)
    return s


# -- acl_get -----------------------------------------------------------------------------


def test_happy_owner_group_and_every_ace_with_names():
    raw = _descriptor([
        _ace(AccessAllowedAce, OWNER, 0x001F01FF),
        _ace(AccessAllowedAce, "S-1-1-0", 0x001200A9, flags=0x03),
        _ace(AccessDeniedAce, "S-1-5-32-546", 0x00000116, flags=0x10),
    ])
    asked = []
    acl = _session(_query_security=lambda unc: asked.append(unc) or raw).acl_get("/docs/a.txt")
    assert asked == [r"\\files.example\share\docs\a.txt"]
    assert (acl["owner"], acl["group"]) == (OWNER, GROUP)
    assert "SELF_RELATIVE" in acl["control_flags"] and "DACL_PRESENT" in acl["control_flags"]
    full, everyone, guests = acl["dacl"]
    assert full == {
        "type": "allow",
        "sid": OWNER,
        "name": "",
        "mask": 0x001F01FF,
        "rights": ["FULL_CONTROL"],
        "flags": 0,
        "flag_names": [],
    }
    assert everyone["name"] == "Everyone" and everyone["type"] == "allow"
    assert everyone["flag_names"] == ["OBJECT_INHERIT", "CONTAINER_INHERIT"]
    assert {
        "READ_DATA",
        "READ_ATTRIBUTES",
        "READ_EA",
        "EXECUTE",
        "READ_CONTROL",
        "SYNCHRONIZE",
    } == set(everyone["rights"])
    assert guests["type"] == "deny" and guests["name"] == "BUILTIN\\Guests"
    assert guests["flag_names"] == ["INHERITED"]
    assert {"WRITE_DATA", "APPEND_DATA", "WRITE_EA", "WRITE_ATTRIBUTES"} == set(guests["rights"])


def test_sad_a_missing_file_is_file_not_found():
    from smbprotocol.exceptions import SMBOSError

    def gone(unc):
        raise SMBOSError(0xC0000034, unc)

    with pytest.raises(FileNotFoundError):
        _session(_query_security=gone).acl_get("/nope.txt")


def test_sad_a_descriptor_that_is_no_descriptor_is_an_oserror():
    with pytest.raises(OSError, match="security descriptor"):
        _session(_query_security=lambda unc: b"\x01").acl_get("/a.txt")


def test_edge_no_dacl_means_no_restriction_and_says_so():
    acl = _session(_query_security=lambda unc: _descriptor(None)).acl_get("/")
    assert acl["dacl"] is None
    assert "DACL_PRESENT" not in acl["control_flags"]
    assert "full access" in acl["note"]


def test_edge_an_empty_dacl_denies_everyone():
    acl = _session(_query_security=lambda unc: _descriptor([])).acl_get("/")
    assert acl["dacl"] == [] and "no access" in acl["note"]


def test_edge_generic_rights_and_unknown_bits_are_kept():
    raw = _descriptor([_ace(AccessAllowedAce, "S-1-5-18", 0x80000000 | 0x00010000 | 0x00000200)])
    (ace,) = _session(_query_security=lambda unc: raw).acl_get("/").get("dacl")
    assert ace["name"] == "NT AUTHORITY\\SYSTEM"
    assert "GENERIC_READ" in ace["rights"] and "DELETE" in ace["rights"]
    assert ace["mask"] & 0x200  # an unnamed bit stays in the mask


# -- dfs_referrals ------------------------------------------------------------------------


def test_happy_dfs_referrals_list_every_target():
    asked = []
    entries = [(r"\files.example\share\docs", r"\srv1\docs", False, 300),
               (r"\files.example\share\docs", r"\srv2\docs", False, 300)]
    out = _session(_dfs_lookup=lambda unc: asked.append(unc) or entries).dfs_referrals("/docs")
    assert asked == [r"\\files.example\share\docs"]
    assert out == [
        {
            "dfs_path": r"\files.example\share\docs",
            "target": r"\srv1\docs",
            "root": False,
            "link": True,
            "ttl": 300,
        },
        {
            "dfs_path": r"\files.example\share\docs",
            "target": r"\srv2\docs",
            "root": False,
            "link": True,
            "ttl": 300,
        },
    ]


def test_sad_a_path_that_is_no_dfs_path_has_no_referrals():
    assert _session(_dfs_lookup=lambda unc: None).dfs_referrals("/") == []


def test_sad_a_failing_lookup_is_an_oserror():
    def broken(unc):
        raise OSError("STATUS_ACCESS_DENIED")

    with pytest.raises(OSError, match="ACCESS_DENIED"):
        _session(_dfs_lookup=broken).dfs_referrals("/x")


# -- live: the lab's Samba ------------------------------------------------------------------

LAB = ("10.99.0.31", 445)


def _lab_up() -> bool:
    try:
        with socket.create_connection(LAB, timeout=2):
            return True
    except OSError:
        return False


lab = pytest.mark.skipif(not _lab_up(), reason="the lab's Samba (10.99.0.31) is not reachable")


@lab
def test_live_samba_hands_out_the_descriptor_of_a_file_and_the_share():
    s = M.SmbSession(
        host=LAB[0], share="testshare", username="smbuser", password="smb123", port=LAB[1]
    )
    try:
        for path in ("/readme.txt", "/"):
            acl = s.acl_get(path)
            assert acl["owner"].startswith("S-1-5-21-") and acl["group"].startswith("S-1-")
            assert acl["dacl"] and any(a["name"] == "Everyone" for a in acl["dacl"])
        with pytest.raises(FileNotFoundError):
            s.acl_get("/no-such-file.txt")
    finally:
        s.close()


@lab
def test_live_an_msdfs_root_hands_out_its_link_and_root():
    """Needs the lab's [dfsroot] share (tests/docker/Dockerfile.smb):
    /srv/dfsroot with the link docs -> two targets."""
    s = M.SmbSession(
        host=LAB[0], share="dfsroot", username="smbuser", password="smb123", port=LAB[1]
    )
    try:
        link = s.dfs_referrals("/docs")
        assert [r["target"] for r in link] == [r"\10.99.0.31\testshare"] * 2
        assert all(r["link"] and not r["root"] and r["ttl"] > 0 for r in link)
        (root,) = s.dfs_referrals("/")
        assert root["root"] and root["target"] == r"\10.99.0.31\dfsroot"
        assert s.dfs_referrals("/nope") == []
    finally:
        s.close()


@lab
def test_live_a_plain_samba_share_has_no_dfs_referrals():
    s = M.SmbSession(
        host=LAB[0], share="testshare", username="smbuser", password="smb123", port=LAB[1]
    )
    try:
        assert s.dfs_referrals("/") == []
    finally:
        s.close()
