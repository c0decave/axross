"""SMB: a recursive remove of a DFS link itself asks first.

Review round 9: smbclient follows the referral of a DFS link, so lstat of
the link sees the target folder - no reparse point - and
``remove("/links/proj", recursive=True)`` deleted everything in the share
the link leads to. On a share that is part of a DFS namespace
(SMB2_SHARE_CAP_DFS) the referral is asked first now: when it names the
path itself as a link, ConfirmationRequired names the TARGET and nothing
is deleted. ``follow_dfs_link=True`` (the pane's Yes) does what Explorer
does: the target's contents go through the link, the link stays. A path
below the link and every share outside DFS go on as before.
"""

from __future__ import annotations

import errno
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

pytest.importorskip("smbprotocol")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from smb_fake_client import make_local_session  # noqa: E402

from core import smb_client  # noqa: E402
from core.backend import ConfirmationRequired  # noqa: E402

LINK = (r"\h\s\links\proj", r"\fs2\projects", False, 300)
ROOT = (r"\h\s", r"\h\s", True, 300)


@pytest.fixture
def dfs(tmp_path):
    """``make(dfs_share, lookup)``: an SMB session over a local folder that
    holds what the link /links/proj leads to."""
    root = tmp_path / "smb"
    (root / "links" / "proj" / "sub").mkdir(parents=True)
    (root / "links" / "proj" / "report.txt").write_bytes(b"keep")
    (root / "links" / "proj" / "sub" / "a.bin").write_bytes(b"keep")
    patches = []

    def make(dfs_share, lookup):
        s, fake = make_local_session(str(root))
        tree = types.SimpleNamespace(is_dfs_share=dfs_share)
        fake._pool = types.SimpleNamespace(get_smb_tree=lambda prefix, **kw: (tree, ""))
        asked: list[str] = []

        def dfs_lookup(unc):
            asked.append(unc)
            return lookup(unc)

        s._dfs_lookup = dfs_lookup
        patch = mock.patch.object(smb_client, "smbclient", fake)
        patch.start()
        patches.append(patch)
        return s, asked

    yield make, root
    for patch in patches:
        patch.stop()


def _link_only(unc):
    if unc.lower().rstrip("\\").endswith(r"\links\proj"):
        return [LINK]
    if r"\links\proj" in unc.lower():
        return [LINK]  # a path below the link: the referral names the link
    return None


# -- happy ---------------------------------------------------------------------------------


def test_happy_confirmed_the_targets_contents_go_and_the_link_stays(dfs):
    make, root = dfs
    s, _asked = make(True, _link_only)
    s.remove("/links/proj", recursive=True, follow_dfs_link=True)  # no error
    assert (root / "links" / "proj").is_dir()  # the link
    assert list((root / "links" / "proj").iterdir()) == []  # the target's contents


def test_happy_a_folder_below_the_link_needs_no_question(dfs):
    make, root = dfs
    s, _asked = make(True, _link_only)
    s.remove("/links/proj/sub", recursive=True)
    assert not (root / "links" / "proj" / "sub").exists()
    assert (root / "links" / "proj" / "report.txt").read_bytes() == b"keep"


def test_happy_a_share_outside_dfs_asks_no_referral(dfs):
    make, root = dfs
    s, asked = make(False, _link_only)
    s.remove("/links/proj", recursive=True)
    assert asked == []
    assert not (root / "links" / "proj").exists()


# -- sad -----------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/links/proj", "/links/proj/"])
def test_sad_unconfirmed_the_link_asks_and_names_the_target(dfs, path):
    make, root = dfs
    s, asked = make(True, _link_only)
    with pytest.raises(ConfirmationRequired) as info:
        s.remove(path, recursive=True)
    exc = info.value
    assert exc.errno == errno.EPERM
    assert exc.kind == "dfs_link" and exc.option == "follow_dfs_link"
    assert exc.details["target"] == r"\\fs2\projects"
    assert r"\\fs2\projects" in exc.explanation and "not only the link" in exc.explanation
    assert asked
    assert (root / "links" / "proj" / "report.txt").read_bytes() == b"keep"
    assert (root / "links" / "proj" / "sub" / "a.bin").read_bytes() == b"keep"


def test_sad_declined_deletes_nothing(dfs):
    make, root = dfs
    s, _asked = make(True, _link_only)
    for _ in range(2):  # asked, No, asked again: still nothing gone
        with pytest.raises(ConfirmationRequired):
            s.remove("/links/proj", recursive=True)
    assert sorted(p.name for p in (root / "links" / "proj").iterdir()) == ["report.txt", "sub"]


def test_sad_a_failing_referral_on_a_dfs_share_asks(dfs):
    make, root = dfs

    def broken(unc):
        raise OSError("STATUS_ACCESS_DENIED")

    s, _asked = make(True, broken)
    with pytest.raises(ConfirmationRequired) as info:
        s.remove("/links/proj", recursive=True)
    assert info.value.details["known"] is False
    assert (root / "links" / "proj" / "report.txt").exists()
    s.remove("/links/proj", recursive=True, follow_dfs_link=True)
    assert not (root / "links" / "proj").exists()  # not known as a link: it all goes


# -- edge ----------------------------------------------------------------------------------


def test_edge_a_plain_folder_on_a_dfs_share_goes(dfs):
    make, root = dfs
    (root / "plain" / "x").mkdir(parents=True)
    s, asked = make(True, lambda unc: None)  # no DFS path: STATUS_NOT_FOUND
    s.remove("/plain", recursive=True)
    assert asked and not (root / "plain").exists()


def test_edge_the_link_is_known_in_another_case_and_host_spelling(dfs):
    make, root = dfs
    s, _asked = make(True, lambda unc: [(r"\H.example.org\S\LINKS\Proj", r"\fs2\p", False, 0)])
    with pytest.raises(ConfirmationRequired):
        s.remove("/links/proj", recursive=True)
    assert (root / "links" / "proj" / "report.txt").exists()


def test_edge_the_dfs_root_entry_is_no_link(dfs):
    make, root = dfs
    s, _asked = make(True, lambda unc: [ROOT])
    s.remove("/links/proj", recursive=True)
    assert not (root / "links" / "proj").exists()
