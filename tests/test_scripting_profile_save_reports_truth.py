"""axross.save_profile / delete_profile say when nothing was saved.

ProfileManager.add/remove return a SaveResult (a full disk, an unreadable
profiles.json); the scripting calls dropped it, so a script logged
"save_profile 'box'" and went on, and the profile was gone at the next
start. They raise OSError now, with the reason.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.profiles as P  # noqa: E402
from core import scripting  # noqa: E402

FULL = P.SaveResult(ok=False, error=OSError(errno.ENOSPC, "No space left on device"),
                    reason="No space left on device")


def _profile(name="box"):
    return P.ConnectionProfile(name=name, protocol="sftp", host="example.org",
                               store_password=False)


def test_sad_a_failed_save_raises(monkeypatch):
    monkeypatch.setattr(P.ProfileManager, "add", lambda self, p, **k: FULL)
    with pytest.raises(OSError, match="No space left"):
        scripting.save_profile(_profile())


def test_sad_a_failed_delete_raises(monkeypatch):
    monkeypatch.setattr(P.ProfileManager, "remove", lambda self, n, **k: FULL)
    monkeypatch.setattr(P.ProfileManager, "list_names", lambda self: ["box"])
    with pytest.raises(OSError, match="not saved"):
        scripting.delete_profile("box")


def test_happy_a_good_save_says_nothing(monkeypatch):
    seen = {}

    def add(self, p, **k):
        seen.update(k)
        return P.SAVED
    monkeypatch.setattr(P.ProfileManager, "add", add)
    scripting.save_profile(_profile())
    assert seen == {"report_failure": False}  # the script gets the error, not a dialog


def test_edge_a_refusal_without_an_exception_still_raises(monkeypatch):
    monkeypatch.setattr(P.ProfileManager, "add",
                        lambda self, p, **k: P.SaveResult(ok=False))
    with mock.patch.object(P.ProfileManager, "list_names", lambda self: []):
        with pytest.raises(OSError, match="profiles file was not written"):
            scripting.save_profile(_profile())
