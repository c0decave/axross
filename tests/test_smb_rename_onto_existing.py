"""SMB rename onto an existing file is FileExistsError, so overwrite works.

Lab (Samba): axross.copy(..., overwrite=True) to an existing SMB file
failed with "Cannot rename .small.txt.copy-....tmp -> small.txt:
[NtStatus 0xc0000022] STATUS_ACCESS_DENIED". The copy writes a sibling
temp and renames it over the target; when that rename says "the target
exists", server_ops swaps through a backup. Samba refuses a rename onto
an existing name with ACCESS_DENIED (not OBJECT_NAME_COLLISION), errno 0,
so the refusal was not recognised. SmbSession.rename now reports a
failed rename whose target exists as FileExistsError; a rename still
never replaces anything.
"""

from __future__ import annotations

import errno
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("smbprotocol")
from smb_fake_client import make_session  # noqa: E402
from smbprotocol.exceptions import SMBOSError  # noqa: E402
from smbprotocol.header import NtStatus  # noqa: E402

from core import smb_client  # noqa: E402


class _Fake:
    def __init__(self, existing):
        self.existing = set(existing)
        self.renamed = []
        self.path = types.SimpleNamespace(exists=lambda unc, **kw: unc in self.existing)

    def rename(self, src, dst, **kw):
        if dst in self.existing:
            raise SMBOSError(NtStatus.STATUS_ACCESS_DENIED, dst)
        if src not in self.existing:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, src)
        self.existing.discard(src)
        self.existing.add(dst)
        self.renamed.append((src, dst))


def _session(monkeypatch, *existing):
    fake = _Fake(existing)
    monkeypatch.setattr(smb_client, "smbclient", fake)
    return fake, make_session(fake)


A, B = "\\\\h\\s\\a.txt", "\\\\h\\s\\b.txt"


# --- happy ----------------------------------------------------------------


def test_happy_a_free_target_is_renamed(monkeypatch):
    fake, s = _session(monkeypatch, A)
    s.rename("/a.txt", "/b.txt")
    assert fake.renamed == [(A, B)]


# --- sad ------------------------------------------------------------------


def test_sad_an_existing_target_is_file_exists(monkeypatch):
    fake, s = _session(monkeypatch, A, B)
    with pytest.raises(FileExistsError) as err:
        s.rename("/a.txt", "/b.txt")
    assert err.value.errno == errno.EEXIST
    assert fake.existing == {A, B}  # nothing replaced


def test_sad_a_missing_source_stays_a_plain_error(monkeypatch):
    _fake, s = _session(monkeypatch)
    with pytest.raises(OSError) as err:
        s.rename("/a.txt", "/b.txt")
    assert not isinstance(err.value, FileExistsError)


# --- edge -----------------------------------------------------------------


def test_edge_overwrite_copy_swaps_through_a_backup(monkeypatch):
    from core.server_ops import _finalize_temp_destination

    fake, s = _session(monkeypatch, A, B)
    s.remove = lambda path, recursive=False: fake.existing.discard(s._unc(path))
    s.is_dir = lambda path: False
    s.exists = lambda path: s._unc(path) in fake.existing
    _finalize_temp_destination(s, "/a.txt", "/b.txt")
    assert fake.existing == {B}
