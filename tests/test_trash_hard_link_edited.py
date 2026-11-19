"""A trashed file that has another name (a hard link) and was edited
through it is the same file: it is restored, not refused as "tampered" -
its content is not what axross signed, so a protected place still needs
the user's yes. Data put in its place is refused, and the message says
what changed (the data, not the record)."""
from __future__ import annotations

import json
import os
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


def test_happy_edited_through_its_hard_link_is_restored(home):
    victim = home / "proj" / "notes.txt"
    victim.write_text("first\n")
    other = home / "elsewhere.txt"
    os.link(victim, other)
    tid = T.trash(LocalFS(), str(victim))
    with open(other, "a") as fh:  # edited in place through the other name
        fh.write("second\n")
    assert T.restore(LocalFS(), tid) == str(victim)
    assert victim.read_text() == "first\nsecond\n"
    assert os.path.samefile(victim, other)


def test_sad_data_put_in_place_of_a_linked_file_is_refused(home):
    victim = home / "proj" / "notes.txt"
    victim.write_text("first\n")
    os.link(victim, home / "elsewhere.txt")
    tid = T.trash(LocalFS(), str(victim))
    data = home / T.TRASH_DIRNAME / tid
    data.unlink()
    data.write_text("planted\n")
    os.link(data, home / "decoy")  # a file with other names, but another file
    with pytest.raises(T.TamperedTrashEntry, match="data .* is not what was trashed"):
        T.restore(LocalFS(), tid)
    assert not victim.exists()


def test_sad_a_changed_record_is_named_as_the_record(home):
    victim = home / "proj" / "notes.txt"
    victim.write_text("first\n")
    tid = T.trash(LocalFS(), str(victim))
    sidecar = home / T.TRASH_DIRNAME / f"{tid}{T.META_SUFFIX}"
    meta = json.loads(sidecar.read_text())
    meta["original_path"] = str(home / "proj" / "other.txt")
    sidecar.write_text(json.dumps(meta))
    with pytest.raises(T.TamperedTrashEntry, match="record"):
        T.restore(LocalFS(), tid)


def test_edge_an_edited_linked_file_into_a_protected_place_needs_a_yes(home, monkeypatch):
    from core import protected_places

    victim = home / "proj" / "run.sh"
    victim.write_text("make\n")
    other = home / "elsewhere.sh"
    os.link(victim, other)
    tid = T.trash(LocalFS(), str(victim))
    with open(other, "a") as fh:
        fh.write("more\n")
    monkeypatch.setattr(protected_places, "refusal",
                        lambda path, entry=False: "a protected place")
    with pytest.raises(T.ProtectedRestoreError) as info:
        T.restore(LocalFS(), tid, allow_protected=True)
    assert info.value.verified is False
