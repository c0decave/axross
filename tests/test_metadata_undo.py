"""Keeping the original of a file whose metadata was removed, and putting it
back with Ctrl+Z.

* ``core.trash.trash_copy`` keeps a copy of a file in the trash while the
  file itself stays where it is (it is about to be replaced atomically).
* ``core.trash.restore_over`` puts that copy back over the cleaned file -
  but only while the file still holds exactly what the removal wrote, so an
  edit made afterwards is never thrown away.
* ``core.undo`` plans and applies the inverse of a ``metadata_remove``
  journal entry (one entry per batch, so one Ctrl+Z restores a whole
  folder) and records an undo so the same entry is not offered twice.
* ``core.media_collect.collect_media`` takes a classifier, so the metadata
  walk reuses its caps and loop guards for Office, PDF and audio files.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import trash as T  # noqa: E402
from core import undo as U  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _replace(path: Path, data: bytes) -> None:
    """What the removal does: a new file renamed over the old one (the kept
    copy may be a hard link to the old one, so writing in place would
    change it too)."""
    tmp = path.with_name(".tmp-replace")
    tmp.write_bytes(data)
    os.replace(tmp, path)


@pytest.fixture
def local(tmp_path):
    fs = LocalFS()
    root = str(tmp_path / "trash-root")
    return fs, root


# ---------------------------------------------------------------------------
# trash_copy
# ---------------------------------------------------------------------------


def test_happy_trash_copy_keeps_the_file_and_lists_a_copy(tmp_path, local):
    fs, root = local
    f = tmp_path / "photo.jpg"
    f.write_bytes(b"original bytes")
    trash_id = T.trash_copy(fs, str(f), root=root)
    assert f.read_bytes() == b"original bytes"
    entries = T.list_trash(fs, root=root)
    assert [e.trash_id for e in entries] == [trash_id]
    assert entries[0].original_path == str(f)
    assert (Path(root) / trash_id).read_bytes() == b"original bytes"


def test_happy_trash_copy_on_a_remote_backend_uploads_the_local_copy(tmp_path):
    ram = RamFsSession()
    with ram.open_write("/a.png") as fh:
        fh.write(b"remote original")
    local_copy = tmp_path / "a.png"
    local_copy.write_bytes(b"remote original")
    trash_id = T.trash_copy(ram, "/a.png", local_source=str(local_copy))
    with ram.open_read("/.axross-trash/" + trash_id) as fh:
        assert fh.read() == b"remote original"
    assert ram.exists("/a.png")


def test_sad_trash_copy_of_a_missing_file(tmp_path, local):
    fs, root = local
    with pytest.raises(OSError):
        T.trash_copy(fs, str(tmp_path / "missing.jpg"), root=root)
    assert T.list_trash(fs, root=root) == []


def test_edge_trash_copy_survives_an_atomic_replace_of_the_original(tmp_path, local):
    """The local copy may be a hard link; replacing the file by rename must
    leave the kept copy with the OLD bytes."""
    fs, root = local
    f = tmp_path / "doc.pdf"
    f.write_bytes(b"old")
    trash_id = T.trash_copy(fs, str(f), root=root)
    tmp = tmp_path / ".tmp-new"
    tmp.write_bytes(b"new")
    os.replace(tmp, f)
    assert (Path(root) / trash_id).read_bytes() == b"old"


def test_happy_discard_removes_a_kept_copy(tmp_path, local):
    fs, root = local
    f = tmp_path / "a.txt"
    f.write_bytes(b"x")
    trash_id = T.trash_copy(fs, str(f), root=root)
    T.discard(fs, trash_id, root=root)
    assert T.list_trash(fs, root=root) == []
    assert f.read_bytes() == b"x"


# ---------------------------------------------------------------------------
# restore_over
# ---------------------------------------------------------------------------


def test_happy_restore_over_puts_the_original_back_byte_identical(tmp_path, local):
    fs, root = local
    f = tmp_path / "photo.jpg"
    f.write_bytes(b"original with GPS")
    trash_id = T.trash_copy(fs, str(f), root=root)
    _replace(f, b"cleaned")
    out = T.restore_over(fs, trash_id, target=str(f), expected_sha256=_sha(b"cleaned"), root=root)
    assert out == str(f)
    assert f.read_bytes() == b"original with GPS"
    assert T.list_trash(fs, root=root) == []


def test_happy_restore_over_on_a_remote_backend(tmp_path):
    ram = RamFsSession()
    with ram.open_write("/a.png") as fh:
        fh.write(b"cleaned")
    src = tmp_path / "orig"
    src.write_bytes(b"original")
    trash_id = T.trash_copy(ram, "/a.png", local_source=str(src))
    T.restore_over(ram, trash_id, target="/a.png", expected_sha256=_sha(b"cleaned"))
    with ram.open_read("/a.png") as fh:
        assert fh.read() == b"original"
    assert T.list_trash(ram) == []


def test_sad_restore_over_refuses_when_the_file_was_changed_since(tmp_path, local):
    fs, root = local
    f = tmp_path / "photo.jpg"
    f.write_bytes(b"original")
    trash_id = T.trash_copy(fs, str(f), root=root)
    _replace(f, b"edited after cleaning")
    with pytest.raises(OSError, match="changed"):
        T.restore_over(fs, trash_id, target=str(f), expected_sha256=_sha(b"cleaned"), root=root)
    assert f.read_bytes() == b"edited after cleaning"
    assert len(T.list_trash(fs, root=root)) == 1


def test_sad_restore_over_unknown_or_unsafe_id(tmp_path, local):
    fs, root = local
    with pytest.raises(OSError):
        T.restore_over(fs, "deadbeef", target=str(tmp_path / "x"), expected_sha256="0", root=root)
    with pytest.raises(OSError):
        T.restore_over(fs, "../../etc", target=str(tmp_path / "x"), expected_sha256="0", root=root)


def test_edge_restore_over_when_the_cleaned_file_is_gone(tmp_path, local):
    fs, root = local
    f = tmp_path / "a.jpg"
    f.write_bytes(b"original")
    trash_id = T.trash_copy(fs, str(f), root=root)
    f.unlink()
    T.restore_over(fs, trash_id, target=str(f), expected_sha256=_sha(b"whatever"), root=root)
    assert f.read_bytes() == b"original"


# ---------------------------------------------------------------------------
# Undo planning
# ---------------------------------------------------------------------------


def _event(
    items, *, status="done", operation_id="m1", backend="Local", operation="metadata_remove"
):
    return {
        "operation_id": operation_id,
        "operation": operation,
        "phase": "finish",
        "status": status,
        "source": "/photos",
        "backend": backend,
        "details": {"mode": "in_place", "items": items},
    }


def test_happy_metadata_remove_plans_a_restore_of_every_item():
    plan = U.plan_undo(
        _event(
            [
                {"path": "/p/a.jpg", "trash_id": "a" * 32, "sha256": "1" * 64, "mode": "in_place"},
                {"path": "/p/b.jpg", "output": "/p/b.clean.jpg", "sha256": "2" * 64,
                 "mode": "copy"},
            ]
        )
    )
    assert plan.reversible and plan.action == "restore_metadata"
    assert len(plan.items) == 2
    assert "2 files" in plan.reason


def test_sad_metadata_remove_without_usable_items_is_not_reversible():
    for items in ([], "nope", [{"path": "/x"}], [{"path": 3, "trash_id": "x", "sha256": "y"}]):
        plan = U.plan_undo(_event(items))
        assert not plan.reversible, items
    assert not U.plan_undo(_event([{"path": "/a", "trash_id": "a", "sha256": "b"}],
                                  status="error")).reversible


def test_happy_record_undone_hides_the_entry_from_the_next_undo(tmp_path, monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    from core.operation_journal import finish_operation, read_recent, start_operation

    op = start_operation("metadata_remove", source="/p", backend="Local")
    finish_operation(op, "metadata_remove", status="done", source="/p", backend="Local",
                     details={"mode": "in_place",
                              "items": [{"path": "/p/a.jpg", "trash_id": "t" * 32,
                                         "sha256": "s" * 64, "mode": "in_place"}]})
    plans = U.undoable(read_recent())
    assert U.pick_undoable(plans, {"Local"}).operation_id == op
    U.record_undone(plans[0])
    plans = U.undoable(read_recent())
    assert U.pick_undoable(plans, {"Local"}) is None
    assert plans[0].operation == "undo" and not plans[0].reversible


def test_happy_apply_restores_in_place_items_and_trashes_clean_copies(tmp_path, local):
    fs, root = local
    a = tmp_path / "a.jpg"
    a.write_bytes(b"A original")
    trash_id = T.trash_copy(fs, str(a), root=root)
    _replace(a, b"A clean")
    b = tmp_path / "b.jpg"
    b.write_bytes(b"B original")
    b_copy = tmp_path / "b.clean.jpg"
    b_copy.write_bytes(b"B clean")
    plan = U.plan_undo(
        _event(
            [
                {"path": str(a), "trash_id": trash_id, "sha256": _sha(b"A clean"),
                 "mode": "in_place"},
                {"path": str(b), "output": str(b_copy), "sha256": _sha(b"B clean"),
                 "mode": "copy"},
            ]
        )
    )

    class _Trash:
        trash_copy = staticmethod(T.trash_copy)

        @staticmethod
        def restore_over(backend, tid, **kw):
            return T.restore_over(backend, tid, root=root, **kw)

        @staticmethod
        def trash(backend, path, **kw):
            return T.trash(backend, path, root=root, **kw)

    U.apply_undo(plan, fs, trash_module=_Trash)
    assert a.read_bytes() == b"A original"
    assert not b_copy.exists() and b.read_bytes() == b"B original"


def test_sad_apply_reports_items_that_could_not_be_restored(tmp_path, local):
    fs, root = local
    a = tmp_path / "a.jpg"
    a.write_bytes(b"A original")
    trash_id = T.trash_copy(fs, str(a), root=root)
    _replace(a, b"edited later")
    plan = U.plan_undo(
        _event([{"path": str(a), "trash_id": trash_id, "sha256": _sha(b"A clean"),
                 "mode": "in_place"}])
    )

    class _Trash:
        @staticmethod
        def restore_over(backend, tid, **kw):
            return T.restore_over(backend, tid, root=root, **kw)

    with pytest.raises(OSError, match="0 of 1"):
        U.apply_undo(plan, fs, trash_module=_Trash)
    assert a.read_bytes() == b"edited later"


def test_edge_an_undo_entry_is_not_itself_undoable():
    plan = U.plan_undo(_event([], operation="undo"))
    assert not plan.reversible and "undo" in plan.reason


# ---------------------------------------------------------------------------
# collect_media with a classifier
# ---------------------------------------------------------------------------


def test_happy_collect_media_with_a_classifier(tmp_path):
    from core.media_collect import collect_media
    from core.metadata_formats import kind_of

    (tmp_path / "sub").mkdir()
    for name in ("a.jpg", "b.docx", "c.mp3", "notes.txt", "sub/d.pdf"):
        (tmp_path / name).write_bytes(b"x")
    scan = collect_media(LocalFS(), str(tmp_path), kinds={"image", "office", "pdf", "audio"},
                         recursive=True, classify=kind_of)
    assert sorted(i.name for i in scan.items) == ["a.jpg", "b.docx", "c.mp3", "d.pdf"]
    assert {i.kind for i in scan.items} == {"image", "office", "pdf", "audio"}


def test_sad_collect_media_without_classifier_still_rejects_unknown_kinds(tmp_path):
    from core.media_collect import collect_media

    with pytest.raises(ValueError):
        collect_media(LocalFS(), str(tmp_path), kinds={"office"})
