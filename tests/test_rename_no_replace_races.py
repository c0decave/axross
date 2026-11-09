"""A move or a finalize that must not replace a file refuses one that
appeared after its check.

Round-5 review: core.server_ops.server_side_move, the temp-file finalize
of "fail" / "newer" jobs (core.transfer_worker) and the undo of a move
(core.undo.apply_undo, move_back) checked that the target was free and
then called rename(), which replaces a file on LocalFS and SFTP - one
that appeared between the check and the rename was overwritten. They now
rename through a no-replace primitive (LocalFS: renameat2(RENAME_NOREPLACE)
or a hard link; SFTP: the plain RENAME; core.server_ops.rename_no_replace)
and refuse with FileExistsError.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import local_fs as LF  # noqa: E402
from core import server_ops as SO  # noqa: E402
from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

# -- happy ------------------------------------------------------------------------------------


def test_happy_localfs_rename_no_replace_renames_onto_a_free_name(tmp_path):
    (tmp_path / "a").write_text("mine")
    LocalFS().rename_no_replace(str(tmp_path / "a"), str(tmp_path / "b"))
    assert (tmp_path / "b").read_text() == "mine" and not (tmp_path / "a").exists()


def test_happy_a_folder_is_renamed_too(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "x").write_text("x")
    LocalFS().rename_no_replace(str(tmp_path / "d"), str(tmp_path / "e"))
    assert (tmp_path / "e" / "x").exists()


def test_happy_server_side_move_to_a_free_name_still_moves(tmp_path):
    (tmp_path / "a").write_text("mine")
    SO.server_side_move(LocalFS(), str(tmp_path / "a"), str(tmp_path / "b"))
    assert (tmp_path / "b").read_text() == "mine"


# -- sad --------------------------------------------------------------------------------------


def test_sad_localfs_rename_no_replace_refuses_an_existing_file(tmp_path):
    (tmp_path / "a").write_text("mine")
    (tmp_path / "b").write_text("theirs")
    with pytest.raises(FileExistsError):
        LocalFS().rename_no_replace(str(tmp_path / "a"), str(tmp_path / "b"))
    assert (tmp_path / "b").read_text() == "theirs" and (tmp_path / "a").exists()


def test_sad_server_side_move_refuses_a_target_that_appeared_after_its_check(tmp_path,
                                                                            monkeypatch):
    (tmp_path / "a").write_text("mine")
    (tmp_path / "b").write_text("theirs")
    # The check ran while "b" was not there yet.
    monkeypatch.setattr(SO, "rename_target_taken", lambda *a, **k: False)
    monkeypatch.setattr(SO, "_exists_true", lambda *a, **k: False)
    with pytest.raises(FileExistsError):
        SO.server_side_move(LocalFS(), str(tmp_path / "a"), str(tmp_path / "b"))
    assert (tmp_path / "b").read_text() == "theirs" and (tmp_path / "a").exists()


def test_sad_undo_move_back_refuses_a_file_that_appeared_after_its_check(tmp_path):
    from core.undo import UndoPlan, apply_undo

    (tmp_path / "moved").write_text("mine")
    (tmp_path / "orig").write_text("theirs")
    plan = UndoPlan(operation_id="op", operation="move", reversible=True, action="move_back",
                    reason="", source=str(tmp_path / "orig"), dest=str(tmp_path / "moved"),
                    backend="Local")

    class Late(LocalFS):
        def exists(self, path):  # the check sees nothing: the file comes right after
            return False

    with pytest.raises(FileExistsError, match="exists again"):
        apply_undo(plan, Late())
    assert (tmp_path / "orig").read_text() == "theirs"
    assert (tmp_path / "moved").read_text() == "mine"


def test_sad_a_fail_copy_does_not_replace_a_file_that_appeared_before_its_rename(tmp_path,
                                                                                monkeypatch):
    src = tmp_path / "src.bin"
    src.write_bytes(b"payload" * 100)
    dst = tmp_path / "dst.bin"
    real = TW.TransferWorker._check_existing_destination

    def check_then_appear(job):
        answer = real(job)
        dst.write_bytes(b"theirs")  # written right after the last look
        return answer

    monkeypatch.setattr(TW.TransferWorker, "_check_existing_destination",
                        staticmethod(check_then_appear))
    job = TW.TransferJob(source_path=str(src), dest_path=str(dst), total_bytes=700,
                         filename=src.name, source_backend=LocalFS(), dest_backend=LocalFS(),
                         if_exists="fail")
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.ERROR
    assert dst.read_bytes() == b"theirs"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dst.bin", "src.bin"]


# -- edge -------------------------------------------------------------------------------------


def test_edge_without_renameat2_a_file_goes_by_hard_link(tmp_path, monkeypatch):
    monkeypatch.setattr(LF, "_renameat2", lambda: None)
    (tmp_path / "a").write_text("mine")
    (tmp_path / "b").write_text("theirs")
    with pytest.raises(FileExistsError):
        LF.rename_no_replace(str(tmp_path / "a"), str(tmp_path / "b"))
    LF.rename_no_replace(str(tmp_path / "a"), str(tmp_path / "c"))
    assert (tmp_path / "c").read_text() == "mine" and not (tmp_path / "a").exists()


def test_edge_without_renameat2_or_links_it_checks_then_renames(tmp_path, monkeypatch):
    monkeypatch.setattr(LF, "_renameat2", lambda: None)

    def no_links(*a, **k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "link", no_links)
    (tmp_path / "a").write_text("mine")
    (tmp_path / "b").write_text("theirs")
    with pytest.raises(FileExistsError):
        LF.rename_no_replace(str(tmp_path / "a"), str(tmp_path / "b"))
    LF.rename_no_replace(str(tmp_path / "a"), str(tmp_path / "c"))
    assert (tmp_path / "c").read_text() == "mine"


def test_edge_a_backend_without_the_primitive_is_checked_then_renamed(tmp_path):
    class Plain:
        def __init__(self):
            self.renamed = []

        def exists(self, path):
            return path == "/taken"

        def rename(self, src, dst):
            self.renamed.append((src, dst))

    plain = Plain()
    with pytest.raises(FileExistsError):
        SO.rename_no_replace(plain, "/a", "/taken")
    SO.rename_no_replace(plain, "/a", "/free")
    assert plain.renamed == [("/a", "/free")]


def test_edge_the_confined_local_fs_refuses_inside_its_root(tmp_path):
    from core.confined_fs import ConfinedLocalFS

    (tmp_path / "a").write_text("mine")
    (tmp_path / "b").write_text("theirs")
    fs = ConfinedLocalFS([str(tmp_path)])
    with pytest.raises(FileExistsError):
        fs.rename_no_replace(str(tmp_path / "a"), str(tmp_path / "b"))
    fs.rename_no_replace(str(tmp_path / "a"), str(tmp_path / "c"))
    assert (tmp_path / "c").read_text() == "mine" and (tmp_path / "b").read_text() == "theirs"


def test_edge_a_replaced_rename_is_honoured_not_gone_around(tmp_path):
    """A subclass (or a stand-in) whose rename refuses: the no-replace
    rename uses it instead of the system call (server_side_move kept the
    source in place)."""
    import errno

    class Denied(LocalFS):
        def rename(self, src, dst):
            raise PermissionError(errno.EACCES, "denied", src)

    (tmp_path / "a").write_text("mine")
    with pytest.raises(PermissionError):
        Denied().rename_no_replace(str(tmp_path / "a"), str(tmp_path / "b"))
    with pytest.raises(PermissionError):
        SO.server_side_move(Denied(), str(tmp_path / "a"), str(tmp_path / "b"))
    assert (tmp_path / "a").exists() and not (tmp_path / "b").exists()
