"""A symbolic link inside a copied folder is copied as the link.

Measured before: a link to a file inside a copied folder arrived as a copy
of the file it points to; a link to a folder (or to nothing) was a failed
row on this machine's disk and, over SFTP, failed the copy ("Transfer
failed: sublink: Failure") - the job opened the link as a file.

Now such a link is made again as a link with the same target, as cp -a,
axross's own server-side copy and the WinRM backend do: what it points to
is never read or followed, also when that is outside the copied folder.
Where one side cannot hold links (an object store, FTP) the link is
skipped with a note - a skipped row, not a failure. A link the user
selected on its own is copied as before (a link to a file as the file).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks")

APP = QApplication.instance() or QApplication([])


def _tree(root: Path) -> list[str]:
    out = []
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if p.is_symlink():
            out.append(f"{rel} -> {os.readlink(p)}")
        elif p.is_dir():
            out.append(rel + "/")
        else:
            out.append(f"{rel} {p.read_bytes()!r}")
    return out


@pytest.fixture
def project(tmp_path, monkeypatch):
    """proj/ with a library and its version links, a link to a sibling
    folder, a link to a folder outside the copy, an absolute link and a
    dangling one."""
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("not part of the copy")
    proj = tmp_path / "src" / "proj"
    (proj / "sub").mkdir(parents=True)
    (proj / "sub" / "mid.txt").write_text("mid")
    (proj / "lib").mkdir()
    (proj / "lib" / "libfoo.so.1.2").write_bytes(b"ELF")
    os.symlink("libfoo.so.1.2", proj / "lib" / "libfoo.so.1")
    os.symlink("libfoo.so.1", proj / "lib" / "libfoo.so")
    os.symlink("../sub", proj / "lib" / "sublink")
    os.symlink(str(outside), proj / "out")
    os.symlink("nowhere/at/all", proj / "dangling")
    os.symlink("..", proj / "up")
    dst = tmp_path / "dst"
    dst.mkdir()
    return proj, dst, outside


def _run(source, dest, paths, dest_dir, *, move=False, timeout=30.0):
    from core.transfer_manager import TransferManager

    mgr = TransferManager()
    done: dict = {}
    mgr.transfer_files_in_background(
        source, dest, [str(p) for p in paths], str(dest_dir), move=move,
        on_done=lambda jobs: done.setdefault("jobs", jobs))
    end = time.monotonic() + timeout
    while time.monotonic() < end and ("jobs" not in done or mgr.unfinished()):
        APP.processEvents()
        time.sleep(0.01)
    APP.processEvents()
    mgr.shutdown()
    return {Path(j.source_path).name: j for j in done.get("jobs", [])}


def test_happy_links_in_a_local_folder_are_copied_as_links(project):
    proj, dst, outside = project
    jobs = _run(LocalFS(), LocalFS(), [proj], dst)
    assert _tree(dst / "proj") == _tree(proj)
    assert all(j.status is TransferStatus.DONE and not j.skipped for j in jobs.values()), \
        {n: (j.status, j.error_message) for n, j in jobs.items()}
    # Nothing behind a folder link was copied: the links are links.
    assert os.path.islink(dst / "proj" / "out")
    assert os.readlink(dst / "proj" / "out") == str(outside)
    assert not (dst / "proj" / "lib" / "sublink").is_dir() or \
        (dst / "proj" / "lib" / "sublink").is_symlink()


def test_happy_a_move_moves_the_links_and_leaves_their_targets(project):
    proj, dst, outside = project
    before = _tree(proj)
    # Across "file systems": another LocalFS subclass instance, so the
    # move is a copy and a remove, not one rename of the folder.
    class OtherFS(LocalFS):
        pass

    _run(OtherFS(), LocalFS(), [proj], dst, move=True)
    assert _tree(dst / "proj") == before
    assert sorted(os.listdir(outside)) == ["secret.txt"]


def test_sad_a_destination_without_links_skips_them_with_a_note(project):
    class NoLinks(LocalFS):
        supports_symlinks = False

    proj, dst, _outside = project
    jobs = _run(LocalFS(), NoLinks(), [proj], dst)
    for name in ("libfoo.so", "libfoo.so.1", "sublink", "out", "dangling", "up"):
        job = jobs[name]
        assert job.status is TransferStatus.DONE and job.skipped, (name, job.status)
        assert "symbolic link not copied" in job.skip_note
    assert (dst / "proj" / "lib" / "libfoo.so.1.2").read_bytes() == b"ELF"
    assert not os.path.lexists(dst / "proj" / "out")
    assert not os.path.lexists(dst / "proj" / "lib" / "libfoo.so")
    from models.transfer_model import status_text

    assert status_text(jobs["out"]).startswith("skipped: symbolic link not copied")


def test_edge_an_existing_destination_is_replaced_only_when_allowed(project):
    from core.transfer_conflicts import ConflictAction, ConflictPlan, scan_conflicts

    proj, dst, _outside = project
    (dst / "proj" / "lib").mkdir(parents=True)
    (dst / "proj" / "lib" / "libfoo.so").write_text("old file")
    scan = scan_conflicts(LocalFS(), LocalFS(), [str(proj)], str(dst))
    plan = ConflictPlan(LocalFS(), scan)
    for conflict in scan.conflicts:
        plan.decide(conflict, ConflictAction.SKIP)
    from core.transfer_manager import TransferManager

    mgr = TransferManager()
    jobs = mgr.transfer_files(LocalFS(), LocalFS(), [str(proj)], str(dst), conflict_plan=plan)
    end = time.monotonic() + 20
    while mgr.unfinished() and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)
    mgr.shutdown()
    assert (dst / "proj" / "lib" / "libfoo.so").read_text() == "old file"
    assert os.path.islink(dst / "proj" / "lib" / "libfoo.so.1")
    assert all(j.status is TransferStatus.DONE for j in jobs)


@pytest.fixture
def sftp(tmp_path, monkeypatch):
    from tests import sftp_testkit
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    with mock.patch("pathlib.Path.home", return_value=home):
        server = sftp_testkit.SftpServer("/")
        session = SSHSession(ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=server.port, username="u"))
        session.connect(password="x", on_unknown_host=lambda _e: True)
    yield session
    session.disconnect()
    server.close()


def test_happy_links_come_down_from_sftp_as_links(project, sftp):
    proj, dst, _outside = project
    jobs = _run(sftp, LocalFS(), [proj], dst)
    assert _tree(dst / "proj") == _tree(proj)
    bad = {n: j.error_message for n, j in jobs.items() if j.status is not TransferStatus.DONE}
    assert not bad, bad


def test_happy_links_go_up_to_sftp_as_links(project, sftp):
    proj, dst, _outside = project
    jobs = _run(LocalFS(), sftp, [proj], dst)
    assert _tree(dst / "proj") == _tree(proj)
    assert all(j.status is TransferStatus.DONE for j in jobs.values())


def test_sad_a_server_without_readlink_skips_the_link_and_copies_the_rest(project, sftp):
    proj, dst, _outside = project

    def unsupported(path):
        raise OSError("SFTP readlink: Operation unsupported")

    with mock.patch.object(sftp, "readlink", unsupported):
        jobs = _run(sftp, LocalFS(), [proj], dst)
    assert jobs["sublink"].skipped and jobs["sublink"].status is TransferStatus.DONE
    assert (dst / "proj" / "sub" / "mid.txt").read_text() == "mid"
    assert not any(j.status is TransferStatus.ERROR for j in jobs.values())
