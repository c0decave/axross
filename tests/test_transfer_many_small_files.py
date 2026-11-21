"""A folder of many small files copies fast, and every file arrives.

Measured before: a folder of 100 folders x 100 files of 10 bytes took
508 s from the local test SFTP server to the local disk (8 s from disk to
disk). Every file cost three round trips one after the other - an OPEN,
a read-ahead window of 32 READs for 10 bytes (31 answered "end of file")
and one READ more for the end - 36 requests per file.

Now a small file is read with one READ of its listed size and one byte
more (``core.sftp_io.expected_size``), and the worker reads the small
files queued after it in one pipelined batch (``read_small_files``):
the same folder copies in seconds. Each job still copies through its own
temp file, checks and renames it, and journals itself.
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

APP = QApplication.instance() or QApplication([])


def _tree(root: Path, folders: int, files: int, size: int = 10) -> None:
    for d in range(folders):
        folder = root / f"d{d:03}"
        folder.mkdir(parents=True)
        for f in range(files):
            (folder / f"f{f}.o").write_bytes(bytes([65 + f % 26]) * size)
    (root / "empty.txt").write_bytes(b"")


def _listing(root: Path) -> list[tuple[str, bytes | str | None]]:
    """Every entry under *root*: a file with its bytes, a link with its
    target, a folder with None."""
    return sorted(
        (str(p.relative_to(root)),
         os.readlink(p) if p.is_symlink() else None if p.is_dir() else p.read_bytes())
        for p in root.rglob("*")
    )


@pytest.fixture
def sftp(tmp_path, monkeypatch):
    """A session on the in-process SFTP server over "/" (its paths are
    this machine's) and the server itself."""
    from tests import sftp_testkit

    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    with mock.patch("pathlib.Path.home", return_value=home):
        server = sftp_testkit.SftpServer("/")
        session = SSHSession(ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=server.port, username="u"))
        session.connect(password="x", on_unknown_host=lambda _e: True)
    yield session, server
    session.disconnect()
    server.close()


def _copy(source, dest, paths, dest_dir, timeout: float = 120.0):
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection, TransferStatus

    mgr = TransferManager(max_parallel=1)
    done: dict = {}
    mgr.transfer_files_in_background(
        source, dest, [str(p) for p in paths], str(dest_dir), TransferDirection.DOWNLOAD,
        on_done=lambda jobs: done.setdefault("jobs", jobs))
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        jobs = done.get("jobs")
        if jobs is not None and mgr.unfinished() == 0:
            break
        time.sleep(0.005)
    jobs = done.get("jobs") or []
    mgr.shutdown()
    assert jobs, "the walk did not finish"
    bad = [(j.source_path, j.status, j.error_message) for j in jobs
           if j.status is not TransferStatus.DONE]
    assert not bad, bad[:5]
    return jobs


def test_happy_2000_small_files_from_sftp_arrive_quickly(sftp, tmp_path):
    session, _server = sftp
    src = tmp_path / "src" / "proj"
    _tree(src, 20, 100)
    dst = tmp_path / "dst"
    dst.mkdir()
    started = time.monotonic()
    jobs = _copy(session, _local(), [src], dst)
    took = time.monotonic() - started
    assert len(jobs) == 2001
    assert _listing(dst / "proj") == _listing(src)
    # Before: about 100 s (50 ms a file). Now a few seconds; the bound is
    # loose for a busy test machine.
    assert took < 45, f"2000 small files took {took:.1f} s"


def test_happy_a_small_file_costs_no_read_ahead_window(sftp, tmp_path):
    """The server counts the READs it serves: one per small file (the
    listed size and a byte more), not 36."""
    session, server = sftp
    src = tmp_path / "src" / "few"
    _tree(src, 2, 25, size=100)
    dst = tmp_path / "dst"
    dst.mkdir()
    server.stats.clear()
    _copy(session, _local(), [src], dst)
    assert _listing(dst / "few") == _listing(src)
    reads = server.stats.get("reads", 0)
    assert reads <= 2 * 51, f"{reads} READs for 51 small files"


def test_sad_a_file_larger_than_listed_is_still_copied_whole(sftp, tmp_path):
    """A file that grew after it was listed: the batch leaves it out (its
    answer had the extra byte) and the job reads all of it."""
    from core.transfer_manager import TransferManager

    session, _server = sftp
    src = tmp_path / "src" / "grow"
    _tree(src, 1, 5)
    real_transfer_file = TransferManager.transfer_file

    def grow_after_listing(self, *args, **kwargs):
        job = real_transfer_file(self, *args, **kwargs)
        if job.source_path.endswith("f3.o"):
            Path(job.source_path).write_bytes(b"G" * 200_000)
        return job

    dst = tmp_path / "dst"
    dst.mkdir()
    with mock.patch.object(TransferManager, "transfer_file", grow_after_listing):
        _copy(session, _local(), [src], dst)
    assert (dst / "grow" / "d000" / "f3.o").read_bytes() == b"G" * 200_000
    assert _listing(dst / "grow") == _listing(src)


def test_happy_2000_small_files_on_disk_all_arrive(tmp_path, monkeypatch):
    """Every entry arrives - the links among the files too (a link to a
    folder failed its row before, and one to a file came as a copy)."""
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    src = tmp_path / "src" / "proj"
    _tree(src, 20, 100)
    os.symlink("../d001", src / "d000" / "to-d001")
    os.symlink("f1.o", src / "d000" / "f1-link.o")
    dst = tmp_path / "dst"
    dst.mkdir()
    started = time.monotonic()
    _copy(_local(), _local(), [src], dst)
    took = time.monotonic() - started
    assert _listing(dst / "proj") == _listing(src)
    assert took < 30, f"2000 small files took {took:.1f} s"


def _local():
    from core.local_fs import LocalFS

    return LocalFS()


# -- uploads: disk -> SFTP, SFTP -> SFTP ---------------------------------------------------
# Measured before: 130 ms per small file to the local test server (22 min
# for 10 000): every upload waited for an OPEN, a WRITE with its CLOSE, two
# LSTATs and a SETSTAT with its RENAME, one after the other - and the two
# pairs each waited ~40 ms more, the server holding its second answer for
# our delayed ACK. Now the small files go in pipelined batches, and the
# client acknowledges at once (core.proxy.enable_quick_ack).


def _copy_with_plan(source, dest, paths, dest_dir, plan_for=None, timeout: float = 120.0):
    """transfer_files with the conflict plan F5 would make (every existing
    name answered with *plan_for*), on a worker; the jobs once all ended."""
    from core.transfer_conflicts import ConflictPlan, scan_conflicts
    from core.transfer_manager import TransferManager

    scan = scan_conflicts(source, dest, [str(p) for p in paths], str(dest_dir))
    plan = ConflictPlan(dest, scan)
    for conflict in scan.conflicts:
        plan.decide(conflict, plan_for)
    mgr = TransferManager(max_parallel=1)
    done: dict = {}
    mgr.transfer_files_in_background(
        source, dest, [str(p) for p in paths], str(dest_dir), conflict_plan=plan,
        on_done=lambda jobs: done.setdefault("jobs", jobs))
    end = time.monotonic() + timeout
    while time.monotonic() < end and ("jobs" not in done or mgr.unfinished()):
        APP.processEvents()
        time.sleep(0.005)
    APP.processEvents()
    mgr.shutdown()
    return {str(Path(j.dest_path).relative_to(dest_dir)): j for j in done.get("jobs", [])}


def _partials(root: Path) -> list[str]:
    return [str(p) for p in root.rglob("*") if ".part-" in p.name]


def test_happy_2000_small_files_go_up_to_sftp_quickly_with_mode_and_time(sftp, tmp_path):
    session, _server = sftp
    src = tmp_path / "src" / "proj"
    _tree(src, 20, 100)
    private = src / "d000" / "f0.o"
    private.chmod(0o600)
    os.utime(private, (1_600_000_000, 1_600_000_000))
    dst = tmp_path / "dst"
    dst.mkdir()
    started = time.monotonic()
    jobs = _copy(_local(), session, [src], dst)
    took = time.monotonic() - started
    assert len(jobs) == 2001
    assert _listing(dst / "proj") == _listing(src)
    copy = dst / "proj" / "d000" / "f0.o"
    assert copy.stat().st_mode & 0o777 == 0o600
    assert int(copy.stat().st_mtime) == 1_600_000_000
    assert _partials(dst) == []
    # Before: about 260 s (130 ms a file). The bound is loose for a busy machine.
    assert took < 45, f"2000 small uploads took {took:.1f} s"


def test_happy_small_files_go_from_sftp_to_sftp_quickly(sftp, tmp_path):
    session, _server = sftp
    src = tmp_path / "src" / "proj"
    _tree(src, 10, 100)
    dst = tmp_path / "dst"
    dst.mkdir()
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection, TransferStatus

    mgr = TransferManager(max_parallel=1)
    done: dict = {}
    started = time.monotonic()
    mgr.transfer_files_in_background(
        session, session, [str(src)], str(dst), TransferDirection.RELAY,
        on_done=lambda jobs: done.setdefault("jobs", jobs))
    end = time.monotonic() + 120
    while time.monotonic() < end and ("jobs" not in done or mgr.unfinished()):
        APP.processEvents()
        time.sleep(0.005)
    took = time.monotonic() - started
    mgr.shutdown()
    assert all(j.status is TransferStatus.DONE for j in done["jobs"])
    assert _listing(dst / "proj") == _listing(src)
    assert took < 30, f"1000 small files SFTP -> SFTP took {took:.1f} s"


def test_sad_a_file_that_appears_before_the_rename_is_not_replaced(sftp, tmp_path):
    """A free name at the conflict check ("fail"): a file put there before
    the batch renames is kept, that job fails, the others land, no partial
    is left."""
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferStatus

    session, _server = sftp
    src = tmp_path / "src" / "proj"
    _tree(src, 1, 10)
    dst = tmp_path / "dst"
    dst.mkdir()
    real = TransferManager.transfer_file

    def then_someone_writes(self, *args, **kwargs):
        job = real(self, *args, **kwargs)
        if job.dest_path.endswith("f3.o"):
            Path(job.dest_path).write_text("theirs")
        return job

    with mock.patch.object(TransferManager, "transfer_file", then_someone_writes):
        jobs = _copy_with_plan(_local(), session, [src], dst)
    taken = jobs["proj/d000/f3.o"]
    assert taken.status is TransferStatus.ERROR and "already exists" in taken.error_message
    assert (dst / "proj" / "d000" / "f3.o").read_text() == "theirs"
    others = [j for name, j in jobs.items() if name != "proj/d000/f3.o"]
    assert all(j.status is TransferStatus.DONE for j in others)
    assert (dst / "proj" / "d000" / "f4.o").read_bytes() == (src / "d000" / "f4.o").read_bytes()
    assert _partials(dst) == []


def test_edge_overwrite_and_newer_answers_hold_in_a_batch(sftp, tmp_path):
    from core.transfer_conflicts import ConflictAction
    from core.transfer_worker import TransferStatus

    session, _server = sftp
    src = tmp_path / "src" / "proj"
    _tree(src, 1, 6)
    dst = tmp_path / "dst"
    (dst / "proj" / "d000").mkdir(parents=True)
    old = dst / "proj" / "d000" / "f1.o"
    old.write_text("older")
    os.utime(old, (1_000_000_000, 1_000_000_000))
    new = dst / "proj" / "d000" / "f2.o"
    new.write_text("newer")
    os.utime(new, (1_000_000_000, 1_000_000_000))
    from core.transfer_manager import TransferManager

    real = TransferManager.transfer_file

    def then_someone_saves(self, *args, **kwargs):
        # Older at the conflict check, newer by the time of the rename.
        job = real(self, *args, **kwargs)
        if job.dest_path.endswith("f2.o"):
            os.utime(new, (4_000_000_000, 4_000_000_000))
        return job

    with mock.patch.object(TransferManager, "transfer_file", then_someone_saves):
        jobs = _copy_with_plan(_local(), session, [src], dst, ConflictAction.OVERWRITE_IF_NEWER)
    assert old.read_bytes() == (src / "d000" / "f1.o").read_bytes()  # source newer: replaced
    assert new.read_text() == "newer"  # destination newer: kept
    assert jobs["proj/d000/f2.o"].skipped
    assert jobs["proj/d000/f1.o"].status is TransferStatus.DONE
    jobs = _copy_with_plan(_local(), session, [src], dst, ConflictAction.OVERWRITE)
    assert new.read_bytes() == (src / "d000" / "f2.o").read_bytes()
    assert _partials(dst) == []


def test_edge_the_ssh_socket_acknowledges_at_once(sftp):
    """The client's TCP socket sets TCP_QUICKACK after every read where
    the system has it: a server's Nagle then waits one round trip for its
    second answer, not a 40 ms delayed ACK."""
    import socket

    from core.proxy import _QuickAckSocket

    session, _server = sftp
    sock = session._transport.sock
    if not hasattr(socket, "TCP_QUICKACK"):
        pytest.skip("no TCP_QUICKACK on this system")
    assert isinstance(sock, _QuickAckSocket)
    assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
