"""Several transfer jobs at once (docs/plans/future-design-decisions.md, entry 3).

The transfer manager ran every job on one worker, one after the other. The
"Parallel transfers" setting (default 1, 1..8) lets up to N jobs run side by
side, started in queue order; a session that is not proven safe for two
threads carries one job at a time, and two jobs never write one path at once.
These tests drive core.transfer_pool's scheduler alone, the manager with real
worker threads over real LocalFS / RamFs storage (slowed down so that jobs
overlap), and the transfer dock offscreen.
"""

from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import open_limits as OL  # noqa: E402
from core import transfer_pool as TP  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.transfer_worker import (  # noqa: E402
    CHUNK_SIZE,
    TransferDirection,
    TransferJob,
    TransferStatus,
    partial_name,
    source_fingerprint,
)

APP = QApplication.instance() or QApplication([])
FINAL = (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "config" / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "operations.jsonl"))


def pump_until(predicate, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return predicate()


class _Handle:
    """A source file handle that counts the job as running until closed."""

    def __init__(self, owner: SlowLocal, fh, path: str) -> None:
        self._owner = owner
        self._fh = fh
        self._path = path
        self._closed = False
        self.bytes_read = 0

    def read(self, n: int = -1) -> bytes:
        if self._owner.read_delay:
            time.sleep(self._owner.read_delay)
        data = self._fh.read(n)
        self.bytes_read += len(data)
        return data

    def seek(self, *args):
        return self._fh.seek(*args)

    def tell(self):
        return self._fh.tell()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._fh.close()
            self._owner._left(self._path, self.bytes_read)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class SlowLocal(LocalFS):
    """Real LocalFS storage, each source read slowed down, and a count of
    how many jobs read from this session at the same time."""

    parallel_transfers_safe = True

    def __init__(self, open_delay: float = 0.0, read_delay: float = 0.0) -> None:
        super().__init__()
        self.open_delay = open_delay
        self.read_delay = read_delay
        self._lock = threading.Lock()
        self.inflight = 0
        self.max_inflight = 0
        self.opened: list[str] = []
        self.read_totals: dict[str, list[int]] = {}

    def open_read(self, path: str):
        with self._lock:
            self.opened.append(path)
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            if self.open_delay:
                time.sleep(self.open_delay)
            return _Handle(self, super().open_read(path), path)
        except BaseException:
            with self._lock:
                self.inflight -= 1
            raise

    def _left(self, path: str, read: int) -> None:
        with self._lock:
            self.inflight -= 1
            self.read_totals.setdefault(path, []).append(read)


class UnsafeSlow(SlowLocal):
    """The same, but a session that may carry one job at a time."""

    parallel_transfers_safe = False


def make_files(folder: Path, count: int, size: int = 2048, prefix: str = "f") -> list[str]:
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for i in range(count):
        p = folder / f"{prefix}{i:03d}.bin"
        p.write_bytes(hashlib.sha256(f"{prefix}{i}".encode()).digest() * (size // 32 + 1))
        paths.append(str(p))
    return paths


def mkd(folder: Path) -> str:
    folder.mkdir(parents=True, exist_ok=True)
    return str(folder)


def manager(n: int = 1):
    from core.transfer_manager import TransferManager

    mgr = TransferManager(max_parallel=n)
    return mgr


def wait_all(mgr, jobs, timeout: float = 30.0) -> None:
    assert pump_until(lambda: all(j.status in FINAL for j in jobs), timeout), [
        (j.filename, j.status) for j in jobs
    ]
    # The manager's slots run on the GUI thread after the worker set the status.
    pump_until(lambda: mgr._active_count == 0 and mgr._queued_count == 0, 5)


def shut(mgr) -> None:
    mgr.shutdown()


def job(src=None, dst=None, source="/s", dest="/d", move=False) -> TransferJob:
    j = TransferJob(source_path=source, dest_path=dest, move=move)
    j.source_backend = src
    j.dest_backend = dst
    return j


class _Session:
    """Not proven safe: the default for a backend outside the table."""


class _SafeSession:
    parallel_transfers_safe = True


# ---------------------------------------------------------------------------
# The setting
# ---------------------------------------------------------------------------


def test_happy_the_setting_defaults_to_one_job_at_a_time() -> None:
    assert TP.DEFAULT_PARALLEL == 1
    assert TP.MAX_PARALLEL == 8
    assert TP.parallel_transfers() == 1


def test_happy_the_setting_is_stored_and_read_back() -> None:
    TP.set_parallel_transfers(4)
    assert TP.parallel_transfers() == 4
    assert OL.read_setting(TP.PARALLEL_SETTING) == 4
    TP.set_parallel_transfers(8)
    assert TP.parallel_transfers() == 8


@pytest.mark.parametrize("bad", [0, 9, -1, True, "4", 2.0, None])
def test_sad_the_setting_refuses_values_outside_one_to_eight(bad) -> None:
    with pytest.raises(ValueError):
        TP.set_parallel_transfers(bad)
    assert TP.parallel_transfers() == 1


@pytest.mark.parametrize("bad", [0, 9, True, "4", [4], {"n": 4}])
def test_edge_a_hand_edited_bad_value_reads_as_the_default(bad) -> None:
    OL.write_setting(TP.PARALLEL_SETTING, bad)
    assert TP.parallel_transfers() == 1


# ---------------------------------------------------------------------------
# Which sessions may carry two jobs at once
# ---------------------------------------------------------------------------


def test_happy_backends_proven_safe_for_two_jobs() -> None:
    from core.smb_client import SmbSession
    from core.ssh_client import SSHSession

    assert TP.parallel_safe(LocalFS())
    assert TP.parallel_safe(RamFsSession())
    assert TP.parallel_safe(object.__new__(SSHSession))
    assert TP.parallel_safe(object.__new__(SmbSession))


def test_sad_backends_not_proven_safe_are_serialized() -> None:
    from core.ftp_client import FtpSession
    from core.mtp_client import MtpSession
    from core.scp_client import SCPSession

    # FtpSession built without __init__ has nothing to open a second
    # control connection with.
    for cls in (FtpSession, SCPSession, MtpSession):
        assert not TP.parallel_safe(object.__new__(cls)), cls
    assert not TP.parallel_safe(_Session())


def test_happy_webdav_s3_and_ftp_with_separate_connections_are_safe() -> None:
    from core.ftp_client import FtpSession
    from core.webdav_client import WebDavSession

    assert TP.parallel_safe(object.__new__(WebDavSession))
    s3 = pytest.importorskip("core.s3_client")
    assert TP.parallel_safe(object.__new__(s3.S3Session))
    ftp = object.__new__(FtpSession)
    ftp._separate_transfers = True
    assert TP.parallel_safe(ftp)


def test_sad_ftp_after_a_refused_second_connection_carries_one_job() -> None:
    from core.ftp_client import FtpSession

    ftp = object.__new__(FtpSession)
    ftp._separate_transfers = True
    assert TP.parallel_safe(ftp)
    ftp._separate_transfers = False  # what the 421 / 530 fallback sets
    assert not TP.parallel_safe(ftp)


class _SwitchingSession:
    """Safe for two jobs until it says otherwise, as FTP does after the
    server refused a second control connection."""

    def __init__(self, safe: bool = True) -> None:
        self.safe = safe

    @property
    def parallel_transfers_safe(self) -> bool:
        return self.safe


class _FailingAnswer:
    @property
    def parallel_transfers_safe(self) -> bool:
        raise RuntimeError("cannot tell")


def test_sad_an_instance_answer_that_fails_counts_as_not_safe() -> None:
    assert not TP.parallel_safe(_FailingAnswer())


def test_edge_an_instance_answer_is_read_from_the_class_body_only() -> None:
    class Child(_SwitchingSession):
        pass

    assert TP.parallel_safe(_SwitchingSession(True))
    assert not TP.parallel_safe(_SwitchingSession(False))
    assert not TP.parallel_safe(Child(True))


def test_edge_a_declaration_is_not_inherited() -> None:
    class Child(_SafeSession):
        pass

    class LocalChild(LocalFS):
        pass

    assert TP.parallel_safe(_SafeSession())
    assert not TP.parallel_safe(Child())
    assert not TP.parallel_safe(LocalChild())  # a subclass may do its I/O differently
    assert TP.parallel_safe(None)  # no backend: nothing to share


# ---------------------------------------------------------------------------
# The scheduler alone
# ---------------------------------------------------------------------------


def _never() -> bool:
    return False


def _take_now(sched, index=0):
    """take() without blocking: None when nothing may start right now."""
    out = []
    stop = threading.Event()
    t = threading.Thread(target=lambda: out.append(sched.take(index, stop.is_set)))
    t.start()
    t.join(0.2)
    if t.is_alive():
        stop.set()
        sched.wake()
        t.join(2)
        return None
    return out[0]


def test_happy_with_limit_one_jobs_start_in_queue_order() -> None:
    sched = TP.JobScheduler(1)
    safe = _SafeSession()
    jobs = [job(safe, safe, f"/s{i}", f"/d{i}") for i in range(5)]
    for j in jobs:
        sched.put(j)
    order = []
    for _ in jobs:
        taken, claimed = sched.take(0, _never)
        assert claimed
        assert _take_now(sched) is None  # one at a time
        order.append(taken)
        sched.done(taken)
    assert order == jobs


def test_happy_up_to_the_limit_run_at_once_in_queue_order() -> None:
    sched = TP.JobScheduler(3)
    safe = _SafeSession()
    jobs = [job(safe, safe, f"/s{i}", f"/d{i}") for i in range(5)]
    for j in jobs:
        sched.put(j)
    first = [sched.take(i, _never)[0] for i in range(3)]
    assert first == jobs[:3]
    assert sched.running() == 3
    assert _take_now(sched, 0) is None  # the limit is reached
    sched.done(first[1])
    assert sched.take(1, _never)[0] is jobs[3]


def test_edge_a_session_not_proven_safe_carries_one_job_while_others_go_on() -> None:
    sched = TP.JobScheduler(4)
    unsafe, safe = _Session(), _SafeSession()
    a = job(unsafe, safe, "/a", "/da")
    b = job(unsafe, safe, "/b", "/db")
    c = job(safe, safe, "/c", "/dc")
    for j in (a, b, c):
        sched.put(j)
    assert sched.take(0, _never)[0] is a
    assert sched.take(1, _never)[0] is c  # b waits for the session, c does not
    assert _take_now(sched, 2) is None
    sched.done(a)
    assert sched.take(2, _never)[0] is b


def test_edge_a_relay_between_two_unsafe_sessions_holds_both() -> None:
    sched = TP.JobScheduler(4)
    s1, s2 = _Session(), _Session()
    relay = job(s1, s2, "/r", "/dr")
    from_s2 = job(s2, _SafeSession(), "/x", "/dx")
    sched.put(relay)
    sched.put(from_s2)
    assert sched.take(0, _never)[0] is relay
    assert _take_now(sched, 1) is None
    sched.done(relay)
    assert sched.take(1, _never)[0] is from_s2


def test_edge_two_jobs_never_write_one_destination_at_once() -> None:
    sched = TP.JobScheduler(4)
    safe = _SafeSession()
    first = job(safe, safe, "/a/x.txt", "/dest/X.txt")
    same = job(safe, safe, "/b/x.txt", "/dest/x.txt")  # one file on a case-insensitive end
    other = job(safe, safe, "/c/y.txt", "/dest/y.txt")
    for j in (first, same, other):
        sched.put(j)
    assert sched.take(0, _never)[0] is first
    assert sched.take(1, _never)[0] is other
    assert _take_now(sched, 2) is None
    sched.done(first)
    assert sched.take(2, _never)[0] is same


def test_edge_nothing_reads_a_path_another_job_writes() -> None:
    sched = TP.JobScheduler(4)
    safe = _SafeSession()
    writer = job(safe, safe, "/src/a", "/mid/a")
    reader = job(safe, safe, "/mid/a", "/out/a")
    copy_same_source = job(safe, safe, "/src/a", "/out2/a")  # reading together is fine
    for j in (writer, reader, copy_same_source):
        sched.put(j)
    assert sched.take(0, _never)[0] is writer
    assert sched.take(1, _never)[0] is copy_same_source
    assert _take_now(sched, 2) is None
    sched.done(writer)
    assert sched.take(2, _never)[0] is reader


def test_edge_a_move_holds_its_source_as_well() -> None:
    sched = TP.JobScheduler(4)
    safe = _SafeSession()
    move = job(safe, safe, "/src/a", "/dst/a", move=True)
    copy = job(safe, safe, "/src/a", "/dst2/a")
    sched.put(move)
    sched.put(copy)
    assert sched.take(0, _never)[0] is move
    assert _take_now(sched, 1) is None
    sched.done(move)
    assert sched.take(1, _never)[0] is copy


def _take_within(sched, index: int, timeout: float = 5.0):
    """The job worker *index* gets; fails instead of blocking the run."""
    out = []
    stop = threading.Event()
    t = threading.Thread(target=lambda: out.append(sched.take(index, stop.is_set)))
    t.start()
    t.join(timeout)
    if t.is_alive():
        stop.set()
        sched.wake()
        t.join(2)
        pytest.fail(f"worker {index} got no job within {timeout} s")
    assert out[0] is not None and out[0][1], out
    return out[0][0]


def test_edge_an_instance_answer_is_asked_again_before_each_job() -> None:
    sched = TP.JobScheduler(4)
    ftp, safe = _SwitchingSession(True), _SafeSession()
    jobs = [job(ftp, safe, f"/s{i}", f"/d{i}") for i in range(5)]
    for j in jobs:
        sched.put(j)
    a = _take_within(sched, 0)
    b = _take_within(sched, 1)
    assert (a, b) == (jobs[0], jobs[1])  # two jobs on one safe session
    ftp.safe = False  # the server refused a second connection mid-run
    assert _take_now(sched, 2) is None
    sched.done(a)
    assert _take_now(sched, 2) is None  # b still runs on the session
    sched.done(b)
    c = _take_within(sched, 2)
    assert c is jobs[2]
    assert _take_now(sched, 3) is None  # one job at a time from now on
    sched.done(c)
    ftp.safe = True
    d = _take_within(sched, 0)
    e = _take_within(sched, 1)
    assert (d, e) == (jobs[3], jobs[4])


def test_edge_a_switching_session_in_a_relay_waits_with_its_partner() -> None:
    sched = TP.JobScheduler(4)
    ftp, unsafe = _SwitchingSession(True), _Session()
    relay = job(ftp, unsafe, "/r", "/dr")
    other = job(ftp, _SafeSession(), "/x", "/dx")
    sched.put(relay)
    sched.put(other)
    assert _take_within(sched, 0) is relay
    assert _take_within(sched, 1) is other  # the FTP side may carry both
    sched.done(other)
    third = job(ftp, unsafe, "/y", "/dy")  # needs the busy unsafe partner
    sched.put(third)
    assert _take_now(sched, 1) is None
    sched.done(relay)
    assert _take_within(sched, 1) is third


def test_edge_a_job_cancelled_while_it_waits_is_handed_out_unclaimed() -> None:
    sched = TP.JobScheduler(4)
    unsafe = _Session()
    a = job(unsafe, _SafeSession(), "/a", "/da")
    b = job(unsafe, _SafeSession(), "/b", "/db")
    sched.put(a)
    sched.put(b)
    assert sched.take(0, _never) == (a, True)
    b.cancel_event.set()
    sched.wake()
    assert sched.take(1, _never) == (b, False)  # without the session a still holds
    sched.done(b)
    sched.done(a)
    assert sched.running() == 0


def test_edge_a_lowered_limit_waits_for_the_running_jobs() -> None:
    sched = TP.JobScheduler(3)
    safe = _SafeSession()
    jobs = [job(safe, safe, f"/s{i}", f"/d{i}") for i in range(5)]
    for j in jobs:
        sched.put(j)
    running = [sched.take(i, _never)[0] for i in range(3)]
    sched.set_limit(1)
    sched.done(running[0])
    assert _take_now(sched, 0) is None  # two still run, the limit is one
    sched.done(running[1])
    sched.done(running[2])
    assert _take_now(sched, 1) is None  # worker 1 is above the limit now
    assert sched.take(0, _never)[0] is jobs[3]


def test_sad_the_scheduler_refuses_a_bad_limit() -> None:
    for bad in (0, 9, True, "2"):
        with pytest.raises(ValueError):
            TP.JobScheduler(bad)
        with pytest.raises(ValueError):
            TP.JobScheduler(2).set_limit(bad)


def test_edge_a_stopped_worker_gets_nothing() -> None:
    sched = TP.JobScheduler(2)
    sched.put(job(_SafeSession(), _SafeSession()))
    assert sched.take(0, lambda: True) is None
    assert sched.pending() == 1


# ---------------------------------------------------------------------------
# The manager with real worker threads
# ---------------------------------------------------------------------------


def test_happy_the_default_runs_one_job_after_the_other(tmp_path) -> None:
    src = SlowLocal(open_delay=0.03)
    mgr = manager()
    try:
        assert mgr.max_parallel == 1
        jobs = mgr.transfer_files(src, LocalFS(), make_files(tmp_path / "a", 6),
                                  mkd(tmp_path / "b"), TransferDirection.DOWNLOAD)
        wait_all(mgr, jobs)
        assert all(j.status == TransferStatus.DONE for j in jobs)
        assert src.max_inflight == 1
        assert len(mgr._pool) == 1
    finally:
        shut(mgr)


def test_happy_four_jobs_run_side_by_side_and_every_byte_arrives(tmp_path) -> None:
    src = SlowLocal(open_delay=0.1)
    dst = tmp_path / "b"
    dst.mkdir()
    mgr = manager(4)
    try:
        paths = make_files(tmp_path / "a", 12)
        jobs = mgr.transfer_files(src, LocalFS(), paths, str(dst), TransferDirection.DOWNLOAD)
        wait_all(mgr, jobs)
        assert [j.status for j in jobs] == [TransferStatus.DONE] * 12
        assert src.max_inflight >= 2
        assert src.max_inflight <= 4
        for p in paths:
            assert (dst / Path(p).name).read_bytes() == Path(p).read_bytes()
    finally:
        shut(mgr)


def test_edge_more_workers_than_jobs(tmp_path) -> None:
    mgr = manager(8)
    try:
        assert len(mgr._pool) == 8
        jobs = mgr.transfer_files(SlowLocal(open_delay=0.05), LocalFS(),
                                  make_files(tmp_path / "a", 2), mkd(tmp_path / "b"),
                                  TransferDirection.DOWNLOAD)
        wait_all(mgr, jobs)
        assert [j.status for j in jobs] == [TransferStatus.DONE] * 2
    finally:
        shut(mgr)
    assert all(thread.isFinished() for _, thread in mgr._pool)


def test_edge_a_session_not_proven_safe_never_sees_two_jobs(tmp_path) -> None:
    src = UnsafeSlow(open_delay=0.05)
    other = SlowLocal(open_delay=0.05)
    mgr = manager(4)
    try:
        jobs = mgr.transfer_files(src, LocalFS(), make_files(tmp_path / "a", 6),
                                  mkd(tmp_path / "b"), TransferDirection.DOWNLOAD)
        jobs += mgr.transfer_files(other, LocalFS(), make_files(tmp_path / "c", 6, prefix="g"),
                                   mkd(tmp_path / "d"), TransferDirection.DOWNLOAD)
        wait_all(mgr, jobs)
        assert all(j.status == TransferStatus.DONE for j in jobs)
        assert src.max_inflight == 1
        assert other.max_inflight >= 2
    finally:
        shut(mgr)


def test_edge_cancel_while_a_job_waits_for_its_session(tmp_path) -> None:
    src = UnsafeSlow(read_delay=0.15)
    big = make_files(tmp_path / "a", 1, size=4 * CHUNK_SIZE, prefix="big")
    small = make_files(tmp_path / "a", 1, prefix="small")
    mgr = manager(4)
    try:
        jobs = mgr.transfer_files(src, LocalFS(), big + small, mkd(tmp_path / "b"),
                                  TransferDirection.DOWNLOAD)
        running, waiting = jobs
        assert pump_until(lambda: running.status == TransferStatus.ACTIVE)
        assert waiting.status == TransferStatus.PENDING
        mgr.cancel_job(waiting.job_id)
        assert pump_until(lambda: waiting.status == TransferStatus.CANCELLED, 3)
        assert running.status == TransferStatus.ACTIVE  # it did not wait for the big one
        assert small[0] not in src.opened  # and never touched the busy session
        wait_all(mgr, jobs)
        assert running.status == TransferStatus.DONE
        assert not (tmp_path / "b" / Path(small[0]).name).exists()
    finally:
        shut(mgr)


def test_sad_an_error_in_one_job_does_not_stop_the_others(tmp_path) -> None:
    paths = make_files(tmp_path / "a", 6)
    os.remove(paths[2])  # vanished after it was listed
    (tmp_path / "b").mkdir()
    mgr = manager(3)
    try:
        jobs = [
            mgr.transfer_file(SlowLocal(open_delay=0.05), LocalFS(), p,
                              str(tmp_path / "b" / Path(p).name), size=2048)
            for p in paths
        ]
        wait_all(mgr, jobs)
        assert jobs[2].status == TransferStatus.ERROR
        assert [j.status for i, j in enumerate(jobs) if i != 2] == [TransferStatus.DONE] * 5
    finally:
        shut(mgr)


def test_happy_cancel_one_running_job_the_others_finish_and_retry_resumes(tmp_path) -> None:
    src = SlowLocal(read_delay=0.1)
    big = make_files(tmp_path / "a", 1, size=8 * CHUNK_SIZE, prefix="big")
    rest = make_files(tmp_path / "a", 3, size=4 * CHUNK_SIZE, prefix="r")
    dst = tmp_path / "b"
    dst.mkdir()
    mgr = manager(4)
    try:
        jobs = mgr.transfer_files(src, LocalFS(), big + rest, str(dst),
                                  TransferDirection.DOWNLOAD)
        target = jobs[0]
        assert pump_until(lambda: target.transferred_bytes >= 2 * CHUNK_SIZE)
        assert sum(j.status == TransferStatus.ACTIVE for j in jobs) >= 2
        mgr.cancel_job(target.job_id)
        wait_all(mgr, jobs)
        assert target.status == TransferStatus.CANCELLED
        assert [j.status for j in jobs[1:]] == [TransferStatus.DONE] * 3
        partial = Path(target.temp_path)
        assert partial.exists() and partial.stat().st_size > 0  # kept for the resume

        retry = mgr.retry_job(target.job_id)
        assert retry is not None and retry.resume
        wait_all(mgr, [retry])
        assert retry.status == TransferStatus.DONE
        assert (dst / Path(big[0]).name).read_bytes() == Path(big[0]).read_bytes()
        # The resume read the verify windows and the tail, not the whole file.
        assert src.read_totals[big[0]][-1] < 7 * CHUNK_SIZE
        assert not partial.exists()
    finally:
        shut(mgr)


def test_happy_the_integrity_check_fails_only_its_own_job(tmp_path) -> None:
    class BadSum(LocalFS):
        parallel_transfers_safe = True

        def checksum(self, path: str, algorithm: str = "sha256") -> str:
            if path.endswith("f001.bin"):
                return "sha256:" + "0" * 64
            return LocalFS.checksum(self, path, algorithm)

    mgr = manager(3)
    try:
        jobs = mgr.transfer_files(SlowLocal(open_delay=0.05), BadSum(),
                                  make_files(tmp_path / "a", 4), mkd(tmp_path / "b"),
                                  TransferDirection.DOWNLOAD)
        wait_all(mgr, jobs)
        assert jobs[1].status == TransferStatus.ERROR
        assert "Integrity FAIL" in jobs[1].error_message
        assert [jobs[i].status for i in (0, 2, 3)] == [TransferStatus.DONE] * 3
    finally:
        shut(mgr)


def test_happy_retry_puts_failed_jobs_back_and_they_run_side_by_side(tmp_path) -> None:
    paths = make_files(tmp_path / "a", 4)
    hidden = {}
    for p in paths:  # all four missing at first
        hidden[p] = Path(p).read_bytes()
        os.remove(p)
    src = SlowLocal(open_delay=0.1)
    dst = tmp_path / "b"
    dst.mkdir()
    mgr = manager(4)
    try:
        jobs = [mgr.transfer_file(src, LocalFS(), p, str(dst / Path(p).name), size=2048)
                for p in paths]
        wait_all(mgr, jobs)
        assert [j.status for j in jobs] == [TransferStatus.ERROR] * 4
        for p, data in hidden.items():
            Path(p).write_bytes(data)
        src.max_inflight = 0
        retries = [mgr.retry_job(j.job_id) for j in jobs]
        assert all(r is not None for r in retries)
        assert all(mgr.retry_job(j.job_id) is None for j in jobs)  # once per job
        wait_all(mgr, retries)
        assert [r.status for r in retries] == [TransferStatus.DONE] * 4
        assert src.max_inflight >= 2
        for p, data in hidden.items():
            assert (dst / Path(p).name).read_bytes() == data
    finally:
        shut(mgr)


def test_happy_leftover_partials_resume_with_jobs_side_by_side(tmp_path) -> None:
    src = SlowLocal(open_delay=0.05)
    size = 4 * CHUNK_SIZE
    paths = make_files(tmp_path / "a", 3, size=size)
    dst = tmp_path / "b"
    dst.mkdir()
    for i, p in enumerate(paths):
        data = Path(p).read_bytes()
        fp = source_fingerprint(LocalFS().stat(p))
        name = partial_name(Path(p).name, f"old{i:05d}", fp)
        (dst / name).write_bytes(data[: len(data) // 2])
    mgr = manager(3)
    try:
        jobs = mgr.transfer_files(src, LocalFS(), paths, str(dst), TransferDirection.DOWNLOAD)
        assert all(j.resume for j in jobs)
        assert len({j.temp_path for j in jobs}) == 3  # each job its own partial
        wait_all(mgr, jobs)
        assert [j.status for j in jobs] == [TransferStatus.DONE] * 3
        for p in paths:
            assert (dst / Path(p).name).read_bytes() == Path(p).read_bytes()
            assert src.read_totals[p][-1] < len(Path(p).read_bytes())
        assert sorted(x.name for x in dst.iterdir()) == sorted(Path(p).name for p in paths)
    finally:
        shut(mgr)


def test_edge_changing_the_limit_while_jobs_run_applies_to_later_jobs(tmp_path) -> None:
    src = SlowLocal(open_delay=0.15)
    mgr = manager(1)
    try:
        jobs = mgr.transfer_files(src, LocalFS(), make_files(tmp_path / "a", 10),
                                  mkd(tmp_path / "b"), TransferDirection.DOWNLOAD)
        assert pump_until(lambda: jobs[0].status == TransferStatus.ACTIVE)
        mgr.set_max_parallel(3)
        assert mgr.max_parallel == 3
        assert pump_until(lambda: src.inflight >= 2, 5)
        mgr.set_max_parallel(1)
        assert pump_until(lambda: mgr._scheduler.running() <= 1, 5)
        src.max_inflight = 0
        wait_all(mgr, jobs)
        assert [j.status for j in jobs] == [TransferStatus.DONE] * 10
        assert src.max_inflight <= 1
    finally:
        shut(mgr)


def test_sad_the_manager_refuses_a_bad_limit() -> None:
    mgr = manager(2)
    try:
        for bad in (0, 9, True, "3", None):
            with pytest.raises(ValueError):
                mgr.set_max_parallel(bad)
        assert mgr.max_parallel == 2
    finally:
        shut(mgr)


def test_edge_without_an_argument_the_manager_reads_the_setting() -> None:
    from core.transfer_manager import TransferManager

    TP.set_parallel_transfers(3)
    mgr = TransferManager()
    try:
        assert mgr.max_parallel == 3
        assert len(mgr._pool) == 3
    finally:
        shut(mgr)


def test_edge_with_two_workers_jobs_are_taken_in_queue_order(tmp_path, monkeypatch) -> None:
    taken = []
    real_take = TP.JobScheduler.take

    def recording_take(self, index, stopped):
        result = real_take(self, index, stopped)
        if result is not None:
            taken.append(result[0])
        return result

    monkeypatch.setattr(TP.JobScheduler, "take", recording_take)
    mgr = manager(2)
    try:
        jobs = mgr.transfer_files(SlowLocal(open_delay=0.03), LocalFS(),
                                  make_files(tmp_path / "a", 8), mkd(tmp_path / "b"),
                                  TransferDirection.DOWNLOAD)
        wait_all(mgr, jobs)
        assert taken == jobs
    finally:
        shut(mgr)


def test_happy_shutdown_stops_every_worker_and_leaves_no_thread(tmp_path) -> None:
    src = SlowLocal(read_delay=0.1)
    mgr = manager(4)
    jobs = mgr.transfer_files(src, LocalFS(), make_files(tmp_path / "a", 6, size=3 * CHUNK_SIZE),
                              mkd(tmp_path / "b"), TransferDirection.DOWNLOAD)
    assert pump_until(lambda: sum(j.status == TransferStatus.ACTIVE for j in jobs) >= 2)
    mgr.shutdown()
    assert all(thread.isFinished() for _, thread in mgr._pool)
    assert not any(thread.isRunning() for _, thread in mgr._pool)
    assert all(j.status in FINAL or j.status == TransferStatus.PENDING for j in jobs)
    assert not any(j.status == TransferStatus.ACTIVE for j in jobs)


# ---------------------------------------------------------------------------
# The transfer dock, offscreen
# ---------------------------------------------------------------------------


def test_e2e_the_dock_shows_several_running_jobs_with_their_progress_and_speed(tmp_path) -> None:
    from models.transfer_model import COL_PROGRESS, COL_SPEED, COL_STATUS
    from ui.transfer_dock import TransferDock

    src = SlowLocal(read_delay=0.12)
    ram = RamFsSession(label="dock-e2e")
    ram.mkdir("/in")
    mgr = manager(3)
    dock = TransferDock(mgr)
    dock.resize(900, 300)
    dock.show()
    try:
        paths = make_files(tmp_path / "a", 4, size=6 * CHUNK_SIZE)
        jobs = mgr.transfer_files(src, ram, paths, "/in", TransferDirection.UPLOAD)
        model = dock._model

        def text(row, col):
            return model.data(model.index(row, col))

        def busy_rows():
            return [r for r in range(model.rowCount()) if text(r, COL_STATUS) == "active"]

        def two_moving() -> bool:
            rows = busy_rows()
            moving = [r for r in rows if text(r, COL_SPEED) and text(r, COL_PROGRESS) != "0%"]
            return len(moving) >= 2

        assert pump_until(two_moving, 20), [
            [text(r, c) for c in (COL_PROGRESS, COL_SPEED, COL_STATUS)]
            for r in range(model.rowCount())
        ]
        rows = busy_rows()
        assert 2 <= len(rows) <= 3
        speeds = [text(r, COL_SPEED) for r in rows if text(r, COL_SPEED)]
        assert all(s.endswith("/s") for s in speeds)
        assert dock._overall_progress.format() == "%p%"
        wait_all(mgr, jobs, 60)
        APP.processEvents()
        assert [text(r, COL_STATUS) for r in range(model.rowCount())] == ["done"] * 4
        for p in paths:
            with ram.open_read("/in/" + Path(p).name) as fh:
                assert fh.read() == Path(p).read_bytes()
    finally:
        dock.close()
        dock.deleteLater()
        shut(mgr)


# ---------------------------------------------------------------------------
# The journal is written before the job reads as finished
# ---------------------------------------------------------------------------
# A caller that waits for job.status (tests, scripts, the undo menu on
# job_finished) read the journal before the worker thread had written the
# finish event: tests/test_undo_transfer_journal.py failed 4 of 60 runs under
# load on the base commit. With more workers the window only gets wider.


def _status_at_finish(monkeypatch):
    from core import operation_journal

    seen = []
    real = operation_journal.finish_operation

    def recording(op_id, *args, **kwargs):
        seen.append((kwargs.get("status"), current["job"].status))
        return real(op_id, *args, **kwargs)

    current = {}
    monkeypatch.setattr(operation_journal, "finish_operation", recording)
    return seen, current


def _journal_job(tmp_path, name: str, **kw) -> TransferJob:
    j = TransferJob(source_path=str(tmp_path / name), dest_path=str(tmp_path / "out" / name),
                    filename=name, operation_id="op-" + name, **kw)
    j.source_backend = LocalFS()
    j.dest_backend = LocalFS()
    return j


def test_happy_a_finished_job_is_in_the_journal_before_it_reads_done(tmp_path, monkeypatch) -> None:
    from core.transfer_worker import TransferWorker

    seen, current = _status_at_finish(monkeypatch)
    (tmp_path / "out").mkdir()
    (tmp_path / "a.txt").write_bytes(b"payload")
    current["job"] = j = _journal_job(tmp_path, "a.txt")
    TransferWorker()._process_job(j)
    assert j.status == TransferStatus.DONE
    assert seen == [("done", TransferStatus.ACTIVE)]


@pytest.mark.parametrize("case", ["error", "cancelled", "skipped", "mismatch"])
def test_sad_every_final_state_is_journaled_before_it_shows(tmp_path, monkeypatch, case) -> None:
    from core.transfer_worker import TransferWorker

    seen, current = _status_at_finish(monkeypatch)
    (tmp_path / "out").mkdir()
    (tmp_path / "a.txt").write_bytes(b"payload")
    kw = {}
    if case == "skipped":
        (tmp_path / "out" / "a.txt").write_bytes(b"newer")
        os.utime(tmp_path / "a.txt", (1, 1))
        kw["if_exists"] = "newer"
    current["job"] = j = _journal_job(tmp_path, "missing.txt" if case == "error" else "a.txt",
                                      **kw)
    if case == "cancelled":
        j.cancel_event.set()
    if case == "mismatch":
        class Bad(LocalFS):
            def checksum(self, path, algorithm="sha256"):
                return "sha256:" + "0" * 64

        j.dest_backend = Bad()
    TransferWorker()._process_job(j)
    expected = {"error": "error", "cancelled": "cancelled", "skipped": "skipped",
                "mismatch": "error"}[case]
    assert seen == [(expected, TransferStatus.ACTIVE)]
    assert j.status in FINAL


def test_edge_a_cancelled_waiting_job_is_journaled_before_it_shows(monkeypatch) -> None:
    from core.transfer_worker import TransferWorker

    seen, current = _status_at_finish(monkeypatch)
    current["job"] = j = job(_Session(), _SafeSession())
    j.operation_id = "op-wait"
    TransferWorker()._report_cancelled(j)
    assert j.status == TransferStatus.CANCELLED
    assert seen == [("cancelled", TransferStatus.ACTIVE)]
