"""Several transfer jobs at once on one FTP, WebDAV or S3 session, live.

0.14.58 let up to N transfer jobs run side by side, but only on sessions
proven safe for two threads (core.transfer_pool._PARALLEL_SAFE); FTP,
WebDAV and S3 carried one job at a time. FTP now runs every transfer on a
control connection of its own, WebDAV gives every thread a requests.Session
of its own and S3 builds its client from a boto3 Session of its own.

Driven against the podman lab (tests/docker/docker-compose.yml: ftp-server
= pure-ftpd with at most 5 connections per address, webdav-server = Apache
mod_dav, s3-server = MinIO), reached through ``podman unshare
--rootless-netns``; skipped when the lab is not reachable. Every copy is
compared byte for byte.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import open_limits as OL  # noqa: E402
from core import transfer_pool as TP  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferDirection, TransferStatus  # noqa: E402

APP = QApplication.instance() or QApplication([])
FINAL = (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)

FTP = ("10.99.0.30", 21)
WEBDAV = ("10.99.0.32", 80)
S3 = ("10.99.0.33", 9000)
KINDS = ("ftp", "webdav", "s3")


def _reachable(addr) -> bool:
    try:
        with socket.create_connection(addr, timeout=0.5):
            return True
    except OSError:
        return False


def _connect(kind: str):
    if kind == "ftp":
        from core.ftp_client import FtpSession

        return FtpSession(FTP[0], FTP[1], "ftpuser", "ftp123")
    if kind == "webdav":
        from core.webdav_client import WebDavSession

        return WebDavSession(f"http://{WEBDAV[0]}:{WEBDAV[1]}", "davuser", "dav123")
    pytest.importorskip("boto3")
    from core.s3_client import S3Session

    return S3Session(
        bucket="testbucket",
        endpoint=f"http://{S3[0]}:{S3[1]}",
        access_key="minioadmin",
        secret_key="minioadmin123",
        region="us-east-1",
    )


_ADDR = {"ftp": FTP, "webdav": WEBDAV, "s3": S3}


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "config" / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "operations.jsonl"))


@pytest.fixture(params=KINDS)
def remote(request):
    kind = request.param
    if not _reachable(_ADDR[kind]):
        pytest.skip(f"{kind} lab container not reachable")
    session = _connect(kind)
    root = f"/axpar-{uuid.uuid4().hex[:10]}"
    session.mkdir(root)
    try:
        yield kind, session, root
    finally:
        # Disconnected first: the FTP lab allows 5 connections in all.
        session.disconnect()
        try:
            cleanup = _connect(kind)
            try:
                cleanup.remove(root, recursive=True)
            finally:
                cleanup.disconnect()
        except OSError:
            pass


def pump_until(predicate, timeout: float = 120.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return predicate()


def _manager(n: int):
    from core.transfer_manager import TransferManager

    return TransferManager(max_parallel=n)


def _wait(mgr, jobs, timeout: float = 180.0) -> None:
    assert pump_until(lambda: all(j.status in FINAL for j in jobs), timeout), [
        (j.filename, j.status) for j in jobs
    ]
    pump_until(lambda: mgr._active_count == 0 and mgr._queued_count == 0, 10)


def _content(i: int, size: int) -> bytes:
    return hashlib.sha256(f"axpar{i}".encode()).digest() * (size // 32) + bytes([i % 256])


def _local_files(folder: Path, count: int, size: int) -> list[str]:
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    for i in range(count):
        p = folder / f"f{i:03d}.bin"
        p.write_bytes(_content(i, size))
        out.append(str(p))
    return out


def _remote_bytes(session, path: str) -> bytes:
    with session.open_read(path) as fh:
        return fh.read()


def _count_inflight_reads(session) -> dict:
    """Count open_read calls in flight (open to close of the handle) on
    *session*, by an instance attribute: the class stays the same."""
    state = {"now": 0, "peak": 0}
    lock = threading.Lock()
    real = session.open_read

    def leave():
        with lock:
            state["now"] -= 1

    class _Handle:
        def __init__(self, fh):
            self._fh = fh
            self._closed = False

        def read(self, n=-1):
            return self._fh.read(n)

        def seek(self, *a):
            return self._fh.seek(*a)

        def tell(self):
            return self._fh.tell()

        def close(self):
            if not self._closed:
                self._closed = True
                try:
                    self._fh.close()
                finally:
                    leave()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()

    def open_read(path):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        try:
            time.sleep(0.05)  # hold the slot so that overlapping jobs show
            return _Handle(real(path))
        except BaseException:
            leave()
            raise

    session.open_read = open_read
    return state


# ---------------------------------------------------------------- happy path


def test_happy_four_jobs_on_one_session_upload_and_download_byte_exact(remote, tmp_path):
    kind, session, root = remote
    assert TP.parallel_safe(session), f"{kind} is still serialized"
    paths = _local_files(tmp_path / "up", 24, 64 * 1024)
    mgr = _manager(4)
    try:
        up = mgr.transfer_files(LocalFS(), session, paths, root, TransferDirection.UPLOAD)
        _wait(mgr, up)
        assert [j.status for j in up] == [TransferStatus.DONE] * 24, [
            (j.filename, j.status, j.error_message) for j in up
        ]
        for i in range(24):
            assert _remote_bytes(session, f"{root}/f{i:03d}.bin") == _content(i, 64 * 1024)

        inflight = _count_inflight_reads(session)
        back = tmp_path / "back"
        back.mkdir()
        # The folder, as F5 on it queues it: one listing, then the jobs.
        # (Selected one by one, each path costs the GUI thread an is_dir on
        # the shared connection, and the jobs finish faster than they are
        # queued.)
        down = mgr.transfer_files(session, LocalFS(), [root], str(back), TransferDirection.DOWNLOAD)
        _wait(mgr, down)
        assert pump_until(lambda: mgr._active_count == 0 and mgr._queued_count == 0, 120)
        got = back / root.lstrip("/")
        for i in range(24):
            assert (got / f"f{i:03d}.bin").read_bytes() == _content(i, 64 * 1024)
        assert 2 <= inflight["peak"] <= 4, inflight
        assert TP.parallel_safe(session)
    finally:
        mgr.shutdown()


# ------------------------------------------------------------------ sad path


def test_sad_a_failing_job_leaves_the_others_intact(remote, tmp_path):
    kind, session, root = remote
    for i in range(8):
        with session.open_write(f"{root}/f{i}.bin") as fh:
            fh.write(_content(i, 32 * 1024))
    back = tmp_path / "back"
    back.mkdir()
    mgr = _manager(4)
    try:
        jobs = [
            mgr.transfer_file(
                session, LocalFS(), f"{root}/f{i}.bin", str(back / f"f{i}.bin"),
                TransferDirection.DOWNLOAD,
            )
            for i in range(4)
        ]
        jobs.append(
            mgr.transfer_file(
                session, LocalFS(), f"{root}/missing.bin", str(back / "missing.bin"),
                TransferDirection.DOWNLOAD,
            )
        )
        jobs += [
            mgr.transfer_file(
                session, LocalFS(), f"{root}/f{i}.bin", str(back / f"f{i}.bin"),
                TransferDirection.DOWNLOAD,
            )
            for i in range(4, 8)
        ]
        jobs = [j for j in jobs if j is not None]
        _wait(mgr, jobs)
        by_name = {j.filename: j for j in jobs}
        assert by_name["missing.bin"].status == TransferStatus.ERROR
        for i in range(8):
            assert by_name[f"f{i}.bin"].status == TransferStatus.DONE
            assert (back / f"f{i}.bin").read_bytes() == _content(i, 32 * 1024)
        assert not (back / "missing.bin").exists()
    finally:
        mgr.shutdown()


def test_sad_disconnect_while_jobs_run(remote, tmp_path):
    kind, session, root = remote
    paths = _local_files(tmp_path / "up", 24, 128 * 1024)
    mgr = _manager(4)
    try:
        jobs = mgr.transfer_files(LocalFS(), session, paths, root, TransferDirection.UPLOAD)
        assert pump_until(lambda: any(j.status == TransferStatus.DONE for j in jobs), 60)
        session.disconnect()
        _wait(mgr, jobs)  # no job hangs
        session.disconnect()  # the jobs after the first disconnect reconnected
        check = _connect(kind)
        try:
            for i, j in enumerate(jobs):
                if j.status == TransferStatus.DONE:
                    assert _remote_bytes(check, f"{root}/f{i:03d}.bin") == _content(i, 128 * 1024)
                else:
                    assert j.status == TransferStatus.ERROR, (j.filename, j.status)
        finally:
            check.disconnect()
    finally:
        mgr.shutdown()


# ---------------------------------------------------------------- edge cases


def test_edge_stress_many_threads_on_one_session(remote):
    """Eight threads, each writing, reading back, stat-ing and listing its
    own files on ONE session: shared state between threads (a reply handed
    to the wrong request, a response body read by another thread) shows
    up as wrong bytes, a wrong size or an exception."""
    kind, session, root = remote
    errors: list = []
    rounds = 10

    def worker(t: int) -> None:
        try:
            for r in range(rounds):
                name = f"t{t}-r{r}.bin"
                path = f"{root}/{name}"
                data = _content(t * 1000 + r, 1024 * (1 + (t * 7 + r * 3) % 24))
                with session.open_write(path) as fh:
                    fh.write(data)
                got = _remote_bytes(session, path)
                if got != data:
                    errors.append((path, "bytes", len(got), len(data)))
                size = session.stat(path).size
                if size != len(data):
                    errors.append((path, "stat", size, len(data)))
                if name not in {i.name for i in session.list_dir(root)}:
                    errors.append((path, "list"))
        except Exception as exc:  # noqa: BLE001 - collected for the assertion
            errors.append((t, repr(exc)))

    threads = [threading.Thread(target=worker, args=(t,), daemon=True) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(300)
        assert not t.is_alive(), "a worker hung"
    assert errors == []
    assert len(session.list_dir(root)) == 8 * rounds


def test_edge_ftp_two_sessions_beyond_the_server_limit(tmp_path):
    """pure-ftpd allows 5 connections per address: two sessions with four
    uploads each ask for more. Refused ones run on the shared connection;
    every byte still arrives and no session hangs."""
    if not _reachable(FTP):
        pytest.skip("ftp lab container not reachable")
    a, b = _connect("ftp"), _connect("ftp")
    root = f"/axpar-{uuid.uuid4().hex[:10]}"
    a.mkdir(root)
    errors: list = []

    def upload(s, name, data):
        try:
            with s.open_write(f"{root}/{name}") as fh:
                fh.write(data)
        except Exception as exc:  # noqa: BLE001
            errors.append((name, repr(exc)))

    try:
        threads = []
        for label, s in (("a", a), ("b", b)):
            for i in range(4):
                data = _content(ord(label) + i, 256 * 1024)
                threads.append(threading.Thread(target=upload, args=(s, f"{label}{i}", data)))
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
            assert not t.is_alive()
        assert errors == []
        for label in ("a", "b"):
            for i in range(4):
                assert _remote_bytes(a, f"{root}/{label}{i}") == _content(
                    ord(label) + i, 256 * 1024
                )
        refused = [s for s in (a, b) if s._separate_cap is not None or not s._separate_transfers]
        assert refused, "the server refused no connection: the limit was not reached"
    finally:
        b.disconnect()
        try:
            a.remove(root, recursive=True)
        finally:
            a.disconnect()
