"""Retry after a reconnect runs on the new session, not the dropped one.

Auto-reconnect (ui/main_window.py _start_auto_reconnect) gave the pane and
its editors the new session, but not the transfers: TransferManager.retry_job
copied the failed job's backends - the dead SSHSession - so Retry failed
the same way ("Not connected"), and so did every job still queued on it.

Now the reconnect rebinds the queued and failed jobs of the dropped
session (TransferManager.rebind_backend), and retry_job asks the window
(set_backend_resolver) for the backend a pane now uses for the same
connection when the job's own one is no longer connected.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

QtWidgets = pytest.importorskip("PyQt6.QtWidgets")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_manager import TransferManager  # noqa: E402

DATA = os.urandom(200_000)


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _pump(app, cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def manager(app):
    m = TransferManager(max_parallel=1)
    yield m
    m.shutdown()


@pytest.fixture
def sftp(tmp_path):
    """A loopback SFTP server and a connect() that opens a new session."""
    from sftp_testkit import SftpServer

    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    (tmp_path / "srv").mkdir()
    (tmp_path / "home" / ".ssh").mkdir(parents=True)
    (tmp_path / "srv" / "report.bin").write_bytes(DATA)
    with mock.patch("pathlib.Path.home", return_value=tmp_path / "home"):
        srv = SftpServer(str(tmp_path / "srv"))
        prof = ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                 port=srv.port, username="u")
        sessions: list = []

        def connect():
            s = SSHSession(prof)
            s.connect(password="x", on_unknown_host=lambda _e: True)
            sessions.append(s)
            return s

        def drop():
            for t in list(srv._transports):
                t.close()
            time.sleep(0.3)

        try:
            yield SimpleNamespace(connect=connect, drop=drop, tmp=tmp_path)
        finally:
            for s in sessions:
                s.disconnect()
            srv.close()


def _failed_download(manager, old, dest: Path) -> TW.TransferJob:
    job = TW.TransferJob(source_path="/report.bin", dest_path=str(dest),
                         filename="report.bin", total_bytes=len(DATA),
                         source_backend=old, dest_backend=LocalFS(), use_temp_file=True)
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.ERROR
    manager._jobs[job.job_id] = job
    return job


# -- happy -------------------------------------------------------------------


def test_happy_retry_after_the_reconnect_rebind_succeeds(app, manager, sftp):
    old = sftp.connect()
    sftp.drop()
    dest = sftp.tmp / "report.bin"
    job = _failed_download(manager, old, dest)
    new = sftp.connect()
    assert manager.rebind_backend(old, new) == 1
    retry = manager.retry_job(job.job_id)
    assert retry.source_backend is new
    assert _pump(app, lambda: retry.status in (TW.TransferStatus.DONE, TW.TransferStatus.ERROR))
    assert retry.status == TW.TransferStatus.DONE, retry.error_message
    assert dest.read_bytes() == DATA


def test_happy_retry_asks_for_the_panes_backend_when_its_own_is_closed(app, manager, sftp):
    old = sftp.connect()
    sftp.drop()
    dest = sftp.tmp / "report.bin"
    job = _failed_download(manager, old, dest)
    new = sftp.connect()   # e.g. reconnected by hand: no rebind
    manager.set_backend_resolver(lambda b: new if b is old else None)
    retry = manager.retry_job(job.job_id)
    assert retry.source_backend is new
    assert _pump(app, lambda: retry.status in (TW.TransferStatus.DONE, TW.TransferStatus.ERROR))
    assert retry.status == TW.TransferStatus.DONE, retry.error_message


# -- sad ---------------------------------------------------------------------


class _B:
    def __init__(self, connected: bool = True, key: str = "k") -> None:
        self.connected = connected
        self.name = "fake"
        self._axross_profile_key = key


def _job(manager, status, source, dest=None, retried=False) -> TW.TransferJob:
    job = TW.TransferJob(source_path="/a", dest_path="/b", filename="a",
                         source_backend=source, dest_backend=dest or _B())
    job.status = status
    job.retried = retried
    manager._jobs[job.job_id] = job
    return job


def test_sad_queued_and_failed_jobs_move_running_done_and_retried_stay(manager):
    old, new = _B(connected=False), _B()
    S = TW.TransferStatus
    queued = _job(manager, S.PENDING, old)
    failed = _job(manager, S.ERROR, old)
    cancelled = _job(manager, S.CANCELLED, _B(), dest=old)
    running = _job(manager, S.ACTIVE, old)
    done = _job(manager, S.DONE, old)
    retried = _job(manager, S.ERROR, old, retried=True)
    other = _job(manager, S.PENDING, _B())
    assert manager.rebind_backend(old, new) == 3
    assert queued.source_backend is new and failed.source_backend is new
    assert cancelled.dest_backend is new
    for job in (running, done, retried):
        assert job.source_backend is old
    assert other.source_backend is not new


class _Probed(_B):
    """A session whose ``connected`` goes to the network (SMB lists the
    share; on a dead pooled connection that redials for up to a minute)."""

    def __init__(self) -> None:
        self.name = "fake"
        self._axross_profile_key = "k"
        self.probes = 0

    @property
    def connected(self) -> bool:
        self.probes += 1
        time.sleep(2)  # the redial the GUI thread waited for
        return True


def test_sad_retry_takes_the_panes_session_without_probing_the_old_one(manager):
    """Round 6 (repro_retry_probe_blocks_gui / repro_retry_resurrects_old_smb):
    retry_job (GUI thread) read ``old.connected`` - a share listing that
    redialled the replaced SMB session, ~59 s per job and side, and bound
    the retry to that retired session when the server answered."""
    old, pane_session = _Probed(), _B()
    manager.set_backend_resolver(lambda b: pane_session if b is old else None)
    job = _job(manager, TW.TransferStatus.ERROR, old)
    t0 = time.monotonic()
    retry = manager.retry_job(job.job_id)
    assert time.monotonic() - t0 < 1.0
    assert old.probes == 0  # no network on the GUI thread
    assert retry.source_backend is pane_session  # not the retired one
    retry.cancel_event.set()


def test_happy_retry_keeps_the_jobs_session_when_no_pane_has_another(manager):
    own = _B(connected=True)
    manager.set_backend_resolver(lambda b: None)
    job = _job(manager, TW.TransferStatus.ERROR, own)
    retry = manager.retry_job(job.job_id)
    assert retry.source_backend is own
    retry.cancel_event.set()


# -- edge --------------------------------------------------------------------


def test_edge_a_failing_resolver_keeps_the_jobs_backend(manager):
    dead = _B(connected=False)

    def boom(_b):
        raise RuntimeError("window gone")

    manager.set_backend_resolver(boom)
    job = _job(manager, TW.TransferStatus.ERROR, dead)
    assert manager.retry_job(job.job_id).source_backend is dead


def test_edge_rebind_of_nothing_or_the_same_session_is_a_no_op(manager):
    b = _B()
    _job(manager, TW.TransferStatus.PENDING, b)
    assert manager.rebind_backend(b, b) == 0
    assert manager.rebind_backend(None, b) == 0
    assert manager.rebind_backend(b, None) == 0


# -- the window --------------------------------------------------------------


@pytest.fixture
def window(app, tmp_path):
    from ui import main_window as MW

    with mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        yield MW, win
    finally:
        _pump(app, lambda: win._transfer_manager.unfinished() == 0, 5)
        win._quit_with_transfers = True
        win._pane_profiles.clear()
        win.close()
        win.deleteLater()
        app.processEvents()


class _FS(_B):
    def __init__(self, home: str, connected: bool = True) -> None:
        super().__init__(connected)
        self._home = home

    def home(self):
        return self._home

    def list_dir(self, path):
        return []

    def is_dir(self, path):
        return True

    def exists(self, path):
        return True

    def normalize(self, path):
        return path

    def join(self, *parts):
        return os.path.join(*parts)

    def parent(self, path):
        return os.path.dirname(path)

    def disconnect(self):
        self.connected = False


def test_happy_auto_reconnect_rebinds_the_failed_transfers(app, window, tmp_path):
    MW, win = window
    pane = win._panes[0]
    dropped, fresh = _FS(str(tmp_path), connected=False), _FS(str(tmp_path))
    pane._backend = dropped
    profile = mock.Mock(host="h")
    profile.name = "box"
    win._pane_profiles[pane] = profile
    failed = _job(win._transfer_manager, TW.TransferStatus.ERROR, dropped)
    cm = win._connection_manager
    with (
        mock.patch.object(MW, "_is_ssh_session", return_value=True),
        mock.patch.object(cm, "connect", return_value=fresh),
        mock.patch.object(cm, "release"),
    ):
        win._check_connections()
        assert _pump(app, lambda: pane.backend is fresh)
    assert failed.source_backend is fresh


def test_edge_the_window_names_the_panes_backend_of_the_same_connection(window, tmp_path):
    _MW, win = window
    pane = win._panes[0]
    old, current = _FS(str(tmp_path), connected=False), _FS(str(tmp_path))
    pane._backend = current
    assert win._backend_now_for(old) is current          # same key "k"
    assert win._backend_now_for(_B(key="other")) is None  # another connection
    assert win._backend_now_for(object()) is None          # not from a profile
    assert win._backend_now_for(current) is None           # itself: nothing else
