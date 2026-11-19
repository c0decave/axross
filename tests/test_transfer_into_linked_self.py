"""A folder copied or moved into a symlink to itself does not nest for ever.

Review: SFTP, folder ``/a`` copied into ``/b/link`` where ``/b/link`` is a
symlink (on the server) to ``/a``. The into-itself guard compared remote
paths as text, so nothing was refused; the walk made ``/b/link/a`` (that
is ``/a/a``) before it listed ``/a``, found that new folder in the
listing, descended into it, made ``/a/a/a`` ... about 975 levels, until
the path or the connection gave out.

Now: ``is_within`` resolves through the server's realpath where the
backend has one (SFTP), the walk lists a folder before it makes its copy,
never descends into a folder it made itself, and stops at
MAX_RECURSIVE_DELETE_DEPTH levels.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks")

APP = QApplication.instance() or QApplication([])


def _nesting(root: Path, name: str) -> int:
    depth, p = 0, root
    while (p / name).is_dir() and not (p / name).is_symlink():
        depth += 1
        p = p / name
    return depth


@pytest.fixture
def server(tmp_path, monkeypatch):
    """An SFTP server over tmp_path/srv with /a/f.txt and /b."""
    from tests import sftp_testkit

    srv_root = tmp_path / "srv"
    (srv_root / "a").mkdir(parents=True)
    (srv_root / "b").mkdir()
    (srv_root / "a" / "f.txt").write_text("F")
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    made = []

    def connect(resolve_links: bool = False):
        from core.profiles import ConnectionProfile
        from core.ssh_client import SSHSession

        with mock.patch("pathlib.Path.home", return_value=home):
            srv = sftp_testkit.SftpServer(str(srv_root), resolve_links=resolve_links)
            session = SSHSession(ConnectionProfile(
                name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"))
            session.connect(password="x", on_unknown_host=lambda _e: True)
        made.append((srv, session))
        return session

    yield srv_root, connect
    for srv, session in made:
        session.disconnect()
        srv.close()


def _copy(session, source: str, dest_dir: str, timeout: float = 30.0):
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection, TransferStatus

    mgr = TransferManager()
    result: dict = {}
    mgr.transfer_files_in_background(
        source_backend=session, dest_backend=session, source_paths=[source],
        dest_dir=dest_dir, direction=TransferDirection.RELAY,
        on_done=lambda jobs: result.setdefault("jobs", jobs),
        on_error=lambda e: result.setdefault("err", e))
    end = time.monotonic() + timeout

    def settled() -> bool:
        if "err" in result:
            return True
        jobs = result.get("jobs")
        return jobs is not None and all(
            j.status in (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)
            for j in jobs)

    while time.monotonic() < end and not settled():
        APP.processEvents()
        time.sleep(0.02)
    mgr.cancel_all()
    mgr.shutdown()
    return result


def test_hostile_is_within_resolves_a_remote_link_through_the_server(server):
    from core.storage_identity import is_within

    srv_root, connect = server
    os.symlink("../a", srv_root / "b" / "link")
    session = connect(resolve_links=True)
    assert is_within(session, "/a", session, "/b/link")
    assert is_within(session, "/a", session, "/b/link/a")  # not there yet
    assert not is_within(session, "/a", session, "/b")
    assert not is_within(session, "/b", session, "/a")


def test_hostile_copy_into_a_link_to_itself_does_not_nest_on_a_text_only_server(server):
    """A server whose realpath does not resolve links: the up-front guard
    cannot see it; the walk lists /a before it makes /a/a and copies once."""
    srv_root, connect = server
    os.symlink("../a", srv_root / "b" / "link")
    session = connect(resolve_links=False)
    result = _copy(session, "/a", "/b/link")
    assert "jobs" in result, result
    assert _nesting(srv_root, "a") <= 2  # /a and /a/a, no deeper


def test_hostile_walk_never_descends_into_a_folder_it_made(server, monkeypatch):
    """/b/link -> /a/s: the copy of /a goes to /a/s/a. Listing first is
    not enough here (/a/s is listed after /a/s/a was made); the walk does
    not descend into a folder it made itself, even when the up-front
    guard is not there to refuse the copy."""
    from core import transfer_manager as TM

    srv_root, connect = server
    (srv_root / "a" / "s").mkdir()
    os.symlink("../a/s", srv_root / "b" / "link")
    session = connect(resolve_links=True)
    monkeypatch.setattr(TM, "_self_target_refusal", lambda *a, **k: "")
    result = _copy(session, "/a", "/b/link")
    assert "jobs" in result, result
    assert (srv_root / "a" / "s" / "a" / "f.txt").read_text() == "F"
    assert not (srv_root / "a" / "s" / "a" / "s" / "a").exists()


def test_hostile_folder_walk_stops_at_the_depth_cap(tmp_path, monkeypatch):
    from core import transfer_manager as TM
    from core.local_fs import LocalFS
    from core.transfer_worker import TransferDirection

    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    monkeypatch.setattr(TM, "MAX_RECURSIVE_DELETE_DEPTH", 3)
    deep = tmp_path / "src" / "t"
    (deep / "d" / "d" / "d" / "d" / "d").mkdir(parents=True)
    (tmp_path / "dst").mkdir()
    mgr = TM.TransferManager()
    try:
        jobs = mgr._transfer_directory(
            LocalFS(), LocalFS(), str(deep), str(tmp_path / "dst" / "t"),
            TransferDirection.DOWNLOAD)
    finally:
        mgr.shutdown()
    assert _nesting(tmp_path / "dst" / "t", "d") == 3
    refused = [j for j in jobs if j.error_message]
    assert len(refused) == 1 and "deeper than 3" in refused[0].error_message
