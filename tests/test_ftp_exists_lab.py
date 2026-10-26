"""FTP exists() against the lab's FTP servers, live.

Every FTP flavour of tests/docker/docker-compose.yml: ftp-server (pure-ftpd,
5 connections per address), ftps-server (pure-ftpd, explicit TLS),
tiny-ftp-server (pure-ftpd on a 16 MB tmpfs). Reached through ``podman
unshare --rootless-netns``; skipped when a server is not reachable.

Measured 2026-10-26: exists() of a missing file sent a failed CWD and an
NLST over a data connection of its own. pure-ftpd delays every failed CWD
by 100 ms times the failed CWDs so far on the connection and drops it
after the 50th, so the 51st check of a new name failed with "connection
closed by server" and an upload of 300 new files lost every 51st file.
pure-ftpd names MLST in FEAT; exists() now asks it on the control
connection.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sys
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

SERVERS = {
    "ftp": dict(host="10.99.0.30", port=21, username="ftpuser", password="ftp123"),
    "ftps": dict(
        host="10.99.0.38", port=21, username="ftpsuser", password="ftps123",
        tls=True, verify_tls=False,  # the lab's self-signed certificate
    ),
    "tiny-ftp": dict(host="10.99.0.60", port=21, username="tinyftp", password="tiny123"),
}
_DATA_VERBS = {"PASV", "EPSV", "PORT", "EPRT", "LIST", "NLST", "MLSD", "RETR", "STOR"}


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _connect(kind: str):
    from core.ftp_client import FtpSession

    return FtpSession(**SERVERS[kind])


@pytest.fixture(params=sorted(SERVERS))
def remote(request):
    kind = request.param
    cfg = SERVERS[kind]
    if not _reachable(cfg["host"], cfg["port"]):
        pytest.skip(f"{kind} lab container not reachable")
    session = _connect(kind)
    root = session.join(session.home(), f"axexists-{uuid.uuid4().hex[:10]}")
    session.mkdir(root)
    try:
        yield kind, session, root
    finally:
        session.disconnect()  # the lab allows 5 connections per address
        try:
            cleanup = _connect(kind)
            try:
                cleanup.remove(root, recursive=True)
            finally:
                cleanup.disconnect()
        except OSError:
            pass


def _record(session) -> list[str]:
    """Every command verb but NOOP the session's control connection sends
    from now on (an instance attribute: ftplib calls self.putcmd)."""
    ftp = session._ensure_connected()
    sent: list[str] = []
    real = ftp.putcmd

    def putcmd(line):
        verb = line.split(" ", 1)[0].upper()
        if verb != "NOOP":  # the liveness check, when the last one is old
            sent.append(verb)
        return real(line)

    ftp.putcmd = putcmd
    return sent


def _put(session, path: str, data: bytes) -> None:
    with session.open_write(path) as fh:
        fh.write(data)


# --- happy ----------------------------------------------------------------


def test_happy_absent_file_costs_one_mlst_and_no_data_connection(remote):
    _kind, s, root = remote
    s.exists(root)  # FEAT goes out with the first check
    sent = _record(s)
    assert s.exists(f"{root}/missing.bin") is False
    assert sent == ["MLST"], sent


def test_happy_present_entries(remote):
    _kind, s, root = remote
    _put(s, f"{root}/a.bin", b"a")
    s.mkdir(f"{root}/sub dir")
    _put(s, f"{root}/sub dir/with space ü é.txt", b"u")
    sent = _record(s)
    for path in (f"{root}/a.bin", root, f"{root}/sub dir", f"{root}/sub dir/",
                 f"{root}/sub dir/with space ü é.txt"):
        assert s.exists(path) is True, path
    assert not set(sent) & _DATA_VERBS, sent
    assert "CWD" not in sent, sent


# --- sad ------------------------------------------------------------------


def test_sad_missing_names_and_a_file_on_the_way(remote):
    _kind, s, root = remote
    _put(s, f"{root}/a.bin", b"a")
    sent = _record(s)
    for path in (f"{root}/missing ä.txt", f"{root}/a.bin/below", f"{root}/no-dir/x.bin",
                 f"{root}/a.bin.part"):
        assert s.exists(path) is False, path
    assert not set(sent) & _DATA_VERBS, sent


def test_sad_a_line_break_in_the_name_is_refused(remote):
    _kind, s, root = remote
    with pytest.raises(OSError):
        s.exists(f"{root}/a\r\nDELE {root}/x")


# --- edge -----------------------------------------------------------------


def test_edge_sixty_new_names_in_a_row_keep_the_connection(remote):
    """The 51st failed CWD made pure-ftpd drop the connection."""
    _kind, s, root = remote
    ftp = s._ensure_connected()
    started = time.monotonic()
    assert [s.exists(f"{root}/f{i:05d}.bin") for i in range(60)] == [False] * 60
    assert s._ftp is ftp  # no reconnect on the way
    assert time.monotonic() - started < 30  # was 100 ms more per check


def test_edge_type_i_before_size_on_the_fallback(remote, monkeypatch):
    """Without MLST the SIZE / CWD / listing chain answers, in TYPE I."""
    from core import ftp_client as FC

    _kind, s, root = remote
    _put(s, f"{root}/a.bin", b"abc")
    s.list_dir(root)  # leaves the connection in TYPE A
    monkeypatch.setattr(FC, "_features", lambda ftp: frozenset())
    sent = _record(s)
    assert s.exists(f"{root}/a.bin") is True
    assert sent[:2] == ["TYPE", "SIZE"], sent
    assert s.exists(root) is True
    assert s.exists(f"{root}/missing.bin") is False


# --- regression: the benchmark's 300 new files ------------------------------


def test_regression_300_new_files_upload_without_425_and_byte_exact(tmp_path, monkeypatch):
    """remote_bench upload_many against pure-ftpd: 5 of 300 files failed
    ("Cannot safely stream to destination without probing whether it
    exists", one "425 ... Address already in use"). Four jobs at a time."""
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    cfg = SERVERS["ftp"]
    if not _reachable(cfg["host"], cfg["port"]):
        pytest.skip("ftp lab container not reachable")
    from PyQt6.QtWidgets import QApplication

    from core import open_limits as OL
    from core.local_fs import LocalFS
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection, TransferStatus

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "config" / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "operations.jsonl"))
    app = QApplication.instance() or QApplication([])
    final = (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)

    many = tmp_path / "many"
    many.mkdir()
    expected = {}
    for i in range(300):
        data = hashlib.sha256(f"axexists{i}".encode()).digest() * 128  # 4 KiB
        (many / f"f{i:05d}.bin").write_bytes(data)
        expected[f"f{i:05d}.bin"] = data

    s = _connect("ftp")
    root = f"/axexists300-{uuid.uuid4().hex[:10]}"
    s.mkdir(root)
    mgr = TransferManager(max_parallel=4)
    try:
        jobs = mgr.transfer_files(LocalFS(), s, [str(many)], root, TransferDirection.UPLOAD)
        end = time.monotonic() + 600
        while time.monotonic() < end and not (
            jobs and all(j.status in final for j in jobs)
            and mgr._active_count == 0 and mgr._queued_count == 0
        ):
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()
        bad = [(j.filename, j.status, j.error_message) for j in jobs
               if j.status != TransferStatus.DONE]
        assert not bad, bad
        assert len(jobs) == 300
        names = {i.name: i.size for i in s.list_dir(f"{root}/many")}
        assert names == {n: 4096 for n in expected}
        for name, data in expected.items():
            with s.open_read(f"{root}/many/{name}") as fh:
                assert fh.read() == data, name
    finally:
        mgr.shutdown()
        try:
            s.remove(root, recursive=True)
        finally:
            s.disconnect()
