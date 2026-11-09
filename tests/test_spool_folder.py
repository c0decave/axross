"""Download spools go where there is room, and say so early when there is none.

Measured before (review round 6): every spooled download (FTP, S3,
Azure, WebDAV, OneDrive, Dropbox) and the FTP / Telnet upload spools
rolled over into /tmp past 8 MiB. /tmp is a tmpfs of half the RAM on many
systems: a large download ended in ENOSPC half-way (or pushed the machine
into swap). Now a spool goes next to the transfer's local destination when
the engine knows one, else to $AXROSS_SPOOL_DIR / set_spool_dir(), else -
unless the user chose the temp folder - to $XDG_CACHE_HOME/axross/spool;
a spool of known size checks the free space first (ENOSPC before the
download starts).
"""

from __future__ import annotations

import errno
import io
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import read_spool as RS  # noqa: E402
from core import transfer_hooks  # noqa: E402

BIG = 100 * 1024 * 1024


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    monkeypatch.delenv("TMPDIR", raising=False)
    monkeypatch.delenv(RS.SPOOL_DIR_ENV, raising=False)
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    RS.set_spool_dir(None)
    yield tmp_path
    RS.set_spool_dir(None)


def test_happy_default_spool_folder_is_the_cache_not_tmp(clean_env):
    folder = RS.spool_dir()
    assert folder == str(clean_env / "cache" / "axross" / "spool")
    assert os.stat(folder).st_mode & 0o777 == 0o700
    with RS.new_read_spool() as spool:
        spool.write(b"x" * (RS.READ_SPOOL_MAX + 1))  # rolls over into the folder
        if os.path.isdir("/proc/self/fd"):
            where = os.readlink(f"/proc/self/fd/{spool.fileno()}")
            assert where.startswith(folder + os.sep), where


def test_happy_env_and_setting_choose_the_folder(clean_env, monkeypatch):
    RS.set_spool_dir(str(clean_env / "chosen"))
    assert RS.spool_dir() == str(clean_env / "chosen")
    monkeypatch.setenv(RS.SPOOL_DIR_ENV, str(clean_env / "env"))
    assert RS.spool_dir() == str(clean_env / "env")


def test_edge_a_temp_folder_the_user_chose_is_kept(clean_env, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(clean_env))
    assert RS.spool_dir() is None  # tempfile's own choice: TMPDIR
    monkeypatch.delenv("TMPDIR")
    monkeypatch.setattr(tempfile, "tempdir", str(clean_env))  # the tmpfs setting
    assert RS.spool_dir() is None


def test_happy_a_transfer_spools_next_to_its_local_destination(clean_env):
    hooks = transfer_hooks.TransferHooks()
    hooks.spool_dir = str(clean_env)
    with transfer_hooks.active(hooks):
        assert RS.spool_dir() == str(clean_env)


def test_sad_no_room_for_a_known_size_fails_before_the_download(clean_env, monkeypatch):
    from core import posix_compat

    monkeypatch.setattr(posix_compat, "disk_usage", lambda path: (BIG, BIG - 1024, 1024))
    with pytest.raises(OSError) as exc_info:
        RS.new_read_spool(BIG)
    assert exc_info.value.errno == errno.ENOSPC
    assert "AXROSS_SPOOL_DIR" in str(exc_info.value)
    with pytest.raises(OSError):
        RS.spool_chunks(iter([b"x"]), expected_size=BIG)
    RS.new_read_spool(1024).close()  # a small one stays in memory: no check


def test_sad_the_message_is_translated(clean_env, monkeypatch):
    from core import i18n, posix_compat

    monkeypatch.setattr(posix_compat, "disk_usage", lambda path: (BIG, BIG - 1024, 1024))
    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    with pytest.raises(OSError, match="Nicht genug freier Speicher"):
        RS.new_read_spool(BIG)


def test_sad_ftp_download_too_large_for_the_spool_is_refused_before_retr(clean_env, monkeypatch):
    from ftp_fuzz_server import FakeFtpServer

    from core import posix_compat
    from core.ftp_client import FtpSession

    monkeypatch.setattr(posix_compat, "disk_usage", lambda path: (BIG, BIG - 1024, 1024))
    srv = FakeFtpServer(replies={"FEAT": b"211-Features:\r\n SIZE\r\n211 End\r\n",
                                 "SIZE": f"213 {BIG}\r\n".encode()},
                        data={"RETR": b"never sent"})
    with srv:
        s = FtpSession(srv.host, srv.port, "u", "p")
        try:
            with pytest.raises(OSError) as exc_info:
                s.open_read("/big.iso")
            assert exc_info.value.errno == errno.ENOSPC
            assert not any(c.startswith("RETR") for c in srv.commands)
            assert s.list_dir is not None and s.connected  # the session is fine
        finally:
            s.disconnect()


def test_happy_the_engine_tells_the_backend_where_the_destination_is(clean_env):
    from core.local_fs import LocalFS
    from core.ram_fs import RamFsSession
    from core.transfer_worker import TransferJob, TransferStatus, TransferWorker

    seen = []

    class _Spooling(RamFsSession):
        def open_read(self, path, mode="rb"):
            seen.append(RS.spool_dir())
            return io.BytesIO(b"data")

    src = _Spooling()
    dest = clean_env / "out" / "f.bin"
    dest.parent.mkdir()
    job = TransferJob(source_path="/f.bin", dest_path=str(dest), filename="f.bin",
                      total_bytes=4, source_backend=src, dest_backend=LocalFS())
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert seen == [str(dest.parent)]
