"""TFTP with a file list: the list is a shortcut to True, never a "no".

exists() answered ``name in filelist`` whenever the list was on: a file
on the server but not on the list was "absent", so the transfer worker
(if_exists="fail") went ahead and overwrote it, and a name the server
refuses ("Access violation") read as absent too. The server is asked now
whenever the list does not name the file. stat() of a missing file
returned an item of size 0 (every failed size probe read as 0); it raises
FileNotFoundError now.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
pytest.importorskip("tftpy")

from test_tftp_exists_only_not_found_is_false import _Server  # noqa: E402

from core.tftp_client import TftpSession  # noqa: E402


@pytest.fixture
def server():
    srv = _Server()
    yield srv
    srv.close()


def _session(server, **kw) -> TftpSession:
    return TftpSession(host="127.0.0.1", port=server.port, timeout=0.5, retries=1, **kw)


def test_sad_a_file_missing_from_the_list_is_asked_for(server) -> None:
    s = _session(server, filelist=["other.bin"], filelist_enabled=True)
    assert s.exists("/keep.bin") is True
    assert s.exists("/gone.bin") is False


def test_sad_transfer_worker_does_not_overwrite_an_unlisted_file(server) -> None:
    from core.transfer_worker import TransferWorker

    s = _session(server, filelist=["other.bin"], filelist_enabled=True)
    job = NS(if_exists="fail", dest_backend=s, dest_path="/keep.bin")
    with pytest.raises(FileExistsError):
        TransferWorker._check_existing_destination(job)


def test_sad_access_violation_with_a_list_raises(server) -> None:
    s = _session(server, filelist=["other.bin"], filelist_enabled=True)
    with pytest.raises(OSError) as info:
        s.exists("/secret.bin")
    assert not isinstance(info.value, FileNotFoundError)


def test_sad_stat_of_a_missing_file_raises_file_not_found(server) -> None:
    s = _session(server)
    with pytest.raises(FileNotFoundError):
        s.stat("/gone.bin")
    assert s.stat("/keep.bin").size == len(b"PRECIOUS")
