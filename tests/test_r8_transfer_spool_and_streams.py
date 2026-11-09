"""Short reads under /dev, hidden spools, Azure Files resume, named stream errors.

Measured before (review round 8, repros xfer/ and spool/):

* M1 - a download cut half-way was saved without an error under any
  /dev, /sys or /proc path on every backend: an FTP server whose user
  folder is /dev ("dev" projects) delivered 1.5 of 3 MB of /dev/f.bin
  and /proc/f.bin, both DONE. Only a backend whose "/" is a machine's
  root (caps ``machine_root``: local, SFTP, SCP, the shells, ADB) is
  exempt now, and only for a file listed with a pseudo file's size;
* L1 - ADB, TFTP and rsync spools (``axross-adb-XXXX``) sat visibly in
  the user's download folder while they ran and stayed there after a
  crash. They are ``.axross-spool-<tag>-...`` now, and the first named
  spool of a run in a folder sweeps the stale ones (a day old, ours,
  regular files owned by the user);
* L4 - Azure Files said ``seekable_reads=True`` but downloads whole: a
  resume read everything again and needed the room twice;
* L5 - a streamed download that broke lost its name: "('Connection
  broken: IncompleteRead(...)', IncompleteRead(...))".
"""

from __future__ import annotations

import dataclasses
import errno
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import test_backend_conformance as C  # noqa: E402
from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core import read_spool  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

WHOLE = b"\x5a" * 3_000_000
DAY = 24 * 3600


def _job(src_backend, src, dst, size):
    return TransferJob(source_path=src, dest_path=dst, filename=os.path.basename(dst),
                       total_bytes=size, source_backend=src_backend, dest_backend=LocalFS(),
                       use_temp_file=True)


def _cleanup(target) -> None:
    for done in target.cleanup:
        try:
            done()
        except Exception:  # noqa: BLE001 - cleanup only
            pass


@pytest.fixture
def spool_env(monkeypatch, tmp_path):
    folder = tmp_path / "spool"
    monkeypatch.setenv(read_spool.SPOOL_DIR_ENV, str(folder))
    read_spool.set_spool_dir(None)
    monkeypatch.setattr(read_spool, "_swept", set())
    yield folder
    read_spool.set_spool_dir(None)


# ------------------------------------------------------------------ M1
def _ftp_short(src: str, tmp_path) -> TransferJob:
    """An FTP server with MLST and no SIZE that cuts RETR half-way and
    still says 226."""

    def mlst(arg):
        return (f"250-Listing {arg}\r\n type=file;size={len(WHOLE)};"
                f"modify=20260101000000; {arg}\r\n250 End\r\n").encode()

    replies = {"FEAT": b"211-Features:\r\n MLST type*;size*;modify*;\r\n211 End\r\n",
               "MLST": mlst}
    with FakeFtpServer(replies=replies, data={"RETR": WHOLE[:1_500_000]}) as srv:
        s = FC.FtpSession(srv.host, srv.port, "u", "p")
        try:
            job = _job(s, src, str(tmp_path / "f.bin"), len(WHOLE))
            TransferWorker()._process_job(job)
        finally:
            s.close()
    return job


@pytest.mark.parametrize("src", ["/dev/f.bin", "/proc/f.bin", "/sys/f.bin"])
def test_sad_a_cut_ftp_download_under_dev_or_proc_is_refused(tmp_path, src):
    job = _ftp_short(src, tmp_path)
    assert job.status is TransferStatus.ERROR
    assert "were read" in job.error_message
    assert not (tmp_path / "f.bin").exists()


class _Host(RamFsSession):
    """A remote machine (SFTP, a shell): files list *listed* bytes."""

    listed = 4096

    def stat(self, path):
        item = RamFsSession.stat(self, path)
        return item if item.is_dir else dataclasses.replace(item, size=self.listed)


@pytest.fixture
def machine_root(monkeypatch):
    from core import capability_contracts
    from core.backend_registry import RAMFS_CAPS

    original = capability_contracts.caps_for_backend
    monkeypatch.setattr(
        capability_contracts, "caps_for_backend",
        lambda b: dataclasses.replace(RAMFS_CAPS, machine_root=True)
        if isinstance(b, _Host) else original(b))


def _host_job(tmp_path, path: str, listed: int) -> TransferJob:
    src = _Host(f"r8-host-{os.getpid()}-{id(tmp_path)}-{listed}")
    src.listed = listed
    try:
        parent = path.rsplit("/", 1)[0]
        parts = parent.strip("/").split("/")
        for i in range(1, len(parts) + 1):
            src.mkdir("/" + "/".join(parts[:i]))
        with src.open_write(path) as fh:
            fh.write(b"aa:bb\n")
        job = _job(src, path, str(tmp_path / "out"), listed)
        TransferWorker()._process_job(job)
        return job
    finally:
        src.disconnect()


def test_happy_a_sysfs_file_on_a_machine_root_is_copied(tmp_path, machine_root):
    job = _host_job(tmp_path, "/sys/class/net/eth0/address", 4096)
    assert job.status is TransferStatus.DONE, job.error_message
    assert (tmp_path / "out").read_bytes() == b"aa:bb\n"


def test_sad_a_real_size_under_dev_is_refused_even_on_a_machine_root(tmp_path, machine_root):
    job = _host_job(tmp_path, "/dev/disk/image.bin", 3_000_000)
    assert job.status is TransferStatus.ERROR
    assert "were read" in job.error_message


def test_sad_sysfs_size_on_a_backend_without_a_machine_root_is_refused(tmp_path):
    job = _host_job(tmp_path, "/sys/class/net/eth0/address", 4096)
    assert job.status is TransferStatus.ERROR
    assert "were read" in job.error_message


def test_edge_which_backends_show_a_machine_root():
    from core.backend_registry import all_backends

    caps = {b.protocol_id: b.capabilities for b in all_backends()}
    for proto in ("sftp", "scp", "telnet", "rsh", "adb"):
        assert caps[proto].machine_root, proto
    for proto in ("ftp", "smb", "webdav", "s3", "azure_files", "nfs", "mtp", "winrm"):
        if proto in caps:
            assert not caps[proto].machine_root, proto
    from core.capability_contracts import caps_for_backend

    assert caps_for_backend(LocalFS()).machine_root


# ------------------------------------------------------------------ L1
@pytest.fixture
def adb(tmp_path):
    (tmp_path / "device").mkdir()
    t = C.MAKERS["adb"](tmp_path / "device")
    yield t
    _cleanup(t)


def test_happy_an_adb_download_spool_is_hidden_next_to_the_destination(adb, tmp_path):
    with adb.backend.open_write(adb.J("photo.jpg")) as fh:
        fh.write(b"p" * 200_000)
    dest = tmp_path / "Downloads"
    dest.mkdir()
    seen = {}
    pull = adb.backend._device.pull

    def watching(src, dst):
        seen["spool"] = dst
        seen["listing"] = sorted(os.listdir(dest))
        pull(src, dst)

    adb.backend._device.pull = watching
    job = _job(adb.backend, adb.J("photo.jpg"), str(dest / "photo.jpg"), 200_000)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert os.path.basename(seen["spool"]).startswith(".axross-spool-adb-")
    assert all(n.startswith(".") for n in seen["listing"]), seen["listing"]
    assert sorted(os.listdir(dest)) == ["photo.jpg"]


def test_happy_tftp_spools_are_hidden(spool_env, monkeypatch):
    pytest.importorskip("tftpy")
    from test_tftp_size_probe import _FakeTftpServer

    from core import tftp_client
    from core.tftp_client import TftpSession

    names = []
    original = tftp_client.new_named_spool

    def recording(*args, **kwargs):
        spool = original(*args, **kwargs)
        names.append(spool.name)
        return spool

    monkeypatch.setattr(tftp_client, "new_named_spool", recording)
    server = _FakeTftpServer({"f.bin": b"t" * 1500}, tsize=False)
    try:
        s = TftpSession(host="127.0.0.1", port=server.port, timeout=2, retries=1)
        assert s._probe_size("f.bin") == 1500
    finally:
        server.close()
    assert names
    for name in names:
        assert Path(name).parent == spool_env
        assert Path(name).name.startswith(".axross-spool-tftp-")
    assert list(spool_env.iterdir()) == []


def test_happy_rsync_read_folders_and_spools_are_hidden(spool_env, monkeypatch):
    from core.rsync_client import RsyncSession

    s = object.__new__(RsyncSession)
    seen = {}

    def run(args, timeout=None):
        folder = args[-1].rstrip(os.sep)
        seen["folder"] = folder
        Path(folder, "f.bin").write_bytes(b"rs")

    monkeypatch.setattr(s, "_build_url", lambda path: "rsync://h/m" + path, raising=False)
    monkeypatch.setattr(s, "_run_rsync", run, raising=False)
    fh = s.open_read("/f.bin")
    try:
        assert fh.read() == b"rs"
        assert Path(seen["folder"]).name.startswith(".axross-spool-rsync-")
        assert Path(seen["folder"]).parent == spool_env
        assert [p.name[:20] for p in spool_env.iterdir()] == [".axross-spool-rsync-"]
    finally:
        fh.close()
    assert list(spool_env.iterdir()) == []


def _aged(path: Path, days: float = 2) -> Path:
    then = time.time() - days * DAY
    os.utime(path, (then, then), follow_symlinks=False)
    return path


def test_sad_a_crashed_runs_spools_are_swept(spool_env, tmp_path):
    spool_env.mkdir(parents=True)
    stale = spool_env / ".axross-spool-adb-abc123"
    stale.write_bytes(b"x")
    _aged(stale)
    rsync_dir = spool_env / ".axross-spool-rsync-dir1"
    rsync_dir.mkdir()
    (rsync_dir / ".partial").write_bytes(b"p")
    _aged(rsync_dir / ".partial")
    _aged(rsync_dir)
    spool = read_spool.new_named_spool(tag="adb")
    try:
        left = sorted(p.name for p in spool_env.iterdir())
    finally:
        spool.close()
    assert stale.name not in left
    assert rsync_dir.name not in left


def test_edge_the_sweep_keeps_what_is_not_a_stale_spool_of_ours(spool_env, tmp_path):
    spool_env.mkdir(parents=True)
    fresh = spool_env / ".axross-spool-tftp-fresh"
    fresh.write_bytes(b"in use")
    foreign = spool_env / "axross-adb-old"  # no dot: maybe the user's
    foreign.write_bytes(b"x")
    _aged(foreign)
    other = spool_env / ".axross-spoolish"
    other.write_bytes(b"x")
    _aged(other)
    outside = tmp_path / "target"
    outside.write_bytes(b"keep")
    link = spool_env / ".axross-spool-link"
    link.symlink_to(outside)
    _aged(link)
    nested = spool_env / ".axross-spool-rsync-nested"
    (nested / "sub").mkdir(parents=True)
    _aged(nested)
    spool = read_spool.new_named_spool(tag="adb")
    spool.close()
    left = {p.name for p in spool_env.iterdir()}
    assert {fresh.name, foreign.name, other.name, link.name, nested.name} <= left
    assert outside.read_bytes() == b"keep"


def test_edge_the_sweep_runs_once_per_folder_in_a_run(spool_env):
    spool_env.mkdir(parents=True)
    read_spool.new_named_spool(tag="t").close()
    late = spool_env / ".axross-spool-adb-late"
    late.write_bytes(b"x")
    _aged(late)
    read_spool.new_named_spool(tag="t").close()
    assert late.exists()
    assert read_spool.sweep_stale_spools(str(spool_env)) == 1
    assert not late.exists()


# ------------------------------------------------------------------ L4
def test_sad_azure_files_resume_does_not_claim_offset_reads():
    from core.backend_registry import AZURE_FILES_CAPS

    assert AZURE_FILES_CAPS.seekable_reads is False


def test_edge_a_resume_from_azure_files_starts_over():
    import fake_azure_files

    from core.transfer_worker import _source_reads_at_offset

    assert _source_reads_at_offset(fake_azure_files.make_session()) is False


# ------------------------------------------------------------------ L5
def _broken_chunks(exc):
    yield b"x" * 10
    raise exc


def test_sad_a_broken_stream_names_the_file():
    requests = pytest.importorskip("requests")
    urllib3 = pytest.importorskip("urllib3")
    inner = urllib3.exceptions.ProtocolError(
        "Connection broken: IncompleteRead(10 bytes read, 90 more expected)",
        urllib3.exceptions.IncompleteRead(10, 90))
    body = read_spool.StreamedBody(
        _broken_chunks(requests.exceptions.ChunkedEncodingError(inner)),
        expected_size=100, what="Cannot read /big.bin")
    with pytest.raises(OSError) as info:
        body.read()
    message = str(info.value)
    assert "/big.bin" in message
    assert "Connection broken: IncompleteRead(10 bytes read, 90 more expected)" in message
    assert "('Connection broken" not in message
    assert info.value.errno == errno.EIO


def test_sad_an_os_error_keeps_its_type_and_errno_and_gains_the_name():
    body = read_spool.StreamedBody(
        _broken_chunks(ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")),
        what="Cannot read /a.bin")
    with pytest.raises(ConnectionResetError) as info:
        body.read()
    assert info.value.errno == errno.ECONNRESET
    assert "Cannot read /a.bin" in str(info.value)
    assert isinstance(info.value.__cause__, ConnectionResetError)


def test_edge_cancel_passes_unchanged():
    from core.transfer_hooks import CANCELLED

    cancel = InterruptedError(CANCELLED)
    body = read_spool.StreamedBody(_broken_chunks(cancel), what="Cannot read /c.bin")
    with pytest.raises(InterruptedError) as info:
        body.read()
    assert info.value is cancel
