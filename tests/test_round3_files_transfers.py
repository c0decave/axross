"""Review round 3 (files): transfers and saves. Each test names what was
measured before its fix."""

from __future__ import annotations

import io
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import transfer_conflicts as TC  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX modes")


class _Server(LocalFS):
    """A destination written by name, as a server is (not LocalFS's own
    private writes), that can create a file with a mode from its first
    byte (SFTP: the permissions of the OPEN request)."""

    def __init__(self) -> None:
        super().__init__()
        self.created: list[tuple[str, int]] = []
        self.opened_by_name: list[str] = []

    def open_write(self, path, append=False):
        self.opened_by_name.append(path)
        return open(path, "ab" if append else "wb")

    def open_write_new(self, path, mode):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        self.created.append((path, stat.S_IMODE(os.fstat(fd).st_mode)))
        return os.fdopen(fd, "wb")


@posix_only
def test_sad_a_server_temp_file_is_private_from_its_first_byte(tmp_path):
    """Measured before: the temp file was created empty with the server's
    default mode (0644) and chmod-ed after - anyone could open it in
    between and read the key through that handle once it was written."""
    src = tmp_path / "key"
    src.write_bytes(b"secret key")
    src.chmod(0o600)
    (tmp_path / "out").mkdir()
    dst = tmp_path / "out" / "key"
    backend = _Server()
    job = TransferJob(source_path=str(src), dest_path=str(dst), filename="key",
                      total_bytes=10, source_mode=0o600)
    job.source_backend = LocalFS()
    job.dest_backend = backend
    TransferWorker()._process_job(job)
    assert job.status == TransferStatus.DONE, job.error_message
    assert backend.created and backend.created[0][1] & 0o077 == 0
    assert backend.opened_by_name == []
    assert dst.read_bytes() == b"secret key"
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600


def test_sad_a_resume_compares_the_middle_of_a_long_partial(tmp_path):
    """Measured before: the first and the last 64 KiB were compared - a
    partial whose middle differs (another version of the same size and
    time) was continued, the copy a splice of two files."""
    data = os.urandom(1024 * 1024)
    partial = bytearray(data[: 768 * 1024])
    partial[len(partial) // 2] ^= 0xFF  # neither end window
    path = tmp_path / "partial"
    path.write_bytes(bytes(partial))
    assert not TransferWorker._partial_matches_source(
        io.BytesIO(data), LocalFS(), str(path), len(partial))
    path.write_bytes(data[: 768 * 1024])
    assert TransferWorker._partial_matches_source(
        io.BytesIO(data), LocalFS(), str(path), 768 * 1024)


def test_sad_a_conflict_is_found_on_a_case_insensitive_destination(tmp_path, monkeypatch):
    """Measured before: "Readme.txt" onto a folder holding "README.txt" of
    an SMB share or a Mac disk was no conflict - the copy failed at run
    time (or replaced the file) instead of asking."""
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "Readme.txt").write_text("new")
    (dst / "README.txt").write_text("old")
    fs = LocalFS()
    monkeypatch.setattr(TC, "case_insensitive_names", lambda backend, folder: True)
    scan = TC.scan_conflicts(fs, fs, [str(src / "Readme.txt")], str(dst))
    assert [c.name for c in scan.conflicts] == ["Readme.txt"]
    plan = TC.ConflictPlan(fs, scan)
    plan.decide(scan.conflicts[0], TC.ConflictAction.RENAME)
    target, _mode = plan.resolve(str(dst / "Readme.txt"), str(src / "Readme.txt"))
    assert os.path.basename(target) == "Readme (1).txt"


def test_happy_case_rules_follow_the_destination(monkeypatch):
    from core import tmpfs_detect

    class SMB:
        case_insensitive_names = True

    assert TC.case_insensitive_names(SMB(), "/x")
    monkeypatch.setattr(TC.sys, "platform", "linux")
    monkeypatch.setattr(tmpfs_detect, "fs_type", lambda path: "ext4")
    assert not TC.case_insensitive_names(LocalFS(), "/home")
    monkeypatch.setattr(tmpfs_detect, "fs_type", lambda path: "vfat")
    assert TC.case_insensitive_names(LocalFS(), "/media/stick")
    monkeypatch.setattr(TC.sys, "platform", "darwin")
    monkeypatch.setattr(tmpfs_detect, "fs_type", lambda path: "")
    assert TC.case_insensitive_names(LocalFS(), "/Users/x")


@posix_only
def test_sad_a_saved_file_gets_its_group_before_its_data(tmp_path, monkeypatch):
    """Measured before: the temp file of a save was written with the user's
    own group and given the file's group only afterwards - a 0640 file of
    group "staff" was readable by the user's primary group meanwhile."""
    from core import atomic_io, local_fs

    target = tmp_path / "conf"
    target.write_text("old")
    target.chmod(0o640)
    seen = {}
    real = local_fs.create_private_file

    def create(path, mode=None, group=None):
        seen["group"] = group
        return real(path, mode, group=group)

    monkeypatch.setattr(local_fs, "create_private_file", create)
    atomic_io.atomic_write(LocalFS(), str(target), b"new")
    assert seen["group"] == os.stat(target).st_gid
    assert target.read_bytes() == b"new"


@posix_only
def test_sad_a_group_that_cannot_be_given_keeps_the_group_out(tmp_path):
    from core.local_fs import create_private_file

    groups = set(os.getgroups()) | {os.getgid()}
    other = next(g for g in range(60000, 65000) if g not in groups)
    with create_private_file(str(tmp_path / "f"), 0o640, group=other) as fh:
        assert stat.S_IMODE(os.fstat(fh.fileno()).st_mode) == 0o600


@posix_only
def test_sad_an_sftp_file_is_created_with_its_mode(tmp_path, monkeypatch):
    """SSHSession.open_write_new sends the mode in the OPEN request: the
    server creates the file with it, nothing is chmod-ed after."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sftp_testkit import SftpServer

    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    root = tmp_path / "srv"
    root.mkdir()
    server = SftpServer(str(root))
    try:
        profile = ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                    port=server.port, username="u")
        session = SSHSession(profile)
        session.connect(password="x", on_unknown_host=lambda _e: True)
        try:
            with session.open_write_new("/key", 0o600) as fh:
                assert stat.S_IMODE(os.stat(root / "key").st_mode) == 0o600
                fh.write(b"secret")
        finally:
            session.disconnect()
    finally:
        server.close()
    assert (root / "key").read_bytes() == b"secret"


class _RemoteOwned(LocalFS):
    """A server destination with owner_ids() and chown() (SFTP as root):
    the file saved belongs to uid 33, a new temp file to the login."""

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target = target
        self.chowned: list[tuple[str, int]] = []
        self.owners: dict[str, tuple[int, int]] = {target: (33, 33)}

    def open_write(self, path, append=False):  # not LocalFS's private writes
        return open(path, "ab" if append else "wb")

    def owner_ids(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        return self.owners.get(path, (0, 0))

    def chown(self, path, uid, gid):
        self.chowned.append((path, os.path.getsize(path)))
        self.owners[path] = (uid, gid)


@pytest.mark.parametrize("stream", [False, True])
def test_sad_a_remote_save_gives_the_owner_before_the_data(tmp_path, stream, monkeypatch):
    """Measured before: atomic_write gave the temp file the owner and group
    of the file it replaces after the data (readable by the login's group
    meanwhile); atomic_write_stream (FUSE commits, a metadata clean, a
    restore) never did - the file came back owned by the login."""
    from core import atomic_io

    target = tmp_path / "config.php"
    target.write_text("old")
    backend = _RemoteOwned(str(target))
    monkeypatch.setattr(atomic_io, "_is_local", lambda b: False)
    if stream:
        atomic_io.atomic_write_stream(backend, str(target), io.BytesIO(b"new content"))
    else:
        atomic_io.atomic_write(backend, str(target), b"new content")
    assert target.read_bytes() == b"new content"
    assert backend.chowned and all(size == 0 for _path, size in backend.chowned)


@pytest.mark.parametrize("method", ["scp", "base64"])
def test_sad_an_scp_file_is_created_with_its_mode(method):
    """SCPSession.open_write_new: the scp C line carries the mode, a shell
    upload runs under umask 077 - not precreated 0644 and chmod-ed after."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_scp_protocol_transfer import _session

    s = _session({"-t": b"\0\0\0"}, transfer_method=method)
    with s.open_write_new("/keys/id", 0o600) as fh:
        fh.write(b"secret")
    if method == "scp":
        assert s.channels[0].sent.startswith(b"C0600 6 id\n")
    else:
        assert s.commands and s.commands[-1].startswith("umask 077; base64 -d > ")
