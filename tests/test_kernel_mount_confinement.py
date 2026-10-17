"""NFS / iSCSI stay inside their mount: symlinks, mount options, argv.

docs/SECURITY-REVIEW-2026-10.md C-3. Both backends operate on a kernel
mount through the local file system, and their path guard was lexical
only (``abspath`` + ``commonpath``). A symlink the SERVER planted in the
export (``evil -> ~/.ssh``) is resolved by the client kernel, so
``open_read("/evil/id_rsa")`` read and ``open_write("/evil/...")`` wrote
the user's own files. The mount itself ran (as root via sudo) without
``nosuid,nodev,noexec`` - a set-uid binary on the export became a local
root shell - and the user-supplied host went onto the ``mount`` command
line without validation or a ``--``.

The export is a temp directory standing in for the mounted file system;
``mount`` is replaced at the subprocess boundary of each backend.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import iscsi_client as IC  # noqa: E402
from core import nfs_client as NC  # noqa: E402


def _nfs(mount: Path) -> "NC.NfsSession":
    s = NC.NfsSession.__new__(NC.NfsSession)
    s._mount_point = str(mount)
    s._mounted = True
    return s


def _iscsi(mount: Path) -> "IC.IscsiSession":
    s = IC.IscsiSession.__new__(IC.IscsiSession)
    s._mount_point = str(mount)
    return s


@pytest.fixture
def tree(tmp_path):
    """export/ with a server-planted symlink to a local directory."""
    outside = tmp_path / "home" / ".ssh"
    outside.mkdir(parents=True)
    (outside / "id_rsa").write_bytes(b"PRIVATE KEY")
    export = tmp_path / "export"
    (export / "sub").mkdir(parents=True)
    (export / "sub" / "a.txt").write_bytes(b"inside")
    (export / "evil").symlink_to(outside)
    (export / "evil_file").symlink_to(outside / "id_rsa")
    (export / "ok_link").symlink_to("sub/a.txt")
    return export, outside


BACKENDS = [_nfs, _iscsi]


@pytest.mark.parametrize("make", BACKENDS, ids=["nfs", "iscsi"])
def test_happy_paths_inside_the_export_still_work(tree, make):
    export, _ = tree
    s = make(export)
    assert s.open_read("/sub/a.txt").read() == b"inside"
    assert s.open_read("/ok_link").read() == b"inside"  # link that stays inside
    with s.open_write("/sub/new.txt") as fh:
        fh.write(b"n")
    assert (export / "sub" / "new.txt").read_bytes() == b"n"
    assert "a.txt" in [i.name for i in s.list_dir("/sub")]


@pytest.mark.parametrize("make", BACKENDS, ids=["nfs", "iscsi"])
def test_sad_server_symlinks_do_not_reach_the_local_file_system(tree, make):
    export, outside = tree
    s = make(export)
    with pytest.raises(PermissionError):
        s.open_read("/evil/id_rsa")
    with pytest.raises(PermissionError):
        s.open_read("/evil_file")
    with pytest.raises(PermissionError):
        s.open_write("/evil/authorized_keys")
    with pytest.raises(PermissionError):
        s.list_dir("/evil")
    with pytest.raises(PermissionError):
        s.chmod("/evil_file", 0o777)
    with pytest.raises(PermissionError):
        s.copy("/evil_file", "/sub/stolen")
    assert sorted(p.name for p in outside.iterdir()) == ["id_rsa"]
    assert (outside / "id_rsa").stat().st_mode & 0o777 != 0o777


@pytest.mark.parametrize("make", BACKENDS, ids=["nfs", "iscsi"])
def test_edge_the_link_itself_can_still_be_inspected_and_removed(tree, make):
    export, outside = tree
    s = make(export)
    assert s.exists("/evil")
    assert s.readlink("/evil_file") == str(outside / "id_rsa")
    s.remove("/evil_file")
    assert not (export / "evil_file").is_symlink()
    assert (outside / "id_rsa").read_bytes() == b"PRIVATE KEY"
    with pytest.raises(PermissionError):
        s.open_read("/../home/.ssh/id_rsa")  # lexical escape, as before


# --------------------------------------------------------------------------
# mount command line
# --------------------------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd, check=True, **kw):
        self.calls.append(list(cmd))

        class _Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Done()


def test_happy_nfs_mount_is_nosuid_nodev_noexec_with_end_of_options(tmp_path, monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(NC.NfsSession, "_run", lambda self, cmd, check=True: rec(cmd, check))
    s = NC.NfsSession("nfs.example", "/export", mount_point=str(tmp_path))
    (cmd,) = rec.calls
    opts = cmd[cmd.index("-o") + 1].split(",")
    assert {"nosuid", "nodev", "noexec"} <= set(opts)
    assert cmd[-3:] == ["--", "nfs.example:/export", str(tmp_path)]
    s._mounted = False


@pytest.mark.parametrize(
    "host, export",
    [("-oexec", "/x"), ("nfs host", "/x"), ("h\n", "/x"), ("h", "relative"), ("h", "/x\ny")],
)
def test_sad_nfs_host_and_export_are_validated_before_mount(tmp_path, monkeypatch, host, export):
    rec = _Recorder()
    monkeypatch.setattr(NC.NfsSession, "_run", lambda self, cmd, check=True: rec(cmd, check))
    with pytest.raises((OSError, ValueError)):
        NC.NfsSession(host, export, mount_point=str(tmp_path))
    assert rec.calls == []


def test_edge_iscsi_mount_is_nosuid_nodev_noexec(tmp_path, monkeypatch):
    rec = _Recorder()
    s = _iscsi(tmp_path / "mnt")
    s._device_path = "/dev/sdz"
    monkeypatch.setattr(s, "_detect_filesystem", lambda: "ext4", raising=False)
    monkeypatch.setattr(s, "_existing_mountpoint_for_device", lambda: "", raising=False)
    monkeypatch.setattr(s, "_run_privileged", lambda cmd, **kw: rec(cmd), raising=False)
    s._mount()
    (cmd,) = rec.calls
    opts = cmd[cmd.index("-o") + 1].split(",")
    assert {"nosuid", "nodev", "noexec"} <= set(opts)
    assert cmd[-3:] == ["--", "/dev/sdz", str(tmp_path / "mnt")]
