"""Shell backends: rename and copy never land INSIDE an existing folder.

Plain ``mv src dst`` / ``cp src dst`` put src into dst when dst is a
folder and report success. telnet and scp already guarded rename
(core.telnet_client.rename_command); the review of 2026-10-17 (B6)
reproduced the same bug for ADB (mv and cp, with a POSIX sh standing in
for toybox), and its twins are rsh's rename and every shell copy (ADB,
rsh, scp, telnet, ssh): ``cp -p -- report.txt Archive`` copied into
Archive and returned 0.
"""

from __future__ import annotations

import os
import subprocess
import threading

import pytest

from core import telnet_client as T


def _sh(cmd: str) -> tuple[str, int]:
    r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)
    return r.stdout + r.stderr, r.returncode


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "report.txt").write_text("data")
    (tmp_path / "Archive").mkdir()
    (tmp_path / "old.txt").write_text("old")
    return tmp_path


# -- the commands -----------------------------------------------------------------------


def test_happy_copy_command_copies_onto_a_new_name_and_replaces_a_file(tree):
    out, code = _sh(T.copy_command(str(tree / "report.txt"), str(tree / "copy.txt")))
    assert code == 0 and (tree / "copy.txt").read_text() == "data"
    out, code = _sh(T.copy_command(str(tree / "report.txt"), str(tree / "old.txt")))
    assert code == 0 and (tree / "old.txt").read_text() == "data"


def test_sad_copy_and_rename_onto_a_folder_fail_and_leave_it_alone(tree):
    out, code = _sh(T.copy_command(str(tree / "report.txt"), str(tree / "Archive")))
    assert code != 0 and "is a directory" in out
    out, code = _sh(T.rename_command(str(tree / "report.txt"), str(tree / "Archive")))
    assert code != 0 and "is a directory" in out
    assert os.listdir(tree / "Archive") == [] and (tree / "report.txt").exists()


def test_edge_preserve_and_a_dash_name(tree):
    (tree / "-n").write_text("dash")
    out, code = _sh(T.copy_command(str(tree / "-n"), str(tree / "d.txt"), preserve=True))
    assert code == 0 and (tree / "d.txt").read_text() == "dash"
    assert "cp -p --" in T.copy_command("a", "b", preserve=True)
    assert "cp --" in T.copy_command("a", "b") and "-p" not in T.copy_command("a", "b")


# -- ADB: a device whose shell is a POSIX sh --------------------------------------------


class _Device:
    def shell(self, cmd, transport_timeout_s=None, decode=True):
        return "".join(map(str, _sh(cmd)[:1]))  # adb shell mixes stdout and stderr


def _adb():
    from core import adb_client as A

    s = A.AdbSession.__new__(A.AdbSession)
    s._conn_lock = threading.Lock()
    s._device = _Device()
    s._label = "fake"
    s._transport_timeout = 5
    return s


def test_sad_adb_rename_and_copy_onto_a_folder_raise(tree):
    s = _adb()
    with pytest.raises(OSError, match="is a directory"):
        s.rename(str(tree / "report.txt"), str(tree / "Archive"))
    with pytest.raises(OSError, match="is a directory"):
        s.copy(str(tree / "report.txt"), str(tree / "Archive"))
    assert os.listdir(tree / "Archive") == []


def test_happy_adb_rename_and_copy_still_work(tree):
    s = _adb()
    s.copy(str(tree / "report.txt"), str(tree / "c.txt"))
    s.rename(str(tree / "c.txt"), str(tree / "r.txt"))
    assert (tree / "r.txt").read_text() == "data" and not (tree / "c.txt").exists()


# -- rsh, scp, telnet, ssh send the guarded commands ---------------------------------------


def test_edge_every_shell_backend_sends_the_guarded_copy(monkeypatch):
    from core import rsh_client, scp_client, ssh_client

    sent = []
    rsh = rsh_client.RshSession.__new__(rsh_client.RshSession)
    monkeypatch.setattr(
        rsh, "_run_remote", lambda cmd, *a, **k: sent.append(("rsh", cmd)) or b"", raising=False
    )
    monkeypatch.setattr(rsh, "normalize", lambda p: p, raising=False)
    rsh.copy("/a", "/b")
    rsh.rename("/a", "/b")
    for module, cls in ((scp_client, "SCPSession"), (T, "TelnetSession")):
        session = getattr(module, cls).__new__(getattr(module, cls))
        monkeypatch.setattr(session, "normalize", lambda p: p, raising=False)
        monkeypatch.setattr(
            session,
            "_exec_raw",
            lambda cmd, *a, **k: sent.append((cls, cmd)) or ("", 0),
            raising=False,
        )
        session.copy("/a", "/b")
    guarded = T.copy_command("/a", "/b", preserve=True)
    assert ("rsh", guarded) in sent and ("rsh", T.rename_command("/a", "/b")) in sent
    assert ("SCPSession", guarded + " 2>&1") in sent and (
        "TelnetSession",
        guarded + " 2>&1",
    ) in sent

    class _Chan:
        def exec_command(self, cmd):
            sent.append(("ssh", cmd))

        def makefile_stderr(self, mode):
            import io

            return io.BytesIO(b"")

        def recv_exit_status(self):
            return 0

        def close(self):
            pass

    class _Transport:
        def is_active(self):
            return True

        def open_session(self):
            return _Chan()

    ssh = ssh_client.SSHSession.__new__(ssh_client.SSHSession)
    ssh._transport = _Transport()
    ssh.copy("/a", "/b")
    assert ("ssh", guarded) in sent


# -- ADB list_dir: an ls error is an error, not an empty folder (review B13) -------------


def test_sad_adb_list_dir_of_a_missing_folder_is_file_not_found(tree):
    with pytest.raises(FileNotFoundError):
        _adb().list_dir(str(tree / "does-not-exist"))


def test_sad_adb_list_dir_of_a_file_is_not_a_directory(tree):
    with pytest.raises(NotADirectoryError):
        _adb().list_dir(str(tree / "report.txt"))


def test_edge_adb_toybox_wording_and_an_empty_folder(tree, monkeypatch):
    s = _adb()
    assert s.list_dir(str(tree / "Archive")) == []  # empty, but there
    monkeypatch.setattr(s, "_shell", lambda cmd: "ls: /sdcard/locked/: Permission denied\n")
    with pytest.raises(PermissionError):
        s.list_dir("/sdcard/locked")
    # an entry ls could not stat does not hide the rest of the listing
    good = "-rw-rw---- 1 u0_a1 media_rw 4 2026-01-01 10:00 a.txt\n"
    monkeypatch.setattr(s, "_shell", lambda cmd: "ls: /sdcard/x/bad: Permission denied\n" + good)
    assert [i.name for i in s.list_dir("/sdcard/x")] == ["a.txt"]
