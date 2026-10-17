"""A transfer never targets its own source, nor a folder inside itself.

Measured before, with two panes on the same local folder:

* F6 (move) of a file onto itself copied the file over itself and then
  deleted "the source" -- the only copy. The job reported DONE.
* F5 (copy) of a folder into itself created ``dir/dir/dir/...`` 992 levels
  deep until a RecursionError escaped ``transfer_files`` on the GUI thread.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import storage_identity as SI  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402


class _Remote:
    """A network session that names its server, like SFTP/SMB do."""

    def __init__(self, host, port=22) -> None:
        self._profile = type("P", (), {"host": host, "port": port})()

    def separator(self) -> str:
        return "/"


class _OtherRemote(_Remote):
    pass


class SameEntryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "d").mkdir()
        (self.tmp / "d" / "f.txt").write_text("x")

    def test_happy_two_local_panes_on_one_folder_are_the_same_entry(self) -> None:
        f = str(self.tmp / "d" / "f.txt")
        self.assertTrue(SI.same_entry(LocalFS(), f, LocalFS(), f))

    def test_happy_a_different_folder_is_not_the_same_entry(self) -> None:
        (self.tmp / "e").mkdir()
        self.assertFalse(
            SI.same_entry(LocalFS(), str(self.tmp / "d" / "f.txt"),
                          LocalFS(), str(self.tmp / "e" / "f.txt"))
        )

    def test_edge_a_symlinked_folder_is_seen_through(self) -> None:
        os.symlink(self.tmp / "d", self.tmp / "alias")
        self.assertTrue(
            SI.same_entry(LocalFS(), str(self.tmp / "d" / "f.txt"),
                          LocalFS(), str(self.tmp / "alias" / "f.txt"))
        )

    def test_edge_a_symlinked_file_is_its_own_entry(self) -> None:
        """Moving a link next to its target removes the link, not the data."""
        (self.tmp / "e").mkdir()
        os.symlink(self.tmp / "d" / "f.txt", self.tmp / "e" / "f.txt")
        self.assertFalse(
            SI.same_entry(LocalFS(), str(self.tmp / "e" / "f.txt"),
                          LocalFS(), str(self.tmp / "d" / "f.txt"))
        )

    def test_edge_one_backend_object_compares_normalised_paths(self) -> None:
        ram = RamFsSession()
        self.assertTrue(SI.same_entry(ram, "/a/b.txt", ram, "/a/./b.txt"))
        self.assertFalse(SI.same_entry(ram, "/a/b.txt", RamFsSession(), "/a/b.txt"))

    def test_edge_two_sessions_to_one_server_compare_paths(self) -> None:
        self.assertTrue(SI.same_entry(_Remote("nas"), "/x", _Remote("NAS."), "/x"))
        self.assertFalse(SI.same_entry(_Remote("nas"), "/x", _Remote("nas", port=2222), "/x"))
        self.assertFalse(SI.same_entry(_Remote("nas"), "/x", _OtherRemote("nas"), "/x"))

    def test_sad_within_catches_a_folder_inside_itself(self) -> None:
        d = str(self.tmp / "d")
        self.assertTrue(SI.is_within(LocalFS(), d, LocalFS(), os.path.join(d, "d")))
        self.assertTrue(SI.is_within(LocalFS(), d, LocalFS(), d))
        self.assertFalse(SI.is_within(LocalFS(), d, LocalFS(), str(self.tmp / "dd")))


class ManagerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)
        self.errors: list[tuple[str, str]] = []
        self.mgr.job_error.connect(lambda jid, msg: self.errors.append((jid, msg)))

    def _wait(self, jobs) -> None:
        deadline = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)
        self.app.processEvents()

    def test_happy_a_move_to_another_folder_still_works(self) -> None:
        src = self.tmp / "a.txt"
        src.write_bytes(b"data")
        (self.tmp / "out").mkdir()
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp / "out"),
                                       move=True)
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.DONE])
        self.assertEqual((self.tmp / "out" / "a.txt").read_bytes(), b"data")
        self.assertFalse(src.exists())

    def test_sad_moving_a_file_onto_itself_keeps_it(self) -> None:
        src = self.tmp / "only-copy.txt"
        src.write_bytes(b"precious")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp), move=True)
        self._wait(jobs)
        self.assertEqual(src.read_bytes(), b"precious")
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertIn("same", jobs[0].error_message)
        self.assertEqual([e[0] for e in self.errors], [jobs[0].job_id])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["only-copy.txt"])

    def test_sad_copying_a_folder_into_itself_is_refused(self) -> None:
        d = self.tmp / "dir"
        d.mkdir()
        (d / "a.txt").write_bytes(b"x")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(d)], str(d))
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertEqual(sorted(os.listdir(d)), ["a.txt"])

    def test_sad_moving_a_folder_onto_itself_keeps_its_files(self) -> None:
        d = self.tmp / "dir"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "a.txt").write_bytes(b"x")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(d)], str(self.tmp), move=True)
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertEqual((d / "sub" / "a.txt").read_bytes(), b"x")

    def test_edge_through_a_symlinked_target_folder(self) -> None:
        src = self.tmp / "f.txt"
        src.write_bytes(b"keep")
        os.symlink(self.tmp, self.tmp.parent / (self.tmp.name + "-alias"))
        self.addCleanup(os.unlink, self.tmp.parent / (self.tmp.name + "-alias"))
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)],
                                       str(self.tmp.parent / (self.tmp.name + "-alias")),
                                       move=True)
        self._wait(jobs)
        self.assertEqual(src.read_bytes(), b"keep")

    def test_edge_retrying_a_refused_move_is_still_refused(self) -> None:
        src = self.tmp / "f.txt"
        src.write_bytes(b"keep")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp), move=True)
        self._wait(jobs)
        retry = self.mgr.retry_job(jobs[0].job_id)
        assert retry is not None
        self._wait([retry])
        self.assertEqual(retry.status, TransferStatus.ERROR)
        self.assertEqual(src.read_bytes(), b"keep")

    def test_edge_one_ram_session_move_onto_itself(self) -> None:
        ram = RamFsSession()
        with ram.open_write("/d/x.bin") as fh:
            fh.write(b"ram")
        jobs = self.mgr.transfer_files(ram, ram, ["/d/x.bin"], "/d", move=True)
        self._wait(jobs)
        with ram.open_read("/d/x.bin") as fh:
            self.assertEqual(fh.read(), b"ram")


class InodeAliasTest(unittest.TestCase):
    """One directory entry reached under two paths is still one entry.

    Measured before: a bind mount (``/srv/share`` on ``~/share``) or a
    case-insensitive folder typed as ``Docs`` and ``docs`` gave two path
    strings for one file; F6 + Overwrite copied the file over itself and
    then removed "the source" -- the only copy -- and reported DONE.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "a").mkdir()
        (self.tmp / "b").mkdir()
        (self.tmp / "a" / "f.txt").write_bytes(b"x")

    def test_sad_a_second_name_for_one_inode_is_the_same_entry(self) -> None:
        os.link(self.tmp / "a" / "f.txt", self.tmp / "b" / "f.txt")
        self.assertTrue(
            SI.same_entry(LocalFS(), str(self.tmp / "a" / "f.txt"),
                          LocalFS(), str(self.tmp / "b" / "f.txt"))
        )

    def test_edge_a_missing_destination_is_not_the_same_entry(self) -> None:
        self.assertFalse(
            SI.same_entry(LocalFS(), str(self.tmp / "a" / "f.txt"),
                          LocalFS(), str(self.tmp / "b" / "f.txt"))
        )

    def test_happy_an_equal_copy_elsewhere_is_not_the_same_entry(self) -> None:
        (self.tmp / "b" / "f.txt").write_bytes(b"x")
        self.assertFalse(
            SI.same_entry(LocalFS(), str(self.tmp / "a" / "f.txt"),
                          LocalFS(), str(self.tmp / "b" / "f.txt"))
        )


_ALIAS_SCRIPT = r"""
import os, sys
real, alias, mode = sys.argv[1], sys.argv[2], sys.argv[3]
from core import storage_identity as SI
from core.local_fs import LocalFS
fs = LocalFS()
if mode == "entry":
    print(SI.same_entry(fs, os.path.join(real, "f.txt"), fs, os.path.join(alias, "f.txt")))
elif mode == "within":
    print(SI.is_within(fs, os.path.join(real, "sub"), fs, os.path.join(alias, "sub", "copy")))
else:
    from PyQt6.QtWidgets import QApplication
    import time
    app = QApplication.instance() or QApplication([])
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferStatus
    tm = TransferManager()
    jobs = tm.transfer_files(fs, fs, [os.path.join(real, "f.txt")], alias, move=True)
    end = time.monotonic() + 20
    while time.monotonic() < end and any(
        j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs
    ):
        app.processEvents()
        time.sleep(0.01)
    tm.shutdown()
    print(sorted(os.listdir(real)), [j.status.value for j in jobs])
"""


def _unshare_works() -> bool:
    import subprocess

    try:
        return subprocess.run(
            ["unshare", "-Urm", "true"], capture_output=True, timeout=10
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(sys.platform.startswith("linux") and _unshare_works(),
                     "needs an unprivileged mount namespace (unshare -Urm)")
class BindMountAliasTest(unittest.TestCase):
    """A real bind mount in a private user + mount namespace."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.real = self.tmp / "real"
        self.alias = self.tmp / "alias"
        (self.real / "sub").mkdir(parents=True)
        self.alias.mkdir()
        (self.real / "f.txt").write_bytes(b"the only copy")
        self.script = self.tmp / "probe.py"
        self.script.write_text(_ALIAS_SCRIPT)

    def _run(self, mode: str) -> str:
        import subprocess

        root = str(Path(__file__).resolve().parents[1])
        env = dict(os.environ, PYTHONPATH=root, QT_QPA_PLATFORM="offscreen")
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        cmd = (
            'mount --bind "$1" "$2" && exec "$3" "$4" "$1" "$2" "$5"'
        )
        out = subprocess.run(
            ["unshare", "-Urm", "sh", "-c", cmd, "sh", str(self.real), str(self.alias),
             sys.executable, str(self.script), mode],
            capture_output=True, text=True, timeout=60, env=env, cwd=root,
        )
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        return out.stdout.strip().splitlines()[-1]

    def test_sad_a_file_seen_through_a_bind_mount_is_the_same_entry(self) -> None:
        self.assertEqual(self._run("entry"), "True")

    def test_sad_a_folder_copied_into_its_bind_mounted_self_is_within(self) -> None:
        self.assertEqual(self._run("within"), "True")

    def test_sad_moving_a_file_onto_its_bind_mounted_self_keeps_it(self) -> None:
        self.assertEqual(self._run("move"), "['f.txt', 'sub'] ['error']")
        self.assertEqual((self.real / "f.txt").read_bytes(), b"the only copy")


class _AliasFS(LocalFS):
    """A session that shows a local folder under another name and does not
    say where it lives -- like sshfs of localhost, or one share mounted
    twice through two protocols."""

    def __init__(self, alias: str, real: str) -> None:
        self._alias, self._real = alias, real

    def _map(self, path: str) -> str:
        if path == self._alias or path.startswith(self._alias + os.sep):
            return self._real + path[len(self._alias):]
        return path

    def local_path(self, path: str) -> str:  # type: ignore[override]
        return ""

    def stat(self, path):
        return super().stat(self._map(path))

    def exists(self, path: str) -> bool:
        return super().exists(self._map(path))

    def is_dir(self, path: str) -> bool:
        return super().is_dir(self._map(path))

    def open_read(self, path: str):
        return super().open_read(self._map(path))

    def remove(self, path: str, recursive: bool = False) -> None:
        super().remove(self._map(path), recursive)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return super().checksum(self._map(path), algorithm)


class WorkerNetTest(unittest.TestCase):
    """The worker refuses on its own: jobs also arrive via transfer_file."""

    def test_sad_a_move_whose_source_folder_shows_the_temp_file_keeps_the_source(self) -> None:
        """No path or inode proves the alias; the copy's own temp file
        showing up in the source folder does."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        real = tmp / "real"
        real.mkdir()
        (real / "f.txt").write_bytes(b"the only copy")
        alias = str(tmp / "alias")
        src_fs = _AliasFS(alias, str(real))
        job = TransferJob(source_path=os.path.join(alias, "f.txt"),
                          dest_path=str(real / "f.txt"), total_bytes=13, filename="f.txt",
                          move=True, source_backend=src_fs, dest_backend=LocalFS())
        TransferWorker()._process_job(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertIn("same", job.error_message)
        self.assertEqual(sorted(os.listdir(real)), ["f.txt"])
        self.assertEqual((real / "f.txt").read_bytes(), b"the only copy")

    def test_happy_a_move_through_an_alias_to_another_folder_still_works(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        real = tmp / "real"
        real.mkdir()
        (tmp / "out").mkdir()
        (real / "f.txt").write_bytes(b"data")
        alias = str(tmp / "alias")
        job = TransferJob(source_path=os.path.join(alias, "f.txt"),
                          dest_path=str(tmp / "out" / "f.txt"), total_bytes=4,
                          filename="f.txt", move=True,
                          source_backend=_AliasFS(alias, str(real)), dest_backend=LocalFS())
        TransferWorker()._process_job(job)
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertEqual(os.listdir(real), [])
        self.assertEqual((tmp / "out" / "f.txt").read_bytes(), b"data")

    def test_sad_a_same_entry_move_job_fails_before_touching_anything(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        f = tmp / "f.txt"
        f.write_bytes(b"keep")
        job = TransferJob(source_path=str(f), dest_path=str(f), total_bytes=4, filename="f.txt",
                          move=True, source_backend=LocalFS(), dest_backend=LocalFS())
        TransferWorker()._process_job(job)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertEqual(f.read_bytes(), b"keep")
        self.assertEqual(os.listdir(tmp), ["f.txt"])


if __name__ == "__main__":
    unittest.main()
