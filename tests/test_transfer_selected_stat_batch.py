"""Copying a selection of remote files asks the server about all of them at once.

F5 on N selected files (Select All in a folder, then Copy) stated every
source path in the destination check, then asked ``is_dir`` and ``stat``
of each again in the walk: three waited-for round trips per file before
the first byte moved (measured on the lab at 20 ms: 100 files, 2.4 s of
check and 5.1 s of walk). The SFTP backend now answers ``stat_many`` with
pipelined LSTATs, and the check and the walk use it; its ``is_dir`` is the
same LSTAT's type, so the walk takes that from the batch too. Same jobs,
same sizes, times and modes, same conflicts, same handling of a path that
cannot be read.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from paramiko.sftp import CMD_LSTAT  # noqa: E402
from sftp_testkit import SftpServer  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "srv"
        (self.root / "src" / "sub").mkdir(parents=True)
        for i in range(40):
            p = self.root / "src" / f"f{i:02d}.bin"
            p.write_bytes(b"x" * (i * 10))
            os.chmod(p, 0o600 if i % 2 else 0o644)
            os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))
        (self.root / "src" / "sub" / "inner.txt").write_text("in")
        os.symlink("f01.bin", self.root / "src" / "link")
        self.dst = self.tmp / "dst"
        self.dst.mkdir()
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        p = mock.patch("pathlib.Path.home", return_value=home)
        p.start()
        self.addCleanup(p.stop)
        self.server = SftpServer(str(self.root))
        self.addCleanup(self.server.close)
        profile = ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                    port=self.server.port, username="u")
        self.s = SSHSession(profile)
        self.s.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.s.disconnect)
        self.paths = sorted(f"/src/{n}" for n in os.listdir(self.root / "src"))

    def count_calls(self, backend, names=("stat", "is_dir")):
        """Counts *names* calls on *backend* (instance attributes)."""
        counts = {n: 0 for n in names}
        for name in names:
            real = getattr(backend, name)

            def counted(*a, _real=real, _n=name, **k):
                counts[_n] += 1
                return _real(*a, **k)

            setattr(self, f"_patch_{name}", mock.patch.object(backend, name, counted))
            getattr(self, f"_patch_{name}").start()
            self.addCleanup(getattr(self, f"_patch_{name}").stop)
        return counts


class StatManyTest(_Base):
    def test_happy_each_answer_is_what_stat_returns(self) -> None:
        got = self.s.stat_many(self.paths)
        self.assertEqual(len(got), len(self.paths))
        for path, item in zip(self.paths, got):
            self.assertEqual(item, self.s.stat(path), path)

    def test_happy_the_lstats_are_pipelined(self) -> None:
        from paramiko import sftp_client

        waited = []
        real = sftp_client.SFTPClient._request

        def request(client, t, *args):
            waited.append(t)
            return real(client, t, *args)

        with mock.patch.object(sftp_client.SFTPClient, "_request", request):
            self.s.stat_many(self.paths)
        self.assertNotIn(CMD_LSTAT, waited)
        self.assertEqual(dict(self.s.sftp._expecting), {})

    def test_sad_a_missing_path_answers_with_the_error_stat_raises(self) -> None:
        got = self.s.stat_many(["/src/f01.bin", "/src/nope", "/nodir/x"])
        self.assertEqual(got[0], self.s.stat("/src/f01.bin"))
        for result, path in ((got[1], "/src/nope"), (got[2], "/nodir/x")):
            with self.assertRaises(OSError) as caught:
                self.s.stat(path)
            self.assertIsInstance(result, type(caught.exception))
            self.assertEqual(result.errno, caught.exception.errno)

    def test_sad_a_lost_connection_raises_oserror(self) -> None:
        for t in self.server._transports:
            t.close()
        with self.assertRaises(OSError):
            self.s.stat_many(self.paths)

    def test_edge_no_paths_and_repeated_paths(self) -> None:
        self.assertEqual(self.s.stat_many([]), [])
        a, b = self.s.stat_many(["/src/f03.bin", "/src/f03.bin"])
        self.assertEqual(a, b)


class _Manager(_Base):
    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        super().setUp()
        self.mgr = TransferManager()
        self.addCleanup(self._stop)
        p = mock.patch.object(self.mgr._worker, "enqueue")  # inspect jobs only
        p.start()
        self.addCleanup(p.stop)

    def _stop(self) -> None:
        self.mgr._worker.stop()
        self.mgr._thread.quit()
        self.mgr._thread.wait(2000)

    @staticmethod
    def shape(jobs) -> list[tuple]:
        return sorted((j.source_path, j.dest_path, j.total_bytes, j.source_fingerprint,
                       j.source_mode, j.source_mtime, j.status.name, j.error_message)
                      for j in jobs)

    def reference_jobs(self, paths, plan=None) -> list[tuple]:
        """The jobs the per-path calls (no stat_many) produce."""
        with mock.patch.object(SSHSession, "stat_many", None, create=True):
            return self.shape(self.mgr.transfer_files(self.s, LocalFS(), paths, str(self.dst),
                                                      conflict_plan=plan))


class SelectionWalkTest(_Manager):
    def test_happy_selected_files_need_no_stat_or_is_dir_per_path(self) -> None:
        files = [p for p in self.paths if p.endswith(".bin")]
        expected = self.reference_jobs(files)
        counts = self.count_calls(self.s)
        jobs = self.mgr.transfer_files(self.s, LocalFS(), files, str(self.dst))
        self.assertEqual(counts, {"stat": 0, "is_dir": 0})
        self.assertEqual(self.shape(jobs), expected)
        self.assertEqual(len(jobs), 40)

    def test_happy_a_folder_and_a_link_in_the_selection_are_handled_as_before(self) -> None:
        expected = self.reference_jobs(self.paths)
        jobs = self.mgr.transfer_files(self.s, LocalFS(), self.paths, str(self.dst))
        self.assertEqual(self.shape(jobs), expected)
        self.assertIn("/src/sub/inner.txt", [j.source_path for j in jobs])

    def test_sad_a_path_that_vanished_is_handled_as_before(self) -> None:
        paths = ["/src/f05.bin", "/src/gone.bin"]
        expected = self.reference_jobs(paths)
        jobs = self.mgr.transfer_files(self.s, LocalFS(), paths, str(self.dst))
        self.assertEqual(self.shape(jobs), expected)

    def test_sad_a_failing_batch_falls_back_to_the_per_path_calls(self) -> None:
        files = ["/src/f01.bin", "/src/f02.bin"]
        expected = self.reference_jobs(files)
        with mock.patch.object(self.s, "stat_many", side_effect=OSError("dropped")):
            jobs = self.mgr.transfer_files(self.s, LocalFS(), files, str(self.dst))
        self.assertEqual(self.shape(jobs), expected)

    def test_edge_a_backend_without_stat_many_is_asked_per_path(self) -> None:
        local = LocalFS()
        src = self.root / "src"
        files = [str(src / "f01.bin"), str(src / "f02.bin")]
        counts = self.count_calls(local)
        jobs = self.mgr.transfer_files(local, local, files, str(self.dst))
        self.assertEqual(len(jobs), 2)
        self.assertEqual(counts["is_dir"], 2)

    def test_edge_a_single_path_and_a_conflict_plan(self) -> None:
        from core.transfer_conflicts import ConflictAction, ConflictPlan, scan_conflicts

        (self.dst / "f03.bin").write_text("taken")
        files = ["/src/f03.bin", "/src/f04.bin"]
        scan = scan_conflicts(self.s, LocalFS(), files, str(self.dst))
        plan = ConflictPlan(LocalFS(), scan)
        for conflict in scan.conflicts:
            plan.decide(conflict, ConflictAction.RENAME)
        expected = self.reference_jobs(files, plan)
        self.assertEqual(self.shape(self.mgr.transfer_files(
            self.s, LocalFS(), files, str(self.dst), conflict_plan=plan)), expected)
        one = self.mgr.transfer_files(self.s, LocalFS(), ["/src/f06.bin"], str(self.dst))
        self.assertEqual(self.shape(one), self.reference_jobs(["/src/f06.bin"]))


class ConflictScanTest(_Base):
    def test_happy_the_destination_check_asks_no_stat_per_path(self) -> None:
        from core.transfer_conflicts import scan_conflicts

        for name in ("f01.bin", "f02.bin", "sub"):
            target = self.dst / name
            target.mkdir() if name == "sub" else target.write_text("old")
        with mock.patch.object(SSHSession, "stat_many", None, create=True):
            expected = scan_conflicts(self.s, LocalFS(), self.paths, str(self.dst))
        counts = self.count_calls(self.s, ("stat",))
        got = scan_conflicts(self.s, LocalFS(), self.paths, str(self.dst))
        self.assertEqual(counts["stat"], 0)
        self.assertEqual(got.conflicts, expected.conflicts)
        self.assertEqual(got.taken, expected.taken)
        self.assertTrue(got.conflicts)

    def test_sad_an_unreadable_source_is_still_scanned_like_a_file(self) -> None:
        from core.transfer_conflicts import scan_conflicts

        (self.dst / "gone.bin").write_text("old")
        paths = ["/src/gone.bin"]
        with mock.patch.object(SSHSession, "stat_many", None, create=True):
            expected = scan_conflicts(self.s, LocalFS(), paths, str(self.dst))
        got = scan_conflicts(self.s, LocalFS(), paths, str(self.dst))
        self.assertEqual(got.conflicts, expected.conflicts)


if __name__ == "__main__":
    unittest.main()
