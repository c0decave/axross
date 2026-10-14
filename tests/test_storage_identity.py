"""Can two backends be showing the same file?

The Duplicate Finder may only trash a copy when another copy survives on
*different* storage. Two backends are not two storages when they reach the
same machine: SMB and SFTP to one NAS, LocalFS on a kernel NFS / CIFS /
sshfs mount and a remote session to that server, LocalFS and SFTP to
localhost. Whatever cannot be told apart counts as "maybe the same".
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import storage_identity as SI  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

MOUNTINFO = """\
38 1 8:3 / / rw,relatime shared:1 - ext4 /dev/sda3 rw
50 38 0:51 / /mnt/nas rw,relatime shared:30 - nfs4 nas.lan:/export rw,vers=4.2
51 38 0:52 / /mnt/smb rw,relatime shared:31 - cifs //NAS.lan/share rw
52 38 0:53 / /mnt/ssh rw,relatime shared:32 - fuse.sshfs dash@build.example:/srv rw
53 38 0:54 / /mnt/v6 rw,relatime shared:33 - nfs [fd00::7]:/data rw
54 38 0:55 / /mnt/phone rw,relatime shared:34 - fuse.jmtpfs jmtpfs rw
"""


class _Remote:
    """Stand-in for a network session; only what identification reads."""

    def __init__(self, host) -> None:
        self._host = host


class _ProfiledRemote:
    def __init__(self, host) -> None:
        self._profile = type("P", (), {"host": host})()


class _Opaque:
    """A backend that tells nothing about where it lives (cloud APIs)."""


class MountSourceTest(unittest.TestCase):
    def _source(self, dev_minor: int):
        st = mock.Mock(st_dev=os.makedev(0, dev_minor))
        with (
            mock.patch.object(SI, "_read_mountinfo", return_value=MOUNTINFO),
            mock.patch.object(SI.os, "stat", return_value=st),
        ):
            return SI.storage_host_of_local_path("/whatever")

    def test_happy_network_mounts_name_their_server(self) -> None:
        self.assertEqual(self._source(51), "nas.lan")
        self.assertEqual(self._source(52), "nas.lan")  # //NAS.lan/share, case folded
        self.assertEqual(self._source(53), "build.example")
        self.assertEqual(self._source(54), "fd00::7")

    def test_happy_a_local_disk_is_localhost(self) -> None:
        st = mock.Mock(st_dev=os.makedev(8, 3))
        with (
            mock.patch.object(SI, "_read_mountinfo", return_value=MOUNTINFO),
            mock.patch.object(SI.os, "stat", return_value=st),
        ):
            self.assertEqual(SI.storage_host_of_local_path("~"), "localhost")

    def test_edge_a_local_fuse_device_is_localhost(self) -> None:
        self.assertEqual(self._source(55), "localhost")

    def test_sad_no_mountinfo_means_unknown(self) -> None:
        with mock.patch.object(SI, "_read_mountinfo", side_effect=OSError):
            self.assertIsNone(SI.storage_host_of_local_path("/x"))

    def test_sad_a_device_missing_from_mountinfo_is_unknown(self) -> None:
        st = mock.Mock(st_dev=os.makedev(0, 999))
        with (
            mock.patch.object(SI, "_read_mountinfo", return_value=MOUNTINFO),
            mock.patch.object(SI.os, "stat", return_value=st),
        ):
            self.assertIsNone(SI.storage_host_of_local_path("/x"))

    def test_edge_the_real_root_filesystem_resolves(self) -> None:
        self.assertIsNotNone(SI.storage_host_of_local_path("/"))


class NormaliseTest(unittest.TestCase):
    def test_loopback_names_are_localhost(self) -> None:
        for name in (
            "localhost",
            "LOCALHOST.",
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "[::1]",
            socket.gethostname(),
        ):
            self.assertEqual(SI.normalise_host(name), "localhost", name)

    def test_other_names_are_case_and_dot_folded(self) -> None:
        self.assertEqual(SI.normalise_host("NAS.Lan."), "nas.lan")


class SameStorageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.a = self.tmp / "a.txt"
        self.b = self.tmp / "b.txt"
        self.a.write_text("x")
        self.b.write_text("x")
        self.local = LocalFS()

    def test_sad_local_and_sftp_to_localhost_may_be_the_same(self) -> None:
        self.assertTrue(SI.may_be_same_file(self.local, str(self.a), _Remote("127.0.0.1"), "/a"))

    def test_sad_two_protocols_to_one_nas_may_be_the_same(self) -> None:
        self.assertTrue(
            SI.may_be_same_file(_Remote("nas.lan"), "/x", _ProfiledRemote("NAS.lan."), "/y")
        )

    def test_sad_a_backend_that_says_nothing_may_be_anything(self) -> None:
        self.assertTrue(SI.may_be_same_file(_Opaque(), "/x", _Remote("far.example"), "/y"))

    def test_sad_a_local_network_mount_of_the_same_server(self) -> None:
        with mock.patch.object(SI, "storage_host_of_local_path", return_value="nas.lan"):
            self.assertTrue(SI.may_be_same_file(self.local, str(self.a), _Remote("nas.lan"), "/a"))

    def test_sad_two_local_names_for_one_file(self) -> None:
        os.link(self.a, self.tmp / "hard.txt")
        self.assertTrue(
            SI.may_be_same_file(self.local, str(self.a), self.local, str(self.tmp / "hard.txt"))
        )

    def test_happy_different_servers_are_different_storage(self) -> None:
        self.assertFalse(
            SI.may_be_same_file(_Remote("nas-a.lan"), "/x", _Remote("nas-b.lan"), "/x")
        )

    def test_happy_local_disk_and_a_remote_server(self) -> None:
        with mock.patch.object(SI, "storage_host_of_local_path", return_value="localhost"):
            self.assertFalse(
                SI.may_be_same_file(self.local, str(self.a), _Remote("far.example"), "/a")
            )

    def test_happy_two_separate_local_files(self) -> None:
        self.assertFalse(SI.may_be_same_file(self.local, str(self.a), self.local, str(self.b)))

    def test_edge_a_mounted_session_is_compared_by_its_local_path(self) -> None:
        class Mounted:  # NFS / iSCSI: virtual path -> mounted local path
            def __init__(self, root) -> None:
                self._root = root

            def local_path(self, path: str) -> str:
                return os.path.join(self._root, path.lstrip("/"))

        self.assertTrue(
            SI.may_be_same_file(Mounted(str(self.tmp)), "/a.txt", self.local, str(self.a))
        )
        self.assertFalse(
            SI.may_be_same_file(Mounted(str(self.tmp)), "/b.txt", self.local, str(self.a))
        )


class DeleteAcrossBackendsTest(unittest.TestCase):
    """End to end through cas.delete_duplicates."""

    def setUp(self) -> None:
        from core import cas as CAS
        from core import trash as T

        self.CAS = CAS
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = self.tmp / "cas.sqlite"
        self.trash_root = str(self.tmp / T.TRASH_DIRNAME)
        self.a = self.tmp / "a.txt"
        self.a.write_bytes(b"same\n")
        self.value = LocalFS().checksum(str(self.a)).split(":", 1)[1]

    def _run(self, other_backend):
        CAS = self.CAS
        CAS.upsert(self.db, "LocalFS:Local", str(self.a), "sha256", self.value, 5)
        CAS.upsert(self.db, "Remote:x", str(self.a), "sha256", self.value, 5)
        groups = CAS.duplicates(self.db)
        mine = [e for e in groups[0] if e.backend_id == "LocalFS:Local"]
        return CAS.delete_duplicates(
            mine,
            groups,
            {"LocalFS:Local": LocalFS(), "Remote:x": other_backend},
            db_path=self.db,
            trash_root=self.trash_root,
        )

    def test_sad_the_same_file_seen_through_sftp_to_localhost_is_kept(self) -> None:
        class LoopbackSftp(LocalFS):  # serves the very same files
            same_file = None
            _host = "localhost"

        out = self._run(LoopbackSftp())
        self.assertEqual(out.removed, [])
        self.assertTrue(self.a.exists())

    def test_happy_a_copy_on_another_server_lets_the_local_one_go(self) -> None:
        far = self.tmp / "far"
        far.mkdir()
        (far / "a.txt").write_bytes(b"same\n")

        class FarSftp(LocalFS):  # a different machine, simulated by another folder
            same_file = None
            _host = "far.example"

            def local_path(self, path):
                return None

            def stat(self, path):
                return super().stat(str(far / "a.txt"))

            def checksum(self, path, algorithm="sha256"):
                return super().checksum(str(far / "a.txt"), algorithm)

        with mock.patch.object(SI, "storage_host_of_local_path", return_value="localhost"):
            out = self._run(FarSftp())
        self.assertEqual([e.path for e in out.removed], [str(self.a)])


if __name__ == "__main__":
    unittest.main()
