"""Cancel reaches inside a folder that is being deleted.

Before: the pane's Delete (ui/file_pane.py ``_run_removal``) checked Cancel
only between the selected top-level entries. One huge folder was one
``backend.remove(path, recursive=True)`` call - shutil.rmtree for a local
path (a kernel-mounted share too), the SMB / SFTP / FTP backends' own tree
walks for a remote one - so Cancel could not stop it: the status said
"cancelling" and the whole folder went anyway ("0 of 1").

Now the delete runs inside :func:`core.removal_cancel.cancellable_removal`:
the tree walks (core.removal_cancel.rmtree for local paths, the SMB, SFTP
and FTP walkers) call ``checkpoint()`` before every entry and ``removed()``
after it. A cancel stops at the next entry with ``RemovalCancelled``, which
carries how many entries inside were removed, and the pane says that the
folder was partly deleted - never "nothing was deleted" when part was.
Backends whose server removes a tree in one request (WebDAV, S3, cloud
drives, ``rm -rf`` over a shell) cannot be stopped inside that request.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import removal_cancel as RC  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _tree(root: Path, files: int = 20, sub_files: int = 5) -> Path:
    big = root / "big"
    (big / "sub").mkdir(parents=True)
    for n in range(files):
        (big / f"f{n:03d}.txt").write_text("x")
    for n in range(sub_files):
        (big / "sub" / f"s{n}.txt").write_text("y")
    return big


def _count(path: Path) -> int:
    return sum(len(dirs) + len(files) for _r, dirs, files in os.walk(path))


class _Counting:
    """cancelled() turns true once *after* entries were removed."""

    def __init__(self, after: int) -> None:
        self.after = after
        self.removed: list[str] = []

    def cancelled(self) -> bool:
        return len(self.removed) >= self.after

    def on_removed(self, count: int, path: str) -> None:
        self.removed.append(path)
        assert count == len(self.removed)


class LocalRmtreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_happy_without_a_scope_the_whole_tree_goes(self) -> None:
        big = _tree(self.root)
        RC.rmtree(str(big))
        self.assertFalse(big.exists())

    def test_happy_inside_a_scope_without_cancel_the_whole_tree_goes(self) -> None:
        big = _tree(self.root)
        c = _Counting(after=10**9)
        with RC.cancellable_removal(c.cancelled, c.on_removed):
            RC.rmtree(str(big))
        self.assertFalse(big.exists())
        self.assertEqual(len(c.removed), 26)  # 20 files, sub, 5 files in sub

    def test_happy_cancel_stops_between_entries_inside_the_folder(self) -> None:
        big = _tree(self.root)
        before = _count(big)
        c = _Counting(after=3)
        with RC.cancellable_removal(c.cancelled, c.on_removed):
            with self.assertRaises(RC.RemovalCancelled) as caught:
                RC.rmtree(str(big))
        self.assertEqual(caught.exception.removed, 3)
        self.assertTrue(big.is_dir())
        self.assertEqual(_count(big), before - 3)

    def test_happy_localfs_remove_honours_the_scope(self) -> None:
        big = _tree(self.root)
        c = _Counting(after=1)
        with RC.cancellable_removal(c.cancelled, c.on_removed):
            with self.assertRaises(RC.RemovalCancelled):
                LocalFS().remove(str(big), recursive=True)
        self.assertTrue(big.is_dir())

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores modes")
    def test_sad_an_entry_that_cannot_be_removed_is_an_oserror(self) -> None:
        big = _tree(self.root, files=0, sub_files=1)
        (big / "sub").chmod(0o500)
        self.addCleanup((big / "sub").chmod, 0o700)
        with RC.cancellable_removal(lambda: False):
            with self.assertRaises(OSError):
                RC.rmtree(str(big))
        self.assertTrue((big / "sub" / "s0.txt").exists())

    def test_sad_the_cancel_signal_is_not_an_oserror(self) -> None:
        # Backends turn OSError (and ValueError, KeyError...) into their own
        # messages; the cancel must pass through them untouched.
        self.assertFalse(issubclass(RC.RemovalCancelled, (OSError, ValueError, KeyError)))
        self.assertTrue(issubclass(RC.RemovalCancelled, Exception))

    def test_edge_a_link_inside_is_removed_never_followed(self) -> None:
        big = _tree(self.root, files=1, sub_files=0)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep")
        (big / "link").symlink_to(outside, target_is_directory=True)
        with RC.cancellable_removal(lambda: False):
            RC.rmtree(str(big))
        self.assertFalse(big.exists())
        self.assertEqual((outside / "keep.txt").read_text(), "keep")

    def test_edge_a_top_level_link_is_refused_like_shutil(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep")
        link = self.root / "link"
        link.symlink_to(outside, target_is_directory=True)
        with RC.cancellable_removal(lambda: False):
            with self.assertRaises(OSError):
                RC.rmtree(str(link))
        self.assertTrue((outside / "keep.txt").exists())

    def test_edge_a_tree_deeper_than_the_recursion_limit_goes(self) -> None:
        depth = sys.getrecursionlimit() + 50
        top = self.root / "deep"
        top.mkdir()
        fd = os.open(top, os.O_RDONLY)
        try:
            for _ in range(depth):  # relative mkdir: no path-length limit
                os.mkdir("d", dir_fd=fd)
                new = os.open("d", os.O_RDONLY, dir_fd=fd)
                os.close(fd)
                fd = new
        finally:
            os.close(fd)
        c = _Counting(after=10**9)
        with RC.cancellable_removal(c.cancelled, c.on_removed):
            RC.rmtree(str(top))
        self.assertFalse(top.exists())
        self.assertEqual(len(c.removed), depth)

    def test_edge_checkpoint_outside_a_scope_does_nothing_and_scopes_nest(self) -> None:
        RC.checkpoint("/x")
        RC.removed("/x")
        with RC.cancellable_removal(lambda: True):
            with RC.cancellable_removal(lambda: False):
                RC.checkpoint("/inner")  # the inner scope decides
            with self.assertRaises(RC.RemovalCancelled):
                RC.checkpoint("/outer")
        RC.checkpoint("/after")

    def test_edge_the_scope_is_per_thread(self) -> None:
        seen = []
        with RC.cancellable_removal(lambda: True):
            t = threading.Thread(target=lambda: (RC.checkpoint("/t"), seen.append("ok")))
            t.start()
            t.join(5)
        self.assertEqual(seen, ["ok"])  # another thread's delete is not cancelled


# --- the remote tree walks ------------------------------------------------------


def test_happy_smb_walk_stops_at_the_next_entry(monkeypatch):
    pytest.importorskip("smbprotocol")
    from smb_fake_client import DirEntry, FakeSmbClient, make_session

    from core import smb_client

    fake = FakeSmbClient()
    monkeypatch.setattr(smb_client, "smbclient", fake)
    s = make_session(fake)
    sub = "\\\\h\\s\\sub"
    fake.listings = {sub: [DirEntry("a.txt"), DirEntry("b.txt"), DirEntry("c.txt")]}
    c = _Counting(after=1)
    with RC.cancellable_removal(c.cancelled, c.on_removed):
        with pytest.raises(RC.RemovalCancelled) as caught:
            s.remove("/sub", recursive=True)
    assert caught.value.removed == 1
    assert [x for x in fake.calls if x[0] != "scandir"] == [("remove", sub + "\\a.txt")]


def test_happy_smb_walk_counts_every_entry_when_not_cancelled(monkeypatch):
    pytest.importorskip("smbprotocol")
    from smb_fake_client import DirEntry, FakeSmbClient, make_session, smb_info

    from core import smb_client

    fake = FakeSmbClient()
    monkeypatch.setattr(smb_client, "smbclient", fake)
    s = make_session(fake)
    sub = "\\\\h\\s\\sub"
    fake.listings = {
        sub: [DirEntry("a.txt"), DirEntry("d", smb_info(attrs=0x10, size=0))],
        sub + "\\d": [DirEntry("b.txt")],
    }
    c = _Counting(after=10**9)
    with RC.cancellable_removal(c.cancelled, c.on_removed):
        s.remove("/sub", recursive=True)
    assert len(c.removed) == 3  # a.txt, d/b.txt, d
    assert fake.calls[-1] == ("rmdir", sub)


def test_happy_sftp_walk_stops_at_the_next_entry():
    from paramiko import SFTPAttributes
    from sftp_hostile_kit import attr, hostile_session

    with hostile_session() as (script, s):
        st = SFTPAttributes()
        st.st_mode, st.st_size = 0o040755, 0
        script.stat = st
        script.listing = [attr("a.txt"), attr("b.txt"), attr("c.txt")]
        calls = []
        real_remove, real_rmdir = s.sftp.remove, s.sftp.rmdir
        s.sftp.remove = lambda p: (calls.append(("remove", p)), real_remove(p))
        s.sftp.rmdir = lambda p: (calls.append(("rmdir", p)), real_rmdir(p))
        c = _Counting(after=2)
        with RC.cancellable_removal(c.cancelled, c.on_removed):
            with pytest.raises(RC.RemovalCancelled) as caught:
                s.remove("/sub", recursive=True)
        assert caught.value.removed == 2
        assert calls == [("remove", "/sub/a.txt"), ("remove", "/sub/b.txt")]


def test_happy_ftp_walk_stops_at_the_next_entry():
    from ftp_fuzz_server import FakeFtpServer

    from core import ftp_client as FC

    listing = (
        b"-rw-r--r-- 1 u g 5 Jan  1 00:00 a.txt\r\n"
        b"-rw-r--r-- 1 u g 5 Jan  1 00:00 b.txt\r\n"
    )
    replies = {
        "MLSD": b"500 unknown\r\n",
        "FEAT": b"211 end\r\n",
        "DELE": b"250 ok\r\n",
        "RMD": b"250 ok\r\n",
        "CWD": lambda arg: b"250 ok\r\n" if arg in ("/d", "/") else b"550 no\r\n",
    }
    root = b"drwxr-xr-x 1 u g 0 Jan  1 00:00 d\r\n"

    def list_reply(arg: str) -> bytes:
        return listing if arg.rstrip().endswith("/d") else root

    def nlst_reply(arg: str) -> bytes:
        return b"a.txt\r\nb.txt\r\n" if arg.rstrip().endswith("/d") else b"d\r\n"

    with FakeFtpServer(replies=replies, data={"LIST": list_reply, "NLST": nlst_reply}) as srv:
        s = FC.FtpSession(srv.host, srv.port, "u", "p")
        c = _Counting(after=1)
        with RC.cancellable_removal(c.cancelled, c.on_removed):
            with pytest.raises(RC.RemovalCancelled) as caught:
                s.remove("/d", recursive=True)
        dele = [x for x in srv.commands if x.startswith(("DELE", "RMD"))]
    assert caught.value.removed == 1
    assert dele == ["DELE /d/a.txt"]


# --- the pane ---------------------------------------------------------------------


from tests.test_pane_async_delete import _Base  # noqa: E402


class PaneCancelInsideFolderTest(_Base):
    def _tree(self, **kw) -> Path:
        big = _tree(self.root, **kw)
        self.pane.navigate(str(self.root))  # the listing predates the tree
        self.app.processEvents()
        return big

    def _gate_removed(self, after: int):
        """The walk blocks right after its *after*-th removed entry until
        released; returns (entered, release)."""
        entered, release = threading.Event(), threading.Event()
        real = RC.removed
        calls = [0]

        def removed(path):
            real(path)
            calls[0] += 1
            if calls[0] == after:
                entered.set()
                release.wait(10)

        patcher = mock.patch.object(RC, "removed", side_effect=removed)
        patcher.start()
        self.addCleanup(patcher.stop)
        return entered, release

    def test_e2e_cancel_inside_one_big_folder_reports_the_partial_delete(self) -> None:
        big = self._tree(files=30, sub_files=0)
        before = _count(big)
        entered, release = self._gate_removed(after=4)
        self.select("big")
        with self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.wait(entered.is_set, timeout=10))
            self.pane._cancel_delete_btn.click()
            release.set()
            self.assertTrue(self.idle())
        warning.assert_not_called()  # a cancel is no error
        self.assertTrue(big.is_dir())  # the folder and the rest stay
        self.assertEqual(_count(big), before - 4)
        status = self.pane._status.text()
        self.assertIn("cancelled", status.lower())
        self.assertIn("partly deleted", status)
        self.assertIn("4 entries inside", status)
        self.assertIn("big", self.names())
        self.assertEqual(self.pane._removal_ctx, {})

    def test_sad_cancel_before_anything_inside_went_keeps_the_entry_untouched(self) -> None:
        big = self._tree(files=3, sub_files=0)
        before = _count(big)
        self.select("big")
        with self.question(), self.warning():
            with mock.patch.object(RC, "checkpoint", side_effect=RC.RemovalCancelled("/x", 0)):
                self.pane._delete_selected()
                self.assertTrue(self.idle())
        self.assertEqual(_count(big), before)
        status = self.pane._status.text()
        self.assertNotIn("partly", status)
        self.assertIn("1 kept", status)

    def test_edge_the_progress_counts_entries_inside_the_folder(self) -> None:
        self._tree(files=10, sub_files=0)
        entered, release = self._gate_removed(after=5)
        self.select("big")
        with self.question(), self.warning():
            self.pane._delete_selected()
            self.assertTrue(self.wait(entered.is_set, timeout=10))
            self.assertTrue(
                self.wait(lambda: "5 removed inside" in self.pane._status.text(), timeout=3),
                self.pane._status.text(),
            )
            release.set()
            self.assertTrue(self.idle())
        self.assertFalse((self.root / "big").exists())
        self.assertIn("Deleted 1 of 1", self.pane._status.text())

    def test_edge_cancel_after_a_finished_entry_names_both(self) -> None:
        self._tree(files=10, sub_files=0)
        entered, release = self._gate_removed(after=2)
        self.select("a.txt", "big", "b.txt")
        order = [i.name for i in self.pane.selected_file_items()]
        at = order.index("big")
        with self.question(), self.warning():
            self.pane._delete_selected()
            self.assertTrue(self.wait(entered.is_set, timeout=10))
            self.pane._cancel_delete_btn.click()
            release.set()
            self.assertTrue(self.idle())
        status = self.pane._status.text()
        for name in order[:at]:
            self.assertFalse((self.root / name).exists(), name)
        for name in order[at + 1 :]:
            self.assertTrue((self.root / name).exists(), name)
        self.assertTrue((self.root / "big").is_dir())
        self.assertIn(f"after {at} of 3", status)
        self.assertIn("partly deleted", status)
        self.assertIn("2 entries inside", status)
        self.assertIn(f"{2 - at} kept", status)


if __name__ == "__main__":
    unittest.main()
