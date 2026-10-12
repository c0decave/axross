"""Destructive operations must not reach beyond the named target."""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from core import imap_client, pjl_client, rsync_client
from core.sqlite_fs_client import SqliteFsSession


class SqliteSubtreeDeleteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = os.path.join(tempfile.mkdtemp(), "fs.sqlite")
        self.fs = SqliteFsSession(url=self.db)
        for d in ("/Foo", "/foo"):
            self.fs.mkdir(d)
            for name in ("a", "b"):
                with self.fs.open_write(f"{d}/{name}") as fh:
                    fh.write(b"x")

    def _names(self, d: str) -> list[str]:
        return sorted(i.name for i in self.fs.list_dir(d))

    def test_delete_is_case_sensitive(self) -> None:
        self.fs.remove("/Foo", recursive=True)
        self.assertFalse(self.fs.exists("/Foo"))
        self.assertEqual(self._names("/foo"), ["a", "b"])

    def test_percent_and_underscore_are_literal(self) -> None:
        self.fs.mkdir("/f_o")
        with self.fs.open_write("/f_o/x") as fh:
            fh.write(b"x")
        self.fs.remove("/f_o", recursive=True)
        self.assertEqual(self._names("/foo"), ["a", "b"])

    def test_sibling_prefix_survives(self) -> None:
        self.fs.mkdir("/foobar")
        self.fs.remove("/foo", recursive=True)
        self.assertTrue(self.fs.exists("/foobar"))


class PjlRootDeleteTest(unittest.TestCase):
    def test_root_is_refused(self) -> None:
        session = pjl_client.PjlSession.__new__(pjl_client.PjlSession)
        session._volume = "0:"
        with mock.patch.object(session, "_ensure_safe"), mock.patch.object(
            pjl_client, "_open_socket"
        ) as opened:
            for path in ("/", "/x/..", ""):
                with self.assertRaises(OSError):
                    session.remove(path)
            opened.assert_not_called()


class RsyncGlobTest(unittest.TestCase):
    def test_metacharacters_are_escaped(self) -> None:
        esc = rsync_client._escape_rsync_pattern
        self.assertEqual(esc("plain.txt"), "plain.txt")
        self.assertEqual(esc("*"), r"\*")
        self.assertEqual(esc("a?b"), r"a\?b")
        self.assertEqual(esc("[abc]"), r"\[abc]")
        self.assertEqual(esc("back\\slash"), "back\\\\slash")


class ImapExpungeTest(unittest.TestCase):
    def _imap(self, *, uidplus: bool, other_deleted: list[bytes]):
        imap = mock.Mock()
        imap.capabilities = ("IMAP4REV1", "UIDPLUS") if uidplus else ("IMAP4REV1",)
        imap.uid.side_effect = lambda cmd, *a: (
            ("OK", [b" ".join(other_deleted + [b"7"])]) if cmd == "SEARCH" else ("OK", [b""])
        )
        return imap

    def test_uid_expunge_when_uidplus(self) -> None:
        imap = self._imap(uidplus=True, other_deleted=[b"3"])
        imap_client._expunge_one(imap, "7")
        calls = [c.args[0] for c in imap.uid.call_args_list]
        self.assertIn("EXPUNGE", calls)
        imap.expunge.assert_not_called()

    def test_bare_expunge_only_when_nothing_else_is_flagged(self) -> None:
        imap = self._imap(uidplus=False, other_deleted=[])
        imap_client._expunge_one(imap, "7")
        imap.expunge.assert_called_once()

    def test_foreign_deleted_messages_are_left_alone(self) -> None:
        imap = self._imap(uidplus=False, other_deleted=[b"3"])
        imap_client._expunge_one(imap, "7")
        imap.expunge.assert_not_called()


if __name__ == "__main__":
    unittest.main()
