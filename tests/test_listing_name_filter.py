"""Hostile file names in remote listings never reach consumers."""
from __future__ import annotations

import unittest
from unittest import mock

from core import path_policy
from core.ssh_client import SSHSession
from models.file_item import FileItem


def _items(*names: str) -> list[FileItem]:
    return [FileItem(name=n) for n in names]


class DropUnsafeNamesTest(unittest.TestCase):
    def test_traversal_and_separators_are_dropped(self) -> None:
        kept = path_policy.drop_unsafe_names(
            _items("ok.txt", "../../.bashrc", "a/b", "back\\slash", "nul\x00", "also ok")
        )
        self.assertEqual([i.name for i in kept], ["ok.txt", "also ok"])

    def test_dot_entries_are_dropped_unless_asked(self) -> None:
        self.assertEqual(path_policy.drop_unsafe_names(_items(".", "..", "x")), _items("x"))
        kept = path_policy.drop_unsafe_names(_items(".", "..", "x"), keep_dots=True)
        self.assertEqual([i.name for i in kept], [".", "..", "x"])

    def test_empty_list(self) -> None:
        self.assertEqual(path_policy.drop_unsafe_names([]), [])

    def test_unicode_names_survive(self) -> None:
        kept = path_policy.drop_unsafe_names(_items("größe.txt", "日本語.md"))
        self.assertEqual(len(kept), 2)


class SftpListingTest(unittest.TestCase):
    def test_list_dir_filters_hostile_names(self) -> None:
        import paramiko

        def attr(name: str):
            a = paramiko.SFTPAttributes()
            a.filename = name
            a.st_mode = 0o100644
            return a

        session = SSHSession.__new__(SSHSession)
        fake = mock.Mock()
        fake.listdir_attr.return_value = [attr("good"), attr("../../etc/passwd"), attr("x/y")]
        sftp = mock.patch.object(
            SSHSession, "sftp", new_callable=mock.PropertyMock, return_value=fake
        )
        with sftp:
            names = [i.name for i in session.list_dir("/srv")]
        self.assertEqual(names, ["good"])


if __name__ == "__main__":
    unittest.main()
