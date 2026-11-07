"""An entry whose lstat fails (EACCES on a mount point the user may not
enter) stays in the listing: a recursive delete or move over a listing
that silently dropped it would report success with the entry left behind."""

from __future__ import annotations

import errno

from core.local_fs import LocalFS
from models.file_table_model import COL_MODIFIED, COL_PERMS, COL_SIZE, FileTableModel


def _deny(monkeypatch, denied: str):
    real = LocalFS._entry_to_item

    def entry_to_item(self, entry):
        if entry.name == denied:
            raise PermissionError(errno.EACCES, "Permission denied", entry.path)
        return real(self, entry)

    monkeypatch.setattr(LocalFS, "_entry_to_item", entry_to_item)


def test_unstattable_folder_is_listed_as_a_folder(tmp_path, monkeypatch):
    (tmp_path / "ext").mkdir()
    (tmp_path / "plain.txt").write_text("x")
    _deny(monkeypatch, "ext")

    items = {i.name: i for i in LocalFS().list_dir(str(tmp_path))}

    assert set(items) == {"ext", "plain.txt"}
    ext = items["ext"]
    assert ext.is_dir and not ext.is_link
    assert ext.stat_error == "Permission denied"
    assert items["plain.txt"].stat_error == ""


def test_unstattable_file_shows_unknown_attributes(tmp_path, monkeypatch):
    (tmp_path / "secret.bin").write_bytes(b"1234")
    _deny(monkeypatch, "secret.bin")

    (item,) = LocalFS().list_dir(str(tmp_path))
    assert not item.is_dir
    assert item.size_human == "?"
    assert item.mode_str == "-?????????"

    model = FileTableModel()
    assert model.display_text(item, COL_SIZE) == "?"
    assert model.display_text(item, COL_MODIFIED) == "?"
    assert model.display_text(item, COL_PERMS) == "-?????????"


class _DeniedEntry:
    """A DirEntry whose stat is refused; its d_type answers stay."""

    def __init__(self, entry):
        self._entry = entry
        self.name, self.path = entry.name, entry.path

    def is_dir(self, *, follow_symlinks=True):
        return self._entry.is_dir(follow_symlinks=follow_symlinks)

    def is_symlink(self):
        return self._entry.is_symlink()

    def stat(self, *, follow_symlinks=True):
        raise PermissionError(errno.EACCES, "Permission denied", self.path)


def _scandir_denying(denied: str):
    import os

    real = os.scandir

    class _It:
        def __init__(self, path):
            self._it = real(path)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._it.close()

        def __iter__(self):
            for entry in self._it:
                yield _DeniedEntry(entry) if entry.name == denied else entry

    return _It


def test_the_watch_snapshot_keeps_the_entry_as_the_listing_does(tmp_path, monkeypatch):
    """core/watch.py lists a local folder without FileItems; it must see
    the same entries as LocalFS.list_dir, or every poll reports a change."""
    import core.local_fs as local_fs
    import core.watch as watch

    (tmp_path / "ext").mkdir()
    (tmp_path / "plain.txt").write_text("x")
    monkeypatch.setattr(local_fs.os, "scandir", _scandir_denying("ext"))

    listed = watch.PollingWatcher._snapshot_of(LocalFS().list_dir(str(tmp_path)))
    fast = watch._local_snapshot(str(tmp_path))
    assert fast is not None
    assert fast.entries["ext"][2] is True
    assert fast.entries == listed.entries


def test_iscsi_and_nfs_keep_an_unstattable_entry(tmp_path, monkeypatch):
    import os

    from core import iscsi_client, nfs_client

    (tmp_path / "ext").mkdir()
    (tmp_path / "plain.txt").write_text("x")

    iscsi = iscsi_client.IscsiSession.__new__(iscsi_client.IscsiSession)
    iscsi._mount_point = str(tmp_path)
    monkeypatch.setattr(iscsi_client.os, "scandir", _scandir_denying("ext"))
    items = {i.name: i for i in iscsi.list_dir("")}
    assert items["ext"].stat_error == "Permission denied" and items["ext"].is_dir
    monkeypatch.undo()

    nfs = nfs_client.NfsSession.__new__(nfs_client.NfsSession)
    nfs._mount_point = str(tmp_path)
    real_stat = os.stat
    denied = str(tmp_path / "ext")

    def stat(path, *a, **k):
        if str(path) == denied:
            raise PermissionError(errno.EACCES, "Permission denied", path)
        return real_stat(path, *a, **k)

    monkeypatch.setattr(nfs_client.os, "stat", stat)
    items = {i.name: i for i in nfs.list_dir("")}
    assert set(items) == {"ext", "plain.txt"}
    assert items["ext"].stat_error == "Permission denied"
    assert items["plain.txt"].stat_error == ""
