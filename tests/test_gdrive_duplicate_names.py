"""Google Drive: a name two files share is ambiguous, never a guess -
and axross never makes one.

Drive allows two files of one name in a folder. list_dir cached the id
of the LAST one listed under the shared path and _resolve_path took the
first hit of a ``pageSize=1`` query, so removing, reading or renaming
"the" file acted on whichever id the cache held - remove() deleted the
other copy for good. Now a path that names more than one file fails
with an OSError for every operation that would pick one.

open_write treated every lookup failure as "the file does not exist":
a transient API error while resolving an existing file created a
second file of the same name. Only a real "not found" creates now.

mkdir, rename and copy created a second item of a name the folder already
held (Drive allows it): mkdir of an existing name and rename or copy onto
one now raise FileExistsError and change nothing - the way SMB and the SQLite FS
refuse a rename onto an existing name, which server_ops' overwrite then
swaps through a backup.
"""

from __future__ import annotations

import itertools

import pytest

pytest.importorskip("googleapiclient")

from core.gdrive_client import GDriveSession  # noqa: E402

_FOLDER = "application/vnd.google-apps.folder"


class _Exec:
    def __init__(self, fn) -> None:
        self._fn = fn

    def execute(self):
        return self._fn()


class _Drive:
    """files() of a Drive with a name query, listing, get, delete,
    update and create. ``fail_name_lookups`` makes that many name
    queries fail like a transient 503."""

    def __init__(self, store: list[dict], fail_name_lookups: int = 0, fail_names=()) -> None:
        self.store = store
        self.fail_names = set(fail_names)
        self.deleted: list[str] = []
        self.updated: list[str] = []
        self.created: list[str] = []
        self.fail_name_lookups = fail_name_lookups
        self._ids = itertools.count(100)

    def files(self):
        return self

    def list(self, q=None, fields=None, pageSize=None, pageToken=None):
        parent = q.split("'")[1]

        def run():
            hits = [f for f in self.store if f["parent"] == parent]
            if "name = '" in q:
                name = q.split("name = '")[1].split("'")[0]
                if self.fail_name_lookups or name in self.fail_names:
                    self.fail_name_lookups = max(0, self.fail_name_lookups - 1)
                    raise RuntimeError("HttpError 503 backendError (transient)")
                hits = [f for f in hits if f["name"] == name]
            return {"files": hits[: pageSize or None]}

        return _Exec(run)

    def get(self, fileId=None, fields=None):
        def run():
            for f in self.store:
                if f["id"] == fileId:
                    return dict(f)
            raise RuntimeError("HttpError 404")

        return _Exec(run)

    def delete(self, fileId=None):
        def run():
            self.deleted.append(fileId)
            self.store[:] = [f for f in self.store if f["id"] != fileId]
            return {}

        return _Exec(run)

    def update(self, fileId=None, media_body=None, body=None, addParents=None,
               removeParents=None, fields=None):
        def run():
            self.updated.append(fileId)
            for f in self.store:
                if f["id"] == fileId:
                    if body and "name" in body:
                        f["name"] = body["name"]
                    if addParents:
                        f["parent"] = addParents
            return {"id": fileId}

        return _Exec(run)

    def copy(self, fileId=None, body=None):
        def run():
            fid = f"C{next(self._ids)}"
            self.created.append(fid)
            self.store.append(
                {"id": fid, "parent": body["parents"][0], "name": body["name"],
                 "mimeType": "text/plain"}
            )
            return {"id": fid}

        return _Exec(run)

    def create(self, body=None, media_body=None, fields=None):
        def run():
            fid = f"N{next(self._ids)}"
            self.created.append(fid)
            self.store.append(
                {"id": fid, "parent": body["parents"][0], "name": body["name"],
                 "mimeType": body.get("mimeType", "text/plain")}
            )
            return {"id": fid}

        return _Exec(run)


def _file(fid: str, name: str, parent: str = "root", mime: str = "application/pdf") -> dict:
    return {"id": fid, "parent": parent, "name": name, "mimeType": mime, "size": "1",
            "modifiedTime": "2024-01-01T00:00:00Z"}


def _session(drive: _Drive) -> GDriveSession:
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root"}
    return s


def _twins() -> list[dict]:
    return [_file("OLD", "report.pdf"), _file("NEW", "report.pdf"), _file("U", "unique.pdf")]


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("listed_first", [True, False])
def test_sad_remove_of_a_shared_name_deletes_nothing(listed_first):
    drive = _Drive(_twins())
    s = _session(drive)
    if listed_first:
        assert [i.name for i in s.list_dir("/")].count("report.pdf") == 2
    with pytest.raises(OSError, match="2 files"):
        s.remove("/report.pdf")
    assert drive.deleted == []


def test_sad_read_rename_and_overwrite_of_a_shared_name_fail():
    drive = _Drive(_twins())
    s = _session(drive)
    s.list_dir("/")
    with pytest.raises(OSError):
        s.open_read("/report.pdf")
    with pytest.raises(OSError):
        s.rename("/report.pdf", "/x.pdf")
    with pytest.raises(OSError):
        s.open_write("/report.pdf")
    assert drive.updated == [] and drive.created == [] and drive.deleted == []


def test_sad_transient_lookup_error_does_not_create_a_duplicate():
    drive = _Drive([_file("f1", "notes.txt", mime="text/plain")], fail_name_lookups=1)
    s = _session(drive)
    with pytest.raises(OSError):
        s.open_write("/notes.txt")
    assert drive.created == []
    assert [f["name"] for f in drive.store] == ["notes.txt"]


# -- happy -------------------------------------------------------------------


def test_happy_unique_names_still_resolve_after_a_listing():
    drive = _Drive(_twins())
    s = _session(drive)
    s.list_dir("/")
    s.remove("/unique.pdf")
    assert drive.deleted == ["U"]


def test_happy_save_updates_an_existing_file_and_creates_a_new_one():
    drive = _Drive([_file("f1", "notes.txt", mime="text/plain")])
    s = _session(drive)
    with s.open_write("/notes.txt") as w:
        w.write(b"new")
    with s.open_write("/other.txt") as w:
        w.write(b"x")
    assert drive.updated == ["f1"]
    assert len(drive.created) == 1


# -- edge --------------------------------------------------------------------


def test_edge_a_shared_folder_name_on_the_way_is_ambiguous_too():
    drive = _Drive(
        [
            _file("D1", "dir", mime=_FOLDER),
            _file("D2", "dir", mime=_FOLDER),
            _file("C", "a.txt", parent="D1", mime="text/plain"),
        ]
    )
    s = _session(drive)
    with pytest.raises(OSError, match="2 files"):
        s.remove("/dir/a.txt")
    assert drive.deleted == []


def test_edge_removing_one_twin_out_of_band_makes_the_name_usable_again():
    drive = _Drive(_twins())
    s = _session(drive)
    s.list_dir("/")
    drive.store[:] = [f for f in drive.store if f["id"] != "OLD"]
    s.list_dir("/")
    s.remove("/report.pdf")
    assert drive.deleted == ["NEW"]


# -- mkdir / rename never make a duplicate ------------------------------------


@pytest.mark.parametrize("mime", [_FOLDER, "text/plain"], ids=["folder", "file"])
def test_sad_mkdir_of_an_existing_name_creates_nothing(mime):
    drive = _Drive([_file("X", "dir", mime=mime)])
    s = _session(drive)
    with pytest.raises(FileExistsError):
        s.mkdir("/dir")
    assert drive.created == []


def test_sad_mkdir_when_the_name_lookup_fails_creates_nothing():
    drive = _Drive([], fail_names={"dir"})
    s = _session(drive)
    with pytest.raises(OSError) as info:
        s.mkdir("/dir")
    assert not isinstance(info.value, FileExistsError)
    assert drive.created == []


def test_happy_mkdir_of_a_new_name_creates_it_once():
    drive = _Drive([_file("X", "other", mime=_FOLDER)])
    s = _session(drive)
    s.mkdir("/dir")
    assert len(drive.created) == 1
    assert s.is_dir("/dir")
    with pytest.raises(FileExistsError):
        s.mkdir("/dir")
    assert len(drive.created) == 1


def test_edge_mkdir_of_a_name_known_from_a_listing_creates_nothing():
    drive = _Drive([_file("X", "dir", mime=_FOLDER)])
    s = _session(drive)
    s.list_dir("/")
    with pytest.raises(FileExistsError):
        s.mkdir("/dir")
    assert drive.created == []


def test_sad_rename_onto_an_existing_name_changes_nothing():
    drive = _Drive([_file("A", "a.txt"), _file("B", "b.txt")])
    s = _session(drive)
    with pytest.raises(FileExistsError):
        s.rename("/a.txt", "/b.txt")
    assert drive.updated == []
    assert sorted(f["name"] for f in drive.store) == ["a.txt", "b.txt"]


def test_sad_move_onto_an_existing_name_in_another_folder_changes_nothing():
    drive = _Drive(
        [
            _file("D", "dir", mime=_FOLDER),
            _file("A", "a.txt"),
            _file("A2", "a.txt", parent="D"),
        ]
    )
    s = _session(drive)
    with pytest.raises(FileExistsError):
        s.rename("/a.txt", "/dir/a.txt")
    assert drive.updated == []


@pytest.mark.parametrize(
    "store, fail",
    [
        ([_file("A", "a.txt")], {"b.txt"}),
        ([_file("A", "a.txt"), _file("B1", "b.txt"), _file("B2", "b.txt")], set()),
    ],
    ids=["transient-lookup", "shared-name"],
)
def test_sad_rename_with_an_unresolvable_target_changes_nothing(store, fail):
    drive = _Drive(store, fail_names=fail)
    s = _session(drive)
    with pytest.raises(OSError):
        s.rename("/a.txt", "/b.txt")
    assert drive.updated == []


def test_happy_rename_and_move_to_free_names():
    drive = _Drive([_file("D", "dir", mime=_FOLDER), _file("A", "a.txt")])
    s = _session(drive)
    s.rename("/a.txt", "/b.txt")
    s.rename("/b.txt", "/dir/c.txt")
    assert drive.updated == ["A", "A"]
    assert s.stat("/dir/c.txt").name == "c.txt"
    assert not s.exists("/b.txt")


def test_edge_rename_onto_its_own_name_is_no_duplicate():
    drive = _Drive([_file("A", "a.txt")])
    s = _session(drive)
    s.rename("/a.txt", "/a.txt")
    assert [f["name"] for f in drive.store] == ["a.txt"]


def test_sad_copy_onto_an_existing_name_creates_nothing():
    """server_side_copy(overwrite=True) takes FileExistsError from a
    native copy as its cue to stream over the existing file instead."""
    drive = _Drive([_file("A", "a.txt"), _file("B", "b.txt")])
    s = _session(drive)
    with pytest.raises(FileExistsError):
        s.copy("/a.txt", "/b.txt")
    with pytest.raises(FileExistsError):
        s.copy("/a.txt", "/a.txt")
    assert drive.created == []


def test_happy_copy_to_a_free_name():
    drive = _Drive([_file("A", "a.txt")])
    s = _session(drive)
    s.copy("/a.txt", "/b.txt")
    assert sorted(f["name"] for f in drive.store) == ["a.txt", "b.txt"]


def test_edge_copy_with_an_unresolvable_target_creates_nothing():
    drive = _Drive([_file("A", "a.txt")], fail_names={"b.txt"})
    s = _session(drive)
    with pytest.raises(OSError):
        s.copy("/a.txt", "/b.txt")
    assert drive.created == []
