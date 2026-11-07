"""Duplicate Finder, core: what a scan indexes and what counts as a duplicate.

The request was to perfect the Duplicate Finder. A review of core.cas found
these gaps, each covered here:

* a FIFO (or socket, device) in the scanned tree hung the scan forever -
  hashing opened it and waited for a writer, and Cancel could not stop it;
* every empty file formed one large "duplicate" group (``__init__.py``,
  ``.gitkeep``, lock files), offered for removal;
* an ETag (WebDAV ``DAV:getetag``, a non-MD5 S3 ETag) was taken for a
  content hash: different files with one ETag were shown as duplicates and
  the re-check before a removal passed by comparing the ETag again;
* hard links were counted as copies: the wasted space was overstated, and
  "Mark All" + "Move to Trash" refused the whole group because one marked
  name was the kept file under another name;
* rows of deleted or moved files stayed in the index forever (rebuilds were
  only additive), so groups listed files that no longer existed;
* files that could not be read and folders that could not be listed were
  dropped silently - the scan reported success;
* backends without a content checksum of their own (SMB, plain FTP,
  WebDAV with ETags only) indexed nothing at all.

And new: keep rules (newest, shortest path, inside a folder), the bytes a
group would free, and reading files without a checksum as little as
possible (size first, then the first bytes, then the whole file).
"""

from __future__ import annotations

import hashlib
import io
import os
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import cas as CAS  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


def _write(path: Path, data: bytes = b"same content\n", mtime: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


@pytest.fixture
def env(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    return tree, tmp_path / "cas.sqlite"


def _rebuild(tree: Path, db: Path, fs=None, **kw) -> int:
    return CAS.rebuild(fs or LocalFS(), str(tree), backend_id=BID, db_path=db, **kw)


def _paths(groups) -> list[list[str]]:
    return sorted(sorted(e.path for e in g) for g in groups)


def _entry(groups, path: Path):
    return next(e for g in groups for e in g if e.path == str(path))


# --------------------------------------------------------------------------
# Special files: never read
# --------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_sad_a_fifo_in_the_tree_is_skipped_not_waited_on(env):
    tree, db = env
    _write(tree / "a.txt"), _write(tree / "b.txt")
    os.mkfifo(tree / "pipe")
    stats = CAS.RebuildStats()
    done = []
    worker = threading.Thread(
        target=lambda: done.append(_rebuild(tree, db, stats=stats)), daemon=True)
    worker.start()
    worker.join(timeout=20)
    if worker.is_alive():  # unblock the hung open() so the test run goes on
        fd = os.open(tree / "pipe", os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)
        pytest.fail("the scan hung on the FIFO")
    assert done == [2]
    assert stats.special == 1
    assert _paths(CAS.duplicates(db)) == [[str(tree / "a.txt"), str(tree / "b.txt")]]


def test_edge_local_identity_tells_regular_files_from_others(tmp_path):
    f = _write(tmp_path / "f")
    regular, file_id = CAS._local_identity(LocalFS(), str(f))
    st = os.lstat(f)
    assert regular is True and file_id == f"{st.st_dev}:{st.st_ino}"
    assert CAS._local_identity(LocalFS(), str(tmp_path)) == (False, None)
    assert CAS._local_identity(object(), str(f)) == (None, None)


# --------------------------------------------------------------------------
# Empty files and fingerprints that are no content hash
# --------------------------------------------------------------------------


def test_happy_empty_files_are_left_out_on_request(env):
    tree, db = env
    for name in ("__init__.py", "x/__init__.py", ".gitkeep"):
        _write(tree / name, b"")
    _write(tree / "a.txt"), _write(tree / "b.txt")
    _rebuild(tree, db)
    assert len(CAS.duplicates(db)) == 2  # the API default is unchanged
    groups = CAS.duplicates(db, include_empty=False)
    assert _paths(groups) == [[str(tree / "a.txt"), str(tree / "b.txt")]]
    empty = [g for g in CAS.duplicates(db) if CAS.is_empty_content(g[0])]
    assert len(empty) == 1 and len(empty[0]) == 3


def test_edge_empty_digests_cover_the_usual_algorithms():
    for algo in ("md5", "sha1", "sha256", "sha512"):
        assert hashlib.new(algo, b"").hexdigest() in CAS.EMPTY_DIGESTS
    assert hashlib.sha256(b"x").hexdigest() not in CAS.EMPTY_DIGESTS


def test_sad_etags_never_form_a_group(tmp_path):
    db = tmp_path / "cas.sqlite"
    # nginx: ETag = mtime-size, so two different files share one.
    CAS.upsert(db, "WebDAV:x", "/a.txt", "etag", '"5f3a-1c"', 28)
    CAS.upsert(db, "WebDAV:x", "/b.txt", "etag", '"5f3a-1c"', 28)
    CAS.upsert(db, "S3:x", "/c", "s3-etag", "abc-2", 9)
    CAS.upsert(db, "S3:x", "/d", "s3-etag", "abc-2", 9)
    assert CAS.duplicates(db, None) == []
    assert all(s.duplicate_groups == 0 for s in CAS.list_scans(db))
    assert not CAS.is_content_hash("etag") and not CAS.is_content_hash("s3-etag")
    assert CAS.is_content_hash("sha256") and CAS.is_content_hash("md5")


class _EtagFS(LocalFS):
    """A backend whose only checksum is an ETag (WebDAV without oc:checksums)."""

    def checksum(self, path, algorithm="sha256"):
        st = os.stat(path)
        return f"etag:{int(st.st_mtime):x}-{st.st_size:x}"


def test_sad_an_etag_backend_indexes_nothing_without_reading(env):
    tree, db = env
    _write(tree / "a.txt", b"one!", mtime=1000), _write(tree / "b.txt", b"two!", mtime=1000)
    stats = CAS.RebuildStats()
    assert _rebuild(tree, db, fs=_EtagFS(), stats=stats) == 0
    assert stats.no_checksum == 2
    assert CAS.duplicates(db, None) == []


def test_sad_the_recheck_refuses_an_etag(tmp_path):
    f = _write(tmp_path / "a.txt", b"one!", mtime=1000)
    fake = CAS.CasEntry(BID, str(f), "etag", "3e8-4", 4, indexed_at=None)
    assert CAS._still_holds(_EtagFS(), fake) is False


# --------------------------------------------------------------------------
# Hard links: one file under two names is not a duplicate
# --------------------------------------------------------------------------


def _hardlink_tree(tree: Path):
    a = _write(tree / "a.txt", mtime=1000)
    os.link(a, tree / "a-link.txt")
    b = _write(tree / "b.txt", mtime=2000)
    return a, tree / "a-link.txt", b


def test_happy_hard_links_share_a_file_id_and_free_nothing(env):
    tree, db = env
    a, link, b = _hardlink_tree(tree)
    _rebuild(tree, db)
    [group] = CAS.duplicates(db)
    ids = {e.path: e.file_id for e in group}
    assert ids[str(a)] == ids[str(link)] != ids[str(b)]
    assert CAS.distinct_copies(group) == 2
    assert CAS.reclaimable_bytes(group) == b.stat().st_size


def test_happy_mark_all_and_trash_keeps_the_hard_link_and_removes_the_copy(env, tmp_path):
    tree, db = env
    a, link, b = _hardlink_tree(tree)
    _rebuild(tree, db)
    groups = CAS.duplicates(db)
    marked = CAS.mark_duplicates(groups, "oldest").marked
    assert [e.path for e in marked] == [str(b)]  # never the kept file's other name
    # Even when the user selects the hard link too, the real copy still goes.
    out = CAS.delete_duplicates(
        [_entry(groups, link), _entry(groups, b)], groups, {BID: LocalFS()}, db_path=db,
        trash_root=str(tmp_path / "trash" / T.TRASH_DIRNAME))
    assert [e.path for e in out.removed] == [str(b)]
    assert [(e.path, why) for e, why in out.refused] == [(str(link), CAS.ALIAS_REASON)]
    assert a.exists() and link.exists() and not b.exists()


def test_sad_only_hard_links_left_explains_why_nothing_goes(env, tmp_path):
    tree, db = env
    a = _write(tree / "a.txt")
    os.link(a, tree / "a2.txt")
    _rebuild(tree, db)
    groups = CAS.duplicates(db)
    out = CAS.delete_duplicates([_entry(groups, a)], groups, {BID: LocalFS()}, db_path=db,
                                trash_root=str(tmp_path / "t" / T.TRASH_DIRNAME))
    assert out.removed == []
    assert "no other verified copy" in out.refused[0][1]
    assert "same file" in out.refused[0][1]


def test_edge_select_all_keeps_the_survivor_and_its_hard_links(env):
    tree, db = env
    a, link, b = _hardlink_tree(tree)
    _rebuild(tree, db)
    groups = CAS.duplicates(db)
    plan = CAS.plan_deletion([e for g in groups for e in g], groups)
    assert [e.path for e in plan.deletable] == [str(b)]


def test_edge_replacing_a_copy_by_a_hard_link_is_noticed_on_rescan(env):
    tree, db = env
    a = _write(tree / "a.txt", mtime=1000)
    b = _write(tree / "b.txt", mtime=1000)
    _rebuild(tree, db)
    assert CAS.distinct_copies(CAS.duplicates(db)[0]) == 2
    b.unlink()
    os.link(a, b)  # what hard-link dedupe tools do: size and mtime stay
    stats = CAS.RebuildStats()
    _rebuild(tree, db, stats=stats)
    assert stats.unchanged == 2  # not hashed again ...
    assert CAS.distinct_copies(CAS.duplicates(db)[0]) == 1  # ... but the identity is new


def test_edge_an_old_index_gains_the_file_id_column(tmp_path):
    db = tmp_path / "old.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE cas (backend_id TEXT NOT NULL, path TEXT NOT NULL, algorithm TEXT "
        "NOT NULL, value TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, indexed_at TEXT "
        "NOT NULL, mtime REAL, scan_id INTEGER, PRIMARY KEY (backend_id, path, algorithm))")
    conn.execute("INSERT INTO cas VALUES ('b', '/x', 'sha256', 'v', 1, '2024-01-01', 1.0, NULL)")
    conn.execute("INSERT INTO cas VALUES ('b', '/y', 'sha256', 'v', 1, '2024-01-01', 2.0, NULL)")
    conn.commit()
    conn.close()
    [group] = CAS.duplicates(db)
    assert [e.file_id for e in group] == [None, None]
    assert CAS.distinct_copies(group) == 2


# --------------------------------------------------------------------------
# Stale rows, unreadable files, unlisted folders
# --------------------------------------------------------------------------


def test_happy_a_rescan_drops_rows_of_files_that_are_gone(env):
    tree, db = env
    a, b, c = (_write(tree / n) for n in ("a.txt", "b.txt", "c.txt"))
    _rebuild(tree, db)
    c.unlink()
    (tree / "b.txt").rename(tree / "moved.txt")
    stats = CAS.RebuildStats()
    _rebuild(tree, db, stats=stats)
    assert stats.pruned == 2
    assert _paths(CAS.duplicates(db)) == [[str(a), str(tree / "moved.txt")]]


def test_sad_a_cancelled_scan_drops_nothing(env):
    tree, db = env
    for n in ("a.txt", "b.txt", "c.txt"):
        _write(tree / n)
    _rebuild(tree, db)
    (tree / "c.txt").unlink()
    _rebuild(tree, db, cancel=lambda: True)
    assert len(CAS.list_for_backend(db, BID)) == 3


def test_edge_rows_outside_the_scanned_root_stay(env):
    tree, db = env
    _write(tree / "sub" / "a.txt"), _write(tree / "other" / "b.txt")
    _rebuild(tree, db)
    (tree / "other" / "b.txt").unlink()
    CAS.rebuild(LocalFS(), str(tree / "sub"), backend_id=BID, db_path=db)
    assert str(tree / "other" / "b.txt") in {e.path for e in CAS.list_for_backend(db, BID)}


class _Unlistable(LocalFS):
    """A folder that cannot be listed (a permission error on a server)."""

    def __init__(self, blocked: str) -> None:
        super().__init__()
        self.blocked = blocked

    def list_dir(self, path):
        if path == self.blocked:
            raise PermissionError(13, "Permission denied", path)
        return super().list_dir(path)


def test_sad_an_unlisted_folder_is_reported_and_its_rows_kept(env):
    tree, db = env
    _write(tree / "a.txt"), _write(tree / "locked" / "b.txt")
    _rebuild(tree, db)
    stats = CAS.RebuildStats()
    _rebuild(tree, db, fs=_Unlistable(str(tree / "locked")), stats=stats)
    assert stats.unlisted_count == 1
    assert stats.unlisted[0] == (str(tree / "locked"), "Permission denied")
    assert str(tree / "locked" / "b.txt") in {e.path for e in CAS.list_for_backend(db, BID)}


class _Unreadable(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        if path.endswith("secret.txt"):
            raise PermissionError(13, "Permission denied", path)
        return super().checksum(path, algorithm)


def test_sad_an_unreadable_file_is_reported_not_silently_skipped(env):
    tree, db = env
    _write(tree / "a.txt"), _write(tree / "secret.txt")
    stats = CAS.RebuildStats()
    assert _rebuild(tree, db, fs=_Unreadable(), stats=stats) == 1
    assert stats.unreadable_count == 1
    assert stats.unreadable == [(str(tree / "secret.txt"), "Permission denied")]


def test_edge_stats_count_hashed_unchanged_and_bytes(env):
    tree, db = env
    _write(tree / "a.bin", b"x" * 1000), _write(tree / "b.bin", b"y" * 500)
    stats = CAS.RebuildStats()
    _rebuild(tree, db, stats=stats)
    assert (stats.scanned, stats.hashed, stats.unchanged, stats.bytes_hashed) == (2, 2, 0, 1500)
    stats = CAS.RebuildStats()
    _rebuild(tree, db, stats=stats)
    assert (stats.hashed, stats.unchanged, stats.bytes_hashed) == (0, 2, 0)


def test_edge_remove_many_is_one_call(env):
    tree, db = env
    for n in ("a", "b", "c"):
        _write(tree / n)
    _rebuild(tree, db)
    gone = CAS.remove_many(db, [(BID, str(tree / "a")), (BID, str(tree / "b")), (BID, "/nope")])
    assert gone == 2
    assert [e.path for e in CAS.list_for_backend(db, BID)] == [str(tree / "c")]
    assert CAS.remove_many(db, []) == 0


# --------------------------------------------------------------------------
# Backends without a content checksum: read as little as possible
# --------------------------------------------------------------------------


class _NoChecksumFS(LocalFS):
    """SMB-like: no checksum of its own; counts what is read."""

    def __init__(self) -> None:
        super().__init__()
        self.reads: list[tuple[str, int]] = []

    def checksum(self, path, algorithm="sha256"):
        return ""

    def open_read(self, path):
        data = Path(path).read_bytes()
        reads = self.reads

        class _Counting(io.BytesIO):
            def read(self, n=-1):
                chunk = super().read(n)
                reads.append((path, len(chunk)))
                return chunk

        return _Counting(data)

    def bytes_read(self, name: str) -> int:
        return sum(n for p, n in self.reads if p.endswith(name))


def test_happy_without_a_checksum_duplicates_are_found_by_reading(env):
    tree, db = env
    _write(tree / "a.txt"), _write(tree / "b.txt")
    fs = _NoChecksumFS()
    stats = CAS.RebuildStats()
    assert _rebuild(tree, db, fs=fs, read_missing=True, stats=stats) == 2
    assert stats.read == 2
    [group] = CAS.duplicates(db)
    assert group[0].value == hashlib.sha256(b"same content\n").hexdigest()


def test_happy_a_file_of_a_unique_size_is_never_read(env):
    tree, db = env
    _write(tree / "a.txt"), _write(tree / "b.txt"), _write(tree / "odd.txt", b"other size")
    fs = _NoChecksumFS()
    stats = CAS.RebuildStats()
    _rebuild(tree, db, fs=fs, read_missing=True, stats=stats)
    assert fs.bytes_read("odd.txt") == 0
    assert stats.unique_size == 1


def test_happy_same_size_files_that_differ_early_are_not_read_to_the_end(env):
    tree, db = env
    size = 3 * CAS.PARTIAL_BYTES
    _write(tree / "x.bin", b"A" + b"0" * (size - 1))
    _write(tree / "y.bin", b"B" + b"0" * (size - 1))
    _write(tree / "p.bin", b"P" * size), _write(tree / "q.bin", b"P" * size)
    fs = _NoChecksumFS()
    _rebuild(tree, db, fs=fs, read_missing=True)
    assert fs.bytes_read("x.bin") == CAS.PARTIAL_BYTES
    assert fs.bytes_read("y.bin") == CAS.PARTIAL_BYTES
    assert fs.bytes_read("p.bin") == CAS.PARTIAL_BYTES + size  # head, then all of it
    assert _paths(CAS.duplicates(db)) == [[str(tree / "p.bin"), str(tree / "q.bin")]]


def test_edge_a_size_already_in_the_index_is_read_to_pair_across_scans(tmp_path):
    db = tmp_path / "cas.sqlite"
    local = _write(tmp_path / "local" / "photo.jpg", b"J" * 5000)
    CAS.rebuild(LocalFS(), str(tmp_path / "local"), backend_id=BID, db_path=db)
    share = _write(tmp_path / "share" / "copy.jpg", b"J" * 5000)  # alone on its "share"
    CAS.rebuild(_NoChecksumFS(), str(tmp_path / "share"), backend_id="SMB:nas",
                db_path=db, read_missing=True)
    assert _paths(CAS.duplicates(db)) == [[str(local), str(share)]]


def test_sad_without_read_missing_nothing_is_read(env):
    tree, db = env
    _write(tree / "a.txt"), _write(tree / "b.txt")
    fs = _NoChecksumFS()
    stats = CAS.RebuildStats()
    assert _rebuild(tree, db, fs=fs, stats=stats) == 0
    assert fs.reads == [] and stats.no_checksum == 2


def test_sad_cancel_stops_reading_mid_file(env):
    tree, db = env
    size = 4 * CAS.READ_CHUNK
    _write(tree / "a.bin", b"Z" * size), _write(tree / "b.bin", b"Z" * size)
    fs = _NoChecksumFS()
    stop = threading.Event()
    real = fs.open_read

    def open_read(path):
        fh = real(path)
        original = fh.read

        def read(n=-1):
            if fs.bytes_read(".bin") >= CAS.PARTIAL_BYTES * 2 + CAS.READ_CHUNK:
                stop.set()
            return original(n)

        fh.read = read
        return fh

    fs.open_read = open_read
    count = _rebuild(tree, db, fs=fs, read_missing=True, cancel=stop.is_set)
    assert count == 0
    assert fs.bytes_read(".bin") < 2 * size
    assert CAS.list_scans(db)[0].status == CAS.SCAN_CANCELLED


def test_edge_an_unreadable_file_in_the_read_phase_is_reported(env):
    tree, db = env
    _write(tree / "a.txt"), _write(tree / "b.txt")
    fs = _NoChecksumFS()
    real = fs.open_read
    fs.open_read = lambda p: (_ for _ in ()).throw(PermissionError(13, "Permission denied")) \
        if p.endswith("b.txt") else real(p)
    stats = CAS.RebuildStats()
    _rebuild(tree, db, fs=fs, read_missing=True, stats=stats)
    assert stats.unreadable_count == 1 and stats.read == 1


# --------------------------------------------------------------------------
# Keep rules
# --------------------------------------------------------------------------


def _entries(*specs):
    """``(path, mtime[, file_id])`` -> one group of CasEntry rows."""
    out = []
    for spec in specs:
        path, mtime, *fid = spec
        out.append(CAS.CasEntry(BID, path, "sha256", "v", 10, indexed_at=None, mtime=mtime,
                                file_id=fid[0] if fid else None))
    return CAS.order_by_survivor(out)


GROUP = _entries(("/data/photos/a.jpg", 100.0), ("/backup/a.jpg", 300.0),
                 ("/downloads/very/deep/a.jpg", 200.0))


def _marked(rule, folder=None, groups=(GROUP,)):
    return sorted(e.path for e in CAS.mark_duplicates(list(groups), rule, folder).marked)


def test_happy_keep_rules_choose_the_kept_copy():
    assert _marked("oldest") == ["/backup/a.jpg", "/downloads/very/deep/a.jpg"]
    assert _marked("newest") == ["/data/photos/a.jpg", "/downloads/very/deep/a.jpg"]
    assert _marked("shortest-path") == ["/data/photos/a.jpg", "/downloads/very/deep/a.jpg"]
    assert _marked("keep-in-folder", "/downloads") == ["/backup/a.jpg", "/data/photos/a.jpg"]
    assert _marked("mark-in-folder", "/downloads") == ["/downloads/very/deep/a.jpg"]


def test_sad_a_group_entirely_inside_the_folder_still_keeps_one():
    inside = _entries(("/dl/a", 5.0), ("/dl/b", 1.0))
    result = CAS.mark_duplicates([inside], "mark-in-folder", "/dl")
    assert [e.path for e in result.marked] == ["/dl/a"]  # the oldest, /dl/b, stays
    assert [e.path for e in result.kept] == ["/dl/b"]


def test_sad_groups_without_a_copy_in_the_folder_are_left_alone():
    result = CAS.mark_duplicates([GROUP], "keep-in-folder", "/elsewhere")
    assert (result.marked, result.untouched) == ([], 1)


def test_sad_unknown_rules_and_missing_folders_are_refused():
    with pytest.raises(ValueError):
        CAS.mark_duplicates([GROUP], "largest")
    with pytest.raises(ValueError):
        CAS.mark_duplicates([GROUP], "keep-in-folder")


def test_edge_folder_rules_match_whole_components():
    group = _entries(("/data2/x", 1.0), ("/data/x", 2.0))
    assert _marked("mark-in-folder", "/data", [group]) == ["/data/x"]
    assert _marked("mark-in-folder", "/data/", [group]) == ["/data/x"]


def test_edge_newest_with_undated_copies_prefers_a_dated_one():
    group = _entries(("/a", None), ("/b", 50.0), ("/c", 10.0))
    assert _marked("newest", groups=[group]) == ["/a", "/c"]


def test_edge_a_hard_link_of_the_kept_copy_is_never_marked():
    group = _entries(("/a", 1.0, "1:7"), ("/a-link", 1.0, "1:7"), ("/b", 2.0, "1:8"))
    assert _marked("oldest", groups=[group]) == ["/b"]
    assert CAS.reclaimable_bytes(group) == 10


def test_edge_every_rule_keeps_one_copy_per_group():
    groups = [GROUP, _entries(("/dl/a", 5.0), ("/dl/b", 1.0)), _entries(("/x", 1.0), ("/y", 1.0))]
    for rule in CAS.MARK_RULES:
        folder = "/dl" if "folder" in rule else None
        marked = {e.path for e in CAS.mark_duplicates(groups, rule, folder).marked}
        for group in groups:
            assert any(e.path not in marked for e in group), (rule, group)
