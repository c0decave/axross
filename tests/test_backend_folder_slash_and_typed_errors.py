"""A destination ending in "/" names a folder; errors say what went wrong.

Found by tests/test_backend_conformance.py, fixed in its backends; these
are the cases the conformance matrix does not hold exactly:

* ``rename(file, "x/")`` renamed the file to ``x`` on RamFS, SQLite,
  Telnet, rsh, the NFS mount, iSCSI and NFS in user space: each one's
  path handling (normpath, a kernel path join, the NFS path split)
  dropped the slash. It is IsADirectoryError now, through the one
  helper ``core.path_policy.refuse_folder_path`` (the file-write twin is
  in the conformance suite). A folder renamed to ``x/`` still moves, as
  rename(2) allows.
* RamFS and SQLite (core.db_fs_base) answered every refusal - missing,
  a file where a folder was meant, a folder where a file was meant, an
  existing destination - with a plain OSError; callers that need "not
  there" or "already there" could not tell them from "cannot tell".
* The NFS mount's list_dir wrapped the kernel's FileNotFoundError /
  NotADirectoryError in a plain OSError.
* Azure Blob's list_dir answered [] for a FILE name; only an empty Data
  Lake folder (its placeholder blob alone) is an empty listing.
"""

from __future__ import annotations

import errno
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.path_policy import refuse_folder_path  # noqa: E402
from tests.test_backend_conformance import MAKERS, Target  # noqa: E402

#: The backends whose path handling dropped the slash of a destination.
SLASH_DROPPERS = ["ramfs", "sqlite", "telnet", "rsh", "nfs", "iscsi", "nfs_user_v3",
                  "nfs_user_v4"]


def _seeded(name: str, tmp_path) -> Target:
    t = MAKERS[name](tmp_path)
    b = t.backend
    b.mkdir(t.J("d"))
    b.mkdir(t.J("d", "sub"))
    with b.open_write(t.J("g")) as fh:
        fh.write(b"other")
    return t


@pytest.fixture
def make(tmp_path):
    made: list[Target] = []

    def build(name: str) -> Target:
        home = tmp_path / name
        home.mkdir()
        made.append(_seeded(name, home))
        return made[-1]

    yield build
    for t in made:
        for done in t.cleanup:
            try:
                done()
            except Exception:  # noqa: BLE001 - cleanup only
                pass


def _files(t: Target) -> set[str]:
    return {i.name for i in t.backend.list_dir(t.root) if not i.is_dir}


# -- the helper ----------------------------------------------------------------


def test_happy_the_helper_passes_a_file_path_and_the_root():
    """refuse_folder_path is what every backend's write and rename call."""
    assert refuse_folder_path("/a/b") == "/a/b"
    assert refuse_folder_path("/") == "/"
    assert refuse_folder_path("") == ""


def test_sad_the_helper_refuses_a_path_ending_in_a_slash():
    with pytest.raises(IsADirectoryError) as caught:
        refuse_folder_path("/a/b/", "rename to")
    assert caught.value.errno == errno.EISDIR
    assert "rename to /a/b/" in str(caught.value)


def test_edge_a_rename_refuses_only_a_file_source():
    """A folder (or a missing source, whose rename says so itself) may
    take a slash; the source is asked only for such a path."""
    asked = []
    assert refuse_folder_path("/x/", "rename to", source_is_file=lambda: False) == "/x/"
    assert refuse_folder_path("/x", "rename to", source_is_file=lambda: asked.append(1)) == "/x"
    assert asked == []
    with pytest.raises(IsADirectoryError):
        refuse_folder_path("/x/", "rename to", source_is_file=lambda: True)


# -- rename to a path ending in "/" ----------------------------------------------


@pytest.mark.parametrize("name", SLASH_DROPPERS)
def test_sad_a_file_renamed_to_a_path_ending_in_a_slash_is_refused(make, name):
    """Was: the file "g" renamed to a FILE "t". A folder still moves."""
    t = make(name)
    b = t.backend
    with pytest.raises(IsADirectoryError):
        b.rename(t.J("g"), t.J("t") + "/")
    assert "t" not in _files(t)
    with b.open_read(t.J("g")) as fh:
        assert fh.read() == b"other"
    b.rename(t.J("d"), t.J("e") + "/")
    assert b.is_dir(t.J("e", "sub")) and not b.exists(t.J("d"))


# -- RamFS and SQLite say which error --------------------------------------------


@pytest.mark.parametrize("name", ["ramfs", "sqlite"])
def test_sad_ramfs_and_sqlite_refusals_are_typed(make, name):
    """Was: a plain OSError for each of these."""
    t = make(name)
    b, J = t.backend, t.J
    with pytest.raises(FileNotFoundError):
        b.list_dir(J("nope"))
    with pytest.raises(NotADirectoryError):
        b.list_dir(J("g"))
    with pytest.raises(FileNotFoundError):
        b.open_read(J("nope"))
    with pytest.raises(IsADirectoryError):
        b.open_read(J("d"))
    with pytest.raises(IsADirectoryError):
        b.open_write(J("d"))
    with pytest.raises(NotADirectoryError):
        b.open_write(J("g", "x"))
    with pytest.raises(FileNotFoundError):
        b.rename(J("nope"), J("n2"))
    with pytest.raises(FileNotFoundError):
        b.rename(J("nope"), J("n2") + "/")
    with pytest.raises(FileExistsError):
        b.rename(J("g"), J("d"))
    with pytest.raises(FileNotFoundError):
        b.mkdir(J("missing", "x"))
    with pytest.raises(FileNotFoundError):
        b.chmod(J("nope"), 0o600)
    with pytest.raises(OSError) as caught:
        b.remove(J("d"), recursive=False)
    assert caught.value.errno == errno.ENOTEMPTY


@pytest.mark.parametrize("name", ["ramfs", "sqlite"])
def test_edge_a_folder_into_itself_stays_einval(make, name):
    """The refusal it always was, now with its errno (rename(2): EINVAL)."""
    t = make(name)
    with pytest.raises(OSError) as caught:
        t.backend.rename(t.J("d"), t.J("d", "sub", "d"))
    assert caught.value.errno == errno.EINVAL
    assert t.backend.is_dir(t.J("d", "sub"))


# -- NFS mount listing -----------------------------------------------------------


def test_sad_the_nfs_mount_listing_keeps_the_kernels_error(make):
    """Was: FileNotFoundError / NotADirectoryError wrapped in an OSError."""
    t = make("nfs")
    with pytest.raises(FileNotFoundError, match="Cannot list"):
        t.backend.list_dir(t.J("nope"))
    with pytest.raises(NotADirectoryError):
        t.backend.list_dir(t.J("g"))


# -- Azure Blob: an empty Data Lake folder versus a file --------------------------


def test_edge_azure_lists_an_empty_data_lake_folder_but_not_a_file(make):
    """A hierarchical-namespace folder with nothing in it is only its
    placeholder blob (metadata hdi_isfolder=true): nothing lies under its
    prefix, as under a file's name. The first lists empty, the second is
    NotADirectoryError (was: [] for both)."""
    t = make("azure_blob")
    store = t.backend._container
    store.blobs["empty"] = (b"", datetime.now(timezone.utc))
    plain_props = store._props

    def props(name):
        p = plain_props(name)
        if name == "empty":
            p.metadata = {"hdi_isfolder": "true"}
        return p

    store._props = props
    assert t.backend.list_dir("/empty") == []
    with pytest.raises(NotADirectoryError):
        t.backend.list_dir("/g")
    with pytest.raises(FileNotFoundError):
        t.backend.list_dir("/nope")
