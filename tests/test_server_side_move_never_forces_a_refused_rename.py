"""server_side_move: a refused rename is never forced by copy+delete.

``_rename_fallback_allowed`` let every error through to the copy+delete
fallback when the backend declares ``can_rename=False``. On S3 and Azure
Blob, rename() itself is copy+delete and refuses a name that is both a
file and a folder ("logs" and "logs/..."): the fallback then copied and
deleted the FILE and reported success. Now the fallback never runs where
rename() already is copy+delete (``rename_is_copy_delete`` in the caps),
nor for an errno-carrying refusal (EEXIST, EISDIR, ...) on any backend.
"""

from __future__ import annotations

import errno

import pytest

from core.server_ops import _rename_fallback_allowed, server_side_move
from tests.test_object_store_file_beside_a_same_named_folder import MAKERS

BOTH = ["logs", "logs/2026-01.txt", "logs/2026-02.txt"]


class _NoRename:
    """A backend whose rename() is unsupported: the fallback is for it."""


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_a_plain_file_still_moves(maker):
    sess, store = MAKERS[maker](["a.txt"])
    server_side_move(sess, "/a.txt", "/b.txt")
    assert sorted(store) == ["b.txt"]


def test_happy_an_unsupported_rename_still_falls_back():
    assert _rename_fallback_allowed(_NoRename(), NotImplementedError())
    assert _rename_fallback_allowed(_NoRename(), OSError("TFTP does not support rename."))
    assert _rename_fallback_allowed(_NoRename(), OSError(errno.EOPNOTSUPP, "no rename"))


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_sad_an_ambiguous_name_is_not_moved_by_the_fallback(maker):
    sess, store = MAKERS[maker](BOTH)
    with pytest.raises(OSError, match="both a file and a folder"):
        server_side_move(sess, "/logs", "/archive")
    assert sorted(store) == sorted(BOTH)


@pytest.mark.parametrize(
    "exc",
    [
        FileExistsError(errno.EEXIST, "exists"),
        IsADirectoryError(errno.EISDIR, "folder"),
        PermissionError(errno.EACCES, "denied"),
        FileNotFoundError(errno.ENOENT, "gone"),
    ],
    ids=["EEXIST", "EISDIR", "EACCES", "ENOENT"],
)
def test_sad_an_errno_refusal_never_falls_back(exc):
    sess, _ = MAKERS["s3"](["a.txt"])
    assert not _rename_fallback_allowed(sess, exc)
    # Not even on a backend that declares no rename at all.
    assert not _rename_fallback_allowed(_NoRename(), exc)


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_a_trailing_slash_destination_is_refused_not_forced(maker):
    sess, store = MAKERS[maker](["report.txt"])
    with pytest.raises(IsADirectoryError):
        server_side_move(sess, "/report.txt", "/archive/")
    assert sorted(store) == ["report.txt"]
