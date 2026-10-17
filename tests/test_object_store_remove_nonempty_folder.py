"""S3 / Azure Blob: remove(folder, recursive=False) refuses a folder with content.

The non-recursive path deleted only the folder's marker ("photos/") - or
a key that does not exist, which S3 answers with 204 as well - and
reported success, while every file under the folder was still there.
GDrive, Dropbox and OneDrive raise ENOTEMPTY for the same call; S3 and
Azure Blob now do too, and delete nothing.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_object_store_file_beside_a_same_named_folder import _azure, _s3  # noqa: E402

MAKERS = {"s3": _s3, "azure_blob": _azure}


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_an_empty_folder_marker_is_removed(maker):
    sess, store = MAKERS[maker](["photos/", "keep.txt"])
    sess.remove("/photos", recursive=False)
    assert sorted(store) == ["keep.txt"]


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_recursive_remove_still_takes_everything(maker):
    sess, store = MAKERS[maker](["photos/", "photos/a.jpg", "photos/b.jpg", "keep.txt"])
    sess.remove("/photos", recursive=True)
    assert sorted(store) == ["keep.txt"]


@pytest.mark.parametrize("maker", MAKERS)
@pytest.mark.parametrize(
    "keys",
    [["photos/", "photos/a.jpg", "photos/b.jpg"], ["photos/a.jpg", "photos/b.jpg"]],
    ids=["with-marker", "without-marker"],
)
def test_sad_a_folder_with_files_is_refused_and_kept(maker, keys):
    sess, store = MAKERS[maker](keys)
    with pytest.raises(OSError) as info:
        sess.remove("/photos", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert sorted(store) == sorted(keys)


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_an_empty_subfolder_makes_the_folder_non_empty(maker):
    keys = ["photos/", "photos/sub/"]
    sess, store = MAKERS[maker](keys)
    with pytest.raises(OSError) as info:
        sess.remove("/photos", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert sorted(store) == keys


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_a_file_beside_a_full_folder_is_still_the_target(maker):
    sess, store = MAKERS[maker](["photos", "photos/a.jpg"])
    sess.remove("/photos", recursive=False)
    assert sorted(store) == ["photos/a.jpg"]
