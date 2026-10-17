"""Azure Blob on a hierarchical-namespace (Data Lake) account: remove()
deletes the folder's placeholder blob.

Such an account keeps every folder as a 0-byte blob "x" with metadata
hdi_isfolder=true. remove() only knew the "x/" marker of a flat
account: recursive=True deleted the blobs under "x/" and left the
placeholder, so the folder stayed in the listing; recursive=False on an
empty folder deleted the non-existent "x/" and failed with BlobNotFound.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

azure_exceptions = pytest.importorskip("azure.core.exceptions")

from test_object_store_file_beside_a_same_named_folder import _azure  # noqa: E402

FOLDER = {"hdi_isfolder": "true"}


def test_happy_recursive_remove_deletes_children_and_placeholder():
    names = ["logs", "logs/a.txt", "logs/b.txt", "keep.txt"]
    sess, store = _azure(names, {"logs": FOLDER})
    sess.remove("/logs", recursive=True)
    assert sorted(store) == ["keep.txt"]
    assert sess.exists("/logs") is False


def test_happy_non_recursive_remove_of_an_empty_folder_deletes_the_placeholder():
    sess, store = _azure(["empty", "keep.txt"], {"empty": FOLDER})
    sess.remove("/empty", recursive=False)
    assert sorted(store) == ["keep.txt"]


def test_sad_non_recursive_remove_of_a_full_folder_is_refused():
    names = ["logs", "logs/a.txt"]
    sess, store = _azure(names, {"logs": FOLDER})
    with pytest.raises(OSError) as info:
        sess.remove("/logs", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert sorted(store) == names


def test_sad_a_failing_placeholder_probe_deletes_nothing():
    names = ["logs", "logs/a.txt"]
    sess, store = _azure(names, {"logs": FOLDER})
    original = sess._container.get_blob_client

    def failing(name):
        client = original(name)
        if name == "logs":

            def props():
                raise azure_exceptions.HttpResponseError("503 ServerBusy")

            client.get_blob_properties = props
        return client

    sess._container.get_blob_client = failing
    with pytest.raises(OSError):
        sess.remove("/logs", recursive=True)
    assert sorted(store) == names


def test_edge_nested_data_lake_folders_go_with_their_parent():
    names = ["logs", "logs/sub", "logs/sub/a.txt"]
    sess, store = _azure(names, {"logs": FOLDER, "logs/sub": FOLDER})
    sess.remove("/logs", recursive=True)
    assert store == {}


def test_edge_a_flat_account_folder_is_removed_as_before():
    sess, store = _azure(["dir/", "dir/a.txt"])
    sess.remove("/dir", recursive=True)
    assert store == {}
