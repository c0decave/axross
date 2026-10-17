"""Azure Blob on a hierarchical-namespace (Data Lake) account: rename()
moves a folder's placeholder blob with the folder.

Such an account keeps every folder as a 0-byte blob "x" with metadata
hdi_isfolder=true; that blob IS the folder (remove() deletes it last).
rename() moved only the blobs under "x/": the placeholder stayed, so the
renamed folder was still listed under its old name, and an EMPTY folder
(nothing but its placeholder) did not move at all while rename() reported
success. The placeholder is now copied first (Copy Blob carries its
metadata) and deleted last, after the folder's contents.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

azure_exceptions = pytest.importorskip("azure.core.exceptions")

from test_object_store_file_beside_a_same_named_folder import _azure  # noqa: E402

FOLDER = {"hdi_isfolder": "true"}


def _fail_copy_to(sess, target: str) -> None:
    original = sess._container.get_blob_client

    def client(name):
        c = original(name)
        if name == target:

            def copy(url):
                raise azure_exceptions.HttpResponseError("503 ServerBusy")

            c.start_copy_from_url = copy
        return c

    sess._container.get_blob_client = client


# --- happy ------------------------------------------------------------------


def test_happy_a_folder_with_files_moves_with_its_placeholder():
    sess, store = _azure(["logs", "logs/a.txt", "logs/b.txt", "keep"], {"logs": FOLDER})
    sess.rename("/logs", "/moved")
    assert sorted(store) == ["keep", "moved", "moved/a.txt", "moved/b.txt"]
    assert sess._container.meta.get("moved") == FOLDER
    assert sess.exists("/logs") is False
    assert sess.is_dir("/moved") is True


def test_happy_an_empty_folder_is_renamed():
    sess, store = _azure(["empty", "keep"], {"empty": FOLDER})
    sess.rename("/empty", "/renamed")
    assert sorted(store) == ["keep", "renamed"]
    assert sess._container.meta.get("renamed") == FOLDER
    assert sess.exists("/empty") is False
    assert sess.is_dir("/renamed") is True


# --- sad --------------------------------------------------------------------


def test_sad_a_placeholder_that_cannot_be_copied_moves_nothing():
    names = ["logs", "logs/a.txt"]
    sess, store = _azure(names, {"logs": FOLDER})
    _fail_copy_to(sess, "moved")
    with pytest.raises(OSError):
        sess.rename("/logs", "/moved")
    assert sorted(store) == names


def test_sad_a_failed_file_copy_keeps_the_source_folder():
    sess, store = _azure(["logs", "logs/a.txt", "logs/b.txt"], {"logs": FOLDER})
    _fail_copy_to(sess, "moved/b.txt")
    with pytest.raises(OSError):
        sess.rename("/logs", "/moved")
    # What was not moved is still in a folder that exists.
    assert "logs/b.txt" in store and "logs" in store
    assert sess.is_dir("/logs") is True


# --- edge -------------------------------------------------------------------


def test_edge_a_nested_data_lake_folder_keeps_its_placeholder():
    names = ["logs", "logs/sub", "logs/sub/a.txt"]
    sess, store = _azure(names, {"logs": FOLDER, "logs/sub": FOLDER})
    sess.rename("/logs", "/moved")
    assert sorted(store) == ["moved", "moved/sub", "moved/sub/a.txt"]
    assert sess._container.meta.get("moved/sub") == FOLDER


def test_edge_a_flat_account_folder_gets_no_placeholder():
    sess, store = _azure(["dir/", "dir/a.txt"])
    sess.rename("/dir", "/moved")
    assert sorted(store) == ["moved/", "moved/a.txt"]
    assert "moved" not in sess._container.meta
