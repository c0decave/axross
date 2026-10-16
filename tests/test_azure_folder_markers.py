"""Azure Data Lake folder placeholders are folders, listed once.

The anonymous Open Datasets container (azureopendatastorage/nyctlc)
listed fhv, green, yellow and _manifest twice: once as the virtual
folder of the "fhv/" prefix and once as a 0-byte file - the placeholder
blob a hierarchical-namespace account keeps for every folder, marked by
the metadata hdi_isfolder=true. stat("/fhv") called it a file, and an
empty folder (a placeholder and nothing under it) showed only as a
0-byte file. Listing now asks for metadata; a placeholder is a folder,
named once.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("azure.storage.blob")
from test_azure_hostile_answers import _blob_session  # noqa: E402
from test_fuzz_azure import _Storage, blob, listing  # noqa: E402

FOLDER_MD = b"<Metadata><hdi_isfolder>true</hdi_isfolder></Metadata>"


def placeholder(name: bytes) -> bytes:
    return blob(name, size=b"0").replace(b"</Blob>", FOLDER_MD + b"</Blob>")


class _Recording(_Storage):
    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def __call__(self, request):
        self.urls.append(request.url)
        return super().__call__(request)


@pytest.fixture
def storage():
    s = _Recording()
    s.listing = listing(
        blob(b"a.txt")
        + placeholder(b"fhv")
        + blob(b"zero", size=b"0")
        + placeholder(b"empty")
        + b"<BlobPrefix><Name>fhv/</Name></BlobPrefix>"
    )
    return s


# --- happy ----------------------------------------------------------------


def test_happy_a_placeholder_and_its_prefix_are_one_folder(storage):
    items = {i.name: i for i in _blob_session(storage).list_dir("/")}
    names = [i.name for i in _blob_session(storage).list_dir("/")]
    assert names.count("fhv") == 1 and items["fhv"].is_dir
    assert any("include=metadata" in u for u in storage.urls)


def test_happy_an_empty_folder_is_a_folder(storage):
    items = {i.name: i for i in _blob_session(storage).list_dir("/")}
    assert items["empty"].is_dir


# --- sad ------------------------------------------------------------------


def test_sad_a_real_empty_file_stays_a_file(storage):
    items = {i.name: i for i in _blob_session(storage).list_dir("/")}
    assert not items["zero"].is_dir and items["zero"].size == 0
    assert not items["a.txt"].is_dir and items["a.txt"].size == 5


# --- edge -----------------------------------------------------------------


def test_edge_stat_of_a_placeholder_is_a_folder(storage):
    storage.props = {**storage.props, "Content-Length": "0", "x-ms-meta-hdi_isfolder": "true"}
    item = _blob_session(storage).stat("/fhv")
    assert item.is_dir


def test_edge_is_dir_agrees_with_the_listing_for_an_empty_folder(storage):
    # Nothing under "empty/", only its placeholder: the listing calls it a
    # folder, so navigating into it must not be refused.
    storage.listing = listing(b"")
    storage.props = {**storage.props, "Content-Length": "0", "x-ms-meta-hdi_isfolder": "true"}
    assert _blob_session(storage).is_dir("/empty")


def test_sad_is_dir_of_a_plain_file_is_false(storage):
    storage.listing = listing(b"")
    assert not _blob_session(storage).is_dir("/a.txt")
