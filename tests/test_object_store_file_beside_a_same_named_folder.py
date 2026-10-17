"""S3 / Azure Blob: an object ``X`` and a prefix ``X/`` side by side.

An object store allows a file ``logs`` next to the objects under
``logs/``; the listing shows a file and a folder, both named ``logs``.
remove() and rename() asked is_dir() (does the prefix exist?) and so
treated the FILE as the folder: deleting the file (recursive=False, as
the pane passes for a file) deleted the folder's marker - a silent no-op
- and renaming it moved the folder tree and left the file behind.

Now remove(recursive=False) deletes the file when one exists beside the
folder (recursive=True still removes the folder), and rename() refuses a
name that is both, instead of guessing which one the caller meant.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.azure_client import AzureBlobSession
from core.s3_client import S3Session

botocore_exceptions = pytest.importorskip("botocore.exceptions")
azure_exceptions = pytest.importorskip("azure.core.exceptions")


# -- in-memory S3 ------------------------------------------------------------


class _S3:
    def __init__(self, keys, *, head_error: str | None = None):
        self.objects = {k: b"data-" + k.encode() for k in keys}
        self.head_error = head_error

    def list_objects_v2(self, Bucket, Prefix="", Delimiter=None, MaxKeys=1000, **kw):
        keys = sorted(k for k in self.objects if k.startswith(Prefix))
        contents, prefixes = [], []
        for k in keys:
            rest = k[len(Prefix) :]
            if Delimiter and Delimiter in rest:
                p = Prefix + rest.split(Delimiter)[0] + Delimiter
                if {"Prefix": p} not in prefixes:
                    prefixes.append({"Prefix": p})
            else:
                contents.append({"Key": k, "Size": len(self.objects[k])})
        contents = contents[:MaxKeys]
        out = {"Contents": contents, "KeyCount": len(contents) + len(prefixes)}
        if prefixes:
            out["CommonPrefixes"] = prefixes
        return out

    def get_paginator(self, name):
        s3 = self

        class _P:
            def paginate(self, **kw):
                yield s3.list_objects_v2(**kw)

        return _P()

    def head_object(self, Bucket, Key):
        if self.head_error:
            raise botocore_exceptions.ClientError(
                {"Error": {"Code": self.head_error}}, "HeadObject"
            )
        if Key not in self.objects:
            raise botocore_exceptions.ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": len(self.objects[Key])}

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)

    def delete_objects(self, Bucket, Delete):
        for o in Delete["Objects"]:
            self.objects.pop(o["Key"], None)

    def copy_object(self, Bucket, CopySource, Key):
        self.objects[Key] = self.objects[CopySource["Key"]]


def _s3(keys, **kw):
    s = object.__new__(S3Session)
    s._s3 = _S3(keys, **kw)
    s._bucket = "b"
    s._anonymous = False
    return s, s._s3.objects


# -- in-memory Azure Blob ----------------------------------------------------


class _Pages:
    def __init__(self, items):
        self._pages = iter([items])
        self.continuation_token = None

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._pages)


class _Paged:
    def __init__(self, items):
        self.items = items

    def by_page(self):
        return _Pages(self.items)

    def __iter__(self):
        return iter(self.items)


class _BlobClient:
    def __init__(self, store, name):
        self.store, self.name = store, name
        self.url = "mem://" + name

    def get_blob_properties(self):
        if self.name not in self.store.blobs:
            raise azure_exceptions.ResourceNotFoundError("BlobNotFound")
        return SimpleNamespace(
            metadata=self.store.meta.get(self.name, {}),
            copy=SimpleNamespace(status="success", status_description=""),
        )

    def delete_blob(self):
        if self.name not in self.store.blobs:
            raise azure_exceptions.ResourceNotFoundError("BlobNotFound")
        del self.store.blobs[self.name]

    def start_copy_from_url(self, url):
        source = url[len("mem://") :]
        self.store.blobs[self.name] = self.store.blobs[source]
        # Copy Blob without metadata= carries the source's metadata (SDK).
        if source in self.store.meta:
            self.store.meta[self.name] = dict(self.store.meta[source])
        else:
            self.store.meta.pop(self.name, None)


class _Container:
    def __init__(self, names, meta=None):
        self.blobs = {n: b"data-" + n.encode() for n in names}
        self.meta = meta or {}

    def get_blob_client(self, name):
        return _BlobClient(self, name)

    def delete_blob(self, name):
        _BlobClient(self, name).delete_blob()

    def delete_blobs(self, *names):
        for name in names:
            self.delete_blob(name)

    def list_blobs(self, name_starts_with="", **kw):
        return _Paged(
            [SimpleNamespace(name=n) for n in sorted(self.blobs) if n.startswith(name_starts_with)]
        )


def _azure(names, meta=None):
    s = object.__new__(AzureBlobSession)
    s._container = _Container(names, meta)
    return s, s._container.blobs


MAKERS = {"s3": _s3, "azure_blob": _azure}
BOTH = ["logs", "logs/2026-01.txt", "logs/2026-02.txt"]


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_removing_the_file_deletes_only_the_file(maker):
    sess, store = MAKERS[maker](BOTH)
    sess.remove("/logs", recursive=False)
    assert sorted(store) == ["logs/2026-01.txt", "logs/2026-02.txt"]


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_removing_the_folder_keeps_the_file(maker):
    sess, store = MAKERS[maker](BOTH)
    sess.remove("/logs", recursive=True)
    assert sorted(store) == ["logs"]


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_a_plain_file_and_a_plain_folder_rename_as_before(maker):
    sess, store = MAKERS[maker](["a.txt", "dir/x.txt"])
    sess.rename("/a.txt", "/b.txt")
    sess.rename("/dir", "/moved")
    assert sorted(store) == ["b.txt", "moved/x.txt"]


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_sad_renaming_a_name_that_is_both_is_refused_and_moves_nothing(maker):
    sess, store = MAKERS[maker](BOTH)
    with pytest.raises(OSError, match="both a file and a folder"):
        sess.rename("/logs", "/logs.old")
    assert sorted(store) == sorted(BOTH)


def test_sad_s3_a_head_error_other_than_404_is_not_taken_for_absent():
    sess, store = _s3(BOTH, head_error="403")
    with pytest.raises(OSError):
        sess.remove("/logs", recursive=False)
    assert sorted(store) == sorted(BOTH)


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_a_folder_marker_alone_is_still_removed_non_recursively(maker):
    sess, store = MAKERS[maker](["empty/", "keep.txt"])
    sess.remove("/empty", recursive=False)
    assert sorted(store) == ["keep.txt"]


def test_edge_azure_a_data_lake_folder_placeholder_is_the_folder_not_a_file():
    meta = {"logs": {"hdi_isfolder": "true"}}
    sess, store = _azure(BOTH, meta)
    sess.rename("/logs", "/moved")
    # The placeholder moves with the folder (it stayed behind before).
    assert sorted(store) == ["moved", "moved/2026-01.txt", "moved/2026-02.txt"]


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_a_file_only_name_is_removed_without_a_prefix(maker):
    sess, store = MAKERS[maker](["logs", "logsX/a"])
    sess.remove("/logs", recursive=False)
    assert sorted(store) == ["logsX/a"]
