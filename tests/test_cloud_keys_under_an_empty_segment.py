"""S3 and Azure Blob: keys under an empty (or "." / "..") path segment
(review round 2).

The key ``a//x`` lists as the folder prefix ``a//`` under ``a``; its name
was empty and the entry was left out, so a folder copy of ``a`` was
silently incomplete. No path can name such a segment (``/a//x`` is
``/a/x`` once normalized; "." and ".." are navigation), so the entry is
listed under a name marked with a NUL character: the file pane shows it,
the transfer list refuses it visibly ("unsafe name"), and every
operation on a path through it is refused (EINVAL) - it never reaches
the parent's keys.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import azure_client as AZ  # noqa: E402
from core import s3_client as S3  # noqa: E402

MARK = "\x00"


class _Paginator:
    def __init__(self, keys):
        self.keys = keys

    def paginate(self, Bucket, Prefix, Delimiter):  # noqa: N803 - boto3's names
        folders, files = [], []
        for key in self.keys:
            if not key.startswith(Prefix):
                continue
            rest = key[len(Prefix):]
            if Delimiter in rest:
                cp = Prefix + rest[: rest.index(Delimiter) + 1]
                if {"Prefix": cp} not in folders:
                    folders.append({"Prefix": cp})
            else:
                files.append({"Key": key, "Size": 1})
        return [{"CommonPrefixes": folders, "Contents": files}]


def _s3(keys):
    s = object.__new__(S3.S3Session)
    s._bucket = "b"
    s._s3 = SimpleNamespace(get_paginator=lambda _name: _Paginator(keys))
    return s


KEYS = ["a/x", "a//hidden", "a/./dot", "a/../up", "a/..", "/rooted"]


def test_sad_s3_lists_the_empty_segment_folder() -> None:
    names = sorted(i.name for i in _s3(KEYS).list_dir("/a"))
    assert names == sorted([MARK, MARK + ".", MARK + "..", MARK + "..", "x"])


def test_sad_s3_root_lists_a_leading_slash_key() -> None:
    assert MARK in [i.name for i in _s3(KEYS).list_dir("/")]


@pytest.mark.parametrize("path", ["/a/" + MARK, "/a/" + MARK + "/hidden", "/a/" + MARK + ".."])
def test_sad_s3_a_path_through_it_is_refused(path) -> None:
    s = _s3(KEYS)
    for call in (lambda: s._to_key(path), lambda: s._to_prefix(path), lambda: s.list_dir(path)):
        with pytest.raises(OSError) as info:
            call()
        assert info.value.errno == 22


class _Blob(SimpleNamespace):
    pass


def _azure(keys):
    def walk_blobs(name_starts_with, delimiter, include):
        seen = set()
        for key in keys:
            if not key.startswith(name_starts_with):
                continue
            rest = key[len(name_starts_with):]
            if delimiter in rest:
                cp = name_starts_with + rest[: rest.index(delimiter) + 1]
                if cp not in seen:
                    seen.add(cp)
                    yield _Blob(prefix=cp)
            else:
                yield _Blob(name=key, size=1, last_modified=None, metadata={})

    s = object.__new__(AZ.AzureBlobSession)
    s._container = SimpleNamespace(walk_blobs=walk_blobs)
    s._container_name = "c"
    return s


def test_sad_azure_lists_the_empty_segment_folder() -> None:
    names = sorted(i.name for i in _azure(KEYS).list_dir("/a"))
    assert names == sorted([MARK, MARK + ".", MARK + "..", MARK + "..", "x"])


def test_sad_azure_a_path_through_it_is_refused() -> None:
    s = _azure(KEYS)
    with pytest.raises(OSError) as info:
        s._to_key("/a/" + MARK + "/hidden")
    assert info.value.errno == 22


def test_happy_the_transfer_walk_refuses_the_name_visibly() -> None:
    from core.transfer_manager import _safe_basename

    with pytest.raises(ValueError):
        _safe_basename(MARK)
