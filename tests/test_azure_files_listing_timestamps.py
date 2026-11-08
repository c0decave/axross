"""Azure Files listings carry the files' modification times.

What was wrong: list_dir called list_directories_and_files() without
``include=["timestamps"]``. The service sends Last-Modified only when it is
asked for (API 2020-04-08 and later), so every file listed as 1970, and
"overwrite if newer" from Azure Files skipped every changed file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("azure.storage.fileshare")

from core import azure_client as AC  # noqa: E402

WHEN = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)


class _Dir:
    """What the SDK yields: the times only with include=["timestamps"]."""

    def __init__(self, *, old_sdk: bool = False) -> None:
        self.old_sdk = old_sdk
        self.calls: list[dict] = []

    def list_directories_and_files(self, **kw):
        self.calls.append(kw)
        if self.old_sdk and "include" in kw:
            raise TypeError("list_directories_and_files() got an unexpected keyword 'include'")
        timestamps = "timestamps" in (kw.get("include") or [])
        return [{"name": "budget.xlsx", "is_directory": False, "size": 9,
                 "last_modified": WHEN if timestamps else None}]


def _session(directory: _Dir):
    session = object.__new__(AC.AzureFilesSession)
    session._share = SimpleNamespace(get_directory_client=lambda rel: directory)
    return session


def test_sad_a_listed_file_has_its_modification_time():
    item = _session(_Dir()).list_dir("/")[0]
    assert item.modified.astimezone(timezone.utc) == WHEN


def test_edge_an_sdk_without_include_still_lists():
    """Guard (passes on the old code too): an SDK before 12.6 has no
    *include*; the listing is asked for without it."""
    directory = _Dir(old_sdk=True)
    items = _session(directory).list_dir("/")
    assert [i.name for i in items] == ["budget.xlsx"]
    assert directory.calls[-1] == {}
