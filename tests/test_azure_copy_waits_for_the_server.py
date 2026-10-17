"""Azure copy() returns when the server-side copy is done, not when it started.

``start_copy_from_url`` only starts a copy; a large or cross-account
copy reports ``copy_status="pending"`` and finishes later, possibly as
"failed" or "aborted". AzureBlobSession.copy and AzureFilesSession.copy
returned right after the start, so a caller read or deleted the source
while the destination was incomplete, and a failed copy went unnoticed
(rename already waited via _wait_for_copy). AzureFilesSession.copy and
checksum also called a ``_split`` helper that did not exist, so both
always failed. Fake clients, no network.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("azure.storage.blob")

from core import azure_client  # noqa: E402
from core.azure_client import AzureBlobSession, AzureFilesSession  # noqa: E402


class _Copyable:
    """A blob / file client whose copy runs through *states*."""

    def __init__(self, name: str, states: list[str]) -> None:
        self.name, self.url = name, "mem://" + name
        self.states = list(states)
        self.polls = 0

    def start_copy_from_url(self, url):
        return {"copy_status": self.states[0] if self.states else "success"}

    def _props(self):
        self.polls += 1
        status = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return SimpleNamespace(copy=SimpleNamespace(status=status, status_description="why"))

    get_blob_properties = _props
    get_file_properties = _props


def _blob(states):
    s = object.__new__(AzureBlobSession)
    dst = _Copyable("dst", states)
    s._container = SimpleNamespace(
        get_blob_client=lambda name: dst if name == "dst" else _Copyable(name, ["success"])
    )
    s._to_key = lambda p: p.strip("/")
    return s, dst


def _files(states):
    s = object.__new__(AzureFilesSession)
    dst = _Copyable("dst", states)
    s._share = SimpleNamespace(
        get_directory_client=lambda parent: SimpleNamespace(
            get_file_client=lambda name: dst if name == "dst" else _Copyable(name, ["success"])
        )
    )
    return s, dst


def test_happy_files_split_names_parent_and_file():
    # copy() and checksum() called a _split that did not exist.
    s = object.__new__(AzureFilesSession)
    assert s._split("/a/b/c.txt") == ("a/b", "c.txt")
    assert s._split("/c.txt") == ("", "c.txt")


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(azure_client.time, "sleep", lambda s: None)


@pytest.mark.parametrize("make", [_blob, _files], ids=["blob", "files"])
def test_happy_pending_copy_is_waited_for(make):
    s, dst = make(["pending", "pending", "success"])
    s.copy("/src", "/dst")
    assert dst.polls >= 2 and dst.states == ["success"]


@pytest.mark.parametrize("make", [_blob, _files], ids=["blob", "files"])
@pytest.mark.parametrize("final", ["failed", "aborted"])
def test_sad_failed_copy_is_an_oserror(make, final):
    s, _dst = make(["pending", final])
    with pytest.raises(OSError, match=f"status '{final}'"):
        s.copy("/src", "/dst")


@pytest.mark.parametrize("make", [_blob, _files], ids=["blob", "files"])
def test_edge_copy_that_never_finishes_times_out(make, monkeypatch):
    s, _dst = make(["pending"])
    clock = iter(range(0, 10_000, 100))
    monkeypatch.setattr(azure_client.time, "monotonic", lambda: next(clock))
    with pytest.raises(OSError, match="timed out"):
        s.copy("/src", "/dst")
