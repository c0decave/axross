"""Dropbox: a retry after a 5xx that finds the work done; Paper documents.

Round 6 found:

* _GuardedDropbox retried files/move_v2 and files/delete_v2 after a 5xx -
  which a gateway may send after the backend did the work - and the retry
  then failed "not found": a move or delete that succeeded was reported
  as failed (the OneDrive DELETE had the same, fixed in round 5);
* Cancel during the retry pause after a 5xx on the final upload request
  reported the destination untouched (UploadCancelled) although that
  request had committed the file - so nothing was rolled back;
* a Dropbox Paper document could not be read at all ("unsupported_file"
  as a bare EIO).
"""

from __future__ import annotations

import errno
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dropbox")
import dropbox.files as F  # noqa: E402
import fake_dropbox  # noqa: E402
from dropbox.exceptions import InternalServerError  # noqa: E402

from core import cloud_http, transfer_hooks  # noqa: E402


@pytest.fixture
def dbx(monkeypatch):
    monkeypatch.setattr(cloud_http, "_sleep", lambda _s: None)
    fx = fake_dropbox.FakeDropbox()
    s = fake_dropbox.make_session(fx)
    with s.open_write("/a.txt") as fh:
        fh.write(b"data")
    return fx, s


def _5xx():
    return InternalServerError("req", 503, "Service Unavailable")


def _done_then_5xx(monkeypatch, fx, route: str) -> None:
    """*route* does its work, then the gateway answers 503 (once)."""
    real = getattr(fx, route)
    state = {"first": True}

    def flaky(*args, **kwargs):
        result = real(*args, **kwargs)
        if state["first"]:
            state["first"] = False
            raise _5xx()
        return result

    monkeypatch.setattr(fx, route, flaky)


def test_sad_a_move_done_before_its_5xx_is_not_reported_not_found(dbx, monkeypatch):
    fx, s = dbx
    _done_then_5xx(monkeypatch, fx, "files_move_v2")
    s.rename("/a.txt", "/b.txt")  # was FileNotFoundError (from_lookup/not_found)
    assert s.exists("/b.txt") and not s.exists("/a.txt")


def test_sad_a_delete_done_before_its_5xx_is_not_reported_not_found(dbx, monkeypatch):
    fx, s = dbx
    _done_then_5xx(monkeypatch, fx, "files_delete_v2")
    s.remove("/a.txt")  # was FileNotFoundError (path_lookup/not_found)
    assert not s.exists("/a.txt")


def test_happy_a_5xx_that_did_nothing_is_retried(dbx, monkeypatch):
    fx, s = dbx
    real = fx.files_move_v2
    calls = []

    def first_fails(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise _5xx()
        return real(*args, **kwargs)

    monkeypatch.setattr(fx, "files_move_v2", first_fails)
    s.rename("/a.txt", "/b.txt")
    assert len(calls) == 2 and s.exists("/b.txt")


def test_edge_a_real_not_found_after_a_5xx_stays_not_found(dbx, monkeypatch):
    fx, s = dbx
    real = fx.files_move_v2
    calls = []

    def first_fails(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise _5xx()
        return real(*args, **kwargs)

    monkeypatch.setattr(fx, "files_move_v2", first_fails)
    with pytest.raises(FileNotFoundError):
        s.rename("/missing.txt", "/b.txt")  # the destination is not there either


def _cancel_in_the_pause(monkeypatch, cancel: threading.Event) -> None:
    """Cancel is pressed while the retry after the 5xx waits."""
    def pause(attempt, retry_after=None):
        cancel.set()
        transfer_hooks.check()

    monkeypatch.setattr(cloud_http, "pause", pause)


def test_edge_cancel_after_a_committing_5xx_is_no_untouched_report(dbx, monkeypatch):
    fx, s = dbx
    _done_then_5xx(monkeypatch, fx, "files_upload")
    cancel = threading.Event()
    _cancel_in_the_pause(monkeypatch, cancel)
    with transfer_hooks.active(transfer_hooks.TransferHooks(cancel)):
        fh = s.open_write("/new.txt")
        fh.write(b"new content")
        with pytest.raises(InterruptedError) as info:
            fh.close()
    # The file landed: a plain InterruptedError lets the engine roll back.
    assert not isinstance(info.value, transfer_hooks.UploadCancelled)  # was UploadCancelled
    assert s.open_read("/new.txt").read() == b"new content"


def test_edge_cancel_after_a_5xx_that_committed_nothing_is_untouched(dbx, monkeypatch):
    fx, s = dbx

    def refuse(*args, **kwargs):
        raise _5xx()

    monkeypatch.setattr(fx, "files_upload", refuse)
    cancel = threading.Event()
    _cancel_in_the_pause(monkeypatch, cancel)
    with transfer_hooks.active(transfer_hooks.TransferHooks(cancel)):
        fh = s.open_write("/a.txt")
        fh.write(b"other")
        with pytest.raises(transfer_hooks.UploadCancelled):
            fh.close()
    assert s.open_read("/a.txt").read() == b"data"


def test_happy_a_paper_document_is_read_as_its_export(dbx, monkeypatch):
    fx, s = dbx

    def unsupported(path, rev=None):
        raise fake_dropbox._err(F.DownloadError.unsupported_file)

    monkeypatch.setattr(fx, "files_download", unsupported)
    monkeypatch.setattr(
        fx, "files_export", lambda path, export_format=None: (None, fake_dropbox._Resp(b"# Notes\n")),
        raising=False,
    )
    assert s.open_read("/Notes.paper").read() == b"# Notes\n"  # was EIO


def test_sad_a_paper_document_without_an_export_says_so(dbx, monkeypatch):
    fx, s = dbx

    def unsupported(path, rev=None):
        raise fake_dropbox._err(F.DownloadError.unsupported_file)

    def no_export(path, export_format=None):
        raise fake_dropbox._err(F.ExportError.non_exportable)

    monkeypatch.setattr(fx, "files_download", unsupported)
    monkeypatch.setattr(fx, "files_export", no_export, raising=False)
    with pytest.raises(OSError) as info:
        s.open_read("/Notes.paper")
    assert info.value.errno == errno.EOPNOTSUPP
    assert "Paper document" in str(info.value)
