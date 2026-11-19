"""OneDrive and Google Drive: a cancelled upload is never reported
"untouched" when its last chunk may have committed; OneDrive's last
fragment must really commit.

Protocol review (round 1):

* The server committed the last chunk but its answer was lost (a
  connection error, a 5xx), and Cancel came in the retry pause: the
  writer raised UploadCancelled ("nothing committed"), so the transfer
  engine skipped putting the old file back - a cancelled overwrite lost
  the old file. Dropbox already handled it (_CancelledAfterUncertainTry).
  Now such a cancel is a plain InterruptedError (the engine rolls back).
* OneDrive took any answer below 400 to the last fragment for done - a
  202 with nextExpectedRanges too - and a resume offset past the end
  ended the loop as "done": success without a committed item.
"""

from __future__ import annotations

import io
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

import fake_onedrive  # noqa: E402
from fake_onedrive import Resp  # noqa: E402

from core import cloud_http, transfer_hooks  # noqa: E402
import core.onedrive_client as oc  # noqa: E402


@pytest.fixture
def cancel_in_pause(monkeypatch):
    cancel = threading.Event()
    monkeypatch.setattr(cloud_http, "_sleep", lambda s: cancel.set())
    return cancel


# --------------------------------------------------------------- OneDrive
class _LostFinal(fake_onedrive.FakeGraph):
    def put(self, url, headers=None, data=None, **kw):
        r = super().put(url, headers=headers, data=data, **kw)
        if url.startswith("https://upload.fake/") and r.status_code in (200, 201):
            raise requests.ConnectionError("answer lost")  # committed, answer lost
        return r


def test_sad_onedrive_cancel_after_a_lost_last_answer_is_no_upload_cancelled(cancel_in_pause):
    g = _LostFinal()
    od = fake_onedrive.make_session(g)
    with od.open_write("/doc.bin") as fh:
        fh.write(b"OLD")
    size = oc._SIMPLE_UPLOAD_MAX + 1
    hooks = transfer_hooks.TransferHooks(cancel_event=cancel_in_pause)
    with transfer_hooks.active(hooks):
        w = od.open_write("/doc.bin")
    w.write(b"N" * size)
    with pytest.raises(InterruptedError) as info:
        w.close()
    assert not isinstance(info.value, transfer_hooks.UploadCancelled)


def test_happy_onedrive_cancel_between_chunks_is_upload_cancelled(cancel_in_pause):
    od = fake_onedrive.make_session(fake_onedrive.FakeGraph())
    size = oc._UPLOAD_CHUNK * 2 + 1
    hooks = transfer_hooks.TransferHooks(cancel_event=cancel_in_pause)
    cancel_in_pause.set()
    with transfer_hooks.active(hooks):
        w = od.open_write("/big.bin")
    w.write(b"N" * size)
    with pytest.raises(transfer_hooks.UploadCancelled):
        w.close()


class _Final202(fake_onedrive.FakeGraph):
    def put(self, url, headers=None, data=None, **kw):
        if url.startswith("https://upload.fake/"):
            self.calls.append(("PUT", url, len(data)))
            return Resp(202, {"nextExpectedRanges": ["0-"]})
        return super().put(url, headers=headers, data=data, **kw)


def test_sad_onedrive_202_to_the_last_fragment_is_no_success(monkeypatch):
    monkeypatch.setattr(cloud_http, "_sleep", lambda s: None)
    od = fake_onedrive.make_session(_Final202())
    size = oc._SIMPLE_UPLOAD_MAX + 10
    with pytest.raises(OSError):
        od._upload_in_session("/big.bin", io.BytesIO(b"x" * size), size)
    assert not od.exists("/big.bin")


def test_sad_onedrive_resume_offset_past_the_end_is_no_success(monkeypatch):
    monkeypatch.setattr(cloud_http, "_sleep", lambda s: None)
    size = oc._SIMPLE_UPLOAD_MAX + 10

    class _PastEnd(fake_onedrive.FakeGraph):
        def put(self, url, headers=None, data=None, **kw):
            if url.startswith("https://upload.fake/"):
                return Resp(503, b"busy")
            return super().put(url, headers=headers, data=data, **kw)

        def get(self, url, headers=None, **kw):
            if url.startswith("https://upload.fake/S"):
                return Resp(200, {"nextExpectedRanges": [f"{size + 100}-"]})
            return super().get(url, headers=headers, **kw)

    od = fake_onedrive.make_session(_PastEnd())
    with pytest.raises(OSError):
        od._upload_in_session("/big2.bin", io.BytesIO(b"x" * size), size)


def test_happy_onedrive_session_upload_lands():
    od = fake_onedrive.make_session(fake_onedrive.FakeGraph())
    size = oc._UPLOAD_CHUNK + 7
    od._upload_in_session("/ok.bin", io.BytesIO(b"y" * size), size)
    with od.open_read("/ok.bin") as fh:
        assert fh.read() == b"y" * size


# ----------------------------------------------------------- Google Drive
gc = pytest.importorskip("core.gdrive_client")


def _gdrive_writer(cancel, fail_on_chunk: int, n_chunks: int):
    httplib2 = pytest.importorskip("httplib2")
    from googleapiclient.errors import HttpError

    class Req:
        def __init__(self):
            self.n = 0

        def next_chunk(self):
            self.n += 1
            if self.n == fail_on_chunk:
                raise HttpError(httplib2.Response({"status": "503"}), b"backend error")

            class St:
                resumable_progress = gc._UPLOAD_CHUNK * self.n
            if self.n >= n_chunks:
                return St(), {"id": "F1"}
            return St(), None

    class Files:
        def update(self, fileId, media_body=None, **kw):
            return Req()

    class Svc:
        def files(self):
            return Files()

    hooks = transfer_hooks.TransferHooks(cancel_event=cancel)
    with transfer_hooks.active(hooks):
        w = gc._SpooledWriter(Svc(), "x.bin", "root", existing_id="F1")
    w.write(b"x" * (gc._UPLOAD_CHUNK * (n_chunks - 1) + 5))
    return w


def test_sad_gdrive_cancel_after_an_uncertain_last_chunk_is_no_upload_cancelled(cancel_in_pause):
    w = _gdrive_writer(cancel_in_pause, fail_on_chunk=2, n_chunks=2)
    with pytest.raises(InterruptedError) as info:
        w.close()
    assert not isinstance(info.value, transfer_hooks.UploadCancelled)


def test_happy_gdrive_cancel_after_an_uncertain_middle_chunk_is_upload_cancelled(cancel_in_pause):
    w = _gdrive_writer(cancel_in_pause, fail_on_chunk=1, n_chunks=3)
    with pytest.raises(transfer_hooks.UploadCancelled):
        w.close()
