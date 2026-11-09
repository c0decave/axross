"""Cloud protocol findings of the round-5 review (repros in
(round-5 protocol review):

* Dropbox honoured a 429's Retry-After without cap: the SDK sleeps
  int(Retry-After) itself (4 x 3600 s measured) - only the number of
  tries was bounded. The SDK's own retries are off now; _GuardedDropbox
  retries through cloud_http.pause (capped, Cancel wakes it).
* Dropbox upload sessions (> 150 MiB) did not resume after a lost answer:
  the resend got ``incorrect_offset`` and the whole upload failed. It goes
  on from ``correct_offset`` now.
* S3 was left out of the typed errors: the writer's close() let botocore's
  ClientError out (no OSError: an editor Save ended in the global hook),
  every other verb raised an errno-less OSError, and the folder-rename
  paginator was not wrapped at all.
* OneDrive reported an upload as failed when the answer to its last
  fragment was lost (resend -> 404 -> FileNotFoundError, the file complete).
* A DELETE resent after a 5xx / lost answer reported "not found" although
  its first try had deleted the item (OneDrive, Google Drive).
* S3's multipart copy (> 5 GiB) had no CopySourceIfMatch: a source replaced
  mid-copy mixed the parts of two versions.
"""

from __future__ import annotations

import errno
import json
import sys
import threading
import time
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fake_gdrive  # noqa: E402
import fake_onedrive  # noqa: E402
from fake_onedrive import Resp  # noqa: E402
from requests_fuzz_adapter import mount  # noqa: E402

from core import cloud_http, transfer_hooks  # noqa: E402


# ------------------------------------------------------------- Dropbox
@pytest.fixture
def dropbox_sdk(monkeypatch):
    dropbox = pytest.importorskip("dropbox")
    import dropbox.dropbox_client as sdk

    sdk_sleeps: list[float] = []
    pauses: list[float] = []
    monkeypatch.setattr(sdk.time, "sleep", sdk_sleeps.append)
    monkeypatch.setattr(cloud_http, "_sleep", pauses.append)
    return dropbox, sdk_sleeps, pauses


def _dropbox_session(dropbox, responder):
    from core import dropbox_client as D

    sess = requests.Session()
    adapter = mount(sess, responder)
    s = D.DropboxSession.__new__(D.DropboxSession)
    # Built as DropboxSession._connect builds it.
    s._dbx = dropbox.Dropbox(oauth2_access_token="t", session=sess,
                             max_retries_on_rate_limit=D._RATE_LIMIT_RETRIES,
                             max_retries_on_error=D._SERVER_ERROR_RETRIES)
    s._proxies = {}
    return s, adapter


def test_sad_dropbox_retry_after_of_an_hour_is_capped(dropbox_sdk):
    dropbox, sdk_sleeps, pauses = dropbox_sdk
    body = {"error_summary": "too_many_requests/",
            "error": {"reason": {".tag": "too_many_requests"}, "retry_after": 3600}}
    s, adapter = _dropbox_session(dropbox, lambda r: (
        429, {"Content-Type": "application/json", "Retry-After": "3600"}, json.dumps(body).encode()))
    with pytest.raises(BlockingIOError):  # EAGAIN
        s.list_dir("/")
    assert sdk_sleeps == []  # the SDK no longer sleeps the hour itself
    assert len(adapter.requests) == cloud_http.ATTEMPTS
    assert pauses and max(pauses) <= cloud_http.RETRY_AFTER_CAP


def test_happy_dropbox_429_then_answer_succeeds_after_a_capped_pause(dropbox_sdk):
    dropbox, sdk_sleeps, pauses = dropbox_sdk
    answers = [(429, {"Content-Type": "application/json", "Retry-After": "7"},
                json.dumps({"error_summary": "too_many_requests/",
                            "error": {"reason": {".tag": "too_many_requests"},
                                      "retry_after": 7}}).encode()),
               (200, {"Content-Type": "application/json"},
                json.dumps({"entries": [], "cursor": "c", "has_more": False}).encode())]
    s, adapter = _dropbox_session(dropbox, lambda r: answers.pop(0))
    assert s.list_dir("/") == []
    assert pauses == [7.0] and sdk_sleeps == []


def test_edge_dropbox_5xx_is_retried_by_cloud_http_not_the_sdk(dropbox_sdk):
    dropbox, sdk_sleeps, pauses = dropbox_sdk
    s, adapter = _dropbox_session(dropbox, lambda r: (503, {}, b"busy"))
    with pytest.raises(OSError):
        s.list_dir("/")
    assert sdk_sleeps == []
    assert len(adapter.requests) == cloud_http.ATTEMPTS and len(pauses) == cloud_http.ATTEMPTS - 1


def _dropbox_session_server(state):
    def reply(status, body):
        return status, {"Content-Type": "application/json"}, (
            b"null" if body is None else json.dumps(body).encode())

    def responder(req):
        route = req.url.split("/2/", 1)[1]
        arg = json.loads(req.headers.get("Dropbox-API-Arg", "{}"))
        data = req.body or b""
        state["routes"].append(route)
        if route == "files/upload_session/start":
            state["buf"] = bytearray(data)
            return reply(200, {"session_id": "S1"})
        off = arg["cursor"]["offset"]
        if off != len(state["buf"]):
            err = {".tag": "incorrect_offset", "correct_offset": len(state["buf"])}
            if route.endswith("finish"):
                err = {".tag": "lookup_failed", "lookup_failed": err}
            return reply(409, {"error_summary": "incorrect_offset/", "error": err})
        state["buf"] += data
        if route.endswith("append_v2"):
            if state.pop("lose_answer_at", None) == len(state["buf"]):
                return reply(503, None)  # appended, but the answer is an error
            return reply(200, None)
        state["files"][arg["commit"]["path"]] = bytes(state["buf"])
        return reply(200, {".tag": "file", "name": "big.bin", "id": "id:1",
                           "path_lower": "/big.bin", "path_display": "/big.bin",
                           "size": len(state["buf"]), "rev": "0123456789",
                           "client_modified": "2026-01-01T00:00:00Z",
                           "server_modified": "2026-01-01T00:00:00Z"})
    return responder


def test_sad_dropbox_session_resumes_from_the_correct_offset(dropbox_sdk, monkeypatch):
    dropbox, _sdk_sleeps, _pauses = dropbox_sdk
    from core import dropbox_client as D

    monkeypatch.setattr(D, "_UPLOAD_CHUNK", 1024)
    monkeypatch.setattr(D, "_SINGLE_UPLOAD_MAX", 2048)
    state = {"buf": bytearray(), "files": {}, "routes": [], "lose_answer_at": 3072}
    s, _adapter = _dropbox_session(dropbox, _dropbox_session_server(state))
    data = bytes(range(256)) * 20  # 5 chunks
    with s.open_write("/big.bin") as w:
        w.write(data)
    assert state["files"]["/big.bin"] == data
    assert state["routes"].count("files/upload_session/finish") == 1


def test_sad_dropbox_cancel_in_a_session_never_finishes_it(dropbox_sdk, monkeypatch):
    dropbox, _sdk_sleeps, _pauses = dropbox_sdk
    from core import dropbox_client as D

    monkeypatch.setattr(D, "_UPLOAD_CHUNK", 1024)
    state = {"buf": bytearray(), "files": {}, "routes": []}
    s, _adapter = _dropbox_session(dropbox, _dropbox_session_server(state))
    event = threading.Event()

    def progress(kind, done, total):
        if done >= 2048:
            event.set()

    with transfer_hooks.active(transfer_hooks.TransferHooks(event, progress)):
        w = s.open_write("/big.bin")
    w.write(bytes(8 * 1024))
    with pytest.raises(transfer_hooks.UploadCancelled):
        w.close()
    assert "files/upload_session/finish" not in state["routes"]
    assert state["files"] == {}


# ------------------------------------------------------------------ S3
@pytest.fixture
def s3_stubbed():
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    from core.s3_client import S3Session

    client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="a",
                          aws_secret_access_key="b")
    stub = Stubber(client)
    s = object.__new__(S3Session)
    s._s3, s._bucket, s._anonymous = client, "b", False
    stub.activate()
    yield s, stub
    stub.deactivate()


def test_sad_s3_writer_close_raises_a_typed_oserror(s3_stubbed):
    s, stub = s3_stubbed
    stub.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)
    w = s.open_write("/notes.txt")
    w.write(b"hello")
    with pytest.raises(PermissionError) as info:
        w.close()
    assert info.value.filename == "/notes.txt"
    stub.add_client_error("put_object", service_error_code="QuotaExceeded", http_status_code=403)
    with pytest.raises(OSError) as info:
        with s.open_write("/notes.txt") as w:
            w.write(b"x")
    assert info.value.errno == errno.ENOSPC


@pytest.mark.parametrize("op, code, status, kind", [
    ("head_object", "403", 403, PermissionError),
    ("get_object", "AccessDenied", 403, PermissionError),
    ("list_objects_v2", "SlowDown", 503, BlockingIOError),
    ("put_object", "AccessDenied", 403, PermissionError),
])
def test_sad_s3_verbs_raise_typed_oserrors(s3_stubbed, op, code, status, kind):
    s, stub = s3_stubbed
    stub.add_client_error(op, service_error_code=code, http_status_code=status)
    call = {"head_object": lambda: s.stat("/notes.txt"),
            "get_object": lambda: s.open_read("/notes.txt"),
            "list_objects_v2": lambda: s.list_dir("/d"),
            "put_object": lambda: s.mkdir("/new")}[op]
    with pytest.raises(kind) as info:
        call()
    assert info.value.errno


def test_sad_s3_atomic_write_refused_is_an_oserror():
    boto3 = pytest.importorskip("boto3")
    from botocore.awsrequest import AWSResponse

    from core.atomic_io import atomic_write
    from core.s3_client import S3Session

    client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="a",
                          aws_secret_access_key="b")

    def answer(model, params, **kw):
        # A bucket with a write-denying policy: reads find nothing, writes 403.
        if model.name == "PutObject":
            return (AWSResponse("u", 403, {}, None),
                    {"Error": {"Code": "AccessDenied", "Message": "Access Denied"},
                     "ResponseMetadata": {"HTTPStatusCode": 403}})
        if model.name in ("HeadObject", "GetObject"):
            return (AWSResponse("u", 404, {}, None),
                    {"Error": {"Code": "404", "Message": "Not Found"},
                     "ResponseMetadata": {"HTTPStatusCode": 404}})
        if model.name == "ListObjectsV2":
            return (AWSResponse("u", 200, {}, None),
                    {"KeyCount": 0, "ResponseMetadata": {"HTTPStatusCode": 200}})
        return (AWSResponse("u", 200, {}, None), {"ResponseMetadata": {"HTTPStatusCode": 200}})

    client.meta.events.register("before-call.s3.*", answer)
    s = object.__new__(S3Session)
    s._s3, s._bucket, s._anonymous = client, "b", False
    with pytest.raises(OSError) as info:
        atomic_write(s, "/notes.txt", b"edited")
    assert info.value.errno == errno.EACCES


def test_sad_s3_folder_rename_listing_failure_is_typed():
    pytest.importorskip("botocore")
    from botocore.exceptions import ClientError

    from core.s3_client import S3Session

    class Client:
        def list_objects_v2(self, **kw):
            return {"KeyCount": 1, "Contents": [{"Key": "src/a"}]} if kw.get(
                "Prefix") == "src/" else {"KeyCount": 0}

        def head_object(self, **kw):
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")

        def get_paginator(self, name):
            class P:
                def paginate(self, **kw):
                    yield {"Contents": [{"Key": "src/a", "Size": 1}]}
                    raise ClientError({"Error": {"Code": "SlowDown"},
                                       "ResponseMetadata": {"HTTPStatusCode": 503}},
                                      "ListObjectsV2")
            return P()

        def copy_object(self, **kw):
            pass

        def delete_object(self, **kw):
            pass

    s = object.__new__(S3Session)
    s._s3, s._bucket, s._anonymous = Client(), "b", False
    with pytest.raises(BlockingIOError) as info:
        s.rename("/src", "/dst")
    assert info.value.errno == errno.EAGAIN


def test_edge_s3_errno_of_codes_and_transport_failures():
    pytest.importorskip("botocore")
    from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError

    from core.s3_client import _s3_error

    def code(c, status=None):
        resp = {"Error": {"Code": c}}
        if status:
            resp["ResponseMetadata"] = {"HTTPStatusCode": status}
        return _s3_error(ClientError(resp, "Op"), "m").errno

    assert code("NoSuchKey") == errno.ENOENT
    assert code("EntityTooLarge") == errno.EFBIG
    assert code("PreconditionFailed") == errno.ESTALE
    assert code("SomethingNew", 507) == errno.ENOSPC
    assert code("418") == errno.EIO
    assert _s3_error(EndpointConnectionError(endpoint_url="u"), "m").errno == errno.ECONNRESET
    assert _s3_error(ReadTimeoutError(endpoint_url="u"), "m").errno == errno.ETIMEDOUT


def test_happy_s3_multipart_copy_pins_the_source_version():
    from core import s3_client as S

    calls = []

    class Client:
        def head_object(self, **kw):
            return {"ContentLength": S._MAX_SINGLE_COPY + 1, "ETag": '"abc-3"'}

        def create_multipart_upload(self, **kw):
            return {"UploadId": "U"}

        def upload_part_copy(self, **kw):
            calls.append(kw)
            return {"CopyPartResult": {"ETag": f'"p{kw["PartNumber"]}"'}}

        def complete_multipart_upload(self, **kw):
            pass

    s = object.__new__(S.S3Session)
    s._s3, s._bucket, s._anonymous = Client(), "b", False
    s.copy("/big", "/copy")
    assert calls and all(c["CopySourceIfMatch"] == '"abc-3"' for c in calls)


def _s3_multipart_client(seen: list, event: threading.Event | None):
    """A real boto3 client whose requests are answered here (before-send):
    a multipart upload; *event* is set once the first part went up."""
    boto3 = pytest.importorskip("boto3")
    from botocore.awsrequest import AWSResponse

    client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="a",
                          aws_secret_access_key="b")

    class Raw:
        def __init__(self, body=b""):
            self.body = body

        def stream(self, **kw):
            yield self.body

    def send(request, **kw):
        op = kw.get("event_name", "").rsplit(".", 1)[-1]
        if hasattr(request.body, "read"):
            request.body.read()
        url = request.url
        if request.method == "POST" and "uploads" in url:
            seen.append("create")
            return AWSResponse(url, 200, {}, Raw(
                b'<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key>'
                b'<UploadId>U1</UploadId></InitiateMultipartUploadResult>'))
        if request.method == "PUT" and "partNumber" in url:
            seen.append("part")
            if event is not None:
                if "partNumber=1&" not in url + "&":
                    time.sleep(0.5)  # the other parts are still on their way...
                event.set()  # ...when Cancel is pressed after part 1 went up
            return AWSResponse(url, 200, {"ETag": '"e"'}, Raw())
        if request.method == "DELETE":
            seen.append("abort")
            return AWSResponse(url, 204, {}, Raw())
        if request.method == "POST":
            seen.append("complete")
            return AWSResponse(url, 200, {}, Raw(
                b"<CompleteMultipartUploadResult><ETag>x</ETag></CompleteMultipartUploadResult>"))
        seen.append(op or request.method)
        return AWSResponse(url, 200, {"ETag": '"e"'}, Raw())

    client.meta.events.register("before-send.s3", send)
    return client


def _s3_on(client):
    from core import s3_client as S

    s = object.__new__(S.S3Session)
    s._s3, s._bucket, s._anonymous = client, "b", False
    return s


def test_sad_s3_cancelled_multipart_upload_is_aborted():
    seen: list[str] = []
    event = threading.Event()
    s = _s3_on(_s3_multipart_client(seen, event))
    with transfer_hooks.active(transfer_hooks.TransferHooks(event)):
        w = s.open_write("/big.bin")
    w.write(bytes(20 * 1024 * 1024))  # 3 parts of 8 MiB
    with pytest.raises(transfer_hooks.UploadCancelled):
        w.close()
    assert "abort" in seen and "complete" not in seen


def test_happy_s3_multipart_upload_in_a_transfer_reports_and_completes():
    seen: list[str] = []
    s = _s3_on(_s3_multipart_client(seen, None))
    reported = []
    hooks = transfer_hooks.TransferHooks(threading.Event(),
                                         lambda kind, done, total: reported.append(done))
    with transfer_hooks.active(hooks):
        w = s.open_write("/big.bin")
    w.write(bytes(20 * 1024 * 1024))
    w.close()
    assert seen.count("part") == 3 and "complete" in seen and "abort" not in seen
    assert reported[-1] == 20 * 1024 * 1024


def test_edge_s3_custom_endpoint_asks_checksums_only_when_required(monkeypatch):
    pytest.importorskip("boto3")
    from core.s3_client import S3Session

    monkeypatch.setattr(S3Session, "_connect_with_redirect", lambda self, b, kw: None)
    s = S3Session("bucket-x", access_key="a", secret_key="b", endpoint="http://127.0.0.1:9")
    config = s._s3.meta.config
    if hasattr(config, "request_checksum_calculation"):
        assert config.request_checksum_calculation == "when_required"
        assert config.response_checksum_validation == "when_required"
    aws = S3Session("bucket-x", access_key="a", secret_key="b")
    if hasattr(aws._s3.meta.config, "request_checksum_calculation"):
        assert aws._s3.meta.config.request_checksum_calculation != "when_required"


# ------------------------------------------------------------ OneDrive
class _LostFinalAnswer(fake_onedrive.FakeGraph):
    """Graph completes the item with the last fragment and drops the
    upload URL; the answer to that fragment is lost on the way."""

    drop_final = True

    def get(self, url, *a, **kw):
        if url.startswith("https://upload.fake/S") and url.rsplit("/", 1)[1] not in self.sessions:
            return Resp(404, {"error": {"code": "itemNotFound"}})
        return super().get(url, *a, **kw)

    def put(self, url, headers=None, data=None, **kw):
        if url.startswith("https://upload.fake/"):
            sid = url.rsplit("/", 1)[1]
            if sid not in self.sessions:
                return Resp(404, {"error": {"code": "itemNotFound"}})
            r = super().put(url, headers=headers, data=data, **kw)
            if r.status_code in (200, 201):
                del self.sessions[sid]
                if self.drop_final:
                    self.drop_final = False
                    if not self.commit:
                        # a session that expired instead: nothing landed
                        self.nodes.pop("report.bin", None)
                        self.nodes.update(self.saved)
                    raise requests.ConnectionError("connection reset (answer lost)")
            return r
        return super().put(url, headers=headers, data=data, **kw)


@pytest.fixture
def no_pause(monkeypatch):
    monkeypatch.setattr(cloud_http, "_sleep", lambda s: None)


def test_sad_onedrive_lost_answer_to_the_last_fragment_is_success(no_pause):
    g = _LostFinalAnswer()
    g.commit, g.saved = True, {}
    od = fake_onedrive.make_session(g)
    data = b"x" * (12 * 1024 * 1024)
    with od.open_write("/report.bin") as w:
        w.write(data)
    assert od.stat("/report.bin").size == len(data)


def test_edge_onedrive_overwrite_with_lost_last_answer_is_told_by_the_new_tag(no_pause):
    g = _LostFinalAnswer()
    od = fake_onedrive.make_session(g)
    g.drop_final = False
    with od.open_write("/report.bin") as w:
        w.write(b"y" * (12 * 1024 * 1024))  # an older version of the same size
    g.drop_final, g.commit, g.saved = True, True, {}
    with od.open_write("/report.bin") as w:
        w.write(b"x" * (12 * 1024 * 1024))
    with od.open_read("/report.bin") as fh:
        assert fh.read(1) == b"x"


def test_sad_onedrive_session_gone_without_the_item_is_still_a_failure(no_pause):
    g = _LostFinalAnswer()
    od = fake_onedrive.make_session(g)
    g.drop_final = False
    with od.open_write("/report.bin") as w:
        w.write(b"y" * (12 * 1024 * 1024))
    g.drop_final, g.commit = True, False
    g.saved = {"report.bin": dict(g.nodes["report.bin"])}
    with pytest.raises(FileNotFoundError):
        with od.open_write("/report.bin") as w:
            w.write(b"x" * (12 * 1024 * 1024))


class _DeleteAnswerLost(fake_onedrive.FakeGraph):
    lose: int | None = 504

    def delete(self, url, *a, **kw):
        r = super().delete(url, *a, **kw)
        if self.lose and r.status_code == 204:
            status, self.lose = self.lose, None
            return Resp(status, {"error": {"code": "gatewayTimeout"}})
        return r


def test_sad_onedrive_delete_retried_after_its_answer_was_lost_is_done(no_pause):
    g = _DeleteAnswerLost()
    od = fake_onedrive.make_session(g)
    with od.open_write("/a.txt") as w:
        w.write(b"x")
    od.remove("/a.txt")
    assert not od.exists("/a.txt")


def test_edge_onedrive_delete_after_a_429_and_then_404_is_not_found(no_pause):
    g = fake_onedrive.FakeGraph()
    od = fake_onedrive.make_session(g)
    with od.open_write("/a.txt") as w:
        w.write(b"x")
    item = od._graph_get(od._item_path_url("/a.txt"))
    g.nodes.pop("a.txt")  # gone meanwhile (someone else)
    g.throttle = 1  # 429: the first DELETE was not processed
    with pytest.raises(FileNotFoundError):
        od._graph_delete(f"{fake_onedrive.GRAPH}/me/drive/items/{item['id']}")


# -------------------------------------------------------- Google Drive
def test_sad_gdrive_delete_retried_after_a_502_is_done(no_pause):
    drive = fake_gdrive.FakeDrive()
    s = fake_gdrive.make_session(drive)
    with s.open_write("/a.txt") as w:
        w.write(b"x")
    delete = drive._delete
    state = {"lost": True}

    def delete_answer_lost(fid):
        delete(fid)
        if state.pop("lost", False):
            raise fake_gdrive._http_error(502, "Bad Gateway")  # done, answer lost

    drive._delete = delete_answer_lost
    s.remove("/a.txt")
    assert not s.exists("/a.txt")


def test_sad_gdrive_resumable_upload_cancelled_between_chunks_makes_no_file():
    from core import gdrive_client as G

    class Status:
        def __init__(self, done):
            self.resumable_progress = done

    class Request:
        def __init__(self):
            self.steps = 0

        def next_chunk(self):
            self.steps += 1
            if self.steps < 4:
                return Status(self.steps * 100), None
            return None, {"id": "F"}

        def execute(self):
            raise AssertionError("chunked in a transfer")

    request = Request()
    event = threading.Event()

    def progress(kind, done, total):
        if done >= 200:
            event.set()

    hooks = transfer_hooks.TransferHooks(event, progress)
    with pytest.raises(InterruptedError):
        G._upload(request, hooks, 400)
    assert request.steps == 2  # the file is made by the last chunk only


def test_happy_gdrive_writer_reports_the_upload_in_a_transfer():
    drive = fake_gdrive.FakeDrive()
    s = fake_gdrive.make_session(drive)
    seen = []
    hooks = transfer_hooks.TransferHooks(threading.Event(), lambda k, d, t: seen.append((k, d)))
    with transfer_hooks.active(hooks):
        w = s.open_write("/a.txt")
    w.write(b"hello")
    w.close()
    assert hooks.upload_expected and seen[-1] == ("upload", 5)
    with s.open_read("/a.txt") as fh:
        assert fh.read() == b"hello"
