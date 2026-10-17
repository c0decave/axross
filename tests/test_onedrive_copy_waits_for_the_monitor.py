"""OneDrive copy() waits for the server-side copy to end.

Graph answers ``POST .../copy`` with 202 Accepted and a monitor URL in
``Location``; the copy runs afterwards and may still fail (for example
nameAlreadyExists). copy() returned at once, so a failed copy was
reported as done and the target did not exist yet. It now polls the
monitor until the copy is completed or failed, bounded by a timeout.
The monitor URL is pre-authenticated like the upload-session URL: it
gets no bearer token and must be https.

The destination folder goes into ``parentReference`` as ``{driveId, id}``
(the form rename() already uses for its ``{id}``) instead of a
``path``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

requests = pytest.importorskip("requests")

from requests_fuzz_adapter import mount  # noqa: E402

from core.onedrive_client import OneDriveSession  # noqa: E402

MONITOR = "https://api.onedrive.com/monitor/abc"


class _Graph:
    def __init__(self, monitor_answers, *, post_status=202, location=MONITOR):
        self.monitor_answers = list(monitor_answers)
        self.post_status = post_status
        self.location = location
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[dict] = []
        self.monitor_auth: list[str | None] = []

    def __call__(self, request):
        path = request.url.split("v1.0", 1)[-1] if "v1.0" in request.url else request.url
        self.calls.append((request.method, path))
        if request.method == "POST" and request.url.endswith(":/copy"):
            self.bodies.append(json.loads(request.body))
            headers = {"Location": self.location} if self.location else {}
            return self.post_status, headers, b""
        if request.url.startswith(MONITOR) or "monitor" in request.url:
            self.monitor_auth.append(request.headers.get("Authorization"))
            status, body = self.monitor_answers.pop(0)
            return status, {"Location": "https://graph.microsoft.com/v1.0/me/drive/items/NEW"}, (
                json.dumps(body).encode() if body is not None else b""
            )
        if request.url.endswith("root:/dst"):
            item = {"id": "P1", "folder": {}, "parentReference": {"driveId": "D1"}}
            return 200, {}, json.dumps(item).encode()
        if request.url.endswith("/me/drive/root"):
            return 200, {}, json.dumps({"id": "ROOT", "folder": {}}).encode()
        if request.url.endswith("/me/drive"):
            return 200, {}, json.dumps({"id": "D0"}).encode()
        return 404, {}, b'{"error":{"code":"itemNotFound"}}'


def _session(graph: _Graph) -> OneDriveSession:
    s = OneDriveSession.__new__(OneDriveSession)
    s._http = requests.Session()
    mount(s._http, graph)
    s._access_token = "t"
    s._app = mock.Mock()
    s._app.get_accounts.return_value = [{"username": "u"}]
    s._app.acquire_token_silent.return_value = {"access_token": "t"}
    s._cache = mock.Mock(has_state_changed=False)
    s._drive_type = "personal"
    s._site_id = None
    s._scopes = []
    s._COPY_POLL_INTERVAL = 0
    return s


IN_PROGRESS = (202, {"status": "inProgress", "percentageComplete": 50.0})
COMPLETED = (200, {"status": "completed", "resourceId": "NEW"})


# -- happy -------------------------------------------------------------------


def test_happy_copy_polls_until_completed():
    graph = _Graph([IN_PROGRESS, IN_PROGRESS, COMPLETED])
    _session(graph).copy("/a.txt", "/dst/b.txt")
    assert [c for c in graph.calls if c[1] == MONITOR] == [("GET", MONITOR)] * 3
    assert graph.bodies == [{"parentReference": {"driveId": "D1", "id": "P1"}, "name": "b.txt"}]


def test_happy_the_monitor_gets_no_bearer_token():
    graph = _Graph([COMPLETED])
    _session(graph).copy("/a.txt", "/dst/b.txt")
    assert graph.monitor_auth == [None]


def test_happy_a_see_other_answer_means_done_and_is_not_followed():
    graph = _Graph([(303, None)])
    _session(graph).copy("/a.txt", "/dst/b.txt")
    assert not any("items/NEW" in path for _, path in graph.calls)


# -- sad ---------------------------------------------------------------------


def test_sad_a_failed_copy_with_a_taken_name_is_file_exists():
    failed = (200, {"status": "failed", "error": {"code": "nameAlreadyExists"}})
    graph = _Graph([IN_PROGRESS, failed])
    with pytest.raises(FileExistsError):
        _session(graph).copy("/a.txt", "/dst/b.txt")


def test_sad_a_failed_copy_is_an_oserror_with_the_server_code():
    failed = (200, {"status": "failed", "error": {"code": "quotaLimitReached"}})
    graph = _Graph([failed])
    with pytest.raises(OSError, match="quotaLimitReached"):
        _session(graph).copy("/a.txt", "/dst/b.txt")


def test_sad_accepted_without_a_monitor_url_is_an_oserror():
    graph = _Graph([], location="")
    with pytest.raises(OSError, match="monitor"):
        _session(graph).copy("/a.txt", "/dst/b.txt")


def test_sad_a_monitor_error_answer_is_an_oserror():
    graph = _Graph([(500, {"error": {"code": "generalException"}})])
    with pytest.raises(OSError, match="500"):
        _session(graph).copy("/a.txt", "/dst/b.txt")


# -- edge --------------------------------------------------------------------


def test_edge_a_copy_that_never_ends_times_out():
    graph = _Graph([IN_PROGRESS] * 1000)
    s = _session(graph)
    s._COPY_TIMEOUT = 0.05
    s._COPY_POLL_INTERVAL = 0.01
    with pytest.raises(OSError, match="timed out"):
        s.copy("/a.txt", "/dst/b.txt")


def test_edge_a_plain_http_monitor_url_is_refused_unasked():
    graph = _Graph([COMPLETED], location="http://api.onedrive.com/monitor/abc")
    with pytest.raises(OSError, match="https"):
        _session(graph).copy("/a.txt", "/dst/b.txt")
    assert graph.monitor_auth == []


def test_edge_copy_into_the_root_takes_the_drive_id_from_the_drive():
    graph = _Graph([COMPLETED])
    _session(graph).copy("/a.txt", "/b.txt")
    assert graph.bodies == [{"parentReference": {"driveId": "D0", "id": "ROOT"}, "name": "b.txt"}]
