"""remove(folder, recursive=False) refuses a folder that has children.

WebDAV, Dropbox, Google Drive and OneDrive sent their one DELETE call
for a folder whatever ``recursive`` said, and all four services delete
a folder with everything in it. FUSE rmdir and the MCP ``remove`` tool
call ``remove(path, recursive=False)``, so an rmdir of a non-empty
folder wiped the tree. LocalFS answers ENOTEMPTY; so do these now,
without sending the DELETE. An empty folder and a file still go.
"""

from __future__ import annotations

import errno
import json
import os
import sys
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from requests_fuzz_adapter import mount  # noqa: E402

# ---------------------------------------------------------------------------
# WebDAV: axross' own reverse WebDAV server on loopback over a LocalFS dir
# ---------------------------------------------------------------------------


@pytest.fixture
def dav(tmp_path):
    from core.local_fs import LocalFS
    from core.reverse_serve import serve_webdav
    from core.webdav_client import WebDavSession

    os.makedirs(tmp_path / "proj" / "sub")
    (tmp_path / "proj" / "a.txt").write_text("data")
    (tmp_path / "proj" / "sub" / "b.txt").write_text("data")
    os.makedirs(tmp_path / "empty")
    (tmp_path / "f.txt").write_text("x")
    srv = serve_webdav(
        LocalFS(), bind="127.0.0.1", port=0, root_path=str(tmp_path), auth_token=None
    )
    try:
        yield WebDavSession(srv.base_url), tmp_path
    finally:
        srv.shutdown()


def test_sad_webdav_nonrecursive_remove_of_a_full_folder_is_enotempty(dav):
    session, root = dav
    with pytest.raises(OSError) as info:
        session.remove("/proj", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert (root / "proj" / "a.txt").exists()
    assert (root / "proj" / "sub" / "b.txt").exists()


def test_happy_webdav_empty_folder_file_and_recursive_remove(dav):
    session, root = dav
    session.remove("/empty", recursive=False)
    session.remove("/f.txt", recursive=False)
    session.remove("/proj", recursive=True)
    assert not (root / "empty").exists()
    assert not (root / "f.txt").exists()
    assert not (root / "proj").exists()


def test_edge_webdav_folder_path_with_trailing_slash(dav):
    session, root = dav
    with pytest.raises(OSError) as info:
        session.remove("/proj/", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert (root / "proj" / "a.txt").exists()


# ---------------------------------------------------------------------------
# Dropbox: the real SDK over a scripted requests transport
# ---------------------------------------------------------------------------

_DBX_FOLDER = {".tag": "folder", "name": "proj", "id": "id:p", "path_lower": "/proj"}
_DBX_FILE = {
    ".tag": "file",
    "name": "a.txt",
    "id": "id:a",
    "path_lower": "/proj/a.txt",
    "client_modified": "2024-01-02T03:04:05Z",
    "server_modified": "2024-01-02T03:04:05Z",
    "rev": "0123456789abcdef",
    "size": 5,
}


def _dropbox(children: list[dict], target: dict):
    dropbox = pytest.importorskip("dropbox")
    from core.dropbox_client import DropboxSession

    calls: list[str] = []

    def responder(request):
        endpoint = urlsplit(request.url).path
        calls.append(endpoint)
        if endpoint.endswith("/files/get_metadata"):
            body = target
        elif endpoint.endswith("/files/list_folder"):
            body = {"entries": children, "cursor": "c", "has_more": False}
        elif endpoint.endswith("/files/delete_v2"):
            body = {"metadata": target}
        else:
            return 404, {}, b""
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()

    sess = requests.Session()
    mount(sess, responder)
    s = DropboxSession.__new__(DropboxSession)
    s._dbx = dropbox.Dropbox(
        oauth2_access_token="t",
        session=sess,
        max_retries_on_error=0,
        max_retries_on_rate_limit=0,
    )
    s._proxies = {}
    return s, calls


def _deleted(calls: list[str]) -> bool:
    return any(c.endswith("/files/delete_v2") for c in calls)


def test_sad_dropbox_nonrecursive_remove_of_a_full_folder_is_enotempty():
    s, calls = _dropbox([_DBX_FILE], _DBX_FOLDER)
    with pytest.raises(OSError) as info:
        s.remove("/proj", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert not _deleted(calls)


def test_happy_dropbox_empty_folder_file_and_recursive_remove():
    s, calls = _dropbox([], _DBX_FOLDER)
    s.remove("/proj", recursive=False)
    assert _deleted(calls)
    s, calls = _dropbox([], _DBX_FILE)
    s.remove("/proj/a.txt", recursive=False)
    assert _deleted(calls)
    s, calls = _dropbox([_DBX_FILE], _DBX_FOLDER)
    s.remove("/proj", recursive=True)
    assert _deleted(calls)


def test_edge_dropbox_folder_path_with_trailing_slash():
    s, calls = _dropbox([_DBX_FILE], _DBX_FOLDER)
    with pytest.raises(OSError) as info:
        s.remove("/proj/", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert not _deleted(calls)


# ---------------------------------------------------------------------------
# Google Drive: the real discovery client over a scripted httplib2 transport
# ---------------------------------------------------------------------------

_FOLDER_MIME = "application/vnd.google-apps.folder"


class _DriveHttp:
    """Answers files.list / files.get / files.delete for one folder 'proj'
    (id P) and one file 'f.txt' (id F) under root."""

    def __init__(self, children: list[dict]) -> None:
        self.children = children
        self.calls: list[tuple[str, str]] = []

    def request(self, uri, method="GET", body=None, headers=None, **_kwargs):
        import httplib2

        parts = urlsplit(uri)
        self.calls.append((method, parts.path))
        q = parse_qs(parts.query).get("q", [""])[0]
        if method == "DELETE":
            return httplib2.Response({"status": "204"}), b""
        if parts.path.endswith("/files/P"):
            answer = {"id": "P", "name": "proj", "mimeType": _FOLDER_MIME}
        elif parts.path.endswith("/files/F"):
            answer = {"id": "F", "name": "f.txt", "mimeType": "text/plain", "size": "1"}
        elif "'root' in parents" in q and "name = 'proj'" in q:
            answer = {"files": [{"id": "P", "name": "proj", "mimeType": _FOLDER_MIME}]}
        elif "'root' in parents" in q and "name = 'f.txt'" in q:
            answer = {"files": [{"id": "F", "name": "f.txt", "mimeType": "text/plain"}]}
        elif "'P' in parents" in q:
            answer = {"files": self.children}
        else:
            answer = {"files": []}
        resp = httplib2.Response({"status": "200", "content-type": "application/json"})
        return resp, json.dumps(answer).encode()

    def deleted(self) -> list[str]:
        return [p.rsplit("/", 1)[-1] for m, p in self.calls if m == "DELETE"]


def _gdrive(children: list[dict]):
    pytest.importorskip("googleapiclient")
    from googleapiclient.discovery import build

    from core.gdrive_client import GDriveSession

    http = _DriveHttp(children)
    s = GDriveSession.__new__(GDriveSession)
    s._service = build("drive", "v3", http=http, static_discovery=True)
    s._path_cache = {"/": "root"}
    return s, http


def test_sad_gdrive_nonrecursive_remove_of_a_full_folder_is_enotempty():
    s, http = _gdrive([{"id": "C", "name": "a.txt", "mimeType": "text/plain"}])
    with pytest.raises(OSError) as info:
        s.remove("/proj", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert http.deleted() == []


def test_happy_gdrive_empty_folder_file_and_recursive_remove():
    s, http = _gdrive([])
    s.remove("/proj", recursive=False)
    s.remove("/f.txt", recursive=False)
    assert http.deleted() == ["P", "F"]
    s, http = _gdrive([{"id": "C", "name": "a.txt", "mimeType": "text/plain"}])
    s.remove("/proj", recursive=True)
    assert http.deleted() == ["P"]


def test_edge_gdrive_folder_path_with_trailing_slash():
    s, http = _gdrive([{"id": "C", "name": "sub", "mimeType": _FOLDER_MIME}])
    with pytest.raises(OSError) as info:
        s.remove("/proj/", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert http.deleted() == []


# ---------------------------------------------------------------------------
# OneDrive: Graph over a scripted requests transport
# ---------------------------------------------------------------------------


def _onedrive(item: dict, children: list[dict]):
    from core.onedrive_client import OneDriveSession

    calls: list[tuple[str, str]] = []

    def responder(request):
        url = request.url
        calls.append((request.method, url))
        if request.method == "DELETE":
            return 204, {}, b""
        if "/children" in url:
            body = {"value": children}
        else:
            body = item
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()

    s = OneDriveSession.__new__(OneDriveSession)
    s._http = requests.Session()
    mount(s._http, responder)
    s._access_token = "t"
    s._app = mock.Mock()
    s._app.get_accounts.return_value = [{"username": "u"}]
    s._app.acquire_token_silent.return_value = {"access_token": "t"}
    s._cache = mock.Mock(has_state_changed=False)
    s._drive_type = "personal"
    s._site_id = None
    s._site_url = ""
    s._tenant_id = "common"
    s._scopes = []
    s._proxies = {}
    return s, calls


def _od_deleted(calls) -> list[str]:
    return [u.rsplit("/", 1)[-1] for m, u in calls if m == "DELETE"]


def test_sad_onedrive_nonrecursive_remove_of_a_full_folder_is_enotempty():
    item = {"id": "P", "name": "proj", "folder": {"childCount": 2}}
    s, calls = _onedrive(item, [{"id": "C", "name": "a"}])
    with pytest.raises(OSError) as info:
        s.remove("/proj", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert _od_deleted(calls) == []


def test_happy_onedrive_empty_folder_file_and_recursive_remove():
    s, calls = _onedrive({"id": "P", "name": "proj", "folder": {"childCount": 0}}, [])
    s.remove("/proj", recursive=False)
    assert _od_deleted(calls) == ["P"]
    s, calls = _onedrive({"id": "F", "name": "f.txt", "file": {}, "size": 1}, [])
    s.remove("/f.txt", recursive=False)
    assert _od_deleted(calls) == ["F"]
    s, calls = _onedrive({"id": "P", "name": "proj", "folder": {"childCount": 3}}, [{"id": "C"}])
    s.remove("/proj", recursive=True)
    assert _od_deleted(calls) == ["P"]


def test_edge_onedrive_folder_without_a_child_count_is_listed():
    # childCount absent or not a number: the children listing decides.
    s, calls = _onedrive({"id": "P", "name": "proj", "folder": {}}, [{"id": "C", "name": "a"}])
    with pytest.raises(OSError) as info:
        s.remove("/proj", recursive=False)
    assert info.value.errno == errno.ENOTEMPTY
    assert _od_deleted(calls) == []
    s, calls = _onedrive({"id": "P", "name": "proj", "folder": {"childCount": "x"}}, [])
    s.remove("/proj", recursive=False)
    assert _od_deleted(calls) == ["P"]

