"""In-memory Google Drive v3 fake: a ``service`` object for
GDriveSession._service (files/about resources, ``.execute()``); media
downloads go through googleapiclient's real MediaIoBaseDownload.

Written for the protocol review (tests/test_backend_conformance.py,
tests/test_cloud_typed_errors_and_retries.py).

Modelled on Drive:
* a folder may hold several items of one name (create always adds)
* files.list honours q ("'P' in parents", "name = '...'", trashed),
  pageSize and pageToken; ``empty_first_page`` makes the next name query
  answer an empty page WITH a nextPageToken (Drive documents that a page
  may hold fewer than pageSize items, even none, while more exist)
* ``name_ci``: name = '...' matches case-insensitively
* errors are googleapiclient HttpError with resp.status
"""

from __future__ import annotations

import itertools
import re
from datetime import datetime, timezone

import httplib2
from googleapiclient.errors import HttpError

FOLDER = "application/vnd.google-apps.folder"
_ids = itertools.count(1)


def _http_error(status, msg="err"):
    return HttpError(httplib2.Response({"status": str(status)}), msg.encode())


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class _Req:
    def __init__(self, fn, data=None):
        self._fn = fn
        self.data = data

    def execute(self, num_retries=0):
        return self._fn()


class _MediaHttp:
    """What MediaIoBaseDownload asks for the bytes (``http.request``)."""

    def __init__(self, drive, file_id):
        self.drive, self.file_id = drive, file_id

    def request(self, uri, method="GET", headers=None, **kw):
        try:
            data = self.drive.data_of(self.file_id)
        except HttpError as exc:
            return exc.resp, exc.content
        resp = httplib2.Response({"status": "200", "content-length": str(len(data))})
        return resp, data


class _MediaRequest:
    """files.get_media: downloaded by core.gdrive_client._download_spooled
    through googleapiclient's real MediaIoBaseDownload."""

    def __init__(self, drive, file_id):
        self.http = _MediaHttp(drive, file_id)
        self.uri = f"https://fake.drive/{file_id}?alt=media"
        self.headers = {}


class _Files:
    def __init__(self, d):
        self.d = d

    def list(self, q="", fields="", pageSize=100, pageToken=None, **kw):
        return _Req(lambda: self.d._list(q, pageSize, pageToken))

    def get(self, fileId, fields="", **kw):
        return _Req(lambda: self.d._get(fileId))

    def get_media(self, fileId, **kw):
        return _MediaRequest(self.d, fileId)

    def create(self, body, media_body=None, fields="", **kw):
        return _Req(lambda: self.d._create(body, media_body))

    def update(self, fileId, body=None, media_body=None, addParents=None, removeParents=None, **kw):
        return _Req(lambda: self.d._update(fileId, body or {}, media_body, addParents, removeParents))

    def delete(self, fileId, **kw):
        return _Req(lambda: self.d._delete(fileId))

    def copy(self, fileId, body, **kw):
        return _Req(lambda: self.d._copy(fileId, body))


class FakeDrive:
    def __init__(self):
        self.items = {"root": {"id": "root", "name": "My Drive", "mimeType": FOLDER, "parents": []}}
        self.name_ci = False
        self.empty_first_page = 0
        self.calls = []
        self._tokens = {}

    def files(self):
        return _Files(self)

    def about(self):
        class A:
            def get(_s, fields=""):
                return _Req(lambda: {"user": {}, "storageQuota": {"limit": "10", "usage": "1"}})
        return A()

    # -- helpers ---------------------------------------------------------
    def _meta(self, it):
        out = {k: it[k] for k in ("id", "name", "mimeType") if k in it}
        out["modifiedTime"] = it["modifiedTime"] if "modifiedTime" in it else _now()
        if it["mimeType"] != FOLDER:
            out["size"] = str(len(it.get("data", b"")))
        return out

    def _list(self, q, page_size, token):
        self.calls.append(("list", q, page_size, token))
        if token:
            rest = self._tokens.pop(token)
            return self._page(rest, page_size)
        m = re.search(r"'([^']*)' in parents", q)
        parent = m.group(1)
        nm = re.search(r"name = '((?:[^'\\]|\\.)*)'", q)
        want = None
        if nm:
            want = re.sub(r"\\(.)", r"\1", nm.group(1))
        hits = []
        for it in self.items.values():
            if parent not in it.get("parents", []) or it.get("trashed"):
                continue
            if want is not None:
                a, b = (it["name"].lower(), want.lower()) if self.name_ci else (it["name"], want)
                if a != b:
                    continue
            hits.append(self._meta(it))
        if want is not None and self.empty_first_page > 0:
            self.empty_first_page -= 1
            tok = f"t{len(self._tokens)}"
            self._tokens[tok] = hits
            return {"files": [], "nextPageToken": tok}
        return self._page(hits, page_size)

    def _page(self, hits, size):
        head, rest = hits[:size], hits[size:]
        out = {"files": head}
        if rest:
            tok = f"t{len(self._tokens)}"
            self._tokens[tok] = rest
            out["nextPageToken"] = tok
        return out

    def _get(self, fid):
        if fid not in self.items:
            raise _http_error(404, "File not found")
        return self._meta(self.items[fid])

    def _media_bytes(self, media):
        return media.getbytes(0, media.size()) if media.size() else b""

    def _create(self, body, media):
        fid = f"F{next(_ids)}"
        parents = body.get("parents") or ["root"]
        for p in parents:
            if p not in self.items or self.items[p]["mimeType"] != FOLDER:
                raise _http_error(404, "parent not found")
        it = {"id": fid, "name": body["name"], "mimeType": body.get("mimeType", "application/octet-stream"),
              "parents": list(parents), "modifiedTime": _now()}
        if media is not None:
            it["data"] = self._media_bytes(media)
        self.calls.append(("create", body["name"], parents))
        self.items[fid] = it
        return {"id": fid}

    def _update(self, fid, body, media, add, remove):
        if fid not in self.items:
            raise _http_error(404, "File not found")
        it = self.items[fid]
        if media is not None:
            if it["mimeType"] == FOLDER:
                raise _http_error(400, "folder has no content")
            it["data"] = self._media_bytes(media)
        if "name" in body:
            it["name"] = body["name"]
        if add:
            it["parents"].append(add)
        if remove:
            it["parents"].remove(remove)
        it["modifiedTime"] = _now()
        return {"id": fid}

    def _delete(self, fid):
        if fid not in self.items:
            raise _http_error(404, "File not found")
        todo = [fid]
        while todo:
            cur = todo.pop()
            todo += [k for k, v in self.items.items() if cur in v.get("parents", [])]
            self.items.pop(cur, None)
        return None

    def _copy(self, fid, body):
        if fid not in self.items:
            raise _http_error(404, "File not found")
        src = self.items[fid]
        new = dict(src, id=f"F{next(_ids)}", name=body.get("name", src["name"]),
                   parents=list(body.get("parents", src["parents"])), modifiedTime=_now())
        self.items[new["id"]] = new
        return {"id": new["id"]}

    def data_of(self, fid):
        it = self.items.get(fid)
        if it is None:
            raise _http_error(404, "File not found")
        if it["mimeType"] == FOLDER:
            raise _http_error(403, "fileNotDownloadable")
        return it.get("data", b"")


def make_session(drive=None):
    from core.gdrive_client import GDriveSession

    drive = drive or FakeDrive()
    s = GDriveSession.__new__(GDriveSession)
    s._service = drive
    s._path_cache = {"/": "root"}
    return s
