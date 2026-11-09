"""In-memory Microsoft Graph (OneDrive) fake: a ``requests.Session``
stand-in for OneDriveSession._http.

Modelled on Graph:
* item paths are case-insensitive, names keep their case
* children are paged (PAGE per page) with @odata.nextLink
* POST children with conflictBehavior=fail -> 409 nameAlreadyExists
* PUT root:/p:/content creates missing parents, replaces a file,
  409 for a folder of that name
* PATCH items/{id} -> 409 nameAlreadyExists when the target name is taken
  (``patch_conflict`` = "fail"; set "replace" to model the other reading
  of the docs)
* 429 injection: ``throttle`` = number of next requests answered 429
* files carry an eTag and a cTag that change with every upload; DELETE on
  an upload session URL cancels it
"""

from __future__ import annotations

import itertools
import json
import posixpath
import re
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse, parse_qs

GRAPH = "https://graph.microsoft.com/v1.0"
PAGE = 2
_ids = itertools.count(1)


class Resp:
    def __init__(self, status, body=b"", headers=None):
        self.status_code = status
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.content = body
        self.headers = headers or {}

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.content)

    def iter_content(self, n):
        for i in range(0, len(self.content), n or 1):
            yield self.content[i : i + n]

    def close(self):
        pass


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGraph:
    def __init__(self):
        self.nodes = {"": {"id": "ROOT", "name": "root", "is_dir": True, "mtime": _now()}}
        self.sessions = {}
        self.calls = []
        self.throttle = 0
        self.patch_conflict = "fail"
        self.headers = {}

    # -- tree helpers ----------------------------------------------------
    def _by_id(self, item_id):
        for k, n in self.nodes.items():
            if n["id"] == item_id:
                return k
        return None

    def _item(self, low):
        n = self.nodes[low]
        d = {"id": n["id"], "name": n["name"], "lastModifiedDateTime": n["mtime"],
             "parentReference": {"driveId": "DRIVE", "id": self.nodes[posixpath.dirname(low) if "/" in low else ""]["id"]} if low else {}}
        if n["is_dir"]:
            kids = [k for k in self.nodes if self._parent(k) == low and k != low]
            d["folder"] = {"childCount": len(kids)}
            d["size"] = 0
        else:
            d["file"] = {"hashes": {}}
            d["size"] = len(n["data"])
            # Graph: eTag changes with the item, cTag with its content.
            d["eTag"] = f'"{{{n["id"]}}},{n.get("version", 1)}"'
            d["cTag"] = f'"c:{{{n["id"]}}},{n.get("version", 1)}"'
        return d

    @staticmethod
    def _parent(low):
        return low.rsplit("/", 1)[0] if "/" in low else ""

    def _err(self, status, code, msg):
        return Resp(status, {"error": {"code": code, "message": msg}})

    def _subtree(self, low):
        return [k for k in self.nodes if k == low or k.startswith(low + "/")]

    def _ensure_parents(self, rel):
        parts = rel.split("/")[:-1]
        cur = ""
        for p in parts:
            cur = f"{cur}/{p}" if cur else p
            low = cur.lower()
            if low in self.nodes:
                if not self.nodes[low]["is_dir"]:
                    return False
            else:
                self.nodes[low] = {"id": f"I{next(_ids)}", "name": p, "is_dir": True, "mtime": _now()}
        return True

    # -- URL parsing -----------------------------------------------------
    _ROOT = re.compile(r"^/v1\.0/me/drive/root(?::(?P<path>.*?)(?::(?P<rest>/.*)?)?)?(?P<tail>/children|/content)?$")

    def _parse(self, url):
        u = urlparse(url)
        path = u.path
        q = parse_qs(u.query)
        m = re.match(r"^/v1\.0/me/drive/items/(?P<id>[^/]+)(?P<rest>/.*)?$", path)
        if m:
            low = self._by_id(m["id"])
            return ("id", low, m["rest"] or "", q)
        if path == "/v1.0/me/drive":
            return ("drive", None, "", q)
        if path.startswith("/v1.0/me/drive/root"):
            rest = path[len("/v1.0/me/drive/root"):]
            if rest in ("", "/children"):
                return ("path", "", rest, q)
            assert rest.startswith(":"), rest
            rest = rest[1:]
            if ":" in rest:
                p, tail = rest.split(":", 1)
            else:
                p, tail = rest, ""
            rel = unquote(p).strip("/")
            return ("path", rel, tail, q)
        raise AssertionError(url)

    def _throttled(self):
        if self.throttle > 0:
            self.throttle -= 1
            return self._err(429, "activityLimitReached", "throttled")
        return None

    # -- verbs -----------------------------------------------------------
    def get(self, url, headers=None, stream=False, timeout=None, allow_redirects=True, **kw):
        self.calls.append(("GET", url))
        if t := self._throttled():
            return t
        if url.startswith("https://upload.fake/S"):
            # an upload session's state: where it wants the next byte
            s = self.sessions[url.rsplit("/", 1)[1]]
            return Resp(200, {"nextExpectedRanges": [f"{len(s['buf'])}-"]})
        if url.startswith("https://upload.fake/monitor/"):
            if url.endswith("/fail"):
                return Resp(200, {"status": "failed", "error": {"code": "nameAlreadyExists"}})
            return Resp(200, {"status": "completed"})
        kind, rel, tail, q = self._parse(url)
        if kind == "drive":
            return Resp(200, {"id": "DRIVE", "quota": {"total": 10, "used": 1, "remaining": 9}})
        if kind == "path":
            low = rel.lower()
        else:
            low = rel
        if low is None or low not in self.nodes:
            return self._err(404, "itemNotFound", "The resource could not be found.")
        if tail == "/children":
            if not self.nodes[low]["is_dir"]:
                return Resp(200, {"value": []})  # Graph answers a file's children as empty
            kids = sorted(k for k in self.nodes if k != low and self._parent(k) == low and k != "")
            skip = int(q.get("$skiptoken", ["0"])[0])
            top = int(q.get("$top", [str(PAGE)])[0])
            page = kids[skip : skip + top]
            body = {"value": [self._item(k) for k in page]}
            if skip + top < len(kids):
                base = url.split("?")[0]
                body["@odata.nextLink"] = f"{base}?$skiptoken={skip + top}"
            return Resp(200, body)
        if tail == "/content":
            if self.nodes[low]["is_dir"]:
                return self._err(404, "itemNotFound", "folder has no content")
            return Resp(200, self.nodes[low]["data"])
        return Resp(200, self._item(low))

    def post(self, url, headers=None, json=None, timeout=None, **kw):
        self.calls.append(("POST", url, json))
        if t := self._throttled():
            return t
        kind, rel, tail, q = self._parse(url)
        low = rel.lower() if kind == "path" else rel
        if tail == "/children":
            if low not in self.nodes:
                return self._err(404, "itemNotFound", "parent missing")
            name = json["name"]
            child = f"{low}/{name.lower()}" if low else name.lower()
            if child in self.nodes:
                if json.get("@microsoft.graph.conflictBehavior", "fail") == "fail":
                    return self._err(409, "nameAlreadyExists", "Name already exists")
            self.nodes[child] = {"id": f"I{next(_ids)}", "name": name, "is_dir": True, "mtime": _now()}
            return Resp(201, self._item(child))
        if tail == "/createUploadSession":
            sid = f"S{next(_ids)}"
            self.sessions[sid] = {"rel": rel, "buf": bytearray()}
            return Resp(200, {"uploadUrl": f"https://upload.fake/{sid}"})
        if tail == "/copy":
            if low not in self.nodes:
                return self._err(404, "itemNotFound", "source missing")
            parent_low = self._by_id(json["parentReference"]["id"])
            name = json["name"]
            dst = f"{parent_low}/{name.lower()}" if parent_low else name.lower()
            if dst in self.nodes:
                return Resp(202, b"", {"Location": "https://upload.fake/monitor/fail"})
            for k in self._subtree(low):
                n = dict(self.nodes[k])
                n["id"] = f"I{next(_ids)}"
                if k == low:
                    n["name"] = name
                self.nodes[dst + k[len(low):]] = n
            return Resp(202, b"", {"Location": "https://upload.fake/monitor/ok"})
        raise AssertionError(url)

    def patch(self, url, headers=None, json=None, timeout=None, **kw):
        self.calls.append(("PATCH", url, json))
        if t := self._throttled():
            return t
        kind, low, tail, q = self._parse(url)
        if low is None or low not in self.nodes:
            return self._err(404, "itemNotFound", "missing")
        parent = self._parent(low)
        if "parentReference" in json:
            parent = self._by_id(json["parentReference"]["id"])
            if parent is None:
                return self._err(404, "itemNotFound", "parent missing")
        name = json.get("name", self.nodes[low]["name"])
        dst = f"{parent}/{name.lower()}" if parent else name.lower()
        if dst.startswith(low + "/"):
            return self._err(400, "invalidRequest", "cannot move into itself")
        if dst in self.nodes and dst != low:
            if self.patch_conflict == "fail":
                return self._err(409, "nameAlreadyExists", "Name already exists")
            for k in self._subtree(dst):
                del self.nodes[k]
        moved = {}
        for k in self._subtree(low):
            n = self.nodes.pop(k)
            moved[dst + k[len(low):]] = n
        moved[dst]["name"] = name
        self.nodes.update(moved)
        return Resp(200, self._item(dst))

    def delete(self, url, headers=None, timeout=None, **kw):
        self.calls.append(("DELETE", url))
        if t := self._throttled():
            return t
        if url.startswith("https://upload.fake/S"):
            # cancelling an upload session: its fragments are dropped
            self.sessions.pop(url.rsplit("/", 1)[1], None)
            return Resp(204)
        kind, low, tail, q = self._parse(url)
        if low is None or low not in self.nodes:
            return self._err(404, "itemNotFound", "missing")
        for k in self._subtree(low):
            del self.nodes[k]
        return Resp(204)

    def put(self, url, headers=None, data=None, timeout=None, **kw):
        self.calls.append(("PUT", url, len(data or b"")))
        if t := self._throttled():
            return t
        if url.startswith("https://upload.fake/"):
            sid = url.rsplit("/", 1)[1]
            s = self.sessions[sid]
            m = re.match(r"bytes (\d+)-(\d+)/(\d+)", headers["Content-Range"])
            start, end, total = map(int, m.groups())
            assert start == len(s["buf"])
            s["buf"] += data
            if end + 1 == total:
                return self._store(s["rel"], bytes(s["buf"]))
            return Resp(202, {"nextExpectedRanges": [f"{end + 1}-"]})
        kind, rel, tail, q = self._parse(url)
        assert tail == "/content", url
        return self._store(rel, data)

    def _store(self, rel, data):
        low = rel.lower()
        if low in self.nodes and self.nodes[low]["is_dir"]:
            return self._err(409, "nameAlreadyExists", "a folder has this name")
        if not self._ensure_parents(rel):
            return self._err(409, "nameAlreadyExists", "a file is in the way")
        old = self.nodes.get(low)
        self.nodes[low] = {"id": old["id"] if old else f"I{next(_ids)}",
                           "name": old["name"] if old else posixpath.basename(rel),
                           "is_dir": False, "data": bytes(data), "mtime": _now(),
                           "version": (old.get("version", 1) + 1) if old else 1}
        return Resp(201, self._item(low))

    def close(self):
        pass


def make_session(graph=None):
    from core.onedrive_client import OneDriveSession

    s = object.__new__(OneDriveSession)
    s._http = graph or FakeGraph()
    s._drive_type = "personal"
    s._site_id = None
    s._access_token = "tok"
    s._ensure_token = lambda: None
    s._acquire_token = lambda: "tok"
    s._tenant_id = "t"
    s._COPY_POLL_INTERVAL = 0.0
    return s
