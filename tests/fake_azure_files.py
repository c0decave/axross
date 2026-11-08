"""In-memory Azure Files share fake for AzureFilesSession._share.

Modelled on the File service: real directories, case-insensitive and
case-preserving names, Create File on an existing file replaces it,
Create Directory / Rename onto a taken name -> 409 ResourceAlreadyExists,
a missing parent -> 404 ParentNotFound, Delete Directory of a non-empty
one -> 409 DirectoryNotEmpty, file ops on a directory -> 409
ResourceTypeMismatch (and the other way round).
"""

from __future__ import annotations

import hashlib
import posixpath
from datetime import datetime, timezone
from types import SimpleNamespace

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError


def _e(cls, code, msg):
    exc = cls(message=f"{msg}\nErrorCode:{code}")
    exc.error_code = code
    return exc


def _nf(code="ResourceNotFound"):
    return _e(ResourceNotFoundError, code, "The specified resource does not exist.")


class _Paged:
    def __init__(self, items, page=2):
        self.items, self.page = items, page

    def __iter__(self):
        return iter(self.items)

    def by_page(self):
        outer = self

        class Pages:
            continuation_token = None

            def __init__(s):
                s._i = 0

            def __iter__(s):
                return s

            def __next__(s):
                if s._i >= len(outer.items):
                    raise StopIteration
                chunk = outer.items[s._i : s._i + outer.page]
                s._i += outer.page
                s.continuation_token = f"m{s._i}" if s._i < len(outer.items) else None
                return iter(chunk)

        return Pages()


class FakeShare:
    def __init__(self):
        # lower rel path -> {"name": display leaf, "dir": bool, "data", "mtime"}
        self.nodes = {"": {"name": "", "dir": True, "mtime": datetime.now(timezone.utc)}}
        self.calls = []

    def get_directory_client(self, path=""):
        return _Dir(self, path.strip("/"))

    # helpers
    def low(self, rel):
        return rel.strip("/").lower()

    def parent_ok(self, rel):
        par = self.low(posixpath.dirname(rel))
        return par in self.nodes and self.nodes[par]["dir"]


class _Dir:
    def __init__(self, share, rel):
        self.share, self.rel = share, rel

    @property
    def _low(self):
        return self.share.low(self.rel)

    def get_file_client(self, name):
        return _File(self.share, posixpath.join(self.rel, name) if self.rel else name)

    def get_directory_properties(self):
        n = self.share.nodes.get(self._low)
        if n is None:
            raise _nf("ResourceNotFound" if self.share.parent_ok(self.rel) else "ParentNotFound")
        if not n["dir"]:
            raise _e(HttpResponseError, "ResourceTypeMismatch", "type mismatch")
        return {"last_modified": n["mtime"], "name": n["name"]}

    def list_directories_and_files(self, include=None, **kw):
        n = self.share.nodes.get(self._low)
        if n is None or not n["dir"]:
            raise _nf("ResourceNotFound")
        pre = self._low + "/" if self._low else ""
        out = []
        for k, v in sorted(self.share.nodes.items()):
            if k and k.startswith(pre) and "/" not in k[len(pre):]:
                item = {"name": v["name"], "is_directory": v["dir"]}
                if not v["dir"]:
                    item["size"] = len(v["data"])
                    if include:
                        item["last_modified"] = v["mtime"]
                out.append(item)
        return _Paged(out)

    def create_directory(self, **kw):
        if self._low in self.share.nodes:
            raise _e(ResourceExistsError, "ResourceAlreadyExists", "The specified resource already exists.")
        if not self.share.parent_ok(self.rel):
            raise _nf("ParentNotFound")
        self.share.nodes[self._low] = {"name": posixpath.basename(self.rel), "dir": True,
                                       "mtime": datetime.now(timezone.utc)}

    def delete_directory(self, **kw):
        n = self.share.nodes.get(self._low)
        if n is None:
            raise _nf()
        if not n["dir"]:
            raise _e(HttpResponseError, "ResourceTypeMismatch", "type mismatch")
        if any(k.startswith(self._low + "/") for k in self.share.nodes):
            raise _e(ResourceExistsError, "DirectoryNotEmpty", "The specified directory is not empty.")
        del self.share.nodes[self._low]

    def rename_directory(self, new_name, overwrite=None, **kw):
        return _rename(self.share, self.rel, new_name, want_dir=True, overwrite=overwrite)


def _rename(share, rel, new_rel, want_dir, overwrite):
    lo, ln = share.low(rel), share.low(new_rel)
    n = share.nodes.get(lo)
    if n is None or n["dir"] != want_dir:
        raise _nf()
    if ln.startswith(lo + "/"):
        raise _e(HttpResponseError, "InvalidResourceName", "cannot move into itself")
    if ln in share.nodes and ln != lo:
        if not overwrite or share.nodes[ln]["dir"]:
            raise _e(ResourceExistsError, "ResourceAlreadyExists", "The specified resource already exists.")
        del share.nodes[ln]
    if not share.parent_ok(new_rel):
        raise _nf("ParentNotFound")
    moved = {}
    for k in [k for k in share.nodes if k == lo or k.startswith(lo + "/")]:
        moved[ln + k[len(lo):]] = share.nodes.pop(k)
    moved[ln] = dict(moved[ln], name=posixpath.basename(new_rel.strip("/")))
    share.nodes.update(moved)


class _File:
    def __init__(self, share, rel):
        self.share, self.rel = share, rel.strip("/")
        self.url = "mem://" + self.rel

    @property
    def _low(self):
        return self.share.low(self.rel)

    def get_file_properties(self):
        n = self.share.nodes.get(self._low)
        if n is None:
            raise _nf("ResourceNotFound" if self.share.parent_ok(self.rel) else "ParentNotFound")
        if n["dir"]:
            raise _e(HttpResponseError, "ResourceTypeMismatch", "type mismatch")
        props = {"size": len(n["data"]), "last_modified": n["mtime"], "name": n["name"]}

        class P(dict):
            pass
        p = P(props)
        p.content_settings = SimpleNamespace(content_md5=n.get("md5"))
        p.copy = SimpleNamespace(status="success", status_description="")
        return p

    def upload_file(self, data, length=None, **kw):
        body = data.read() if hasattr(data, "read") else bytes(data)
        if not self.share.parent_ok(self.rel):
            raise _nf("ParentNotFound")
        n = self.share.nodes.get(self._low)
        if n is not None and n["dir"]:
            raise _e(HttpResponseError, "ResourceTypeMismatch", "type mismatch")
        self.share.nodes[self._low] = {"name": n["name"] if n else posixpath.basename(self.rel),
                                       "dir": False, "data": body,
                                       "mtime": datetime.now(timezone.utc)}

    def download_file(self, **kw):
        n = self.share.nodes.get(self._low)
        if n is None:
            raise _nf()
        if n["dir"]:
            raise _e(HttpResponseError, "ResourceTypeMismatch", "type mismatch")
        data = n["data"]
        return SimpleNamespace(size=len(data), chunks=lambda: iter([data] if data else []))

    def delete_file(self, **kw):
        n = self.share.nodes.get(self._low)
        if n is None:
            raise _nf("ResourceNotFound" if self.share.parent_ok(self.rel) else "ParentNotFound")
        if n["dir"]:
            raise _e(HttpResponseError, "ResourceTypeMismatch", "type mismatch")
        del self.share.nodes[self._low]

    def rename_file(self, new_name, overwrite=None, **kw):
        return _rename(self.share, self.rel, new_name, want_dir=False, overwrite=overwrite)

    def start_copy_from_url(self, url, **kw):
        src = self.share.nodes.get(self.share.low(url[len("mem://"):]))
        if src is None or src["dir"]:
            raise _nf()
        if not self.share.parent_ok(self.rel):
            raise _nf("ParentNotFound")
        n = self.share.nodes.get(self._low)
        if n is not None and n["dir"]:
            raise _e(HttpResponseError, "ResourceTypeMismatch", "type mismatch")
        self.share.nodes[self._low] = dict(src, name=n["name"] if n else posixpath.basename(self.rel),
                                           mtime=datetime.now(timezone.utc))


def make_session(share=None):
    from core.azure_client import AzureFilesSession

    s = object.__new__(AzureFilesSession)
    s._share = share or FakeShare()
    s._share_name = "share"
    return s
