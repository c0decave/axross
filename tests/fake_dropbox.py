"""In-memory Dropbox API v2 fake for DropboxSession (the SDK's own types
and ApiError unions, so the client's error handling sees what it sees on
the wire).  Semantics modelled on the real service:

* paths are case-insensitive (path_lower), the display name is kept
* files/upload, files/create_folder_v2 create missing parents
* conflicts are WriteError.conflict, absences LookupError.not_found
* list_folder pages (PAGE entries per page) with has_more/cursor
"""

from __future__ import annotations

import hashlib
import io
import itertools
import posixpath
from datetime import datetime, timezone

import dropbox.files as F
from dropbox.exceptions import ApiError

PAGE = 2
_rev = itertools.count(0x100000000)


def _err(e):
    return ApiError("req", e, None, None)


class _Resp:
    def __init__(self, data):
        self._data = data

    def iter_content(self, n):
        for i in range(0, len(self._data), n or 1):
            yield self._data[i : i + n]

    def close(self):
        pass


class FakeDropbox:
    def __init__(self):
        # lower path -> dict(display, is_dir, data, mtime)
        self.nodes: dict[str, dict] = {"": {"display": "", "is_dir": True}}
        self.calls: list[tuple] = []
        self._cursors: dict[str, list] = {}

    # -- helpers -----------------------------------------------------------
    def _check(self, path):
        assert path == "" or path.startswith("/"), path
        return path.lower()

    def _md(self, low):
        n = self.nodes[low]
        name = posixpath.basename(n["display"])
        if n["is_dir"]:
            return F.FolderMetadata(name=name, id="id:" + low, path_lower=low,
                                    path_display=n["display"])
        return F.FileMetadata(
            name=name, id="id:" + low, path_lower=low, path_display=n["display"],
            client_modified=n["mtime"], server_modified=n["mtime"],
            rev=f"{n['rev']:x}", size=len(n["data"]),
            content_hash=hashlib.sha256(n["data"]).hexdigest(), is_downloadable=True,
        )

    def _lookup_error(self, low):
        # an ancestor that is a file -> not_folder, else not_found
        parent = posixpath.dirname(low)
        while parent not in ("", "/"):
            if parent in self.nodes and not self.nodes[parent]["is_dir"]:
                return F.LookupError.not_folder
            parent = posixpath.dirname(parent)
        return F.LookupError.not_found

    def _ensure_parents(self, display):
        """Create missing parents; a file in the way is a conflict."""
        parent = posixpath.dirname(display)
        chain = []
        while parent not in ("", "/"):
            chain.append(parent)
            parent = posixpath.dirname(parent)
        for p in reversed(chain):
            low = p.lower()
            if low in self.nodes:
                if not self.nodes[low]["is_dir"]:
                    return F.WriteError.conflict(F.WriteConflictError.file)
            else:
                self.nodes[low] = {"display": p, "is_dir": True}
        return None

    def _subtree(self, low):
        return [k for k in self.nodes if k == low or k.startswith(low + "/")]

    # -- routes ------------------------------------------------------------
    def users_get_current_account(self):
        return None

    def close(self):
        pass

    def files_get_metadata(self, path, **kw):
        self.calls.append(("get_metadata", path))
        low = self._check(path)
        if low not in self.nodes or low == "":
            raise _err(F.GetMetadataError.path(self._lookup_error(low)))
        return self._md(low)

    def files_list_folder(self, path, limit=None, **kw):
        self.calls.append(("list_folder", path))
        low = self._check(path)
        if low not in self.nodes:
            raise _err(F.ListFolderError.path(self._lookup_error(low)))
        if not self.nodes[low]["is_dir"]:
            raise _err(F.ListFolderError.path(F.LookupError.not_folder))
        prefix = (low + "/") if low else "/"
        kids = sorted(k for k in self.nodes if k.startswith(prefix) and k != low
                      and "/" not in k[len(prefix):])
        entries = [self._md(k) for k in kids]
        return self._page(entries, limit or PAGE)

    def _page(self, entries, size):
        head, rest = entries[:size], entries[size:]
        cursor = f"c{len(self._cursors)}"
        self._cursors[cursor] = rest
        return F.ListFolderResult(entries=head, cursor=cursor, has_more=bool(rest))

    def files_list_folder_continue(self, cursor):
        rest = self._cursors.pop(cursor)
        return self._page(rest, PAGE)

    def files_create_folder_v2(self, path, autorename=False):
        self.calls.append(("create_folder", path))
        low = self._check(path)
        if low in self.nodes:
            kind = F.WriteConflictError.folder if self.nodes[low]["is_dir"] else F.WriteConflictError.file
            raise _err(F.CreateFolderError.path(F.WriteError.conflict(kind)))
        e = self._ensure_parents(path)
        if e:
            raise _err(F.CreateFolderError.path(e))
        self.nodes[low] = {"display": path, "is_dir": True}
        return F.CreateFolderResult(metadata=self._md(low))

    def files_delete_v2(self, path, parent_rev=None):
        self.calls.append(("delete", path))
        low = self._check(path)
        if low not in self.nodes or low == "":
            raise _err(F.DeleteError.path_lookup(self._lookup_error(low)))
        md = self._md(low)
        for k in self._subtree(low):
            del self.nodes[k]
        return F.DeleteResult(metadata=md)

    def _relocate(self, from_path, to_path, keep):
        lf, lt = self._check(from_path), self._check(to_path)
        if lf not in self.nodes or lf == "":
            raise _err(F.RelocationError.from_lookup(self._lookup_error(lf)))
        if lt == lf and keep is False and from_path != to_path:
            pass  # case-only rename: allowed
        elif lt in self.nodes:
            kind = F.WriteConflictError.folder if self.nodes[lt]["is_dir"] else F.WriteConflictError.file
            raise _err(F.RelocationError.to(F.WriteError.conflict(kind)))
        if lt.startswith(lf + "/"):
            raise _err(F.RelocationError.cant_move_folder_into_itself)
        e = self._ensure_parents(to_path)
        if e:
            raise _err(F.RelocationError.to(e))
        moved = {}
        for k in self._subtree(lf):
            n = dict(self.nodes[k])
            n["display"] = to_path + n["display"][len(from_path):]
            if not n["is_dir"]:
                n["rev"] = next(_rev)
            moved[lt + k[len(lf):]] = n
        if not keep:
            for k in self._subtree(lf):
                del self.nodes[k]
        self.nodes.update(moved)
        return F.RelocationResult(metadata=self._md(lt))

    def files_move_v2(self, from_path, to_path, allow_shared_folder=False, autorename=False,
                      allow_ownership_transfer=False):
        self.calls.append(("move", from_path, to_path))
        return self._relocate(from_path, to_path, keep=False)

    def files_copy_v2(self, from_path, to_path, allow_shared_folder=False, autorename=False,
                      allow_ownership_transfer=False):
        self.calls.append(("copy", from_path, to_path))
        return self._relocate(from_path, to_path, keep=True)

    def _put(self, path, data, mode):
        low = self._check(path)
        if low in self.nodes and self.nodes[low]["is_dir"]:
            raise _err(F.UploadError.path(F.UploadWriteFailed(
                reason=F.WriteError.conflict(F.WriteConflictError.folder), upload_session_id="s")))
        if low in self.nodes and mode is not None and mode.is_add():
            raise _err(F.UploadError.path(F.UploadWriteFailed(
                reason=F.WriteError.conflict(F.WriteConflictError.file), upload_session_id="s")))
        e = self._ensure_parents(path)
        if e:
            raise _err(F.UploadError.path(F.UploadWriteFailed(reason=e, upload_session_id="s")))
        display = self.nodes[low]["display"] if low in self.nodes else path
        self.nodes[low] = {"display": display, "is_dir": False, "data": bytes(data),
                           "mtime": datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0),
                           "rev": next(_rev)}
        return self._md(low)

    def files_upload(self, f, path, mode=None, **kw):
        self.calls.append(("upload", path, len(f)))
        return self._put(path, f, mode)

    # upload sessions
    _sessions: dict = {}

    def files_upload_session_start(self, f, **kw):
        sid = f"s{len(self._sessions)}"
        self._sessions[sid] = bytearray(f)
        return F.UploadSessionStartResult(session_id=sid)

    def files_upload_session_append_v2(self, f, cursor, **kw):
        buf = self._sessions[cursor.session_id]
        assert cursor.offset == len(buf), (cursor.offset, len(buf))
        buf += f

    def files_upload_session_finish(self, f, cursor, commit, **kw):
        buf = self._sessions.pop(cursor.session_id)
        assert cursor.offset == len(buf)
        buf += f
        return self._put(commit.path, bytes(buf), commit.mode)

    def files_download(self, path, rev=None):
        self.calls.append(("download", path))
        low = self._check(path)
        if low not in self.nodes:
            raise _err(F.DownloadError.path(self._lookup_error(low)))
        if self.nodes[low]["is_dir"]:
            raise _err(F.DownloadError.path(F.LookupError.not_file))
        return self._md(low), _Resp(self.nodes[low]["data"])


def make_session(fake=None):
    from core.dropbox_client import DropboxSession

    s = object.__new__(DropboxSession)
    s._dbx = fake or FakeDropbox()
    s._proxies = {}
    return s
