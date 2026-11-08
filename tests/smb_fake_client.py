"""A scripted stand-in for the ``smbclient`` module, for the SMB fuzz tests.

There is no in-process SMB2 server to point smbprotocol at, so the SMB
tests replace ``core.smb_client.smbclient`` with this fake. It returns
directory entries and stat results the test controls (odd attributes,
FILETIMEs at the datetime range edges, huge or negative sizes, odd names)
and raises what smbprotocol raises from a broken or hostile server:
SMBOSError for an error status, SMBException for a bad signature or a
closed connection, and - because smbprotocol's message worker stores any
exception from parsing a server message and re-raises it in the caller
(smbprotocol/connection.py _process_message_thread / _check_worker_running)
- KeyError, struct.error, ValueError.
"""

from __future__ import annotations

import io
import types
from datetime import datetime, timezone

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def smb_info(written=None, attrs: int = 0x20, size: int = 5):
    return types.SimpleNamespace(
        last_write_time=written
        if written is not None
        else datetime(2024, 1, 2, tzinfo=timezone.utc),
        file_attributes=attrs,
        end_of_file=size,
    )


class DirEntry:
    def __init__(self, name, info=None, symlink: bool = False) -> None:
        self.name = name
        self.path = f"\\\\h\\s\\{name}"
        self.smb_info = info if info is not None else smb_info()
        self._symlink = symlink

    def is_symlink(self) -> bool:
        return self._symlink


class StatResult:
    def __init__(self, mode: int, size: int, mtime_ns: int) -> None:
        self.st_mode, self.st_size, self.st_mtime_ns = mode, size, mtime_ns


class FakeSmbClient:
    def __init__(self) -> None:
        self.entries: list = [
            DirEntry("a.txt"),
            DirEntry("sub", smb_info(attrs=0x10, size=0)),
        ]
        self.stat_value = StatResult(0o100644, 5, 1_704_164_645_000_000_000)
        self.content = b"hello"
        self.fail: BaseException | None = None
        self.links: set[str] = set()  # UNC paths that are symlinks
        self.junctions: set[str] = set()  # UNC paths that are junctions (reparse points)
        self.listings: dict[str, list] = {}  # per-directory entries (default: entries)
        self.calls: list[tuple[str, str]] = []  # (operation, UNC path)
        self.path = types.SimpleNamespace(
            isdir=self._isdir, exists=self._exists, lexists=self._exists, islink=self._islink
        )

    def _maybe_fail(self) -> None:
        if self.fail is not None:
            raise self.fail

    def scandir(self, unc, **_kw):
        self._maybe_fail()
        self.calls.append(("scandir", unc))
        return iter(list(self.listings.get(unc, self.entries)))

    def listdir(self, unc, **_kw):
        self._maybe_fail()
        return [e.name for e in self.entries]

    def stat(self, unc, **_kw):
        self._maybe_fail()
        return self.stat_value

    def lstat(self, unc, **_kw):
        self._maybe_fail()
        result = StatResult(0o40755, 0, 0)
        result.st_file_attributes = 0x410 if unc in self.junctions else 0x10
        return result

    def _isdir(self, unc, **_kw):
        self._maybe_fail()
        return unc.endswith("sub")

    def _exists(self, unc, **_kw):
        self._maybe_fail()
        return True

    def _islink(self, unc, **_kw):
        self._maybe_fail()
        return unc in self.links

    def open_file(self, unc, mode="rb", **_kw):
        self._maybe_fail()
        return io.BytesIO(self.content)

    def mkdir(self, unc, **_kw):
        self._maybe_fail()

    def rmdir(self, unc, **_kw):
        self._maybe_fail()
        self.calls.append(("rmdir", unc))

    def remove(self, unc, **_kw):
        self._maybe_fail()
        self.calls.append(("remove", unc))

    def rename(self, src, dst, **_kw):
        self._maybe_fail()

    def delete_session(self, *a, **k):
        pass


def make_session(fake: FakeSmbClient):
    from core.smb_client import SmbSession

    s = SmbSession.__new__(SmbSession)
    s._host, s._share, s._port = "h", "s", 445
    s._prefix = "\\\\h\\s"
    return s


# -- a stateful smbclient over a local folder ------------------------------------

UNC_PREFIX = "\\\\h\\s"


class LocalSmbClient:
    """``smbclient`` over a local folder, for the conformance suite.

    Behaves like smbclient 1.17 against a Windows / Samba server where the
    backend contract depends on it: every path goes through
    ``ntpath.normpath`` (smbclient._pool.get_smb_tree - a trailing
    backslash is dropped), and every failure is the SMBOSError smbprotocol
    raises for the NT status the server answers (NAME_NOT_FOUND ->
    ENOENT, NAME_COLLISION -> EEXIST, ACCESS_DENIED -> errno 0, ...), not
    an OSError subclass. A rename does not replace an existing name.
    """

    def __init__(self, root: str) -> None:
        self.root = root
        self.path = types.SimpleNamespace(
            isdir=self._isdir, exists=self._exists, lexists=self._lexists, islink=self._islink
        )

    @staticmethod
    def _error(status: int, unc: str):
        from smbprotocol.exceptions import SMBOSError

        return SMBOSError(status, unc)

    def _local(self, unc: str) -> str:
        import ntpath
        import os

        norm = ntpath.normpath(unc)
        if not norm.lower().startswith(UNC_PREFIX.lower()):
            raise ValueError(f"not on this share: {unc!r}")
        rel = norm[len(UNC_PREFIX):].lstrip("\\")
        return os.path.join(self.root, *[p for p in rel.split("\\") if p])

    def _missing(self, unc: str, local: str):
        import os

        from smbprotocol.header import NtStatus

        status = (NtStatus.STATUS_OBJECT_NAME_NOT_FOUND if os.path.isdir(os.path.dirname(local))
                  else NtStatus.STATUS_OBJECT_PATH_NOT_FOUND)
        return self._error(status, unc)

    def stat(self, unc, follow_symlinks=True, **_kw):
        import os

        from smbprotocol.header import NtStatus

        local = self._local(unc)
        try:
            return os.stat(local) if follow_symlinks else os.lstat(local)
        except FileNotFoundError:
            raise self._missing(unc, local) from None
        except NotADirectoryError:
            raise self._error(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, unc) from None

    def lstat(self, unc, **kw):
        return self.stat(unc, follow_symlinks=False, **kw)

    def _answers(self, fn, unc, **kw):
        try:
            return fn(unc, **kw)
        except OSError as e:
            if e.errno == 2:
                return None
            raise

    def _exists(self, unc, **kw):
        return self._answers(self.stat, unc, **kw) is not None

    def _lexists(self, unc, **kw):
        return self._answers(self.lstat, unc, **kw) is not None

    def _isdir(self, unc, **kw):
        import stat as S

        st = self._answers(self.stat, unc, **kw)
        return st is not None and S.S_ISDIR(st.st_mode)

    def _islink(self, unc, **kw):
        import stat as S

        st = self._answers(self.lstat, unc, **kw)
        return st is not None and S.S_ISLNK(st.st_mode)

    def scandir(self, unc, **_kw):
        import ntpath
        import os

        from smbprotocol.header import NtStatus

        local = self._local(unc)
        if not os.path.lexists(local):
            raise self._missing(unc, local)
        if not os.path.isdir(local):
            raise self._error(NtStatus.STATUS_NOT_A_DIRECTORY, unc)
        out = []
        for e in os.scandir(local):
            st = os.lstat(e.path)
            attrs = 0x10 if e.is_dir(follow_symlinks=False) else 0x20
            if e.is_symlink():
                attrs |= 0x400
            info = types.SimpleNamespace(
                last_write_time=datetime.fromtimestamp(st.st_mtime, timezone.utc),
                file_attributes=attrs,
                end_of_file=st.st_size,
            )
            entry = types.SimpleNamespace(name=e.name, path=ntpath.normpath(unc) + "\\" + e.name,
                                          smb_info=info)
            entry.is_symlink = (lambda link=e.is_symlink(): link)
            out.append(entry)
        return iter(out)

    def listdir(self, unc, **kw):
        return [e.name for e in self.scandir(unc, **kw)]

    def mkdir(self, unc, **_kw):
        import os

        from smbprotocol.header import NtStatus

        local = self._local(unc)
        if os.path.lexists(local):
            raise self._error(NtStatus.STATUS_OBJECT_NAME_COLLISION, unc)
        if not os.path.isdir(os.path.dirname(local)):
            raise self._error(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, unc)
        os.mkdir(local)

    def rmdir(self, unc, **_kw):
        import os

        from smbprotocol.header import NtStatus

        local = self._local(unc)
        if os.path.islink(local):
            os.unlink(local)  # FILE_OPEN_REPARSE_POINT: the link goes
            return
        if not os.path.lexists(local):
            raise self._missing(unc, local)
        if not os.path.isdir(local):
            raise self._error(NtStatus.STATUS_NOT_A_DIRECTORY, unc)
        if os.listdir(local):
            raise self._error(NtStatus.STATUS_DIRECTORY_NOT_EMPTY, unc)
        os.rmdir(local)

    def remove(self, unc, **_kw):
        import os

        from smbprotocol.header import NtStatus

        local = self._local(unc)
        if not os.path.lexists(local):
            raise self._missing(unc, local)
        if os.path.isdir(local) and not os.path.islink(local):
            raise self._error(NtStatus.STATUS_FILE_IS_A_DIRECTORY, unc)
        os.unlink(local)

    def rename(self, src, dst, **_kw):
        import os

        from smbprotocol.header import NtStatus

        s, d = self._local(src), self._local(dst)
        if not os.path.lexists(s):
            raise self._missing(src, s)
        if os.path.lexists(d):
            raise self._error(NtStatus.STATUS_OBJECT_NAME_COLLISION, dst)
        if not os.path.isdir(os.path.dirname(d)):
            raise self._error(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, dst)
        if os.path.isdir(s) and (d + os.sep).startswith(s + os.sep):
            raise self._error(NtStatus.STATUS_INVALID_PARAMETER, src)
        os.rename(s, d)

    def utime(self, unc, times=None, **_kw):
        import os

        os.utime(self._local(unc), times)

    def open_file(self, unc, mode="rb", **_kw):
        import os

        from smbprotocol.header import NtStatus

        local = self._local(unc)
        if os.path.isdir(local):
            raise self._error(NtStatus.STATUS_FILE_IS_A_DIRECTORY, unc)
        if "r" in mode and not os.path.exists(local):
            raise self._missing(unc, local)
        if not os.path.isdir(os.path.dirname(local)):
            raise self._error(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, unc)
        return open(local, mode)

    def delete_session(self, *a, **k):
        pass


def make_local_session(root: str):
    """``(session, fake)``: an SmbSession whose ``smbclient`` is a
    :class:`LocalSmbClient` over *root*. The caller patches
    ``core.smb_client.smbclient`` with the fake."""
    fake = LocalSmbClient(root)
    return make_session(fake), fake
