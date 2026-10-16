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
        self.listings: dict[str, list] = {}  # per-directory entries (default: entries)
        self.calls: list[tuple[str, str]] = []  # (operation, UNC path)
        self.path = types.SimpleNamespace(
            isdir=self._isdir, exists=self._exists, islink=self._islink
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
