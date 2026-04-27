"""Spooled writer for the Git FileBackend. Lives in its own module
so the client doesn't grow another 30-line nested class."""
from __future__ import annotations

import io


class _GitWriter:
    def __init__(self, session, branch: str, sub: str, prelude: bytes = b""):
        self._session = session
        self._branch = branch
        self._sub = sub
        self._buf = io.BytesIO(prelude)
        if prelude:
            self._buf.seek(0, io.SEEK_END)
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("writer closed")
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._session._commit_modification(
            self._branch, self._sub,
            blob_data=self._buf.getvalue(),
            message=f"axross: write {self._sub}",
        )
        self._buf.close()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
