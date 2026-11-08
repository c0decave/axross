"""A transfer that writes straight to its destination never deletes or
empties the source when the destination is the source under another path.

The check that catches "the same folder under another path" (the temp file
looked for next to the source, ``_refuse_aliased_source``) ran only on the
temp-file route. The direct route - WebDAV, FTP, SCP, Telnet, ADB, rsync,
the cloud stores - never ran it: moving local ``X/report.txt`` to the same
folder reached over another protocol (axross's own WebDAV reverse-serve,
FTP or SCP to localhost) uploaded the same bytes, the size checks passed,
and ``remove(source)`` deleted the only copy. A move now writes an empty
probe file through the destination before it touches the destination and
looks for it next to the source. A copy onto itself through a writer that
truncates at open read back an empty source and "succeeded"; the rollback
snapshot of the destination now puts the bytes back.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

from core.local_fs import LocalFS
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker

DATA = b"the only copy of the report"


class _SpoolWriter(io.BytesIO):
    """Uploads on close, as WebDAV / FTP / SCP writers do."""

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path

    def discard(self) -> None:
        super().close()

    def close(self) -> None:
        if not self.closed:
            data = self.getvalue()
            super().close()
            with open(self._path, "wb") as f:
                f.write(data)


class _OtherProtocol:
    """A folder on this machine reached through another protocol: not a
    LocalFS, so no path or inode comparison can tell it is the same one."""

    name = "dav"

    def __init__(self, root: Path, *, truncating: bool = False) -> None:
        self.root = str(root)
        self.truncating = truncating
        self.written: list[str] = []

    def _r(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def separator(self) -> str:
        return "/"

    def parent(self, p: str) -> str:
        return os.path.dirname(p) or "/"

    def join(self, *parts: str) -> str:
        return "/".join(parts)

    def exists(self, p: str) -> bool:
        return os.path.exists(self._r(p))

    def is_dir(self, p: str) -> bool:
        return os.path.isdir(self._r(p))

    def stat(self, p: str):
        return LocalFS().stat(self._r(p))

    def open_read(self, p: str):
        return open(self._r(p), "rb")

    def open_write(self, p: str, append: bool = False):
        self.written.append(p)
        if self.truncating:
            return open(self._r(p), "ab" if append else "wb")
        return _SpoolWriter(self._r(p))

    def remove(self, p: str, recursive: bool = False) -> None:
        os.remove(self._r(p))


def _run(src: Path, dest_backend, dest_path: str, **kw) -> TransferJob:
    job = TransferJob(source_path=str(src), dest_path=dest_path, filename=src.name,
                      total_bytes=src.stat().st_size, use_temp_file=False, **kw)
    job.source_backend = LocalFS()
    job.dest_backend = dest_backend
    TransferWorker()._process_job(job)
    return job


def test_sad_a_direct_move_onto_its_own_folder_keeps_the_only_copy(tmp_path):
    src = tmp_path / "report.txt"
    src.write_bytes(DATA)
    job = _run(src, _OtherProtocol(tmp_path), "/report.txt", move=True)
    assert job.status == TransferStatus.ERROR
    assert "same" in job.error_message
    assert src.read_bytes() == DATA
    assert sorted(os.listdir(tmp_path)) == ["report.txt"]  # no probe left behind


def test_sad_a_direct_move_onto_its_own_folder_under_another_case_keeps_the_copy(tmp_path):
    src = tmp_path / "Report.TXT"
    src.write_bytes(DATA)

    class CaseInsensitive(_OtherProtocol):
        def _r(self, p):
            name = p.lstrip("/")
            for present in os.listdir(self.root):
                if present.casefold() == name.casefold():
                    return os.path.join(self.root, present)
            return os.path.join(self.root, name)

    job = _run(src, CaseInsensitive(tmp_path), "/report.txt", move=True)
    assert job.status == TransferStatus.ERROR
    assert src.read_bytes() == DATA


def test_sad_a_direct_copy_onto_itself_through_a_truncating_writer_keeps_the_bytes(tmp_path):
    src = tmp_path / "report.txt"
    src.write_bytes(DATA)
    job = _run(src, _OtherProtocol(tmp_path, truncating=True), "/report.txt")
    assert job.status == TransferStatus.ERROR
    assert src.read_bytes() == DATA


def test_sad_a_probe_that_cannot_be_written_refuses_the_move(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    src = tmp_path / "a" / "report.txt"
    src.write_bytes(DATA)
    (tmp_path / "b" / "report.txt").write_bytes(b"old")

    class NoProbe(_OtherProtocol):
        def open_write(self, p, append=False):
            if ".part-" in p:
                raise PermissionError("no new files here")
            return super().open_write(p, append)

    job = _run(src, NoProbe(tmp_path / "b"), "/report.txt", move=True)
    assert job.status == TransferStatus.ERROR
    assert "cannot rule out" in job.error_message
    assert src.read_bytes() == DATA
    assert (tmp_path / "b" / "report.txt").read_bytes() == b"old"


def test_happy_a_direct_move_over_a_namesake_elsewhere_still_moves(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    src = tmp_path / "a" / "report.txt"
    src.write_bytes(DATA)
    (tmp_path / "b" / "report.txt").write_bytes(b"old")
    job = _run(src, _OtherProtocol(tmp_path / "b"), "/report.txt", move=True)
    assert job.status == TransferStatus.DONE, job.error_message
    assert not src.exists()
    assert (tmp_path / "b" / "report.txt").read_bytes() == DATA
    assert os.listdir(tmp_path / "b") == ["report.txt"]  # the probe is gone


def test_happy_a_direct_copy_over_a_namesake_through_a_truncating_writer(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    src = tmp_path / "a" / "report.txt"
    src.write_bytes(DATA)
    (tmp_path / "b" / "report.txt").write_bytes(b"older and longer than the new one" * 3)
    job = _run(src, _OtherProtocol(tmp_path / "b", truncating=True), "/report.txt")
    assert job.status == TransferStatus.DONE, job.error_message
    assert (tmp_path / "b" / "report.txt").read_bytes() == DATA


def test_edge_a_direct_move_onto_a_free_name_writes_no_probe(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    src = tmp_path / "a" / "report.txt"
    src.write_bytes(DATA)
    dest = _OtherProtocol(tmp_path / "b")
    job = _run(src, dest, "/report.txt", move=True)
    assert job.status == TransferStatus.DONE, job.error_message
    assert dest.written == ["/report.txt"]  # nothing there, nothing to be the source


def test_edge_a_direct_move_under_a_new_name_writes_no_probe(tmp_path):
    src = tmp_path / "report.txt"
    src.write_bytes(DATA)
    (tmp_path / "renamed.txt").write_bytes(b"old")
    dest = _OtherProtocol(tmp_path)
    job = _run(src, dest, "/renamed.txt", move=True)
    assert job.status == TransferStatus.DONE, job.error_message
    assert dest.written == ["/renamed.txt"]
    assert (tmp_path / "renamed.txt").read_bytes() == DATA and not src.exists()
