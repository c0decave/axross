"""The transfer engine's generic guards follow what each backend's writes
really do (core.server_ops.WriteTraits).

What was wrong: the rollback snapshot, the alias probe, the size checks and
the resume by append all assumed a file system.

* Google Drive: open_write refused an overwrite because the path named
  another file than the one listed (ESTALE, round 1). The rollback then ran
  anyway and wrote the snapshot of the old file over the new one the refusal
  was protecting. Every direct-write store re-uploaded its snapshot the same
  way when the source failed to open. Nothing is rolled back now unless the
  writer was opened.
* IMAP / Exchange only add messages. The alias probe APPENDed a real mail
  that remove() could not take back, and a rollback APPENDed the snapshot
  as one more message. Neither runs on a store that only adds.
* Azure Files: a cancelled upload uploaded its partial, and a partial is
  "appended to" by downloading and uploading it whole, refused above 256
  MiB. Kept for a resume, such a partial failed every later copy of the
  file. No partial is kept or resumed there now.
* Exchange: stat() gives the EWS store size, but the copy is the MIME text,
  so every move of a mail was refused as a "short copy", and so was a copy
  onto an earlier export. Mail sizes are estimates now, and neither size
  guard compares them.
"""

from __future__ import annotations

import io
import os
import posixpath
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import (  # noqa: E402
    TransferDirection,
    TransferJob,
    TransferStatus,
    TransferWorker,
    partial_name,
    source_fingerprint,
)

MiB = 1 << 20


def _process(job: TransferJob) -> TransferJob:
    TransferWorker()._process_job(job)
    return job


# -- 1. no rollback before the writer is opened --------------------------------------


class _Exec:
    def __init__(self, fn):
        self.fn = fn

    def execute(self, *a, **k):
        return self.fn()


class _Drive:
    """files() of the Drive API: report.pdf (id B) was uploaded on the web
    after the pane listed the old report.pdf (id A, renamed away since)."""

    def __init__(self) -> None:
        self.meta = {
            "A": {"id": "A", "name": "report-old.pdf", "parent": "root",
                  "mimeType": "application/pdf"},
            "B": {"id": "B", "name": "report.pdf", "parent": "root",
                  "mimeType": "application/pdf"},
        }
        self.content = {"A": b"OLD version (renamed away on the web)",
                        "B": b"NEW version a colleague just uploaded"}
        self.updated: list[str] = []

    def files(self):
        return self

    def list(self, q=None, fields=None, pageSize=None, pageToken=None):
        parent = q.split("'")[1]

        def run():
            hits = [m for m in self.meta.values() if m["parent"] == parent]
            if "name = '" in q:
                name = q.split("name = '")[1].split("'")[0]
                hits = [m for m in hits if m["name"] == name]
            return {"files": hits}

        return _Exec(run)

    def get(self, fileId=None, fields=None):
        return _Exec(lambda: dict(self.meta[fileId], size=str(len(self.content[fileId]))))

    def get_media(self, fileId=None):
        return fileId

    def update(self, fileId=None, media_body=None, body=None, **kw):
        def run():
            self.updated.append(fileId)
            self.content[fileId] = media_body.read()
            return {"id": fileId}

        return _Exec(run)


def test_sad_a_refused_drive_overwrite_leaves_the_new_file_alone(tmp_path, monkeypatch):
    pytest.importorskip("googleapiclient")
    from core import gdrive_client as G

    drive = _Drive()
    monkeypatch.setattr(G, "_download_spooled", lambda fid: io.BytesIO(drive.content[fid]))
    monkeypatch.setattr(G, "MediaIoBaseUpload", lambda fd, **k: fd)
    session = G.GDriveSession.__new__(G.GDriveSession)
    session._service = drive
    session._path_cache = {"/": "root", "/report.pdf": "A"}  # the pane's last listing
    src = tmp_path / "report.pdf"
    src.write_bytes(b"local copy the user drags over")
    job = _process(TransferJob(source_path=str(src), dest_path="/report.pdf",
                               direction=TransferDirection.UPLOAD, source_backend=LocalFS(),
                               dest_backend=session, use_temp_file=False,
                               if_exists="overwrite", total_bytes=30))
    assert job.status == TransferStatus.ERROR
    assert "names another file" in job.error_message
    assert drive.updated == []
    assert drive.content["B"] == b"NEW version a colleague just uploaded"


class _CountingDest(LocalFS):
    """A direct-write destination (no temp file there) that counts writes."""

    def __init__(self) -> None:
        super().__init__()
        self.writes = 0

    def open_write(self, path, append=False):
        self.writes += 1
        return super().open_write(path, append)


class _Unreadable(LocalFS):
    def open_read(self, path):
        raise PermissionError(f"cannot open {path}")


def test_sad_a_source_that_does_not_open_uploads_nothing(tmp_path):
    """The source fails to open: the destination was not touched, and the
    rollback "restored" it - one more full upload of the old bytes."""
    (tmp_path / "src.txt").write_bytes(b"new")
    (tmp_path / "dst.txt").write_bytes(b"the destination as it was")
    dest = _CountingDest()
    job = _process(TransferJob(source_path=str(tmp_path / "src.txt"),
                               dest_path=str(tmp_path / "dst.txt"), filename="src.txt",
                               source_backend=_Unreadable(), dest_backend=dest,
                               use_temp_file=False, total_bytes=3))
    assert job.status == TransferStatus.ERROR
    assert dest.writes == 0
    assert (tmp_path / "dst.txt").read_bytes() == b"the destination as it was"


# -- 2. stores that only add: no probe, no snapshot, no rollback -----------------------

FETCH = (b"* 1 FETCH (UID 1 RFC822.SIZE 26 INTERNALDATE \"01-Jan-2026 10:00:00 +0000\" "
         b"ENVELOPE (\"Thu, 1 Jan 2026\" \"Hello world\" NIL NIL NIL NIL NIL NIL NIL NIL))\r\n")
NAME = "1_Hello world.eml"  # what the listing calls message 1


@pytest.fixture
def imap(monkeypatch):
    from core import imap_client as IC
    from mail_fuzz_servers import FakeImapServer

    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)
    servers, sessions = [], []

    def make():
        server = FakeImapServer(replies={"FETCH": FETCH})
        servers.append(server)
        session = IC.ImapSession(server.host, server.port, "u", "p", use_ssl=False)
        sessions.append(session)
        return server, session

    yield make
    for session in sessions:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
    for server in servers:
        server.close()


def _appends(server) -> list[str]:
    return [c for c in server.commands if " APPEND " in c]


def test_sad_an_imap_move_onto_an_existing_name_writes_no_probe_mail(imap):
    """The copy step of the move (the source's removal is IMAP's own)."""
    _src_server, src = imap()
    dst_server, dst = imap()
    job = TransferJob(source_path=f"/INBOX/{NAME}", dest_path=f"/INBOX/{NAME}",
                      filename=NAME, direction=TransferDirection.RELAY,
                      source_backend=src, dest_backend=dst, use_temp_file=False,
                      if_exists="overwrite", move=True, total_bytes=26)
    TransferWorker()._do_transfer(job, lambda done, total: None)
    assert len(_appends(dst_server)) == 1  # the mail, no empty probe mail besides


class _BreaksAfterFirstRead(LocalFS):
    def open_read(self, path):
        f = super().open_read(path)
        real, calls = f.read, []

        def read(n=-1):
            calls.append(n)
            if len(calls) > 1:
                raise OSError("connection reset")
            return real(n)

        f.read = read
        return f


def test_sad_a_failed_copy_onto_an_imap_message_appends_nothing(imap, tmp_path):
    """The copy fails half-way: the old message is still there (an APPEND
    replaces nothing), and the rollback APPENDed its snapshot as a second
    copy of it."""
    server, session = imap()
    src = tmp_path / NAME
    src.write_bytes(b"Subject: Hello world\r\n\r\n" + b"x" * (3 * MiB))
    job = _process(TransferJob(source_path=str(src), dest_path=f"/INBOX/{NAME}",
                               filename=NAME, direction=TransferDirection.UPLOAD,
                               source_backend=_BreaksAfterFirstRead(), dest_backend=session,
                               use_temp_file=False, if_exists="overwrite",
                               total_bytes=src.stat().st_size))
    assert job.status == TransferStatus.ERROR
    assert _appends(server) == []


# -- 3. Azure Files: no partial uploaded or resumed by a fake append --------------------


class _AzureFiles:
    """The share of an AzureFilesSession: rel path -> size (contents are
    not kept: only sizes matter here)."""

    def __init__(self) -> None:
        from azure.core.exceptions import ResourceNotFoundError

        self.missing = ResourceNotFoundError
        self.files: dict[str, int] = {}
        self.uploads: list[tuple[str, int]] = []
        self.downloads: list[str] = []

    def get_directory_client(self, rel):
        share = self

        class File:
            def __init__(self, name):
                self.rel = posixpath.join(rel, name) if rel else name

            def get_file_properties(self):
                if self.rel not in share.files:
                    raise share.missing("ResourceNotFound")
                return {"size": share.files[self.rel], "last_modified": None,
                        "content_settings": SimpleNamespace(content_md5=None)}

            def download_file(self):
                share.downloads.append(self.rel)
                size = share.files[self.rel]

                def chunks():
                    left = size
                    while left:
                        n = min(left, 4 * MiB)
                        left -= n
                        yield b"\0" * n

                return SimpleNamespace(size=size, chunks=chunks)

            def upload_file(self, buf, length):
                share.uploads.append((self.rel, length))
                share.files[self.rel] = length

            def delete_file(self):
                share.files.pop(self.rel)

            def rename_file(self, new):
                share.files[new] = share.files.pop(self.rel)

        class Dir:
            def get_file_client(self, name):
                return File(name)

            def get_directory_properties(self):
                if rel:
                    raise share.missing("ResourceNotFound")
                return {}

        return Dir()


def _azure_files(share):
    pytest.importorskip("azure.storage.fileshare")
    from core import azure_client as AC

    session = object.__new__(AC.AzureFilesSession)
    session._share = share
    return session


def test_sad_a_cancelled_azure_files_upload_uploads_no_partial(tmp_path):
    share = _AzureFiles()
    session = _azure_files(share)
    src = tmp_path / "disk.img"
    with open(src, "wb") as f:
        f.truncate(8 * MiB)
    job = TransferJob(source_path=str(src), dest_path="/disk.img",
                      direction=TransferDirection.UPLOAD, source_backend=LocalFS(),
                      dest_backend=session, use_temp_file=True, total_bytes=8 * MiB)

    def progress(done, total):
        if done >= 4 * MiB:
            raise InterruptedError("Transfer cancelled")

    with pytest.raises(InterruptedError):
        TransferWorker()._do_transfer(job, progress)
    assert share.uploads == [] and share.files == {}


def test_sad_an_azure_files_partial_over_the_append_bound_does_not_block_the_name(tmp_path):
    """A partial of 257 MiB left by an earlier cancel: its "resume" failed
    on the append bound and kept it, every time. Now it is dropped and the
    file copied whole - without downloading the partial first."""
    share = _AzureFiles()
    session = _azure_files(share)
    src = tmp_path / "disk.img"
    with open(src, "wb") as f:
        f.truncate(260 * MiB)
    local = LocalFS()
    fingerprint = source_fingerprint(local.stat(str(src)))
    partial = "/" + partial_name("disk.img", "oldjob01", fingerprint)
    share.files[partial.lstrip("/")] = 257 * MiB
    job = TransferJob(source_path=str(src), dest_path="/disk.img",
                      direction=TransferDirection.UPLOAD, source_backend=local,
                      dest_backend=session, use_temp_file=True, resume=True,
                      temp_path=partial, total_bytes=260 * MiB,
                      source_fingerprint=fingerprint)
    TransferWorker()._do_transfer(job, lambda a, b: None)
    assert share.files == {"disk.img": 260 * MiB}
    assert share.downloads == []


# -- 4. mail sizes are estimates ---------------------------------------------------------

MIME = b"Subject: hi\r\nFrom: a@b\r\n\r\n" + b"x" * 2000


def _exchange():
    from core import exchange_client as EC

    message = SimpleNamespace(id="AAMkAD", subject="hi", size=7400,  # the store's size
                              datetime_received=datetime(2026, 1, 2, tzinfo=timezone.utc),
                              mime_content=MIME, has_attachments=False)
    deleted: list[bool] = []
    message.delete = lambda: deleted.append(True)
    session = object.__new__(EC.ExchangeSession)

    def resolve(parts):
        if parts != ["Inbox"]:
            raise OSError("Exchange folder lookup: ErrorFolderNotFound") from FileNotFoundError()
        return SimpleNamespace(name="Inbox")

    def fetch(folder, segment, only=None):
        if not segment.startswith("AAMkAD"):
            raise OSError("Exchange message not found")
        return message

    session._resolve_folder = resolve
    session._fetch_message = fetch
    return session, deleted


def test_sad_an_exchange_mail_moves_although_its_store_size_is_larger(tmp_path):
    session, deleted = _exchange()
    assert session.stat("/Inbox/AAMkAD_hi.eml").size == 7400
    job = _process(TransferJob(source_path="/Inbox/AAMkAD_hi.eml",
                               dest_path=str(tmp_path / "AAMkAD_hi.eml"),
                               filename="AAMkAD_hi.eml", direction=TransferDirection.DOWNLOAD,
                               source_backend=session, dest_backend=LocalFS(), move=True,
                               total_bytes=7400))
    assert job.status == TransferStatus.DONE, job.error_message
    assert deleted == [True]
    assert (tmp_path / "AAMkAD_hi.eml").read_bytes() == MIME


def test_sad_an_exchange_mail_copies_over_an_earlier_export(tmp_path):
    """A direct-write destination (rollback snapshot, size compared): the
    short-copy guard fired on every copy onto an earlier export."""
    session, _deleted = _exchange()
    export = tmp_path / "AAMkAD_hi.eml"
    export.write_bytes(b"an earlier export")
    job = _process(TransferJob(source_path="/Inbox/AAMkAD_hi.eml", dest_path=str(export),
                               filename="AAMkAD_hi.eml", direction=TransferDirection.DOWNLOAD,
                               source_backend=session, dest_backend=_CountingDest(),
                               use_temp_file=False, total_bytes=7400))
    assert job.status == TransferStatus.DONE, job.error_message
    assert export.read_bytes() == MIME
    assert os.listdir(tmp_path) == ["AAMkAD_hi.eml"]
