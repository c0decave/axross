"""Cancel and progress during the network phase of a spooling backend.

Measured before (round-5 protocol review, repros in (round-5 protocol review):
the cloud, FTP, SCP, WebDAV, Telnet and IMAP writers only spool in
``write()`` and upload in ``close()``; OneDrive, Drive, Dropbox, S3, Azure,
WebDAV and SCP download the whole file inside ``open_read()``. The
transfer worker checked ``job.cancel_event`` only in its copy loop, so the
bar reached 100 % at disk speed, then the real upload ran to its end
whatever Cancel said (OneDrive: 3 chunk PUTs after Cancel, the file
committed, the job DONE), and a download could not be cancelled at all.

Now the worker hands the backends a core.transfer_hooks.TransferHooks for
the job: writers check Cancel between chunks during close() and report
network bytes, readers do so while they download, cloud_http's pauses
wake on Cancel, and a cancelled upload commits nothing (the OneDrive
upload session is deleted, S3's multipart upload aborted, Dropbox's
session never finished, Azure's blocks never committed).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import fake_onedrive  # noqa: E402

from core import cloud_http, transfer_hooks  # noqa: E402
from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _job(src_backend, src, dst_backend, dst, size, *, use_temp_file=False):
    return TW.TransferJob(source_path=src, dest_path=dst, filename=os.path.basename(dst),
                          total_bytes=size, source_backend=src_backend,
                          dest_backend=dst_backend, use_temp_file=use_temp_file)


@pytest.fixture
def small_onedrive_chunks(monkeypatch):
    from core import onedrive_client as O

    monkeypatch.setattr(O, "_SIMPLE_UPLOAD_MAX", 320 * 1024)
    monkeypatch.setattr(O, "_UPLOAD_CHUNK", 320 * 1024)
    return 320 * 1024


def _session_puts(graph):
    return [c for c in graph.calls if c[0] == "PUT" and c[1].startswith("https://upload.fake/")]


# ---------------------------------------------------------------- uploads
def test_sad_cancel_during_a_onedrive_upload_stops_it_and_drops_the_session(
        tmp_path, small_onedrive_chunks):
    graph = fake_onedrive.FakeGraph()
    od = fake_onedrive.make_session(graph)
    data = os.urandom(7 * small_onedrive_chunks)
    src = tmp_path / "big.bin"
    src.write_bytes(data)
    job = _job(LocalFS(), str(src), od, "/big.bin", len(data))
    put = graph.put

    def put_then_cancel(url, *a, **kw):
        answer = put(url, *a, **kw)
        if url.startswith("https://upload.fake/") and len(_session_puts(graph)) == 2:
            job.cancel_event.set()  # Cancel pressed while the upload runs
        return answer

    graph.put = put_then_cancel
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.CANCELLED
    assert len(_session_puts(graph)) == 2  # no chunk after the Cancel
    assert not od.exists("/big.bin")  # nothing committed
    assert graph.sessions == {}  # the session was deleted, not left to expire
    assert any(c[0] == "DELETE" and c[1].startswith("https://upload.fake/") for c in graph.calls)


def test_edge_cancel_of_a_onedrive_overwrite_keeps_the_old_file_without_restoring_it(
        tmp_path, small_onedrive_chunks):
    graph = fake_onedrive.FakeGraph()
    od = fake_onedrive.make_session(graph)
    with od.open_write("/doc.bin") as w:
        w.write(b"old content")
    data = os.urandom(5 * small_onedrive_chunks)
    src = tmp_path / "doc.bin"
    src.write_bytes(data)
    job = _job(LocalFS(), str(src), od, "/doc.bin", len(data))
    put = graph.put

    def put_then_cancel(url, *a, **kw):
        answer = put(url, *a, **kw)
        if url.startswith("https://upload.fake/"):
            job.cancel_event.set()
        return answer

    graph.put = put_then_cancel
    before = len(graph.calls)
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.CANCELLED
    with od.open_read("/doc.bin") as fh:
        assert fh.read() == b"old content"
    # UploadCancelled: nothing committed, so no snapshot is uploaded back.
    simple_puts = [c for c in graph.calls[before:]
                   if c[0] == "PUT" and c[1].endswith("/root:/doc.bin:/content")]
    assert simple_puts == []


def test_happy_the_bar_reaches_100_only_when_the_upload_is_done(tmp_path, small_onedrive_chunks):
    graph = fake_onedrive.FakeGraph()
    od = fake_onedrive.make_session(graph)
    data = os.urandom(5 * small_onedrive_chunks)
    src = tmp_path / "big.bin"
    src.write_bytes(data)
    job = _job(LocalFS(), str(src), od, "/big.bin", len(data))
    events: list[tuple] = []
    put = graph.put

    def slow_put(url, *a, **kw):
        if url.startswith("https://upload.fake/"):
            time.sleep(TW.PROGRESS_INTERVAL * 1.3)
            events.append(("put",))
        return put(url, *a, **kw)

    graph.put = slow_put
    worker = TW.TransferWorker()
    worker.progress.connect(lambda _id, done, total: events.append(("progress", done, total)))
    worker._process_job(job)
    assert job.status == TW.TransferStatus.DONE
    puts = [i for i, e in enumerate(events) if e == ("put",)]
    full = [i for i, e in enumerate(events) if e[0] == "progress" and e[1] == e[2] == len(data)]
    assert full and min(full) > puts[-1]  # not 100 % while chunks were still going up
    # Spooling the local file is no progress: nothing is on the server yet.
    assert all(e[1] == 0 for e in events[:puts[0]] if e[0] == "progress")
    between = [e[1] for e in events[puts[0]:puts[-1]] if e[0] == "progress"]
    assert between and all(0 < d < len(data) for d in between)  # moved with the chunks
    assert between == sorted(between)


def test_sad_cancel_during_an_ftp_upload_stops_the_stor_and_removes_the_partial(
        tmp_path, monkeypatch):
    from test_backend_conformance import _FtpServer

    from core.ftp_client import FtpSession

    root = tmp_path / "ftp"
    root.mkdir()
    srv = _FtpServer(root)
    ftp = FtpSession("127.0.0.1", srv.port, "u", "p")
    try:
        data = os.urandom(4 * 1024 * 1024)
        src = tmp_path / "big.bin"
        src.write_bytes(data)
        job = _job(LocalFS(), str(src), ftp, "/big.bin", len(data))
        reads = []
        read = transfer_hooks.ReadProgress.read

        def read_then_cancel(self, n=-1):
            reads.append(n)
            if len(reads) == 20:
                job.cancel_event.set()
            return read(self, n)

        monkeypatch.setattr(transfer_hooks.ReadProgress, "read", read_then_cancel)
        TW.TransferWorker()._process_job(job)
        assert job.status == TW.TransferStatus.CANCELLED
        assert len(reads) == 20  # STOR stopped at the Cancel, not after 4 MiB
        assert not (root / "big.bin").exists()  # the partial was rolled back
        assert [i.name for i in ftp.list_dir("/")] == []  # the session still works
    finally:
        ftp.close()
        srv.close()


# -------------------------------------------------------------- downloads
def test_sad_cancel_during_a_onedrive_download_ends_it_at_once(tmp_path):
    graph = fake_onedrive.FakeGraph()
    od = fake_onedrive.make_session(graph)
    data = os.urandom(4 * 1024 * 1024)
    with od.open_write("/big.bin") as w:
        w.write(data)
    dst = tmp_path / "big.bin"
    job = _job(od, "/big.bin", LocalFS(), str(dst), len(data), use_temp_file=True)
    served = []

    class _Body(fake_onedrive.Resp):
        def iter_content(self, n):
            for i in range(0, len(self.content), 256 * 1024):
                served.append(i)
                if len(served) == 3:
                    job.cancel_event.set()
                yield self.content[i:i + 256 * 1024]

    get = graph.get

    def get_slow(url, *a, **kw):
        answer = get(url, *a, **kw)
        if url.endswith(":/content"):
            answer.__class__ = _Body
        return answer

    graph.get = get_slow
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.CANCELLED
    assert len(served) == 3  # 3 of 16 pieces: not the whole download first
    assert list(tmp_path.iterdir()) == []


def test_happy_a_onedrive_download_reports_its_bytes_and_completes(tmp_path):
    graph = fake_onedrive.FakeGraph()
    od = fake_onedrive.make_session(graph)
    data = os.urandom(3 * 1024 * 1024 + 5)
    with od.open_write("/f.bin") as w:
        w.write(data)
    seen = []
    hooks = transfer_hooks.TransferHooks(threading.Event(),
                                         lambda kind, done, total: seen.append((kind, done)))
    with transfer_hooks.active(hooks):
        fh = od.open_read("/f.bin")
    assert fh.read() == data
    assert seen[-1] == ("download", len(data)) and len(seen) >= 3


# ------------------------------------------------------------ the pauses
def test_sad_a_retry_pause_wakes_on_cancel(monkeypatch):
    monkeypatch.setattr(cloud_http, "_sleep", cloud_http._wait)  # the real, cancellable wait
    event = threading.Event()
    threading.Timer(0.2, event.set).start()
    started = time.monotonic()
    with transfer_hooks.active(transfer_hooks.TransferHooks(event)):
        with pytest.raises(InterruptedError):
            cloud_http.pause(1, retry_after=30)  # a server's Retry-After: 30 s
    assert time.monotonic() - started < 5


def test_edge_a_pause_outside_a_transfer_still_sleeps(monkeypatch):
    slept = []
    monkeypatch.setattr(cloud_http, "_sleep", slept.append)
    cloud_http.pause(1, retry_after=2)
    assert slept == [2]


# ------------------------------------------------------- the bar's phases
class _Remote:
    """A backend that is not this machine's disk."""


def _phases(src, dst):
    shown = []
    job = TW.TransferJob(total_bytes=100, source_backend=src, dest_backend=dst)
    progress = TW._JobProgress(job, lambda done, total: shown.append(done))
    return job, progress, shown


def test_happy_local_to_a_spooling_cloud_counts_only_the_upload():
    job, p, shown = _phases(LocalFS(), _Remote())
    p.hooks.expect_upload()  # what the writer does in open_write
    p.copy_starts()
    p(50, 100)
    p(100, 100)  # the spool is full at disk speed: no movement
    assert max(shown) == 0
    p.copy_ends()
    p.hooks.sent(40, 100)
    p.hooks.sent(100, 100, check=False)
    assert shown[-2:] == [40, 100]


def test_happy_a_cloud_download_to_local_is_the_whole_bar():
    job, p, shown = _phases(_Remote(), LocalFS())
    p.hooks.received(30, 100)
    p.hooks.received(100, 100)
    p.copy_starts()
    p(100, 100)
    assert shown == [30, 100, 100]


def test_edge_remote_to_spooling_cloud_has_two_halves():
    job, p, shown = _phases(_Remote(), _Remote())
    p.hooks.expect_upload()
    p.copy_starts()
    p(100, 100)  # the SFTP-like source read: half the bar
    p.copy_ends()
    p.hooks.sent(50, 100)
    p.hooks.sent(100, 100, check=False)
    assert shown == [50, 75, 100]


def test_edge_the_bar_never_goes_back_inside_a_phase():
    job, p, shown = _phases(LocalFS(), _Remote())
    p.hooks.expect_upload()
    p.copy_starts()
    p.copy_ends()
    p.hooks.sent(60, 100)
    p.hooks.sent(30, 100)  # an upload resumed where the server said
    assert shown[-1] == 60


def test_sad_a_report_after_cancel_does_not_raise_once_committed():
    job, p, shown = _phases(LocalFS(), _Remote())
    job.cancel_event.set()
    p.hooks.sent(100, 100, check=False)  # the last chunk committed the file
    with pytest.raises(InterruptedError):
        p.hooks.sent(10, 100)


def test_edge_a_plain_callback_still_works_for_old_callers(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(b"x" * 10)
    job = _job(LocalFS(), str(src), LocalFS(), str(tmp_path / "b"), 10)
    seen = []
    assert TW.TransferWorker()._do_transfer_direct(job, lambda t, n: seen.append(t)) == 10
    assert seen == [10]


# ---------------------------------------------------- per-backend writers
def _hooks_cancelled_after(calls: int):
    event = threading.Event()
    count = [0]

    def progress(kind, done, total):
        count[0] += 1
        if count[0] >= calls:
            event.set()

    return transfer_hooks.TransferHooks(event, progress), event


def test_sad_azure_blob_cancel_between_blocks_commits_nothing(monkeypatch):
    from core import azure_client as A

    monkeypatch.setattr(A, "_BLOCK", 1024)
    pytest.importorskip("azure.storage.blob")

    class Blob:
        def __init__(self):
            self.staged, self.committed = [], None

        def stage_block(self, block_id, data):
            self.staged.append((block_id, bytes(data)))

        def commit_block_list(self, blocks):
            self.committed = blocks

        def upload_blob(self, *a, **kw):
            raise AssertionError("a multi-block upload goes up block by block")

    blob = Blob()
    hooks, _ = _hooks_cancelled_after(2)
    with transfer_hooks.active(hooks):
        w = A._BlobSpooledWriter(blob, "/b.bin")
    w.write(b"z" * 5000)
    with pytest.raises(transfer_hooks.UploadCancelled):
        w.close()
    assert len(blob.staged) == 2 and blob.committed is None
    assert len({b[0] for b in blob.staged}) == 2


def test_happy_azure_blob_blocks_commit_in_order(monkeypatch):
    from core import azure_client as A

    monkeypatch.setattr(A, "_BLOCK", 1024)
    pytest.importorskip("azure.storage.blob")

    class Blob:
        def __init__(self):
            self.staged, self.committed = {}, None

        def stage_block(self, block_id, data):
            self.staged[block_id] = bytes(data)

        def commit_block_list(self, blocks):
            self.committed = b"".join(self.staged[b.id] for b in blocks)

    blob = Blob()
    data = os.urandom(3000)
    with transfer_hooks.active(transfer_hooks.TransferHooks(threading.Event())):
        w = A._BlobSpooledWriter(blob, "/b.bin")
    w.write(data)
    w.close()
    assert blob.committed == data


def test_sad_webdav_put_cancelled_mid_body_is_an_interrupted_error():
    from core.webdav_client import _SpooledWriter

    class Client:
        blocks = 0

        def upload_from(self, fileobj, path):
            while fileobj.read(8192):  # as http.client sends a file body
                self.blocks += 1

    client = Client()
    hooks, _ = _hooks_cancelled_after(3)
    with transfer_hooks.active(hooks):
        w = _SpooledWriter(client, "/x.bin")
    w.write(b"q" * 100_000)
    with pytest.raises(InterruptedError):
        w.close()
    assert client.blocks == 3


def test_sad_telnet_upload_stops_between_heredocs():
    from core import telnet_client as T

    class Shell:
        def __init__(self):
            self.commands = []

        def execute_checked(self, cmd, timeout=None):
            self.commands.append(cmd)
            return ""

    caps = T._Capabilities(has_base64=True, transfer_method="base64")
    shell = Shell()
    hooks, event = _hooks_cancelled_after(1)
    with transfer_hooks.active(hooks):
        w = T._SpooledWriter(shell, "/r.bin", caps)
    w.write(os.urandom(3 * 57 * (T.MAX_HEREDOC_CHARS // 77)))
    with pytest.raises(InterruptedError):
        w.close()
    # 3 heredocs of the file; Cancel after the report that follows the
    # first: the second was under way, the third is never sent.
    assert len(shell.commands) == 2


def test_sad_scp_upload_streams_and_stops_on_cancel():
    from core import scp_client as S

    sent = []

    def exec_fn(cmd, timeout, stdin_data=None):
        for chunk in S._chunks(stdin_data):
            sent.append(len(chunk))

    caps = S._Capabilities(has_base64=True, transfer_method="base64")
    hooks, _ = _hooks_cancelled_after(2)
    with transfer_hooks.active(hooks):
        w = S._SpooledWriter(exec_fn, "/r.bin", caps)
    w.write(os.urandom(1024 * 1024))
    with pytest.raises(InterruptedError):
        w.close()
    assert len(sent) == 2  # pieces of 48 KiB (base64 of them), not the whole file


def test_sad_imap_append_is_not_sent_after_cancel():
    from core.imap_client import _SpooledWriter

    class Imap:
        appended = 0

        def append(self, *a):
            self.appended += 1
            return "OK", [b""]

    imap = Imap()
    event = threading.Event()
    with transfer_hooks.active(transfer_hooks.TransferHooks(event)):
        w = _SpooledWriter(imap, "INBOX")
    w.write(b"Subject: x\r\n\r\nbody")
    event.set()
    with pytest.raises(transfer_hooks.UploadCancelled):
        w.close()
    assert imap.appended == 0


def test_edge_writers_without_a_transfer_behave_as_before():
    from core.webdav_client import _SpooledWriter

    class Client:
        body = None

        def upload_from(self, fileobj, path):
            self.body = fileobj.read()

    client = Client()
    w = _SpooledWriter(client, "/x")
    w.write(b"abc")
    w.close()
    assert client.body == b"abc"


def test_happy_ftp_shared_connection_reads_the_reply_of_a_cancelled_stor():
    from core import ftp_client as F

    class Ftp:
        replies = 0

        def storbinary(self, cmd, fp):
            while fp.read(8192):
                pass

        def voidresp(self):
            self.replies += 1
            raise F.error_temp("426 Connection closed; transfer aborted.")

    ftp = Ftp()
    hooks, _ = _hooks_cancelled_after(2)
    with transfer_hooks.active(hooks):
        w = F._SpooledWriter(ftp, "/f.bin")
    w.write(b"x" * 100_000)
    with pytest.raises(InterruptedError):
        w.close()
    assert ftp.replies == 1  # the 426 was read: the next command gets its own answer


def test_sad_errno_of_a_cancel_is_not_lost_in_a_typed_wrapper():
    from core.azure_client import _azure_error
    from core.gdrive_client import _drive_error
    from core.s3_client import _s3_error

    for typed in (_azure_error, _drive_error, _s3_error):
        assert type(typed(InterruptedError("Transfer cancelled"), "x")) is InterruptedError
        cancelled = typed(transfer_hooks.UploadCancelled("Transfer cancelled"), "x")
        assert isinstance(cancelled, transfer_hooks.UploadCancelled)
