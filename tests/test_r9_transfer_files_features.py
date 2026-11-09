"""Round-9 files and features findings: partials and short local copies,
and four messages.

Measured before (review round 9):

* A plain copy of a local file that got shorter while it was read ended
  DONE with the short file - over an existing destination too (a move was
  already refused).
* Two axross processes, the first one's writer stalled: the second claimed
  the first one's partial, found other bytes in it and restarted at offset
  0 in the same file the stalled writer still held open - with a destination
  written by path (SFTP, SMB ...) the stalled writer then wrote into the
  committed copy: a torn file, and a move had deleted its source.
* Copying a file again right after Cancel (F5 again, not Retry) started at
  0 - the 30 s idle rule kept this process's own cancelled partial - and
  left that partial behind beside the finished copy.
* A batch undo of a folder move whose file was renamed inside it said
  "[Errno 2] No such file or directory: ...".
* ``axross --script`` tracebacks began with main.py's and the runner's
  frames.
* A failing agent tool showed "error - error: ..." in the transcript.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_manager as TM  # noqa: E402
from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

KIB = 1024
_ROOT = Path(__file__).resolve().parents[1]
_APP = None


@pytest.fixture(autouse=True)
def _journal(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))


def _app():
    global _APP
    from PyQt6.QtWidgets import QApplication

    _APP = QApplication.instance() or QApplication([])
    return _APP


def _job(src: Path, dest: Path, source_backend, dest_backend, **kw) -> TransferJob:
    st = src.stat()
    job = TransferJob(source_path=str(src), dest_path=str(dest), filename=src.name,
                      total_bytes=st.st_size, source_mtime=st.st_mtime, **kw)
    job.source_backend = source_backend
    job.dest_backend = dest_backend
    return job


def _wait(mgr, timeout=30.0) -> None:
    app = _app()
    deadline = time.monotonic() + timeout
    while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in mgr.all_jobs()):
        app.processEvents()
        assert time.monotonic() < deadline, "transfers did not finish"
        time.sleep(0.01)


def _pump_until(check, timeout=10.0) -> bool:
    app = _app()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if check():
            return True
        time.sleep(0.01)
    return check()


def _partials(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir() if TW.PARTIAL_MARK in p.name)


class _CutLocal(LocalFS):
    """A local source whose read ends after *cut* bytes, as a file another
    program truncated while it was copied."""

    def __init__(self, cut: int) -> None:
        super().__init__()
        self.cut = cut

    def open_read(self, path):
        handle = super().open_read(path)
        return io.BytesIO(handle.read(self.cut))


class _ByPath(LocalFS):
    """A destination written by path, as SFTP or SMB are: its open_write is
    not LocalFS's own, so the worker does not use its private local writes."""

    def open_write(self, path, append=False):
        return super().open_write(path, append=append)

    def checksum(self, path, algorithm="sha256"):
        return ""


class _Slow(LocalFS):
    def open_read(self, path):
        handle = super().open_read(path)
        real = handle.read

        def read(n=-1):
            time.sleep(0.02)
            return real(64 * KIB)

        handle.read = read
        return handle


# -- Low 3: a local copy cut short -------------------------------------------------------------


@pytest.mark.parametrize("existing", [False, True])
def test_sad_a_local_copy_cut_short_fails_and_leaves_the_destination(tmp_path, existing):
    data = os.urandom(300 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()
    if existing:
        (out / "f.bin").write_bytes(b"OLD CONTENT")
    job = _job(src, out / "f.bin", _CutLocal(100 * KIB), LocalFS(), use_temp_file=True)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert f"only {100 * KIB} of {300 * KIB} bytes" in job.error_message
    assert "got shorter while it was copied" in job.error_message
    if existing:
        assert (out / "f.bin").read_bytes() == b"OLD CONTENT"
    else:
        assert not (out / "f.bin").exists()
    # The partial as a failed move keeps it: for a Retry to continue.
    move_out = tmp_path / "move_out"
    move_out.mkdir()
    moved = _job(src, move_out / "f.bin", _CutLocal(100 * KIB), LocalFS(),
                 use_temp_file=True, move=True)
    TransferWorker()._process_job(moved)
    assert moved.status is TransferStatus.ERROR
    assert len(_partials(out)) == len(_partials(move_out)) == 1
    assert src.read_bytes() == data


def test_sad_a_local_copy_cut_short_into_a_direct_write_is_not_left_short(tmp_path):
    data = os.urandom(300 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()
    job = _job(src, out / "f.bin", _CutLocal(100 * KIB), LocalFS(), use_temp_file=False)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert "got shorter while it was copied" in job.error_message
    assert not (out / "f.bin").exists() or (out / "f.bin").stat().st_size != 100 * KIB


def test_happy_a_retry_after_the_source_shrank_copies_it_as_it_is_now(tmp_path):
    """Reported as failed, not a refusal of the user's file: Retry (or a new
    copy) takes the file as it is then."""
    from core.transfer_manager import TransferManager

    _app()
    data = os.urandom(600 * KIB)
    src = tmp_path / "src" / "log.bin"
    src.parent.mkdir()
    src.write_bytes(data)
    (tmp_path / "dst").mkdir()

    class _ShrinksOnce(LocalFS):
        done = False

        def open_read(self, path):
            handle = super().open_read(path)
            real = handle.read

            def read(n=-1):
                chunk = real(min(n, 64 * KIB) if n and n > 0 else 64 * KIB)
                if not _ShrinksOnce.done:  # another program cuts the file
                    _ShrinksOnce.done = True
                    os.truncate(path, 200 * KIB)
                return chunk

            handle.read = read
            return handle

    mgr = TransferManager(max_parallel=1)
    try:
        [first] = mgr.transfer_files(_ShrinksOnce(), LocalFS(), [str(src)], str(tmp_path / "dst"))
        _wait(mgr)
        assert first.status is TransferStatus.ERROR, first.error_message
        assert "got shorter" in first.error_message
        retry = mgr.retry_job(first.job_id)
        assert retry is not None
        _wait(mgr)
        assert retry.status is TransferStatus.DONE, retry.error_message
        assert (tmp_path / "dst" / "log.bin").read_bytes() == data[: 200 * KIB]
        assert _partials(tmp_path / "dst") == []
    finally:
        mgr.shutdown()


def test_edge_the_short_copy_message_is_translated():
    import json

    catalogue = json.loads((_ROOT / "resources" / "i18n" / "de.json").read_text("utf-8"))
    key = ("only {copied} of {size} bytes of {source} could be read: the file got "
           "shorter while it was copied. The copy is incomplete and was not saved; "
           "{dest} was left as it was")
    assert "{copied}" in catalogue[key] and "{dest}" in catalogue[key]


# -- Low 1: a mismatched partial a stalled writer still holds ----------------------------------


def test_sad_a_mismatched_partial_restarts_under_a_fresh_name(tmp_path):
    """The claimed partial holds other bytes; the other process's stalled
    writer still has it open and writes on after this job committed: the
    committed copy must not get its bytes."""
    data = os.urandom(600 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()
    fp = TW.source_fingerprint(LocalFS().stat(str(src)))
    left = out / TW.partial_name("f.bin", "0123abcd", fp)
    left.write_bytes(os.urandom(200 * KIB))  # another file's bytes, same fingerprint
    stalled = open(left, "r+b")  # noqa: SIM115 - the other process's writer
    try:
        stalled.seek(200 * KIB)
        job = _job(src, out / "f.bin", LocalFS(), _ByPath(), use_temp_file=True,
                   resume=True, temp_path=str(left), source_fingerprint=fp)
        TransferWorker()._process_job(job)
        assert job.status is TransferStatus.DONE, job.error_message
        stalled.write(b"\xee" * (100 * KIB))  # the stalled writer goes on
        stalled.flush()
    finally:
        stalled.close()
    assert (out / "f.bin").read_bytes() == data
    assert _partials(out) == []  # the mismatched one was removed, not left behind


def test_edge_the_fresh_name_differs_from_the_claimed_one(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    job = TransferJob(source_path=str(tmp_path / "f.bin"), dest_path=str(out / "f.bin"),
                      filename="f.bin", source_fingerprint="deadbeef")
    job.dest_backend = LocalFS()
    claimed = out / TW.partial_name("f.bin", job.job_id, "deadbeef")
    claimed.write_bytes(b"x")
    live: list[str] = []
    try:
        fresh = TransferWorker._restart_under_fresh_partial(job, str(claimed), live)
        assert fresh != str(claimed) and job.temp_path == fresh and live == [fresh]
        assert TW.is_partial_name(Path(fresh).name, "f.bin")
        assert TW.partial_fingerprint(Path(fresh).name, "f.bin") == "deadbeef"
        assert TW.partial_in_use(fresh)
        assert not claimed.exists()
    finally:
        TW._release_live_partials(live)


# -- Low 2: copying again right after Cancel ---------------------------------------------------


def _cancelled_copy(mgr, tmp_path: Path, data: bytes):
    src = tmp_path / "src" / "big.bin"
    src.parent.mkdir()
    src.write_bytes(data)
    dst = tmp_path / "dst"
    dst.mkdir()
    [a] = mgr.transfer_files(_Slow(), LocalFS(), [str(src)], str(dst))
    assert _pump_until(lambda: any(p.stat().st_size > 0 for p in dst.iterdir()
                                   if TW.PARTIAL_MARK in p.name)), "nothing was written"
    mgr.cancel_job(a.job_id)
    _wait(mgr)
    assert a.status is TransferStatus.CANCELLED
    assert len(_partials(dst)) == 1
    return src, dst, a


@pytest.mark.parametrize("again", ["copy", "retry"])
def test_happy_copying_again_after_cancel_resumes_the_cancelled_partial(tmp_path, again):
    from core.transfer_manager import TransferManager

    _app()
    data = os.urandom(2 * 1024 * KIB)
    mgr = TransferManager(max_parallel=1)
    try:
        src, dst, a = _cancelled_copy(mgr, tmp_path, data)
        if again == "copy":  # F5 again, a new LocalFS of the pane as before
            [b] = mgr.transfer_files(_Slow(), LocalFS(), [str(src)], str(dst))
        else:
            b = mgr.retry_job(a.job_id)
        assert b.resume
        _wait(mgr)
        assert b.status is TransferStatus.DONE, b.error_message
        assert (dst / "big.bin").read_bytes() == data
        assert _partials(dst) == []
    finally:
        mgr.shutdown()


def test_edge_a_superseded_partial_of_this_manager_goes_when_the_new_copy_commits(tmp_path):
    """The cancelled partial is not resumed (the source got shorter than it
    in the meantime): removed once the new copy committed."""
    from core.transfer_manager import TransferManager

    _app()
    mgr = TransferManager(max_parallel=1)
    try:
        src, dst, _a = _cancelled_copy(mgr, tmp_path, os.urandom(2 * 1024 * KIB))
        small = os.urandom(10 * KIB)
        src.write_bytes(small)
        [b] = mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(dst))
        assert not b.resume
        _wait(mgr)
        assert b.status is TransferStatus.DONE, b.error_message
        assert (dst / "big.bin").read_bytes() == small
        assert _pump_until(lambda: _partials(dst) == []), _partials(dst)
    finally:
        mgr.shutdown()


def test_sad_an_ended_jobs_partial_a_live_job_writes_is_still_not_adopted(tmp_path):
    dest = tmp_path / "report.pdf"
    partial = tmp_path / TW.partial_name("report.pdf", "0123abcd", "deadbeef")
    partial.write_bytes(b"12345")
    # Recent, but kept by an ended job of this manager: adopted ...
    assert TM._probe_resumable_temp(LocalFS(), str(dest), fingerprint="deadbeef",
                                    owned={str(partial)}) == (str(partial), 5)
    # ... not while a queued or running job has it, nor when nobody owns it.
    assert TM._probe_resumable_temp(LocalFS(), str(dest), fingerprint="deadbeef",
                                    busy={str(partial)}, owned={str(partial)}) is None
    assert TM._probe_resumable_temp(LocalFS(), str(dest), fingerprint="deadbeef") is None


def test_edge_a_time_ahead_of_the_clock_counts_as_recent_only_so_far(tmp_path):
    dest = tmp_path / "report.pdf"
    partial = tmp_path / TW.partial_name("report.pdf", "0123abcd", "deadbeef")
    partial.write_bytes(b"12345")
    ahead = time.time() + 60  # a clock a minute ahead: recent
    os.utime(partial, (ahead, ahead))
    assert TM._probe_resumable_temp(LocalFS(), str(dest), fingerprint="deadbeef") is None
    # Hours ahead (a server listing local time as UTC): that says nothing
    # about the write; never resumed for those hours before.
    ahead = time.time() + TM.RESUME_CLOCK_SKEW_SECONDS + 3600
    os.utime(partial, (ahead, ahead))
    assert TM._probe_resumable_temp(LocalFS(), str(dest), fingerprint="deadbeef") == \
        (str(partial), 5)


# -- polish ------------------------------------------------------------------------------------


def test_sad_a_file_renamed_inside_a_moved_folder_is_said_in_words(tmp_path):
    from core.undo import UndoPlan, unchanged_parts

    fs = LocalFS()
    here = tmp_path / "B" / "proj" / "a.txt"
    here.parent.mkdir(parents=True)
    here.write_text("A")
    gone = tmp_path / "B" / "proj" / "b.txt"  # renamed to c.txt since the move
    parts = tuple(
        UndoPlan(operation_id="", operation="move", reversible=True, action="transfer_back",
                 reason="", source=str(tmp_path / "A" / "proj" / p.name), dest=str(p))
        for p in (here, gone))
    plan = UndoPlan(operation_id="op", operation="move_folder", reversible=True,
                    action="batch", reason="", parts=parts)
    kept, failures = unchanged_parts(plan, fs)
    assert [p.dest for p in kept.parts] == [str(here)]
    assert failures == [f"{tmp_path / 'A' / 'proj' / 'b.txt'}: "
                        "b.txt is no longer where the move put it"]


def test_edge_a_batch_undo_job_whose_file_vanished_is_said_in_words():
    from ui.main_window import MainWindow

    source = "/B/proj/b.txt"
    job = SimpleNamespace(source_path=source,
                          error=FileNotFoundError(2, "No such file or directory", source))
    wait = {"batch": True, "pending": {"j1", "j2"}, "failed": []}
    stub = SimpleNamespace(_undo_waits=[wait],
                           _transfer_manager=SimpleNamespace(get_job=lambda _id: job))
    MainWindow._on_undo_job_error(stub, "j1", f"[Errno 2] No such file or directory: '{source}'")
    assert wait["failed"] == [f"{source}: b.txt is no longer where the move put it"]


def test_happy_a_script_traceback_shows_only_the_script(tmp_path):
    script = tmp_path / "job.py"
    script.write_text("def f():\n    raise ValueError('boom')\nf()\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(_ROOT / "main.py"), "--script", str(script)],
                          cwd=str(_ROOT), env=dict(os.environ), capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 1, proc.stderr[-2000:]
    assert proc.stderr.startswith("Traceback (most recent call last):"), proc.stderr[-2000:]
    assert "ValueError: boom" in proc.stderr
    assert str(script) in proc.stderr
    assert "main.py" not in proc.stderr and "script_runner" not in proc.stderr, proc.stderr


def test_edge_the_runner_frames_are_cut_only_above_the_script():
    from core import script_runner as SR

    with tempfile.TemporaryDirectory() as folder:
        outer = os.path.join(folder, "outer.py")
        try:
            exec(compile("raise KeyError('k')", outer, "exec"), {})  # noqa: S102
        except KeyError:
            text = SR._script_traceback_text(skip=(__file__,))
    assert "outer.py" in text and __file__ not in text and "KeyError" in text


def test_happy_a_failing_tool_says_error_once():
    from ui.agent_dock import AgentTab

    lines: list[tuple] = []
    stub = SimpleNamespace(
        _append=lambda who, text, **kw: lines.append((who, text)),
        _say_unavailable=lambda name: None, _refusals_said=set(),
        _update_status=lambda: None, dock=SimpleNamespace(emit_event=lambda *a: None))
    AgentTab._on_event(stub, {"type": "tool_result", "name": "read_file", "outcome": "error",
                              "detail": "error: no such file: notes.txt"})
    AgentTab._on_event(stub, {"type": "tool_result", "name": "list_dir", "outcome": "error",
                              "detail": "the folder is gone"})
    assert lines == [("←", "read_file: error - no such file: notes.txt"),
                     ("←", "list_dir: error - the folder is gone")]
