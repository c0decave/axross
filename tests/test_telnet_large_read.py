"""Telnet downloads of large files: in pieces, with progress and Cancel.

open_read() ran ONE ``base64 < file`` and collected the whole answer in
one string: a file above ~47 MiB failed after minutes with "Telnet response
exceeds 67108864 character cap", the search for the end marker went over
the whole growing answer after every 4 KiB (16 MiB: 20 s, 4 MiB: 1.5 s),
the progress bar did not move and Cancel was only seen at the end.

Now a file is read in pieces (``dd ... | base64``) of TELNET_READ_CHUNK
bytes into a spool; each piece reports its bytes and checks Cancel, and
the bytes must add up to the size the file had when the read began.

Against a real shell on a pty (tests/telnet_pty_server.py).
"""

from __future__ import annotations

import os
import sys
import threading

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")

from tests.telnet_pty_server import PtyTelnetServer  # noqa: E402

import core.telnet_client as tc  # noqa: E402
from core import transfer_hooks  # noqa: E402


@pytest.fixture
def session(tmp_path):
    with PtyTelnetServer(cwd=str(tmp_path)) as srv:
        s = tc.TelnetSession("127.0.0.1", srv.port, "u", "pw")
        try:
            yield s
        finally:
            s.close()


def test_a_file_larger_than_one_answer_is_read_in_pieces(session, tmp_path, monkeypatch):
    # One answer may hold 1 MiB here; the file needs about 4 of them.
    monkeypatch.setattr(tc, "MAX_READ_UNTIL_CHARS", 1024 * 1024)
    monkeypatch.setattr(tc, "TELNET_READ_CHUNK", 256 * 1024)
    data = os.urandom(3 * 1024 * 1024 + 12345)
    (tmp_path / "big.bin").write_bytes(data)
    with session.open_read(str(tmp_path / "big.bin")) as fh:
        assert fh.read() == data


def test_an_exact_multiple_of_the_piece_and_an_empty_file(session, tmp_path, monkeypatch):
    monkeypatch.setattr(tc, "TELNET_READ_CHUNK", 64 * 1024)
    data = os.urandom(4 * 64 * 1024)
    (tmp_path / "even.bin").write_bytes(data)
    (tmp_path / "empty").write_bytes(b"")
    assert session.open_read(str(tmp_path / "even.bin")).read() == data
    assert session.open_read(str(tmp_path / "empty")).read() == b""


def test_progress_is_reported_per_piece_and_cancel_stops_the_read(session, tmp_path, monkeypatch):
    monkeypatch.setattr(tc, "TELNET_READ_CHUNK", 64 * 1024)
    data = os.urandom(1024 * 1024)
    (tmp_path / "f.bin").write_bytes(data)

    seen: list[tuple[int, int | None]] = []
    hooks = transfer_hooks.TransferHooks(progress=lambda kind, done, total: seen.append((done, total)))
    with transfer_hooks.active(hooks):
        assert session.open_read(str(tmp_path / "f.bin")).read() == data
    assert len(seen) >= 8, seen
    assert seen[-1] == (len(data), len(data))

    cancel = threading.Event()

    def progress(kind, done, total):
        if done >= 128 * 1024:
            cancel.set()

    hooks = transfer_hooks.TransferHooks(cancel_event=cancel, progress=progress)
    with transfer_hooks.active(hooks):
        with pytest.raises(InterruptedError):
            session.open_read(str(tmp_path / "f.bin"))
    # The shell is still usable after the cancelled read.
    assert session.open_read(str(tmp_path / "f.bin")).read() == data


def test_a_folder_or_a_missing_file_is_an_error_not_an_empty_file(session, tmp_path):
    (tmp_path / "d").mkdir()
    with pytest.raises(OSError):
        session.open_read(str(tmp_path / "d"))
    with pytest.raises(FileNotFoundError):
        session.open_read(str(tmp_path / "missing"))
