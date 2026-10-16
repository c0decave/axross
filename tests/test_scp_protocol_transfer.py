"""SCP transfers files with the SCP protocol where the shell has no cat.

test.rebex.net (an SCP test server): the listing works, but every read
failed with "cat failed (exit 127)" - its virtual shell knows ls, cp, mv,
rm, mkdir and a few more, no cat and no base64. The backend moved file
bytes only through those two commands, although the server speaks the
SCP protocol itself (``scp -f`` answered "C0700 379 readme.txt" and the
379 bytes). Without cat and base64 the backend now uses ``scp -f`` to
read and ``scp -t`` to write.

Also from Rebex: ``ls -la`` of a missing path prints nothing and exits 0,
so the missing folder listed as empty. ``ls -la`` of an existing folder
always prints at least "." - nothing at all means no such path.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import scp_client  # noqa: E402


class _Channel:
    """An exec channel that answers with a fixed byte stream."""

    def __init__(self, cmd: str, stream: bytes):
        self.cmd = cmd
        self._stream = stream
        self.sent = b""
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        chunk, self._stream = self._stream[:n], self._stream[n:]
        return chunk

    def shutdown_write(self) -> None:
        pass

    def recv_exit_status(self) -> int:
        return 0

    def close(self) -> None:
        self.closed = True


def _session(streams: dict[str, bytes], transfer_method: str = "scp"):
    s = scp_client.SCPSession.__new__(scp_client.SCPSession)
    s._caps = scp_client._Capabilities(transfer_method=transfer_method)
    s._client = object()
    s._lock = __import__("threading").Lock()
    s.channels = []

    def channel(cmd):
        ch = _Channel(cmd, streams[cmd.split()[1]])
        s.channels.append(ch)
        return ch

    s._scp_channel = channel
    s.commands = []

    def run(cmd, timeout=None, stdin_data=None):
        s.commands.append(cmd)
        if " ls -la " in f" {cmd} ":
            return streams.get("ls", ""), 0
        return "", 0

    s._exec_raw = run
    return s


BODY = b"Welcome to test.rebex.net!\r\n" * 20


# --- happy ----------------------------------------------------------------


def test_happy_read_through_scp_source_mode():
    s = _session({"-f": b"C0700 %d readme.txt\n" % len(BODY) + BODY + b"\0"})
    with s.open_read("/readme.txt") as fh:
        assert fh.read() == BODY
    ch = s.channels[0]
    assert ch.cmd == "scp -f /readme.txt"
    assert ch.sent == b"\0\0\0"  # ready, header taken, data taken


def test_happy_write_through_scp_sink_mode():
    s = _session({"-t": b"\0\0\0"})
    with s.open_write("/upload dir/new.bin") as fh:
        fh.write(BODY)
    ch = s.channels[0]
    assert ch.cmd == "scp -t '/upload dir/new.bin'"
    assert ch.sent == b"C0644 %d new.bin\n" % len(BODY) + BODY + b"\0"


def test_happy_the_probe_picks_scp_without_cat_and_base64():
    def restricted(cmd, timeout):
        return ("-sh: Command not supported.", 127) if not cmd.startswith("echo") else ("x", 0)

    assert scp_client._probe_capabilities(restricted).transfer_method == "scp"


# --- sad ------------------------------------------------------------------


def test_sad_a_missing_file_is_file_not_found():
    s = _session({"-f": b"\x02scp: /nope: No such file or directory\n"})
    with pytest.raises(FileNotFoundError):
        s.open_read("/nope")


def test_sad_a_folder_cannot_be_read_as_a_file():
    s = _session({"-f": b"\x02scp: /pub: Not a regular file\n"})
    with pytest.raises(OSError, match="Not a regular file"):
        s.open_read("/pub")


def test_sad_a_refused_upload_is_an_error():
    s = _session({"-t": b"\0\x02scp: /ro/x: Permission denied\n"})
    fh = s.open_write("/ro/x")
    fh.write(b"data")
    with pytest.raises(OSError, match="Permission denied"):
        fh.close()


def test_sad_a_cut_stream_is_never_a_complete_file():
    s = _session({"-f": b"C0644 100 x\n" + b"a" * 40})
    with pytest.raises(OSError):
        s.open_read("/x")


def test_sad_an_empty_ls_is_a_missing_folder():
    s = _session({"ls": ""}, transfer_method="raw")
    with pytest.raises(FileNotFoundError):
        s.list_dir("/axross-missing")


# --- edge -----------------------------------------------------------------


def test_edge_an_empty_file_round_trips():
    s = _session({"-f": b"C0644 0 empty\n\0", "-t": b"\0\0\0"})
    with s.open_read("/empty") as fh:
        assert fh.read() == b""
    with s.open_write("/empty2") as fh:
        pass
    assert s.channels[1].sent == b"C0644 0 empty2\n\0"


def test_edge_a_name_with_a_newline_is_refused_before_sending():
    s = _session({"-t": b"\0\0\0"})
    fh = s.open_write("/bad\nname")
    fh.write(b"x")
    with pytest.raises(OSError, match="line break"):
        fh.close()
    assert s.channels == []


def test_edge_append_rewrites_the_whole_file_through_scp():
    s = _session({"-f": b"C0644 3 log\nold\0", "-t": b"\0\0\0"})
    s.stat = lambda path: scp_client.FileItem(name="log", size=3)
    with s.open_write("/log", append=True) as fh:
        fh.write(b"new")
    assert s.channels[-1].sent == b"C0644 6 log\noldnew\0"


def test_edge_an_empty_existing_folder_still_lists():
    ls = "drwx------ 2 demo users 0 Mar 31  2023 .\ndrwx------ 2 demo users 0 Apr 30 13:38 ..\n"
    s = _session({"ls": ls}, transfer_method="raw")
    assert s.list_dir("/empty") == []
