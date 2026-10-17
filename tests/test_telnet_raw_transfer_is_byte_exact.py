"""Telnet's raw transfer (no base64/uuencode/xxd on the host) keeps text
files byte for byte.

Upload sent ``cat > f << 'EOF'\\n{text}\\nEOF``: the heredoc always ends
the body with a newline, so every file gained one ("abc\\n" became
"abc\\n\\n", "abc" became "abc\\n"). Read sent ``cat f`` and the shell
session stripped the answer: leading and trailing blank lines and
spaces were lost. Upload now ends the heredoc exactly (a text without a
final newline goes through ``printf '%s' "$(cat ...)"``), read frames the
content with markers of its own and, where ``wc`` exists, checks the
size - the telnet stream drops carriage returns, so a CRLF file is
refused instead of altered, and so is an upload that holds CR or NUL.

The remote end is a real /bin/sh behind a loopback socket that maps
line endings like a pty; the client side is the backend's own telnet
transport, shell session and writer.
"""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import threading

import pytest

from core import telnet_client as TC


class _ShServer:
    """One /bin/sh per connection; CRLF in, LF -> CRLF out (like a pty)."""

    def __init__(self):
        self._lsock = socket.socket()
        self._lsock.bind(("127.0.0.1", 0))
        self._lsock.listen(2)
        self.port = self._lsock.getsockname()[1]
        self._procs: list[subprocess.Popen] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        try:
            conn, _ = self._lsock.accept()
        except OSError:
            return
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
        proc = subprocess.Popen(
            ["sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env
        )
        self._procs.append(proc)

        def pump_in():
            try:
                while data := conn.recv(65536):
                    proc.stdin.write(data.replace(b"\r\n", b"\n"))
                    proc.stdin.flush()
            except OSError:
                pass

        def pump_out():
            try:
                while data := proc.stdout.read1(65536):
                    conn.sendall(data.replace(b"\n", b"\r\n"))
            except OSError:
                pass

        threading.Thread(target=pump_in, daemon=True).start()
        threading.Thread(target=pump_out, daemon=True).start()

    def close(self):
        self._lsock.close()
        for p in self._procs:
            p.kill()
            p.wait(5)


@pytest.fixture
def telnet(tmp_path):
    server = _ShServer()
    transport = TC._TelnetTransport("127.0.0.1", server.port)
    shell = object.__new__(TC._ShellSession)
    shell._transport = transport
    shell._marker_id = secrets.token_hex(8)
    shell._seq = 0
    shell._lock = threading.RLock()
    shell._prompt_ready = True
    sess = object.__new__(TC.TelnetSession)
    sess._caps = TC._Capabilities(transfer_method="raw", has_wc=True)
    sess._ensure_connected = lambda: shell
    try:
        yield sess, tmp_path
    finally:
        transport.close()
        server.close()


def _upload(sess, path, data: bytes) -> None:
    with sess.open_write(str(path)) as fh:
        fh.write(data)


PAYLOADS = [
    b"abc\n",
    b"no newline at end",
    b"a\nb\n",
    b"\n\nleading and trailing blank lines\n\n\n",
    b"  spaces around  ",
    "Grüße ü 名前\n".encode(),
    b"",
    b"line with 'quotes' and $HOME and `backticks` \\ backslash\n",
]


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("payload", PAYLOADS)
def test_happy_upload_stores_the_bytes_unchanged(telnet, payload):
    sess, tmp = telnet
    _upload(sess, tmp / "f.txt", payload)
    assert (tmp / "f.txt").read_bytes() == payload


@pytest.mark.parametrize("payload", PAYLOADS)
def test_happy_read_returns_the_bytes_unchanged(telnet, payload):
    sess, tmp = telnet
    (tmp / "f.txt").write_bytes(payload)
    with sess.open_read(str(tmp / "f.txt")) as fh:
        assert fh.read() == payload


# -- sad ---------------------------------------------------------------------


def test_sad_reading_a_missing_file_raises(telnet):
    sess, tmp = telnet
    with pytest.raises(OSError, match="Cannot read"):
        sess.open_read(str(tmp / "missing.txt"))


@pytest.mark.parametrize("payload", [b"dos\r\nline\r\n", b"nul\x00byte"])
def test_sad_an_upload_raw_cannot_carry_is_refused(telnet, payload):
    sess, tmp = telnet
    with pytest.raises(OSError, match="raw"):
        _upload(sess, tmp / "f.txt", payload)
    assert not (tmp / "f.txt").exists()


def test_sad_a_crlf_file_is_refused_instead_of_altered(telnet):
    sess, tmp = telnet
    (tmp / "dos.txt").write_bytes(b"one\r\ntwo\r\n")
    with pytest.raises(OSError, match="bytes"):
        sess.open_read(str(tmp / "dos.txt"))


# -- edge --------------------------------------------------------------------


def test_edge_append_keeps_both_parts_exact(telnet):
    sess, tmp = telnet
    (tmp / "f.txt").write_bytes(b"first")
    with sess.open_write(str(tmp / "f.txt"), append=True) as fh:
        fh.write(b" second\n")
    assert (tmp / "f.txt").read_bytes() == b"first second\n"


def test_edge_content_that_looks_like_the_markers_stays_content(telnet):
    sess, tmp = telnet
    payload = b"__AXX_EOF__\n__AXROSS_RAW_BEGIN__ x __AXROSS_RAW_END__\n"
    _upload(sess, tmp / "f.txt", payload)
    assert (tmp / "f.txt").read_bytes() == payload
    with sess.open_read(str(tmp / "f.txt")) as fh:
        assert fh.read() == payload


def test_edge_without_wc_the_read_still_frames_exactly(telnet):
    sess, tmp = telnet
    sess._caps = TC._Capabilities(transfer_method="raw", has_wc=False)
    (tmp / "f.txt").write_bytes(b"\n  x  \n\n")
    with sess.open_read(str(tmp / "f.txt")) as fh:
        assert fh.read() == b"\n  x  \n\n"
