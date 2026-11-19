"""WinRM: connecting is checked, failures say what to do, one call at a time.

Review of the WinRM backend (connection types, 2026-11):

* home() swallowed every failure and answered C:\\Users\\<user>: Test
  Connection succeeded against a host that refused the connection or the
  login, and a new pane failed only at its first listing.
* Failures were pywinrm / requests texts ("HTTPSConnectionPool(host=...):
  Max retries exceeded ... NewConnectionError(<urllib3.connection...>")
  with the cause dropped, so the message could not be explained. HTTPS
  against the HTTP listener (5985) and a self-signed listener certificate
  now say what to change.
* use_https was always True: port 5985, Windows' default HTTP listener,
  got a TLS handshake. Without an explicit choice 5985 is HTTP now.
* pywinrm's own URL parser turned an IPv6 literal into host "https".
* pywinrm's Protocol closes its requests session after every command and
  keeps one message-encryption context: two threads (a pane, a transfer)
  on one session broke each other. Calls are serialised.
* open_read read the whole file into the remote PowerShell's memory before
  refusing anything above 32 MiB; large files are read in ranges now.
* A curly quote (U+2018/U+2019) ends a PowerShell single-quoted string
  as ' does: exec()'s environment values and cim_query let it through.

Real pywinrm against real local sockets where it matters (a closed port,
a plain HTTP server, a TLS server with an untrusted certificate); a fake
PowerShell host for the scripts.
"""

from __future__ import annotations

import base64
import re
import socket
import ssl
import sys
import threading
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("winrm")

from core import winrm_client as W  # noqa: E402
from core.user_errors import describe  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Listener:
    """Accepts connections; answers each with *reply* (or a TLS handshake
    with *tls_context* first). Records the first bytes it got."""

    def __init__(self, reply: bytes = b"", tls_context: ssl.SSLContext | None = None):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.reply, self.tls = reply, tls_context
        self.received: list[bytes] = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                if self.tls is not None:
                    try:
                        conn = self.tls.wrap_socket(conn, server_side=True)
                    except (ssl.SSLError, OSError):
                        conn.close()
                        continue
                data = conn.recv(65536)
                self.received.append(data)
                if self.reply:
                    conn.sendall(self.reply)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        self._stop = True
        self.sock.close()


# --- Test Connection / home() ---------------------------------------------


def test_sad_home_against_a_closed_port_fails_and_says_refused():
    s = W.WinRMSession("127.0.0.1", "u", "p", port=_free_port(), use_https=False)
    with pytest.raises(OSError) as info:
        s.home()
    text = describe(info.value)
    assert "refused the connection" in text, text


def test_sad_wrong_password_is_a_refused_login():
    reply = (b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
             b"WWW-Authenticate: Basic realm=\"WSMAN\"\r\nConnection: close\r\n\r\n")
    srv = _Listener(reply)
    try:
        s = W.WinRMSession("127.0.0.1", "u", "p", port=srv.port, use_https=False,
                           transport="basic")
        with pytest.raises(OSError) as info:
            s.home()
    finally:
        srv.close()
    assert "refused the login" in describe(info.value)


def test_sad_https_against_the_http_listener_names_the_ports():
    srv = _Listener(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    try:
        s = W.WinRMSession("127.0.0.1", "u", "p", port=srv.port, use_https=True)
        with pytest.raises(OSError) as info:
            s.home()
    finally:
        srv.close()
    text = describe(info.value)
    assert "5985" in text and "5986" in text, text


def test_sad_an_untrusted_certificate_points_at_the_profile_setting():
    from proxy_http_testkit import TestPki

    pki = TestPki()
    cert, key = pki.issue("127.0.0.1")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = _Listener(tls_context=ctx)
    try:
        s = W.WinRMSession("127.0.0.1", "u", "p", port=srv.port, use_https=True)
        with pytest.raises(OSError) as info:
            s.home()
    finally:
        srv.close()
    text = describe(info.value)
    assert "certificate" in text and "self-signed" in text, text


def test_edge_home_falls_back_only_when_the_answer_is_unreadable():
    s = _fake_session(lambda script: (0, b"not base64 at all!", b""))
    assert s.home() == "C:\\Users\\u"


# --- endpoint ---------------------------------------------------------------


def _endpoint(s) -> str:
    return s._session.protocol.transport.endpoint


def test_happy_port_5985_is_http_and_5986_https():
    assert _endpoint(W.WinRMSession("h.example", "u", "p", port=5985)).startswith("http://")
    assert _endpoint(W.WinRMSession("h.example", "u", "p", port=5986)).startswith("https://")
    assert _endpoint(W.WinRMSession("h.example", "u", "p")) == "https://h.example:5986/wsman"


def test_edge_an_explicit_choice_wins_over_the_port():
    s = W.WinRMSession("h.example", "u", "p", port=5985, use_https=True)
    assert _endpoint(s) == "https://h.example:5985/wsman"
    s = W.WinRMSession("h.example", "u", "p", port=8443, use_https=False)
    assert _endpoint(s) == "http://h.example:8443/wsman"


def test_edge_an_ipv6_literal_keeps_its_address():
    s = W.WinRMSession("fe80::1", "u", "p", port=5985)
    assert _endpoint(s) == "http://[fe80::1]:5985/wsman"
    s = W.WinRMSession("[::1]", "u", "p", port=5986)
    assert _endpoint(s) == "https://[::1]:5986/wsman"


def test_happy_the_request_reaches_the_http_listener():
    srv = _Listener(b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    try:
        s = W.WinRMSession("127.0.0.1", "u", "p", port=srv.port, use_https=False,
                           transport="basic")
        with pytest.raises(OSError):
            s.stat("C:\\x")
        deadline = time.time() + 5
        while not srv.received and time.time() < deadline:
            time.sleep(0.05)
    finally:
        srv.close()
    assert srv.received and srv.received[0].startswith(b"POST /wsman HTTP/1.1")


# --- one call at a time -------------------------------------------------------


class _Host:
    """pywinrm's Session replaced: run_ps answers through *answer*."""

    def __init__(self, answer):
        self.answer = answer
        self.scripts: list[str] = []
        self.busy = 0
        self.overlaps = 0
        self._guard = threading.Lock()

    def run_ps(self, script):
        with self._guard:
            self.busy += 1
            self.overlaps += self.busy > 1
        try:
            self.scripts.append(script)
            time.sleep(0.002)
            rc, out, err = self.answer(script)
            return types.SimpleNamespace(status_code=rc, std_out=out, std_err=err)
        finally:
            with self._guard:
                self.busy -= 1


def _fake_session(answer) -> W.WinRMSession:
    s = W.WinRMSession.__new__(W.WinRMSession)
    s._session = _Host(answer)
    s._host, s._username = "h", "u"
    return s


def test_edge_two_threads_never_run_scripts_at_once():
    s = _fake_session(lambda script: (0, b"YES", b""))
    errors = []

    def work():
        try:
            for _ in range(15):
                s.exists("C:\\x")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors and s._session.overlaps == 0


# --- large files ----------------------------------------------------------------


def _file_host(data: bytes):
    def answer(script):
        if "ReadAllBytes" in script:
            m = re.search(r"\$item\.Length -gt (\d+)", script)
            if m and len(data) > int(m.group(1)):
                return 0, f"AXROSS-LARGE {len(data)}".encode(), b""
            return 0, base64.b64encode(data), b""
        m = re.search(r"Seek\((\d+),.*?New-Object byte\[\] (\d+)", script, re.S)
        if m:
            off, n = int(m.group(1)), int(m.group(2))
            return 0, base64.b64encode(data[off:off + n]), b""
        raise AssertionError(script[:200])

    return answer


def test_happy_a_large_file_is_read_in_ranges():
    data = bytes(range(256)) * (5 * 4096 + 7)  # ~5 MiB, not a chunk multiple
    s = _fake_session(_file_host(data))
    fh = s.open_read("C:\\big.bin")
    got = bytearray()
    while True:
        piece = fh.read(1 << 20)
        if not piece:
            break
        got += piece
    assert bytes(got) == data
    ranged = [sc for sc in s._session.scripts if "Seek(" in sc]
    assert len(ranged) >= 2


def test_edge_a_large_read_resumes_at_an_offset():
    data = b"x" * (W._READ_CHUNK + 10) + b"TAIL"
    s = _fake_session(_file_host(data))
    fh = s.open_read("C:\\big.bin")
    fh.seek(len(data) - 4)
    assert fh.read() == b"TAIL"


def test_happy_a_small_file_is_one_call():
    s = _fake_session(_file_host(b"hello"))
    assert s.open_read("C:\\a.txt").read() == b"hello"
    assert len(s._session.scripts) == 1


# --- quoting ----------------------------------------------------------------------


@pytest.mark.parametrize("quote", ["'", "\u2018", "\u2019", "\u201a", "\u201b"])
def test_sad_every_single_quote_kind_is_doubled_in_exec_env(quote):
    s = _fake_session(lambda script: (0, b"", b""))
    s.exec("echo $env:A", env={"A": f"x{quote}; Remove-Item C:\\x; {quote}"})
    sent = s._session.scripts[-1]
    prefix = sent.split("; echo", 1)[0]
    assert prefix == f"$env:A = 'x{quote * 2}; Remove-Item C:\\x; {quote * 2}'"


@pytest.mark.parametrize("quote", ["\u2018", "\u2019", "\u201a", "\u201b"])
def test_sad_a_curly_quote_in_wql_is_refused(quote):
    s = _fake_session(lambda script: (0, b"[]", b""))
    with pytest.raises(ValueError):
        s.cim_query(f"SELECT * FROM Win32_Process WHERE Name = {quote}x{quote}")
    assert s._session.scripts == []


def test_edge_disk_usage_takes_only_a_drive_letter():
    s = _fake_session(lambda script: (0, b"1 2", b""))
    assert s.disk_usage("\u2019:\\x") == (0, 0, 0)
    assert s._session.scripts == []
    assert s.disk_usage("d:\\x") == (3, 1, 2)
