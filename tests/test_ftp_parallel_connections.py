"""FTP transfers on control connections of their own, so that several
transfer jobs can share one FtpSession.

Before: a download already took a connection of its own (one spare kept),
but an upload ran its whole STOR on the session's shared connection while
holding the session lock - four jobs uploading through one session ran one
STOR after the other. Now an upload takes a logged-in connection from a
small pool as a download does, with the same fallback to the shared
connection when the server refuses a second login (421 / 530); after that
the session tells the transfer scheduler to carry one job at a time.

Driven against a scripted FTP server on 127.0.0.1 that keeps the data
socket per control connection (so several transfers can run at once),
stores what STOR / APPE send, and counts connections and concurrent STORs.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from fuzz_testkit import ScriptedServer, recv_line  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core import transfer_pool as TP  # noqa: E402


class _StoreServer:
    """FTP server: login, PASV per connection, STOR / APPE / RETR,
    RNFR / RNTO, an empty MLSD. Connections beyond ``max_conns`` get a 421
    greeting. ``store_delay`` holds every STOR open that long so that
    concurrent ones overlap; a STOR of a path in ``refuse`` gets 553."""

    def __init__(self, *, max_conns=None, store_delay=0.0, refuse=(), pass_delay=None):
        self.max_conns = max_conns
        self.store_delay = store_delay
        self.refuse = set(refuse)
        # pass_delay(connection number) -> seconds before the PASS reply
        # (a server hashing passwords slowly under load).
        self.pass_delay = pass_delay
        self.files: dict[str, bytes] = {}
        self.lock = threading.Lock()
        self.attempts = 0  # connections accepted, refused ones included
        self.refused = 0
        self.open_conns = 0
        self.logins = 0
        self.noops: dict[int, int] = {}  # per connection number
        self.hang_up_idle = False  # close a connection that is idle after a STOR
        self.active_stores = 0
        self.peak_stores = 0
        self.stores_by_conn: dict[int, int] = {}
        self.server = ScriptedServer(self._handle)
        self.host, self.port = self.server.host, self.server.port

    def close(self) -> None:
        self.server.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def wait_open(self, count: int, timeout: float = 5.0) -> int:
        end = time.monotonic() + timeout
        while time.monotonic() < end and self.open_conns != count:
            time.sleep(0.01)
        return self.open_conns

    def _handle(self, conn: socket.socket) -> None:
        with self.lock:
            self.attempts += 1
            number = self.attempts
            if self.max_conns is not None and self.open_conns >= self.max_conns:
                self.refused += 1
                refuse = True
            else:
                self.open_conns += 1
                refuse = False
        if refuse:
            conn.sendall(b"421 Too many connections from your address\r\n")
            return
        try:
            self._serve(conn, number)
        finally:
            with self.lock:
                self.open_conns -= 1

    def _serve(self, conn: socket.socket, number: int) -> None:
        conn.sendall(b"220 ready\r\n")
        data_sock = None
        rename_from = None
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            if verb == "USER":
                conn.sendall(b"331 password please\r\n")
            elif verb == "PASS":
                if self.pass_delay is not None and self.pass_delay(number):
                    time.sleep(self.pass_delay(number))
                with self.lock:
                    self.logins += 1
                conn.sendall(b"230 logged in\r\n")
            elif verb == "NOOP":
                with self.lock:
                    self.noops[number] = self.noops.get(number, 0) + 1
                conn.sendall(b"200 ok\r\n")
            elif verb in ("OPTS", "TYPE"):
                conn.sendall(b"200 ok\r\n")
            elif verb == "QUIT":
                conn.sendall(b"221 bye\r\n")
                return
            elif verb == "PASV":
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_sock.bind(("127.0.0.1", 0))
                data_sock.listen(1)
                data_sock.settimeout(5)
                port = data_sock.getsockname()[1]
                conn.sendall(
                    f"227 Entering Passive Mode (127,0,0,1,{port >> 8},{port & 255})\r\n".encode()
                )
            elif verb in ("STOR", "APPE", "RETR", "MLSD"):
                ds, data_sock = data_sock, None
                if ds is None:
                    conn.sendall(b"425 no data connection\r\n")
                    continue
                if verb == "RETR" and arg not in self.files:
                    ds.close()
                    conn.sendall(b"550 No such file\r\n")
                    continue
                conn.sendall(b"150 opening data connection\r\n")
                dconn, _ = ds.accept()
                ds.close()
                if verb in ("STOR", "APPE"):
                    self._store(conn, dconn, verb, arg, number)
                    if self.hang_up_idle and number > 1:
                        conn.sendall(b"421 Timeout\r\n")
                        return
                    continue
                dconn.sendall(self.files[arg] if verb == "RETR" else b"")
                dconn.close()
                conn.sendall(b"226 done\r\n")
            elif verb == "RNFR":
                rename_from = arg
                conn.sendall(b"350 ready for RNTO\r\n")
            elif verb == "RNTO":
                with self.lock:
                    self.files[arg] = self.files.pop(rename_from)
                conn.sendall(b"250 renamed\r\n")
            else:
                conn.sendall(b"502 not implemented\r\n")

    def _store(self, conn, dconn, verb, path, number) -> None:
        with self.lock:
            self.active_stores += 1
            self.peak_stores = max(self.peak_stores, self.active_stores)
            self.stores_by_conn[number] = self.stores_by_conn.get(number, 0) + 1
        try:
            if self.store_delay:
                time.sleep(self.store_delay)
            chunks = []
            while chunk := dconn.recv(65536):
                chunks.append(chunk)
            dconn.close()
        finally:
            with self.lock:
                self.active_stores -= 1
        if path in self.refuse:
            conn.sendall(b"553 Could not create file\r\n")
            return
        with self.lock:
            old = self.files.get(path, b"") if verb == "APPE" else b""
            self.files[path] = old + b"".join(chunks)
        conn.sendall(b"226 stored\r\n")


def _session(srv) -> FC.FtpSession:
    return FC.FtpSession(srv.host, srv.port, "u", "p")


def _payload(i: int, size: int = 50_000) -> bytes:
    return hashlib.sha256(f"file{i}".encode()).digest() * (size // 32)


def _upload(s, path: str, data: bytes, errors: list) -> None:
    try:
        with s.open_write(path) as fh:
            fh.write(data)
    except Exception as exc:  # noqa: BLE001 - collected for the assertion
        errors.append((path, exc))


def _upload_all(s, items: dict[str, bytes], timeout: float = 20.0) -> list:
    errors: list = []
    threads = [
        threading.Thread(target=_upload, args=(s, p, d, errors), daemon=True)
        for p, d in items.items()
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)
        assert not t.is_alive(), "an upload hung"
    return errors


# ---------------------------------------------------------------- happy path


def test_happy_uploads_on_one_session_run_side_by_side():
    with _StoreServer(store_delay=0.3) as srv:
        s = _session(srv)
        items = {f"/f{i}": _payload(i) for i in range(4)}
        assert _upload_all(s, items) == []
        assert srv.files == items
        assert srv.peak_stores >= 2, f"STORs ran one after the other ({srv.peak_stores})"
        assert TP.parallel_safe(s)
        s.disconnect()


def test_happy_uploads_and_downloads_together_are_byte_exact():
    with _StoreServer(store_delay=0.05) as srv:
        s = _session(srv)
        srv.files.update({f"/r{i}": _payload(100 + i) for i in range(4)})
        errors: list = []
        got: dict[str, bytes] = {}

        def download(path):
            try:
                with s.open_read(path) as fh:
                    got[path] = fh.read()
            except Exception as exc:  # noqa: BLE001
                errors.append((path, exc))

        threads = [threading.Thread(target=download, args=(f"/r{i}",)) for i in range(4)]
        threads += [
            threading.Thread(target=_upload, args=(s, f"/w{i}", _payload(i), errors))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(20)
        assert errors == []
        assert got == {f"/r{i}": _payload(100 + i) for i in range(4)}
        assert all(srv.files[f"/w{i}"] == _payload(i) for i in range(4))
        s.disconnect()


def test_happy_append_runs_on_its_own_connection():
    with _StoreServer() as srv:
        s = _session(srv)
        srv.files["/a"] = b"head-"
        with s.open_write("/a", append=True) as fh:
            fh.write(b"tail")
        assert srv.files["/a"] == b"head-tail"
        # The session's connection (the first) carried no STOR / APPE.
        assert 1 not in srv.stores_by_conn
        s.disconnect()


# ------------------------------------------------------------------ sad path


def test_sad_a_server_allowing_one_connection_serializes_uploads_on_the_shared_one():
    with _StoreServer(max_conns=1, store_delay=0.1) as srv:
        s = _session(srv)
        assert TP.parallel_safe(s)
        items = {f"/f{i}": _payload(i) for i in range(4)}
        assert _upload_all(s, items) == []
        assert srv.files == items
        assert srv.peak_stores == 1
        assert srv.stores_by_conn == {1: 4}  # all on the session's connection
        assert not TP.parallel_safe(s)  # one job at a time from now on
        # Refused (once per upload that asked at the same time), then not
        # asked again.
        refused = srv.refused
        assert 1 <= refused <= 4
        assert _upload_all(s, {f"/g{i}": b"x" for i in range(4)}) == []
        assert srv.refused == refused
        s.disconnect()


def test_sad_a_limit_above_one_keeps_the_connections_it_has():
    # The session's connection plus two: the third concurrent transfer is
    # refused. The session keeps its two and stays parallel safe; the
    # refused transfer runs on the shared connection.
    with _StoreServer(max_conns=3, store_delay=0.3) as srv:
        s = _session(srv)
        items = {f"/f{i}": _payload(i) for i in range(4)}
        assert _upload_all(s, items) == []
        assert srv.files == items
        assert srv.peak_stores >= 2
        assert TP.parallel_safe(s)
        refused = srv.refused
        assert refused >= 1
        # The limit is remembered: another round asks for no connection
        # the server already refused.
        more = {f"/g{i}": _payload(10 + i) for i in range(4)}
        assert _upload_all(s, more) == []
        assert all(srv.files[p] == d for p, d in more.items())
        assert srv.refused == refused
        s.disconnect()


def test_sad_a_refused_upload_leaves_the_others_intact():
    with _StoreServer(store_delay=0.1, refuse={"/bad"}) as srv:
        s = _session(srv)
        items = {f"/f{i}": _payload(i) for i in range(3)}
        items["/bad"] = b"refused"
        errors = _upload_all(s, items)
        assert [p for p, _ in errors] == ["/bad"]
        assert isinstance(errors[0][1], OSError)
        assert "/bad" not in srv.files
        assert all(srv.files[p] == d for p, d in items.items() if p != "/bad")
        # The connection that got the 553 is still good and kept.
        logins = srv.logins
        assert _upload_all(s, {"/after": b"ok"}) == []
        assert srv.logins == logins
        s.disconnect()


def test_sad_disconnect_while_uploads_run():
    with _StoreServer(store_delay=0.5) as srv:
        s = _session(srv)
        errors: list = []
        threads = [
            threading.Thread(target=_upload, args=(s, f"/f{i}", _payload(i), errors))
            for i in range(3)
        ]
        for t in threads:
            t.start()
        time.sleep(0.2)
        s.disconnect()
        for t in threads:
            t.join(10)
            assert not t.is_alive(), "an upload hung after disconnect"
        # Every upload either landed whole or failed with an OSError.
        for i in range(3):
            path = f"/f{i}"
            failed = [e for p, e in errors if p == path]
            if failed:
                assert isinstance(failed[0], OSError)
            else:
                assert srv.files[path] == _payload(i)
        # Nothing of the session stays connected.
        assert srv.wait_open(0) == 0


def test_sad_a_refusal_right_after_our_own_login_timed_out_is_not_final(monkeypatch):
    # Connections 2 and 3 answer PASS only after the client gave up; the
    # server still counts them, so connection 4 gets a 421. That refusal
    # is caused by our own abandoned logins, not by a one-connection
    # limit: the session must not turn to one job at a time for good.
    monkeypatch.setattr(FC, "SOCKET_TIMEOUT", 0.5)
    with _StoreServer(
        max_conns=3, store_delay=0.1, pass_delay=lambda n: 2.0 if n in (2, 3) else 0
    ) as srv:
        s = _session(srv)
        items = {f"/f{i}": _payload(i) for i in range(3)}
        assert _upload_all(s, items) == []
        assert srv.files == items
        assert TP.parallel_safe(s)
        time.sleep(2.0)  # the abandoned logins end on the server
        more = {f"/g{i}": _payload(10 + i) for i in range(2)}
        assert _upload_all(s, more) == []
        assert all(srv.files[p] == d for p, d in more.items())
        assert TP.parallel_safe(s)
        assert max(srv.stores_by_conn) > 3  # a connection of its own again
        s.disconnect()


def test_sad_a_refusal_long_after_a_timeout_still_falls_back(monkeypatch):
    monkeypatch.setattr(FC, "SOCKET_TIMEOUT", 0.5)
    monkeypatch.setattr(FC, "LOGIN_FAILURE_GRACE", 0.0)
    with _StoreServer(max_conns=1) as srv:
        s = _session(srv)
        s._login_failed_at = time.monotonic() - 1.0
        with s.open_write("/f") as fh:
            fh.write(b"x")
        assert srv.files == {"/f": b"x"}
        assert not TP.parallel_safe(s)
        s.disconnect()


# ---------------------------------------------------------------- edge cases


def test_edge_sequential_uploads_reuse_one_connection():
    with _StoreServer() as srv:
        s = _session(srv)
        for i in range(5):
            with s.open_write(f"/f{i}") as fh:
                fh.write(_payload(i))
        assert srv.logins == 2  # the session's and one for the transfers
        assert srv.stores_by_conn == {2: 5}
        s.disconnect()


def test_edge_a_connection_used_a_moment_ago_is_reused_without_a_noop():
    with _StoreServer() as srv:
        s = _session(srv)
        for i in range(4):
            with s.open_write(f"/f{i}") as fh:
                fh.write(_payload(i))
        # Not on the transfer connection: one round trip per upload saved.
        assert sum(n for conn, n in srv.noops.items() if conn > 1) == 0
        s.disconnect()


def test_edge_a_connection_idle_for_long_is_checked_first(monkeypatch):
    monkeypatch.setattr(FC, "LIVENESS_WINDOW", 0.0)
    with _StoreServer() as srv:
        s = _session(srv)
        for i in range(3):
            with s.open_write(f"/f{i}") as fh:
                fh.write(_payload(i))
        assert sum(n for conn, n in srv.noops.items() if conn > 1) >= 2
        s.disconnect()


def test_edge_an_idle_connection_the_server_closed_is_replaced():
    with _StoreServer() as srv:
        srv.hang_up_idle = True
        s = _session(srv)
        for i in range(3):
            with s.open_write(f"/f{i}") as fh:
                fh.write(_payload(i))
            time.sleep(0.1)  # the 421 + FIN arrive
        assert srv.files == {f"/f{i}": _payload(i) for i in range(3)}
        assert srv.logins == 1 + 3  # each upload found its spare closed
        s.disconnect()


def test_edge_idle_connections_are_bounded(monkeypatch):
    monkeypatch.setattr(FC, "IDLE_CONNECTIONS", 2)
    with _StoreServer(store_delay=0.3) as srv:
        s = _session(srv)
        items = {f"/f{i}": _payload(i) for i in range(5)}
        assert _upload_all(s, items) == []
        assert srv.peak_stores >= 3
        # The session's connection and two idle ones stay; the rest quit.
        assert srv.wait_open(3) == 3
        s.disconnect()
        assert srv.wait_open(0) == 0


def test_edge_many_threads_one_session_stay_within_the_pool_bound(monkeypatch):
    monkeypatch.setattr(FC, "IDLE_CONNECTIONS", 3)
    with _StoreServer(store_delay=0.02) as srv:
        s = _session(srv)
        items = {f"/f{i:02d}": _payload(i, 4096) for i in range(40)}
        assert _upload_all(s, items, timeout=60) == []
        assert srv.files == items
        assert srv.wait_open(1 + 3) <= 1 + 3
        s.disconnect()
        assert srv.wait_open(0) == 0


def test_edge_the_default_idle_bound_is_the_parallel_maximum():
    assert FC.IDLE_CONNECTIONS == TP.MAX_PARALLEL


def test_edge_disconnect_closes_every_idle_connection():
    with _StoreServer(store_delay=0.2) as srv:
        s = _session(srv)
        assert _upload_all(s, {f"/f{i}": _payload(i) for i in range(3)}) == []
        assert srv.open_conns >= 2
        s.disconnect()
        assert srv.wait_open(0) == 0


def test_edge_a_session_built_without_init_is_not_parallel_safe():
    s = object.__new__(FC.FtpSession)
    assert not TP.parallel_safe(s)
