"""POP3 exists() says False only when the message is not in the mailbox.

stat() turned every failure of ``LIST n`` into a plain OSError and
exists() read any OSError as "absent": a dropped connection (poplib's
``-ERR EOF``), a timeout, or a ``-ERR [SYS/TEMP]`` the server sends for a
message it does have all answered False. The transfer worker and
server_side_copy(overwrite=False) take False as the go-ahead to write.

Absence is now FileNotFoundError at its source: ``LIST n`` failed AND the
mailbox listing does not carry the number, or the path names no message
at all. Every other failure is an OSError that exists() passes on.

Driven end to end against an in-process POP3 server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.pop3_client import Pop3Session  # noqa: E402

_SIZES = {1: 120, 2: 80, 3: 40}


class _ScriptedPop3:
    """A POP3 server whose ``LIST`` answers the test scripts.

    ``single`` decides the ``LIST n`` reply: "real" (the mailbox),
    "temp" (``-ERR [SYS/TEMP]`` for any number), "drop" (close the
    connection), "stall" (never answer). ``full`` does the same for the
    bare ``LIST``: "real" or "temp" or "drop".
    """

    def __init__(self) -> None:
        self.single = "real"
        self.full = "real"
        self.deleted: set[int] = set()
        self.commands: list[str] = []
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _present(self) -> dict[int, int]:
        return {n: size for n, size in _SIZES.items() if n not in self.deleted}

    def _session(self, conn: socket.socket) -> None:
        conn.sendall(b"+OK ready\r\n")
        for raw in conn.makefile("rb"):
            line = raw.decode().strip()
            self.commands.append(line)
            cmd, *args = line.split()
            cmd = cmd.upper()
            if cmd in ("USER", "PASS", "NOOP"):
                out = b"+OK\r\n"
            elif cmd == "LIST" and args:
                mode = self.single
                if mode == "drop":
                    break
                if mode == "stall":
                    continue
                n = int(args[0])
                if mode == "temp":
                    out = b"-ERR [SYS/TEMP] try again later\r\n"
                elif n in self._present():
                    out = f"+OK {n} {_SIZES[n]}\r\n".encode()
                elif n in self.deleted:
                    out = f"-ERR message {n} already deleted\r\n".encode()
                else:
                    out = b"-ERR no such message\r\n"
            elif cmd == "LIST":
                if self.full == "drop":
                    break
                if self.full == "temp":
                    out = b"-ERR [SYS/TEMP] try again later\r\n"
                else:
                    rows = "".join(f"{n} {s}\r\n" for n, s in self._present().items())
                    out = f"+OK {len(self._present())} messages\r\n{rows}.\r\n".encode()
            elif cmd == "DELE" and args and int(args[0]) in self._present():
                self.deleted.add(int(args[0]))
                out = b"+OK marked\r\n"
            elif cmd == "QUIT":
                conn.sendall(b"+OK bye\r\n")
                break
            else:
                out = b"-ERR unsupported\r\n"
            conn.sendall(out)
        conn.close()

    def stop(self) -> None:
        self._srv.close()


@pytest.fixture
def srv():
    server = _ScriptedPop3()
    yield server
    server.stop()


@pytest.fixture
def pop(srv):
    s = Pop3Session("127.0.0.1", srv.port, "u", "p", use_ssl=False)
    yield s
    try:
        s.close()
    except Exception:  # noqa: BLE001 - the connection may be gone on purpose
        pass


# --- happy ------------------------------------------------------------------


def test_happy_present_and_absent_messages(pop):
    assert pop.exists("/1_one.eml") is True
    assert pop.exists("/3_three.eml") is True
    assert pop.exists("/9_gone.eml") is False
    assert pop.exists("/") is True


def test_happy_a_missing_message_is_file_not_found(pop):
    with pytest.raises(FileNotFoundError):
        pop.stat("/9_gone.eml")


# --- sad --------------------------------------------------------------------


def test_sad_a_temporary_error_for_a_listed_message_is_an_oserror(pop, srv):
    srv.single = "temp"
    with pytest.raises(OSError) as info:
        pop.exists("/1_one.eml")
    assert not isinstance(info.value, FileNotFoundError)


def test_sad_a_dropped_connection_is_an_oserror(pop, srv):
    srv.single = "drop"
    with pytest.raises(OSError) as info:
        pop.exists("/1_one.eml")
    assert not isinstance(info.value, FileNotFoundError)


def test_sad_a_timeout_is_an_oserror(pop, srv):
    srv.single = "stall"
    pop._pop.sock.settimeout(0.3)
    with pytest.raises(OSError) as info:
        pop.exists("/1_one.eml")
    assert not isinstance(info.value, FileNotFoundError)


def test_sad_an_unconfirmed_absence_is_an_oserror(pop, srv):
    # LIST n refused, and the listing that would decide it fails too.
    srv.single = "temp"
    srv.full = "temp"
    with pytest.raises(OSError) as info:
        pop.exists("/9_gone.eml")
    assert not isinstance(info.value, FileNotFoundError)


# --- edge -------------------------------------------------------------------


def test_edge_a_message_deleted_in_this_session_is_absent(pop, srv):
    pop.remove("/2_two.eml")
    assert pop.exists("/2_two.eml") is False


def test_edge_a_path_that_names_no_message_is_absent(pop, srv):
    assert pop.exists("/readme.txt") is False
    assert pop.exists("/sub/1_one.eml") is False
    with pytest.raises(FileNotFoundError):
        pop.stat("/readme.txt")
    # Decided from the path alone: no round trip.
    assert not any(c.upper().startswith("LIST") for c in srv.commands)


def test_edge_a_present_message_costs_one_round_trip(pop, srv):
    assert pop.exists("/1_one.eml") is True
    assert [c for c in srv.commands if c.upper().startswith("LIST")] == ["LIST 1"]
