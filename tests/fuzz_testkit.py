"""Shared helpers for the protocol fuzz suites (``tests/test_fuzz_*.py``).

The suites feed axross protocol clients hostile server behaviour - garbage,
truncation, lying sizes, invalid UTF-8, huge tokens, traversal names, early
EOF, stalls - and hold every call to one contract:

* it returns sane data, or raises an exception class the callers handle
  (``OSError`` and its subclasses, or a module's own documented error type);
* it never raises the "programming error" classes callers do not catch
  (IndexError, KeyError, ValueError, UnicodeError, AttributeError,
  TypeError, struct.error, RecursionError, ...);
* it finishes within a hard deadline (a stalled server must time out).

Mutation is deterministic: ``random.Random(seed)`` over a corpus of valid
replies. ``AXROSS_FUZZ_ITERATIONS`` raises the number of mutants per corpus
entry for a deeper sweep (default: a fast smoke sweep).
"""

from __future__ import annotations

import os
import random
import socket
import struct
import threading
from tests.socket_lifecycle import close_socket  # noqa: E402
import traceback
from collections.abc import Callable, Iterable, Iterator

# Exception classes no caller of a backend handles; a server must never be
# able to provoke one of them.
FORBIDDEN = (
    AssertionError,
    AttributeError,
    IndexError,
    KeyError,
    LookupError,
    RecursionError,
    TypeError,
    UnicodeError,
    ValueError,
    ZeroDivisionError,
    OverflowError,
    MemoryError,
    struct.error,
)

# Odd tokens spliced into mutants.
ODD_TOKENS: tuple[bytes, ...] = (
    b"\x00",
    b"\xff\xfe\xfd",
    b"\xc3\x28",  # invalid UTF-8 continuation
    b"\xed\xa0\x80",  # UTF-8 encoded surrogate
    b"\r",
    b"\n",
    b"\r\n",
    b"../",
    b"/",
    b"..",
    b"-1",
    b"-9223372036854775809",
    b"99999999999999999999999999999999999999",
    b"1e309",
    b"NaN",
    b"%s%n%x",
    b"\x1b[2J",
    b"\xe2\x80\xae",  # RIGHT-TO-LEFT OVERRIDE
    b" ",
    b"\t",
    b";",
    b"=",
    b":",
    b'"',
    b"<",
    b"&",
    b"A" * 4096,
)


def iterations(default: int) -> int:
    """Mutants per corpus entry: ``AXROSS_FUZZ_ITERATIONS`` or *default*."""
    raw = os.environ.get("AXROSS_FUZZ_ITERATIONS", "").strip()
    if raw:
        try:
            value = int(raw)
        except ValueError:
            return default
        if value > 0:
            return value
    return default


def mutate(data: bytes, rng: random.Random) -> bytes:
    """One deterministic mutation of *data*."""
    buf = bytearray(data)
    op = rng.randrange(9)
    if not buf:
        return rng.choice(ODD_TOKENS)
    pos = rng.randrange(len(buf) + 1)
    if op == 0:  # bit flip
        i = rng.randrange(len(buf))
        buf[i] ^= 1 << rng.randrange(8)
    elif op == 1:  # truncate
        del buf[pos:]
    elif op == 2:  # delete a slice
        end = min(len(buf), pos + rng.randrange(1, 16))
        del buf[pos:end]
    elif op == 3:  # duplicate a slice
        end = min(len(buf), pos + rng.randrange(1, 64))
        buf[pos:pos] = buf[pos:end]
    elif op == 4:  # insert an odd token
        buf[pos:pos] = rng.choice(ODD_TOKENS)
    elif op == 5:  # replace a byte with a random one
        i = rng.randrange(len(buf))
        buf[i] = rng.randrange(256)
    elif op == 6:  # replace a digit run with an absurd number
        digits = [i for i, b in enumerate(buf) if 48 <= b <= 57]
        if digits:
            i = rng.choice(digits)
            j = i
            while j < len(buf) and 48 <= buf[j] <= 57:
                j += 1
            buf[i:j] = rng.choice((b"-1", b"0", b"99999999999999999999", b"4294967296", b""))
        else:
            buf[pos:pos] = b"-1"
    elif op == 7:  # swap two bytes
        i, j = rng.randrange(len(buf)), rng.randrange(len(buf))
        buf[i], buf[j] = buf[j], buf[i]
    else:  # stack two mutations
        return mutate(mutate(bytes(buf), rng), rng)
    return bytes(buf)


def mutants(corpus: Iterable[bytes], seed: int, per_entry: int) -> Iterator[bytes]:
    """``per_entry`` deterministic mutants of every corpus entry."""
    rng = random.Random(seed)
    for entry in corpus:
        for _ in range(per_entry):
            yield mutate(entry, rng)


def run_bounded(fn: Callable[[], object], timeout: float = 10.0):
    """Run *fn* on a daemon thread; ``(result, exception)``.

    Fails the test when *fn* is still running after *timeout* seconds - a
    hostile server must never hang a client call.
    """
    box: dict[str, object] = {}

    def target() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            box["exc"] = exc

    t = threading.Thread(target=target, daemon=True, name="fuzz-call")
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise AssertionError(f"call did not finish within {timeout}s (hang)")
    return box.get("result"), box.get("exc")


def check_contract(
    fn: Callable[[], object],
    allowed: tuple[type[BaseException], ...] = (OSError,),
    timeout: float = 10.0,
    context: str = "",
):
    """Call *fn* under a deadline; return its result or the allowed exception.

    Raises AssertionError (with the traceback of the offending exception)
    when *fn* raised anything outside *allowed*.
    """
    result, exc = run_bounded(fn, timeout)
    if exc is None:
        return result
    if any(a in (Exception, BaseException) for a in allowed):
        raise AssertionError("check_contract: an allowed class this broad tests nothing")
    if isinstance(exc, allowed):
        return exc
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    raise AssertionError(
        f"{context}: raised {type(exc).__name__} outside the contract "
        f"{[c.__name__ for c in allowed]}:\n{tb}"
    )


class ScriptedServer:
    """A TCP server on 127.0.0.1 whose connections run ``handler(conn)``.

    Every accepted connection gets its own daemon thread. ``close()`` (or the
    context manager) stops accepting and closes every open connection, so a
    handler that stalls on purpose never outlives the test.
    """

    def __init__(self, handler: Callable[[socket.socket], None]) -> None:
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self.host = "127.0.0.1"
        self._conns: list[socket.socket] = []
        self._closed = threading.Event()
        threading.Thread(target=self._accept, daemon=True, name="fuzz-srv").start()

    def _accept(self) -> None:
        while not self._closed.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self._conns.append(conn)
            threading.Thread(target=self._run, args=(conn,), daemon=True).start()

    def _run(self, conn: socket.socket) -> None:
        try:
            self._handler(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._closed.set()
        close_socket(self._sock)
        for conn in list(self._conns):
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def __enter__(self) -> "ScriptedServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def recv_line(conn: socket.socket, limit: int = 65536) -> bytes:
    """Read one LF-terminated line from *conn* (b"" on EOF)."""
    out = bytearray()
    while len(out) < limit:
        b = conn.recv(1)
        if not b:
            break
        out += b
        if b == b"\n":
            break
    return bytes(out)


def stall(conn: socket.socket, seconds: float = 30.0) -> None:
    """Keep *conn* open without sending anything (slow-loris)."""
    conn.settimeout(seconds)
    try:
        while conn.recv(4096):
            pass
    except OSError:
        pass
