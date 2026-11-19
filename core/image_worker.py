"""Decode pictures in a killable child process.

Qt's image plugins (libjpeg, libpng, libwebp, libtiff) and Pillow parse a
picture in native code: a crafted file could keep a decoder busy for ever
or crash it, and inside axross that pinned the image viewer's, the media
viewer's or a thumbnail thread for good, or took the whole program down.
So :mod:`core.previews` decodes in a child interpreter: a few reused
children (:func:`borrowed`, the open of a picture pays no start), each
request bounded by :data:`DECODE_SECONDS` of wall-clock time (the parent
kills the child) and a CPU budget the child sets itself, its data memory
capped (RLIMIT_DATA), and the child ends with its parent
(PR_SET_PDEATHSIG on Linux, a kill-on-close job object on Windows). A hang
or a crash ends only that child; the next request starts a fresh one.

The child is ``python -I -c`` :data:`_CHILD_SOURCE` (a frozen build answers
``--image-worker``, main.py). It runs core.previews' own decoders
(``core.previews._decode_here``) under the gates the parent passes along.

Protocol (integers big-endian), as core.pdf_worker's: parent -> child
``u32 len`` + a JSON request; child -> parent ``u32 len`` + a JSON answer +
``u32 len`` + a body (PNG bytes, or a decoded picture's pixels).

Pure Python, no Qt at import: the headless server imports core.previews.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import struct
import subprocess
import sys
import threading
import time

from core import process_launcher
from core.subprocess_env import worker_env

log = logging.getLogger(__name__)

#: Seconds one picture may take to be decoded, the child's start included.
DECODE_SECONDS = 30.0
#: Data memory of the child (bytes): Qt, the decoder and the picture (Qt's
#: own cap is core.previews.QIMAGE_ALLOC_LIMIT_MIB, Pillow's
#: PILLOW_ALLOC_LIMIT_MIB with its copies).
DATA_LIMIT = 2 * 1024**3
#: Largest answer header the parent reads, and largest body.
_MAX_HEADER = 64 * 1024
MAX_BODY = 512 * 1024**2
#: Bodies from this size on come through the memory file (Linux), not the pipe.
_SHM_FROM = 256 * 1024
#: Idle children kept for the next picture, and the pictures one child
#: decodes before it is replaced (a decoder's caches do not grow for ever).
POOL_SIZE = 3
DECODES_PER_CHILD = 500
#: An idle child unused this long is ended at the next borrow (about 50 MB each).
POOL_IDLE_SECONDS = 180.0

_CHILD_SOURCE = r'''
import sys
if sys.argv[-4] not in sys.path:
    # a source checkout (an installed axross is on the path already: put
    # first, its folder - site-packages - would shadow the standard library)
    sys.path.insert(0, sys.argv[-4])
from core.image_worker import _serve
_serve()
'''


class ImageWorkerError(Exception):
    """The child could not decode the picture; ``str()`` says why."""


class ImageTooSlow(ImageWorkerError):
    """A request took longer than its bound (the child was killed)."""


class ImageCrashed(ImageWorkerError):
    """The child ended in the middle of a request."""


class ImageCancelled(ImageWorkerError):
    """The caller no longer wanted the answer (the child was ended)."""


def cpu_seconds_for(seconds: float) -> int:
    """The child's CPU budget per request: the wall-clock bound with room to
    spare (the parent's timer normally ends it first)."""
    return int(seconds) * 2 + 5


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def worker_argv(seconds: float | None = None) -> list[str]:
    """The command that starts a decoding child. A frozen build has no
    ``python -c``: the binary itself answers ``--image-worker`` (main.py).
    The last four arguments: the folder ``core`` is in, this process's pid,
    the CPU seconds per request, the data-memory limit."""
    seconds = DECODE_SECONDS if seconds is None else seconds
    tail = [_project_root(), str(os.getpid()), str(cpu_seconds_for(seconds)), str(DATA_LIMIT)]
    if getattr(sys, "frozen", False):
        return [sys.executable, "--image-worker", *tail]
    return [sys.executable, "-I", "-c", _CHILD_SOURCE, *tail]


# -- the child -------------------------------------------------------------------


def _bind_to_parent(parent: int) -> None:
    """End with *parent* (Linux); a child whose parent is someone else ends now."""
    if not sys.platform.startswith("linux"):
        return
    import ctypes

    try:
        # PR_SET_PDEATHSIG = 1, SIGKILL = 9
        ctypes.CDLL(None, use_errno=True).prctl(1, 9, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    if os.getppid() == parent:
        return
    # A one-file build: its own bootloader between the program and this child.
    try:
        with open(f"/proc/{os.getppid()}/stat", "rb") as stat:
            grand = int(stat.read().rsplit(b")", 1)[1].split()[1])
    except (OSError, ValueError, IndexError):
        grand = -1
    if grand != parent:
        os._exit(1)


def _limit_memory(space: int) -> None:
    try:
        import resource
    except ImportError:
        return
    # RLIMIT_DATA, not RLIMIT_AS: an allocator may reserve address space up
    # front (pdfium's did); RLIMIT_DATA counts what is written to.
    for name, value in (("RLIMIT_CORE", 0), ("RLIMIT_DATA", space)):
        try:
            resource.setrlimit(getattr(resource, name), (value, value))
        except (ValueError, OSError, AttributeError):
            pass


def _cpu_budget(cpu: int) -> None:
    """What this child used so far plus *cpu* seconds (SIGXCPU ends it)."""
    try:
        import resource

        used = resource.getrusage(resource.RUSAGE_SELF)
        soft = int(used.ru_utime + used.ru_stime) + cpu
        hard = resource.getrlimit(resource.RLIMIT_CPU)[1]
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
    except (ImportError, ValueError, OSError, AttributeError):
        pass


def _serve() -> None:
    """The child's loop: one request in, one answer out, until stdin ends."""
    from core import previews

    serve(previews._decode_request, ready=previews._qt_gui)


def serve(handle, ready=None) -> None:
    """A child's loop (this one's, core.lex_worker's): bound to its parent,
    its memory capped, then ``handle(request) -> (header, body)`` for every
    request until stdin ends; *ready()* runs once before the first."""
    parent, cpu, space = (int(a) for a in sys.argv[-3:])
    _bind_to_parent(parent)
    _limit_memory(space)
    inp = sys.stdin.buffer
    # The answers get stdout to themselves: what a library prints goes to stderr.
    out = os.fdopen(os.dup(1), "wb")
    with contextlib.suppress(OSError):
        os.dup2(2, 1)

    def read(n: int) -> bytes:
        data = inp.read(n)
        if len(data) != n:
            os._exit(0)
        return data

    def answer(head: dict, body=b"") -> None:
        # *body*: bytes, or an object whose parts() are buffers (the pixels
        # of a decoded picture, written without a copy).
        data = json.dumps(head).encode()
        out.write(struct.pack(">I", len(data)) + data + struct.pack(">I", len(body)))
        for part in (body.parts() if hasattr(body, "parts") else (body,)):
            if len(part):
                out.write(part)
        out.flush()

    if ready is not None:
        ready()  # e.g. Qt's image classes loaded while the first request is still coming
    while True:
        request = json.loads(read(struct.unpack(">I", read(4))[0]))
        _cpu_budget(cpu)
        try:
            head, body = handle(request)
        except MemoryError:
            head, body = {"error": "memory"}, b""
        shm = request.get("shm")
        if isinstance(shm, int) and len(body) >= _SHM_FROM:
            try:
                os.ftruncate(shm, len(body))
                offset = 0
                for part in (body.parts() if hasattr(body, "parts") else (body,)):
                    view = memoryview(part).cast("B")
                    while view:
                        count = os.pwrite(shm, view, offset)
                        offset, view = offset + count, view[count:]
                head, body = {**head, "shm": offset}, b""
            except (OSError, MemoryError):
                with contextlib.suppress(OSError):
                    os.ftruncate(shm, 0)
        answer(head, body)


def _child_main() -> int:
    """The frozen build's ``--image-worker`` entry point."""
    _serve()
    return 0


# -- the parent ------------------------------------------------------------------


class SharedBody:
    """An answer's body the child left in its memory file (Linux): read
    straight into where it is wanted - a QImage's own pixels - with no copy
    between. Valid inside :meth:`ImageChild.ask`'s *consume* only."""

    def __init__(self, fd: int, length: int) -> None:
        self._fd, self._length = fd, length

    def __len__(self) -> int:
        return self._length

    def read_into(self, view: memoryview, offset: int = 0) -> None:
        """``len(view)`` bytes from *offset* into *view* (writable)."""
        view = view.cast("B")
        if offset < 0 or offset + len(view) > self._length:
            raise SharedBodyError("read past the body")
        got = 0
        try:
            while got < len(view):
                count = os.preadv(self._fd, [view[got:]], offset + got)
                if count <= 0:
                    raise SharedBodyError("the body is shorter than said")
                got += count
        except OSError as exc:
            raise SharedBodyError(str(exc)) from None

    def tail(self, offset: int) -> bytes:
        """The body from *offset* to its end."""
        out = bytearray(max(0, self._length - offset))
        self.read_into(memoryview(out), offset)
        return bytes(out)

    def read_all(self) -> bytearray:
        out = bytearray(self._length)
        self.read_into(memoryview(out))
        return out

    def release(self) -> None:
        """Empty the memory file (its pages are given back)."""
        with contextlib.suppress(OSError):
            os.ftruncate(self._fd, 0)


class SharedBodyError(Exception):
    """The child's memory file does not hold what its answer said."""


class ImageChild:
    """One decoding child; one request at a time (the pool hands it to one
    caller). A request past *seconds* kills it (:class:`ImageTooSlow`), a
    child that dies raises :class:`ImageCrashed`. core.lex_worker's child
    is one with another command and other words."""

    #: What a request does, and the child, in the texts of the errors.
    work_text = "decoding the picture"
    process_text = "the picture decoding process"

    def __init__(self, seconds: float | None = None) -> None:
        self._seconds = self._default_seconds() if seconds is None else float(seconds)
        self._proc: subprocess.Popen | None = None
        self._replies: queue.Queue | None = None
        self._shm: int | None = None
        #: A request was sent and its answer not yet read: the channel is
        #: in an unknown state if the caller leaves now.
        self._busy = False
        self.requests = 0

    @staticmethod
    def _default_seconds() -> float:
        return DECODE_SECONDS

    def _argv(self) -> list[str]:
        return worker_argv(self._seconds)

    def _start(self) -> None:
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if self._shm is None and hasattr(os, "memfd_create"):
            # Big answers (a photo's 45 MB of pixels) come through a memory
            # file the child writes: through the pipe they took 0.2-0.5 s.
            with contextlib.suppress(OSError):
                self._shm = os.memfd_create("axross-image", getattr(os, "MFD_CLOEXEC", 1))
        if self._shm is not None:
            kwargs["pass_fds"] = (self._shm,)
        try:
            # From the launcher thread: PR_SET_PDEATHSIG fires when the thread
            # that started the child ends - a pooled child started by a short-lived
            # worker (ui.off_gui) was killed with it.
            proc = process_launcher.popen(self._argv(), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         env=worker_env(), close_fds=True, **kwargs)
        except OSError as exc:
            raise ImageWorkerError(f"{self.process_text} could not start: {exc}") from exc
        try:
            from core.regex_worker import _kill_with_parent_windows

            _kill_with_parent_windows(proc)
        except ImportError:  # an exported tool comes without the regex worker
            pass
        replies: queue.Queue = queue.Queue()
        threading.Thread(target=self._read_loop, args=(proc, replies),
                         name="image-worker-reader", daemon=True).start()
        self._proc, self._replies = proc, replies

    @staticmethod
    def _read_exact(stream, n: int) -> bytes | None:
        data = stream.read(n)
        return data if data is not None and len(data) == n else None

    @staticmethod
    def _read_body(stream, n: int) -> bytearray | None:
        """*n* bytes read into one buffer (no joined copy of a big picture)."""
        body = bytearray(n)
        view, got = memoryview(body), 0
        while got < n:
            count = stream.readinto(view[got:])
            if not count:
                return None
            got += count
        return body

    @classmethod
    def _read_loop(cls, proc: subprocess.Popen, replies: queue.Queue) -> None:
        stream = proc.stdout
        try:
            while True:
                head = cls._read_exact(stream, 4)
                if head is None:
                    return
                (size,) = struct.unpack(">I", head)
                if size > _MAX_HEADER:
                    return
                header = json.loads(cls._read_exact(stream, size) or b"null")
                if not isinstance(header, dict):
                    return
                body_size = cls._read_exact(stream, 4)
                if body_size is None:
                    return
                (length,) = struct.unpack(">I", body_size)
                if length > MAX_BODY:
                    return
                body = cls._read_body(stream, length) if length else b""
                if body is None:
                    return
                replies.put((header, body))
        except (OSError, ValueError, RecursionError, struct.error):
            return
        finally:
            replies.put(None)

    @property
    def alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def pid(self) -> int | None:
        proc = self._proc
        return proc.pid if proc is not None else None

    def ask(self, request: dict, consume=None, cancel=None):
        """*request* answered by the child: ``(header, body)`` - or, given
        *consume*, ``consume(header, body)``, called before this returns
        (the body may be a :class:`SharedBody`, valid only until then).
        *cancel()* is asked now and then while the child works: True ends
        the child and raises :class:`ImageCancelled`."""
        if self._proc is None:
            self._start()
        self.requests += 1
        proc, replies = self._proc, self._replies
        if self._shm is not None:
            request = {**request, "shm": self._shm}
        data = json.dumps(request).encode()
        self._busy = True
        try:
            proc.stdin.write(struct.pack(">I", len(data)) + data)
            proc.stdin.flush()
        except (OSError, ValueError):
            pass  # the reader reports the end below
        try:
            reply = self._wait(replies, cancel)
        except queue.Empty:
            self.close()
            raise ImageTooSlow(f"{self.work_text} took longer than {self._seconds:g} s") from None
        if reply is None:
            code = proc.poll()
            if code is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    code = proc.wait(timeout=2)
            self.close()
            how = f"signal {-code}" if code is not None and code < 0 else f"exit status {code}"
            raise ImageCrashed(f"{self.process_text} ended ({how})")
        self._busy = False
        header, body = reply
        if "shm" not in header:
            return consume(header, body) if consume is not None else (header, body)
        shared = self._shared(header.pop("shm"))
        try:
            if consume is not None:
                return consume(header, shared)
            return header, shared.read_all()
        except SharedBodyError:
            self.close()
            raise ImageCrashed(f"{self.process_text} answered nonsense") from None
        finally:
            shared.release()

    def _wait(self, replies: queue.Queue, cancel):
        """The next answer; queue.Empty past the time."""
        if cancel is None:
            return replies.get(timeout=self._seconds)
        deadline = time.monotonic() + self._seconds
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise queue.Empty
            try:
                return replies.get(timeout=min(0.1, left))
            except queue.Empty:
                if cancel():
                    self.close()
                    raise ImageCancelled(f"{self.work_text} was no longer wanted") from None

    def _shared(self, length) -> SharedBody:
        fd = self._shm
        try:
            length = int(length)
            if fd is None or not 0 < length <= MAX_BODY or os.fstat(fd).st_size < length:
                raise ValueError(length)
        except (OSError, ValueError, TypeError):
            self.close()
            raise ImageCrashed(f"{self.process_text} answered nonsense") from None
        return SharedBody(fd, length)

    def close(self) -> None:
        proc, self._proc = self._proc, None
        self._replies = None
        shm, self._shm = self._shm, None
        if shm is not None:
            with contextlib.suppress(OSError):
                os.close(shm)
        if proc is None:
            return
        if proc.poll() is None:
            with contextlib.suppress(OSError):
                proc.kill()
        for stream in (proc.stdin, proc.stdout):
            with contextlib.suppress(OSError, ValueError):
                stream.close()
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            proc.wait(timeout=5)

    def __del__(self) -> None:
        proc = getattr(self, "_proc", None)
        if proc is not None:
            with contextlib.suppress(Exception):
                if proc.poll() is None:
                    proc.kill()


class ChildPool:
    """A few idle children of one kind, reused: :meth:`borrowed` hands one
    to one caller; it goes back unless it failed in the middle of a request.
    *make()* makes a new child; *size()*, *idle()* (seconds an idle child
    is kept) and *per_child()* (requests before it is replaced) are asked
    each time, so the module's settings hold."""

    def __init__(self, make, size, idle, per_child, name: str) -> None:
        self._make, self._size, self._idle, self._per_child = make, size, idle, per_child
        self._name = name
        self._pool: list[tuple[float, ImageChild]] = []
        self._lock = threading.Lock()
        self._reaper: threading.Thread | None = None

    def _take_stale(self, now: float) -> list[ImageChild]:
        stale = [c for at, c in self._pool if now - at > self._idle()]
        self._pool[:] = [(at, c) for at, c in self._pool if now - at <= self._idle()]
        return stale

    @contextlib.contextmanager
    def borrowed(self):
        with self._lock:
            stale = self._take_stale(time.monotonic())
            child = None
            for entry in self._pool:
                if entry[1]._seconds == entry[1]._default_seconds():
                    child = entry[1]
                    self._pool.remove(entry)
                    break
        for old in stale:
            old.close()
        if child is None:
            child = self._make()
        try:
            yield child
        except BaseException:
            if child._busy or not child.alive:
                # Left in the middle of a request (or the child died): ended.
                # A refusal raised over a complete answer keeps the child.
                child.close()
            else:
                self.give_back(child)
            raise
        self.give_back(child)

    def give_back(self, child: ImageChild) -> None:
        with self._lock:
            if (len(self._pool) < self._size() and child.alive
                    and child.requests < self._per_child()):
                self._pool.append((time.monotonic(), child))
                if self._reaper is None or not self._reaper.is_alive():
                    self._reaper = threading.Thread(target=self._reap, daemon=True,
                                                    name=f"{self._name}-reaper")
                    self._reaper.start()
                return
        child.close()

    def _reap(self) -> None:
        """End the children idle past their time - not only at the next
        borrow: a viewer opened once left them (about 50 MB each) until
        axross ended. Ends itself when the pool is empty."""
        while True:
            time.sleep(max(1.0, self._idle() / 4))
            with self._lock:
                stale = self._take_stale(time.monotonic())
                empty = not self._pool
            for child in stale:
                child.close()
            if empty:
                return

    def ask(self, request: dict, consume=None, cancel=None):
        with self.borrowed() as child:
            return child.ask(request, consume, cancel)

    def warm(self) -> None:
        """Start a child now when none is idle, without waiting for it: a
        caller about to ask has the start (0.1-0.3 s) behind it by then."""
        with self._lock:
            if self._pool:
                return
        child = self._make()
        try:
            child._start()
        except ImageWorkerError as exc:
            log.debug("%s: no child started ahead: %s", self._name, exc)
            return
        self.give_back(child)

    def idle_pids(self) -> list[int]:
        with self._lock:
            return [c.pid() for _at, c in self._pool if c.pid() is not None]

    def close(self) -> None:
        with self._lock:
            pool = [c for _at, c in self._pool]
            self._pool.clear()
        for child in pool:
            child.close()


_POOL = ChildPool(ImageChild, lambda: POOL_SIZE, lambda: POOL_IDLE_SECONDS,
                  lambda: DECODES_PER_CHILD, "image-worker")


def borrowed():
    """An :class:`ImageChild` from the pool (see :class:`ChildPool`)."""
    return _POOL.borrowed()


def ask(request: dict, consume=None):
    """*request* answered by a pooled child (see :meth:`ImageChild.ask`)."""
    return _POOL.ask(request, consume)


def warm() -> None:
    """Start a decoding child for the pool now, without waiting for it: a
    viewer about to decode has the start behind it by the time its first
    picture is read. Never raises."""
    _POOL.warm()


def idle_pids() -> list[int]:
    """The process ids of the idle pooled children (tests)."""
    return _POOL.idle_pids()


def close_pool() -> None:
    """End the pooled children (tests; the children end with axross anyway)."""
    _POOL.close()


__all__ = [
    "DATA_LIMIT",
    "DECODE_SECONDS",
    "ImageCancelled",
    "ImageCrashed",
    "ImageTooSlow",
    "ChildPool",
    "ImageChild",
    "ImageWorkerError",
    "SharedBody",
    "SharedBodyError",
    "ask",
    "borrowed",
    "close_pool",
    "idle_pids",
    "warm",
    "worker_argv",
]
