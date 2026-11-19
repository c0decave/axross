"""Draw PDF pages in a killable child process.

pdfium (QtPdf) parses whatever a PDF holds - fonts, images, streams,
cross references - in native code: a hostile PDF can keep it busy for
ever or crash it, and inside axross that pinned a viewer or thumbnail
thread for good or took the whole program down. So a PDF is opened and
drawn in a child interpreter: one long-lived child per open document (the
media viewer turns pages and zooms through it without a new start), and
a few reused children for thumbnails (:func:`borrowed`). The parent kills
a child that takes longer than :data:`RENDER_SECONDS` for one request;
the next request starts a fresh one. A hang or a crash ends only that
child - the caller gets a :class:`PdfError` whose text says why.

The child is ``python -I -c`` :data:`_CHILD_SOURCE` (a frozen build
answers ``--pdf-worker``, main.py). It reads only the file it is told to
open; its memory and CPU time are capped (RLIMIT_DATA; RLIMIT_CPU per
request, so the bound holds without the parent) and it ends with its
parent (PR_SET_PDEATHSIG on Linux, a kill-on-close job object on Windows).

Protocol (integers big-endian): parent -> child ``u32 len`` + a JSON
request; child -> parent ``u32 len`` + a JSON answer + ``u32 len`` + the
picture (empty but for a drawn page: ``width * height * 4`` bytes of
QImage.Format_RGB32, the page on white).

Pure Python, no Qt at import: the headless server imports core.media_load.
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

#: Seconds one request (open, page size, one page drawn) may take,
#: the child's start included.
RENDER_SECONDS = 15.0
#: Data memory of the child (bytes): Qt, pdfium, the document and one page.
DATA_LIMIT = 4 * 1024**3
#: The most pixels one drawn page may have (4 bytes each through the pipe).
MAX_PIXELS = 24_000_000
#: The longest side of one drawn page.
MAX_EDGE = 12_000
#: Largest answer header the parent reads.
_MAX_HEADER = 64 * 1024
#: Children kept for :func:`borrowed` between thumbnails, and the documents
#: one child opens before it is replaced (pdfium's caches do not grow for ever).
POOL_SIZE = 3
DOCUMENTS_PER_CHILD = 200
#: A pooled child idle this long is ended at the next borrow (about 60 MB each).
POOL_IDLE_SECONDS = 120.0

_CHILD_SOURCE = r'''
import json, os, struct, sys
_parent, _cpu, _space = (int(a) for a in sys.argv[-3:])
if sys.platform.startswith("linux"):
    # End with the parent (PR_SET_PDEATHSIG = 1, SIGKILL = 9).
    import ctypes
    try:
        ctypes.CDLL(None, use_errno=True).prctl(1, 9, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    if os.getppid() != _parent:
        # A one-file build: its own bootloader between the program and this child.
        try:
            with open(f"/proc/{os.getppid()}/stat", "rb") as _stat:
                _grand = int(_stat.read().rsplit(b")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            _grand = -1
        if _grand != _parent:
            sys.exit(1)
try:
    import resource
except ImportError:
    resource = None
if resource is not None:
    # RLIMIT_DATA, not RLIMIT_AS: pdfium's allocator reserves tens of GB of
    # address space up front (it stopped with SIGTRAP under 32 GB of RLIMIT_AS);
    # RLIMIT_DATA counts what is written to, not what is reserved.
    for _name, _value in (("RLIMIT_CORE", 0), ("RLIMIT_DATA", _space)):
        try:
            resource.setrlimit(getattr(resource, _name), (_value, _value))
        except (ValueError, OSError):
            pass
def cpu_budget():
    # What this child used so far plus _cpu seconds (SIGXCPU ends it).
    if resource is None:
        return
    try:
        used = resource.getrusage(resource.RUSAGE_SELF)
        soft = int(used.ru_utime + used.ru_stime) + _cpu
        hard = resource.getrlimit(resource.RLIMIT_CPU)[1]
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
    except (ValueError, OSError):
        pass
inp, out = sys.stdin.buffer, sys.stdout.buffer
def read(n):
    data = inp.read(n)
    if len(data) != n:
        os._exit(0)
    return data
def answer(head, body=b""):
    data = json.dumps(head).encode()
    out.write(struct.pack(">I", len(data)) + data + struct.pack(">I", len(body)))
    if body:
        out.write(body)
    out.flush()
try:
    from PyQt6.QtCore import QSize, Qt
    from PyQt6.QtGui import QImage, QPainter
    from PyQt6.QtPdf import QPdfDocument
    missing = ""
except ImportError as exc:
    missing = str(exc) or "QtPdf cannot be loaded"
doc = None
while True:
    request = json.loads(read(struct.unpack(">I", read(4))[0]))
    cpu_budget()
    op = request.get("op")
    if missing:
        answer({"error": "missing", "text": missing})
        continue
    try:
        if op == "open":
            if doc is not None:
                doc.close()
            else:
                doc = QPdfDocument(None)
            error = doc.load(request["path"])
            if error != QPdfDocument.Error.None_:
                doc.close()
                answer({"error": getattr(error, "name", str(error))})
                continue
            answer({"pages": doc.pageCount()})
        elif op == "meta" and doc is not None:
            info = {}
            for key in request.get("fields", ())[:32]:
                field = getattr(QPdfDocument.MetaDataField, str(key), None)
                if field is None:
                    continue
                value = doc.metaData(field)
                if hasattr(value, "isValid"):
                    if not value.isValid():
                        continue
                    value = value.toString("yyyy-MM-dd HH:mm:ss t")
                if value not in (None, ""):
                    info[str(key)] = str(value)[:4096]
            answer({"meta": info})
        elif op == "close":
            if doc is not None:
                doc.close()
            answer({})
        elif doc is None or not 0 <= request.get("page", -1) < doc.pageCount():
            answer({"error": "page"})
        elif op == "size":
            size = doc.pagePointSize(request["page"])
            answer({"w": size.width(), "h": size.height()})
        elif op == "render":
            w, h = int(request["width"]), int(request["height"])
            rendered = doc.render(request["page"], QSize(w, h))
            if rendered.isNull():
                answer({"error": "render"})
                continue
            # pdfium leaves the page transparent where nothing is drawn.
            image = QImage(rendered.size(), QImage.Format.Format_RGB32)
            image.fill(Qt.GlobalColor.white)
            painter = QPainter(image)
            painter.drawImage(0, 0, rendered)
            painter.end()
            ptr = image.constBits()
            ptr.setsize(image.sizeInBytes())
            answer({"w": image.width(), "h": image.height(), "stride": image.bytesPerLine()},
                   bytes(ptr))
        else:
            answer({"error": "op"})
    except MemoryError:
        answer({"error": "memory"})
'''


class PdfError(Exception):
    """The PDF cannot be shown; ``str()`` is the reason for the user."""


class PdfTooSlow(PdfError):
    """A request took longer than its bound (the child was killed)."""


class PdfCrashed(PdfError):
    """The child ended in the middle of a request."""


class PdfMissing(PdfError):
    """QtPdf cannot be loaded (in the child)."""


#: QPdfDocument.Error names -> the text the user sees.
_OPEN_ERRORS = {
    "IncorrectPassword": "PDF is password-protected",
    "UnsupportedSecurityScheme": "PDF uses an unsupported encryption",
    "InvalidFileFormat": "not a valid PDF",
    "FileNotFound": "PDF file not found",
    "DataNotYetAvailable": "PDF data not available",
}


def error_text(name: str) -> str:
    """The user's text for a QPdfDocument.Error *name*."""
    return _OPEN_ERRORS.get(name, f"cannot open PDF ({name})")


def cpu_seconds_for(seconds: float) -> int:
    """The child's CPU budget per request: the wall-clock bound with room to
    spare (the parent's timer normally ends it first)."""
    return int(seconds) * 2 + 5


def worker_argv(seconds: float = RENDER_SECONDS) -> list[str]:
    """The command that starts the drawing child. A frozen build has no
    ``python -c``: the binary itself answers ``--pdf-worker`` (main.py).
    The last three arguments: this process's pid, the CPU seconds per
    request, the data-memory limit."""
    tail = [str(os.getpid()), str(cpu_seconds_for(seconds)), str(DATA_LIMIT)]
    if getattr(sys, "frozen", False):
        return [sys.executable, "--pdf-worker", *tail]
    return [sys.executable, "-I", "-c", _CHILD_SOURCE, *tail]


def _child_main() -> int:
    """The frozen build's ``--pdf-worker`` entry point."""
    exec(compile(_CHILD_SOURCE, "<pdf-worker>", "exec"), {"__name__": "__pdf_worker__"})
    return 0


def fit_size(width: float, height: float, edge: int) -> tuple[int, int]:
    """A page of *width* x *height* (any unit) drawn with its longer side
    *edge* px, within :data:`MAX_EDGE` and :data:`MAX_PIXELS`."""
    w, h = max(1.0, float(width)), max(1.0, float(height))
    scale = max(1, int(edge)) / max(w, h)
    return clamp_size(w * scale, h * scale)


def clamp_size(width: float, height: float) -> tuple[int, int]:
    """*width* x *height* px shrunk, keeping its shape, to
    :data:`MAX_EDGE` and :data:`MAX_PIXELS`."""
    w, h = max(1.0, float(width)), max(1.0, float(height))
    shrink = min(1.0, MAX_EDGE / max(w, h), (MAX_PIXELS / (w * h)) ** 0.5)
    return max(1, int(w * shrink)), max(1, int(h * shrink))


class PdfRenderer:
    """One child process with at most one open PDF; thread-safe (requests
    run one after another). A request that takes longer than *seconds*
    kills the child and raises :class:`PdfTooSlow`; a child that dies
    raises :class:`PdfCrashed`. The next request starts a new child and
    opens the document again, so one bad page does not end the others."""

    def __init__(self, seconds: float = RENDER_SECONDS) -> None:
        self._seconds = float(seconds)
        self._lock = threading.RLock()
        self._proc: subprocess.Popen | None = None
        self._replies: queue.Queue | None = None
        self._path = ""
        self._pages = 0
        self._sizes: dict[int, tuple[float, float]] = {}
        self.documents = 0
        self._closed = False

    # -- the child ------------------------------------------------------
    def _start(self) -> None:
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            # From the launcher thread: PR_SET_PDEATHSIG fires when the thread
            # that started the child ends - a pooled child started by a short-lived
            # worker (ui.off_gui) was killed with it.
            proc = process_launcher.popen(worker_argv(self._seconds), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         env=worker_env(), close_fds=True, **kwargs)
        except OSError as exc:
            raise PdfError(f"the PDF drawing process could not start: {exc}") from exc
        try:
            from core.regex_worker import _kill_with_parent_windows

            _kill_with_parent_windows(proc)
        except ImportError:  # an exported tool comes without the regex worker
            pass
        replies: queue.Queue = queue.Queue()
        threading.Thread(target=self._read_loop, args=(proc, replies),
                         name="pdf-worker-reader", daemon=True).start()
        self._proc, self._replies = proc, replies

    @staticmethod
    def _read_exact(stream, n: int) -> bytes | None:
        chunks, got = [], 0
        while got < n:
            chunk = stream.read(n - got)
            if not chunk:
                return None
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    @classmethod
    def _read_loop(cls, proc: subprocess.Popen, replies: queue.Queue) -> None:
        """The child's answers as (header dict, picture bytes); None at the end."""
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
                if length > MAX_PIXELS * 4 + 4 * MAX_EDGE:
                    return
                body = cls._read_exact(stream, length) if length else b""
                if body is None:
                    return
                replies.put((header, body))
        except (OSError, ValueError, RecursionError, struct.error):
            return
        finally:
            replies.put(None)

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        self._replies = None
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

    def _ask(self, request: dict, what: str) -> tuple[dict, bytes]:
        if self._proc is None:
            self._start()
        proc, replies = self._proc, self._replies
        data = json.dumps(request).encode()
        try:
            proc.stdin.write(struct.pack(">I", len(data)) + data)
            proc.stdin.flush()
        except (OSError, ValueError):
            pass  # the reader reports the end below
        deadline = time.monotonic() + self._seconds
        try:
            reply = replies.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            self._kill()
            raise PdfTooSlow(f"{what} took longer than {self._seconds:g} s") from None
        if reply is None:
            code = proc.poll()
            if code is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    code = proc.wait(timeout=2)
            self._kill()
            how = (f"signal {-code}" if code is not None and code < 0
                   else f"exit status {code}")
            raise PdfCrashed(f"the PDF drawing process ended while {what[0].lower()}{what[1:]} "
                             f"({how})")
        header, body = reply
        if header.get("error") == "missing":
            self._kill()
            raise PdfMissing(f"PDF viewing needs QtPdf, which cannot be loaded here "
                             f"({header.get('text', '')})")
        if header.get("error") == "memory":
            raise PdfError("not enough memory to draw the PDF page")
        return header, body

    def _ensure_open(self) -> None:
        if self._closed:
            raise PdfError("the PDF was closed")
        if not self._path:
            raise PdfError("no PDF is open")
        if self._proc is None:
            self._open(self._path)

    def _open(self, path: str) -> int:
        header, _ = self._ask({"op": "open", "path": path}, "Opening the PDF")
        if "error" in header:
            raise PdfError(error_text(str(header["error"])))
        pages = int(header.get("pages", 0))
        if pages < 1:
            raise PdfError("PDF has no pages")
        return pages

    # -- the API ----------------------------------------------------------
    def open(self, path: str) -> int:
        """Open the PDF at *path* (closing the one open before); its page count."""
        with self._lock:
            if self._closed:
                raise PdfError("the PDF was closed")
            if self.documents >= DOCUMENTS_PER_CHILD:
                self._kill()
                self.documents = 0
            self._path, self._pages, self._sizes = "", 0, {}
            self.documents += 1
            pages = self._open(path)
            self._path, self._pages = path, pages
            return pages

    @property
    def page_count(self) -> int:
        return self._pages

    @property
    def path(self) -> str:
        return self._path

    def page_size(self, page: int) -> tuple[float, float]:
        """Page *page*'s size in points."""
        with self._lock:
            if page in self._sizes:
                return self._sizes[page]
            self._ensure_open()
            header, _ = self._ask({"op": "size", "page": int(page)},
                                  f"Measuring page {page + 1} of the PDF")
            if "error" in header:
                raise PdfError(f"PDF has no page {page + 1}")
            size = (float(header.get("w", 0.0)), float(header.get("h", 0.0)))
            if len(self._sizes) > 4096:
                self._sizes.clear()
            self._sizes[page] = size
            return size

    def metadata(self, fields) -> dict[str, str]:
        """The document information *fields* (QPdfDocument.MetaDataField
        names) the open PDF has, as text."""
        with self._lock:
            self._ensure_open()
            header, _ = self._ask({"op": "meta", "fields": list(fields)},
                                  "Reading the PDF's information")
            meta = header.get("meta")
            if not isinstance(meta, dict):
                raise PdfError("cannot read the PDF's information")
            return {str(k): str(v) for k, v in meta.items()}

    def render(self, page: int, width: int, height: int) -> tuple[int, int, int, bytes]:
        """Page *page* drawn at *width* x *height* px (clamped, see
        :func:`clamp_size`) on white: ``(width, height, bytes_per_line,
        Format_RGB32 bytes)``."""
        width, height = clamp_size(width, height)
        with self._lock:
            self._ensure_open()
            header, body = self._ask(
                {"op": "render", "page": int(page), "width": width, "height": height},
                f"Drawing page {page + 1} of the PDF")
            if "error" in header:
                if header["error"] == "page":
                    raise PdfError(f"PDF has no page {page + 1}")
                raise PdfError("cannot render PDF page")
            w, h, stride = int(header["w"]), int(header["h"]), int(header["stride"])
            if w < 1 or h < 1 or stride < 4 * w or len(body) != stride * h:
                raise PdfError("cannot render PDF page")
            return w, h, stride, body

    def render_edge(self, page: int, edge: int) -> tuple[int, int, int, bytes]:
        """Page *page* with its longer side *edge* px (see :meth:`render`)."""
        w, h = self.page_size(page)
        return self.render(page, *fit_size(w, h, edge))

    @property
    def alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def pid(self) -> int | None:
        proc = self._proc
        return proc.pid if proc is not None else None

    def release_document(self) -> None:
        """Close the open PDF in the child (its file is no longer held), keep the child."""
        with self._lock:
            self._path, self._pages, self._sizes = "", 0, {}
            if self._proc is not None:
                with contextlib.suppress(PdfError):
                    self._ask({"op": "close"}, "Closing the PDF")

    def close(self) -> None:
        """End the child; later requests raise :class:`PdfError`. Never
        waits for a request in flight: its child is killed, and the
        request ends with an error at once."""
        self._closed = True
        self._path = ""
        proc = self._proc
        if proc is not None and proc.poll() is None:
            with contextlib.suppress(OSError):
                proc.kill()
        if self._lock.acquire(timeout=1.0):
            try:
                self._kill()
            finally:
                self._lock.release()

    def __del__(self) -> None:
        # A renderer dropped without close(): its child goes with it, not
        # only when axross ends.
        proc = getattr(self, "_proc", None)
        if proc is not None:
            with contextlib.suppress(Exception):
                if proc.poll() is None:
                    proc.kill()

    def __enter__(self) -> PdfRenderer:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


_pool: list[tuple[float, PdfRenderer]] = []
_pool_lock = threading.Lock()


@contextlib.contextmanager
def borrowed(seconds: float = RENDER_SECONDS):
    """A :class:`PdfRenderer` from a small pool (thumbnails: one child for
    many documents); it goes back when the block ends without having
    failed, a failed one is closed."""
    now = time.monotonic()
    with _pool_lock:
        stale = [r for at, r in _pool if now - at > POOL_IDLE_SECONDS]
        _pool[:] = [(at, r) for at, r in _pool if now - at <= POOL_IDLE_SECONDS]
        renderer = next((r for _at, r in _pool if r._seconds == seconds), None)
        if renderer is not None:
            _pool[:] = [(at, r) for at, r in _pool if r is not renderer]
    for old in stale:
        old.close()
    if renderer is None:
        renderer = PdfRenderer(seconds)
    try:
        yield renderer
    except BaseException:
        renderer.close()
        raise
    renderer.release_document()
    with _pool_lock:
        if len(_pool) < POOL_SIZE and renderer.alive:
            _pool.append((time.monotonic(), renderer))
            return
    renderer.close()


def close_pool() -> None:
    """End the pooled children (tests; the children end with axross anyway)."""
    with _pool_lock:
        pool = [r for _at, r in _pool]
        _pool.clear()
    for renderer in pool:
        renderer.close()


__all__ = [
    "MAX_PIXELS",
    "RENDER_SECONDS",
    "PdfCrashed",
    "PdfError",
    "PdfMissing",
    "PdfRenderer",
    "PdfTooSlow",
    "borrowed",
    "clamp_size",
    "close_pool",
    "error_text",
    "fit_size",
    "worker_argv",
]
