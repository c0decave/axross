"""Find Files: the search engine behind the Find Files dialog and Smart Folders.

Built on :mod:`core.search_federation`: a :class:`SearchQuery` (name glob /
regex, content, size, mtime, file categories, inside archives, hidden
files) runs over a list of :class:`SearchScope` - a folder on one backend
each - and, as an option, over the offline metadata index.

* **Streaming and cancellable.** Every hit is handed to ``on_hit`` the
  moment it is found; ``cancel()`` is polled between entries, between
  read chunks and by a watcher of every external tool, so a Cancel stops
  a local run well within half a second. A remote ``list_dir`` that
  blocks finishes first: a socket read cannot be interrupted from here.
* **Fast on local folders.** ``fd`` lists the tree and ``rg`` searches
  the content when they are installed (``PATH``, or ``bin/`` next to a
  frozen build). Without them a pure-Python walker and reader give the
  same results: the tools only produce candidates, every filter is
  applied here, and both read at most ``max_content_bytes`` of a file -
  larger files are searched in that prefix by Python, never by ``rg``.
* **Remote folders** go through the backend API (``list_dir``,
  ``open_read``), so every protocol works.
* **Archives** (zip, tar.*, single gz / bz2 / xz / zst files; 7z and rar
  by name) are searched when the query asks for it, nested archives too,
  bounded by member count, member size, nesting depth, decompressed
  total and the zip-bomb ratio guard of :mod:`core.archive`.
* **Bounded.** Max hits, max depth, max visited entries; symlinks are
  never followed into (no loops), FIFOs and devices are never opened.

Content matching is line-wise like grep: a literal or regex must match
within one line; ``^`` / ``$`` anchor at line boundaries.
"""

from __future__ import annotations

import bz2
import codecs
import fnmatch
import gzip
import io
import logging
import lzma
import os
import re
import shutil
import stat as stat_module
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from core import archive as AR
from core.file_categories import classify_local, classify_name, primary_category
from core.search_federation import MAX_GENERIC_VISITED, SearchHit, SearchQuery, _to_epoch

log = logging.getLogger(__name__)

#: Bytes read from a file per step.
_CHUNK = 1024 * 1024
#: A "line" without a newline is searched in pieces this long ...
_MAX_LINE = 1024 * 1024
#: ... each overlapping the previous by this much.
_LINE_OVERLAP = 4096
#: Files handed to one ``rg`` call; also flushed after this many seconds.
_RG_BATCH = 256
_RG_FLUSH_S = 0.25
#: A zip whose central directory claims more entries than this is not
#: opened at all: ``zipfile`` would build every entry first.
_ZIP_DIRECTORY_HARD_CAP = 100_000
_ZIP_DIRECTORY_MAX_BYTES = 16 * 1024 * 1024
#: Error messages kept in a summary.
MAX_ERRORS = 50
#: Office / e-book files are zip containers, not archives to the user.
_NOT_ARCHIVES = (".docx", ".xlsx", ".odt", ".epub")


@dataclass
class SearchScope:
    """One place to search: *root* on *backend*. ``kind="index"`` scopes
    are made by the engine for metadata-index hits (``backend`` is None,
    ``label`` the index's backend id)."""

    backend: Any
    root: str
    label: str = ""
    kind: str = "backend"

    def __post_init__(self) -> None:
        if self.label:
            return
        if self.kind == "index":
            self.label = "Index"
        elif _is_local(self.backend):
            self.label = self.root
        else:
            name = getattr(self.backend, "name", "") or type(self.backend).__name__
            self.label = f"{name}:{self.root}"


@dataclass
class SearchLimits:
    """Caps of one run. Every field must be a positive integer."""

    max_hits: int = 5000
    max_visited: int = 2_000_000
    #: Content is searched in the first this-many bytes of a file.
    max_content_bytes: int = 32 * 1024 * 1024
    #: A remote archive is copied to a private temp file to be read; larger ones are skipped.
    max_remote_archive_bytes: int = 256 * 1024 * 1024
    max_archive_members: int = AR.MAX_EXTRACT_FILES
    #: A nested archive is read into memory up to this size.
    max_member_bytes: int = 64 * 1024 * 1024
    #: Archive levels opened: 1 = the archive itself, 2 = one nested in it, ...
    max_archive_depth: int = 3
    #: Bytes decompressed per top-level archive (members read plus tar data skipped).
    max_archive_total_bytes: int = AR.MAX_EXTRACT_TOTAL_BYTES

    def validate(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass
class SearchSummary:
    """What a run did. ``skipped`` counts by reason: ``bomb``,
    ``encrypted``, ``too_large``, ``archive_members``, ``archive_budget``,
    ``archive_too_large``, ``no_content`` (7z / rar members),
    ``index_content`` (the index has no content), ``visited``."""

    found: int = 0
    scanned: int = 0
    archives: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    cancelled: bool = False
    elapsed_s: float = 0.0
    #: scope label -> "fd", "fd+rg", "python", "fd+python", "walk", "index"
    engines: dict[str, str] = field(default_factory=dict)


HitCallback = Callable[[SearchScope, SearchHit], None]
HitFilter = Callable[[SearchScope, SearchHit], bool]


class _Stop(Exception):
    """Cancelled or max hits reached: the whole run ends."""


class _StopArchive(Exception):
    """One archive hit a cap: the run goes on with the next entry."""


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def find_tool(name: str) -> str | None:
    """Path of ``fd`` or ``rg``: a binary in ``bin/`` of a frozen build
    first, then ``PATH`` (``fd`` is ``fdfind`` on Debian / Ubuntu)."""
    names = {"fd": ("fd", "fdfind"), "rg": ("rg",)}.get(name, (name,))
    suffix = ".exe" if os.name == "nt" else ""
    bundle = getattr(sys, "_MEIPASS", None)
    if getattr(sys, "frozen", False) and bundle:
        for candidate in names:
            path = os.path.join(bundle, "bin", candidate + suffix)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    for candidate in names:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def archive_kind(name: str) -> str | None:
    """The :func:`core.archive.archive_family` of *name*, except for
    Office / e-book files (zip containers nobody calls an archive)."""
    if name.lower().endswith(_NOT_ARCHIVES):
        return None
    return AR.archive_family(name)


# ---------------------------------------------------------------------------
# Content matching
# ---------------------------------------------------------------------------


def _snippet(text: str, start: int, end: int) -> str:
    """The match with 30 characters of context, inside its line."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    a = max(line_start, start - 30)
    b = min(line_end, end + 30)
    return text[a:b].replace("\r", "").replace("\t", " ")[:200]


class _ContentMatcher:
    """``query.contains`` as a line-wise matcher on decoded text."""

    def __init__(self, query: SearchQuery) -> None:
        self.case_sensitive = query.case_sensitive
        self.pattern = query.contains_regex() if query.contains_is_regex else None
        self.needle = query.contains if query.case_sensitive else query.contains.lower()

    def find(self, text: str) -> str | None:
        """A snippet of the first line of *text* that matches, or None."""
        if self.pattern is None:
            hay = text if self.case_sensitive else text.lower()
            idx = hay.find(self.needle)
            if idx < 0:
                return None
            source = text if len(hay) == len(text) else hay
            return _snippet(source, idx, idx + len(self.needle))
        m = self.pattern.search(text)
        if m is None:
            return None
        if "\n" not in m.group(0):
            return _snippet(text, m.start(), m.end())
        # The match spans lines (``\s`` ate a newline): look line by line.
        for line in text.split("\n"):
            m = self.pattern.search(line)
            if m is not None:
                return _snippet(line, m.start(), m.end())
        return None

    def snippet_for_line(self, line: str) -> str:
        found = self.find(line)
        return found if found is not None else line.strip()[:200]


def scan_stream(read: Callable[[int], bytes], matcher: _ContentMatcher, cap: int,
                cancel: Callable[[], bool]) -> str | None:
    """Search the first *cap* bytes that *read* yields, line by line.
    A snippet on a match, else None. Raises :class:`_Stop` on cancel."""
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    carry = ""
    remaining = cap
    while remaining > 0:
        if cancel():
            raise _Stop
        chunk = read(min(_CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        text = carry + decoder.decode(chunk)
        cut = text.rfind("\n")
        if cut < 0:
            if len(text) > _MAX_LINE:
                found = matcher.find(text)
                if found is not None:
                    return found
                carry = text[-_LINE_OVERLAP:]
            else:
                carry = text
            continue
        block, carry = text[:cut], text[cut + 1 :]
        found = matcher.find(block)
        if found is not None:
            return found
    text = carry + decoder.decode(b"", final=True)
    return matcher.find(text) if text else None


# ---------------------------------------------------------------------------
# External tools
# ---------------------------------------------------------------------------


class _ToolProcess:
    """An fd / rg process whose output is read in chunks; a watcher kills
    it when *cancel* turns true, so a read never outlives a Cancel."""

    def __init__(self, argv: list[str], cancel: Callable[[], bool]) -> None:
        from core.subprocess_env import clean_child_env

        self.proc = subprocess.Popen(  # noqa: S603 - an argument list, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_child_env(os.environ),
        )
        self._stderr = bytearray()
        self._done = threading.Event()
        self._cancel = cancel
        self._threads = [
            threading.Thread(target=self._drain_stderr, daemon=True, name="search-tool-err"),
            threading.Thread(target=self._watch, daemon=True, name="search-tool-watch"),
        ]
        for thread in self._threads:
            thread.start()

    def _drain_stderr(self) -> None:
        stream = self.proc.stderr
        while True:
            data = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
            if not data:
                return
            if len(self._stderr) < 8192:
                self._stderr += data[: 8192 - len(self._stderr)]

    def _watch(self) -> None:
        while not self._done.wait(0.05):
            if self._cancel():
                self.kill()
                return

    def kill(self) -> None:
        try:
            self.proc.kill()
        except OSError:
            pass

    def chunks(self) -> Iterator[bytes]:
        stream = self.proc.stdout
        while True:
            data = stream.read1(65536)
            if not data:
                return
            yield data

    def close(self) -> None:
        self._done.set()
        if self.proc.poll() is None:
            self.kill()
        self.proc.wait()
        for thread in self._threads:
            thread.join(timeout=1.0)
        for stream in (self.proc.stdout, self.proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    @property
    def returncode(self) -> int | None:
        return self.proc.returncode

    @property
    def stderr(self) -> str:
        return bytes(self._stderr).decode("utf-8", "replace")

    def __enter__(self) -> _ToolProcess:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _split_records(chunks: Iterator[bytes], sep: bytes) -> Iterator[bytes]:
    buf = b""
    for chunk in chunks:
        buf += chunk
        parts = buf.split(sep)
        buf = parts.pop()
        yield from parts
    if buf:
        yield buf


def _parse_rg(chunks: Iterator[bytes]) -> Iterator[tuple[str, str]]:
    """``path NUL line LF`` records; a path may hold a newline, never a NUL."""
    buf = b""
    for chunk in chunks:
        buf += chunk
        while True:
            nul = buf.find(b"\0")
            if nul < 0:
                break
            newline = buf.find(b"\n", nul + 1)
            if newline < 0:
                break
            yield os.fsdecode(buf[:nul]), buf[nul + 1 : newline].decode("utf-8", "replace")
            buf = buf[newline + 1 :]


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------


@dataclass
class _ArchiveCtx:
    scope: SearchScope
    display: str  # the archive file's path on the backend
    mtime: float
    members: int = 0
    total: int = 0


def _read_capped(stream, n: int, cancel: Callable[[], bool]) -> bytes:
    out = bytearray()
    while len(out) < n:
        if cancel():
            raise _Stop
        chunk = stream.read(min(_CHUNK, n - len(out)))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def _single_reader(fh, family_name: str):
    lower = family_name.lower()
    if lower.endswith(".gz"):
        return gzip.GzipFile(fileobj=fh, mode="rb")
    if lower.endswith(".bz2"):
        return bz2.BZ2File(fh, "rb")
    if lower.endswith(".xz"):
        return lzma.LZMAFile(fh, "rb")
    from core import packer

    return packer.zstd_reader(fh)


_ARCHIVE_ERRORS = (
    OSError,
    EOFError,
    ValueError,
    RuntimeError,
    NotImplementedError,
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    tarfile.TarError,
    zlib.error,
    lzma.LZMAError,
    AR.UnsafeArchive,
    AR.RarUnavailable,
)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def _compile_ignore(patterns) -> re.Pattern[str] | bool:
    """One expression that matches what fnmatch.fnmatch matches for any of
    *patterns* (both sides through os.path.normcase, as fnmatch does);
    False when there are none."""
    if not patterns:
        return False
    return re.compile(
        "|".join(f"(?:{fnmatch.translate(os.path.normcase(p))})" for p in patterns))


class _Run:
    def __init__(self, query: SearchQuery, limits: SearchLimits, on_hit: HitCallback,
                 cancel: Callable[[], bool], progress, use_tools: bool, use_sift: bool,
                 accept: HitFilter | None = None) -> None:
        self.q = query
        self.accept = accept
        self.limits = limits
        self.on_hit = on_hit
        self.cancel = cancel
        self.progress = progress
        self.use_sift = use_sift
        self.wanted = set(query.categories)
        self.matcher = _ContentMatcher(query) if query.contains else None
        self.summary = SearchSummary()
        self.fd = find_tool("fd") if use_tools else None
        self.rg = find_tool("rg") if use_tools and query.contains else None
        self._visited = 0
        self._index_scopes: dict[str, SearchScope] = {}
        #: ignored(): the compiled ignore_dirs (False: none) and the tuple it is of.
        self._ignore_rx = None
        self._ignore_for = None

    # -- bookkeeping ------------------------------------------------------
    def check(self) -> None:
        if self.cancel():
            self.summary.cancelled = True
            raise _Stop

    def error(self, message: str) -> None:
        log.debug("find files: %s", message)
        if len(self.summary.errors) < MAX_ERRORS:
            self.summary.errors.append(message)

    def skip(self, reason: str) -> None:
        self.summary.skipped[reason] = self.summary.skipped.get(reason, 0) + 1

    def seen(self, path: str) -> None:
        self.summary.scanned += 1
        if self.progress is not None:
            try:
                self.progress(self.summary.scanned, self.summary.found, path)
            except Exception as exc:  # noqa: BLE001 - a progress sink never stops a search
                log.debug("find files: progress callback raised: %s", exc)

    def visit(self) -> bool:
        self._visited += 1
        if self._visited > self.limits.max_visited:
            if not self.summary.skipped.get("visited"):
                self.skip("visited")
                self.error(f"stopped after {self.limits.max_visited} entries")
            return False
        return True

    def emit(self, scope: SearchScope, hit: SearchHit) -> None:
        # A hit the caller filters out (Find Files' tag) neither counts nor
        # uses up max_hits.
        if self.accept is not None and not self.accept(scope, hit):
            return
        if self.summary.found >= self.limits.max_hits:
            self.summary.truncated = True
            raise _Stop
        self.summary.found += 1
        self.on_hit(scope, hit)

    def passes(self, name: str, size: int, mtime: float) -> bool:
        return self.q.matches_name(name) and self.q.matches_size(size) and self.q.matches_mtime(
            mtime
        )

    def categories(self, cats: set[str]) -> str | None:
        """The category a row shows, or None when the filter drops it."""
        if self.wanted:
            chosen = cats & self.wanted
            return primary_category(chosen) if chosen else None
        return primary_category(cats)

    def ignored(self, name: str) -> bool:
        """``any(fnmatch.fnmatch(name, p) for p in ignore_dirs)``, as one
        compiled expression: it runs for every entry or path part, and ten
        fnmatch calls each cost ~3 us (258 ms per 80,000 names)."""
        patterns = self.q.ignore_dirs
        if self._ignore_rx is None or self._ignore_for is not patterns:
            self._ignore_rx = _compile_ignore(patterns)
            self._ignore_for = patterns
        return self._ignore_rx is not False and (
            self._ignore_rx.match(os.path.normcase(name)) is not None)

    # -- local folders ----------------------------------------------------
    def run_local(self, scope: SearchScope) -> None:
        root = os.path.abspath(scope.root)
        if not os.path.isdir(root):
            self.error(f"{root}: not a folder")
            return
        pending: list[tuple[str, SearchHit]] = []
        pending_since = 0.0
        entries = self._fd_entries(root) if self.fd else self._py_entries(root)
        try:
            for path, name, st in entries:
                self.check()
                self.seen(path)
                searched_inside = False
                if self.q.search_archives and stat_module.S_ISREG(st.st_mode):
                    family = archive_kind(name)
                    if family:
                        self._archive_file(scope, path, family, st.st_mtime, local_path=path)
                        searched_inside = True
                if not self.passes(name, st.st_size, st.st_mtime):
                    continue
                if searched_inside and self.matcher is not None:
                    continue  # its members were searched; the container is no content hit
                shown = self.categories(
                    classify_local(path, wanted=self.wanted, use_sift=self.use_sift, name=name)
                    if self.wanted
                    else classify_name(name, path)
                )
                if shown is None:
                    continue
                hit = SearchHit(backend_label=_backend_name(scope.backend), path=path,
                                size=st.st_size, mtime=st.st_mtime, category=shown)
                if self.matcher is None:
                    self.emit(scope, hit)
                    continue
                try:
                    real = os.stat(path)
                except OSError:
                    continue
                if not stat_module.S_ISREG(real.st_mode):
                    continue  # a FIFO, a device or a link to a folder: never opened
                if self.rg and real.st_size <= self.limits.max_content_bytes:
                    if not pending:
                        pending_since = time.monotonic()
                    pending.append((path, hit))
                    if len(pending) >= _RG_BATCH or time.monotonic() - pending_since > _RG_FLUSH_S:
                        self._flush_rg(scope, pending)
                    continue
                # Larger than the content cap: its prefix is searched here,
                # never by rg (which can only skip a file whole).
                self._scan_local(scope, path, hit)
            if pending:
                self._flush_rg(scope, pending)
        finally:
            close = getattr(entries, "close", None)
            if close is not None:
                close()
            label = "fd" if self.fd else "python"
            if self.matcher is not None:
                content = "rg" if self.rg else "python"
                if content != label:
                    label = f"{label}+{content}"
            self.summary.engines[scope.label] = label

    def _path_allowed(self, parts: list[str]) -> bool:
        if self.q.max_depth >= 0 and len(parts) - 1 > self.q.max_depth:
            return False
        for part in parts:
            if self.ignored(part):
                return False
            if not self.q.include_hidden and part.startswith("."):
                return False
        return True

    def _fd_entries(self, root: str) -> Iterator[tuple[str, str, os.stat_result]]:
        # fd starts one thread per core by default; on a busy many-core host
        # that start-up alone took half a second for a three-file folder.
        threads = str(max(1, min(8, os.cpu_count() or 1)))
        argv = [self.fd, "--type", "f", "--type", "l", "--no-ignore", "--print0",
                "--absolute-path", "--color", "never", "--threads", threads]
        if self.q.include_hidden:
            argv.append("--hidden")
        if self.q.max_depth >= 0:
            argv += ["--max-depth", str(self.q.max_depth + 1)]
        for pattern in self.q.ignore_dirs:
            argv += ["--exclude", pattern]
        argv += ["--search-path", root]
        try:
            tool = _ToolProcess(argv, self.cancel)
        except OSError as exc:
            self.error(f"fd could not start ({exc}); using the built-in walker")
            self.fd = None
            yield from self._py_entries(root)
            return
        real_root = os.path.realpath(root)
        with tool:
            for raw in _split_records(tool.chunks(), b"\0"):
                if not self.visit():
                    tool.kill()
                    break
                path = os.fsdecode(raw)
                rel = _relative(path, root, real_root)
                if rel is None:
                    continue
                parts = rel.split(os.sep)
                if not self._path_allowed(parts):
                    continue
                full = os.path.join(root, rel)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat_module.S_ISREG(st.st_mode) or stat_module.S_ISLNK(st.st_mode):
                    yield full, parts[-1], st
        self.check()
        if tool.returncode not in (0, None, -9) and tool.stderr.strip():
            self.error(f"fd: {tool.stderr.strip().splitlines()[0]}")

    def _py_entries(self, root: str) -> Iterator[tuple[str, str, os.stat_result]]:
        stack: list[tuple[str, int]] = [(root, 0)]
        seen_dirs: set[tuple[int, int]] = set()
        while stack:
            self.check()
            path, depth = stack.pop()
            try:
                st = os.stat(path)
                key = (st.st_dev, st.st_ino)
                if key in seen_dirs:
                    continue
                seen_dirs.add(key)
                with os.scandir(path) as it:
                    entries = list(it)
            except OSError as exc:
                self.error(f"{path}: {exc.strerror or exc}")
                continue
            subdirs = []
            for entry in sorted(entries, key=lambda e: e.name):
                name = entry.name
                if self.ignored(name) or (not self.q.include_hidden and name.startswith(".")):
                    continue
                if not self.visit():
                    return
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if self.q.max_depth < 0 or depth < self.q.max_depth:
                            subdirs.append(entry.path)
                        continue
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat_module.S_ISREG(est.st_mode) or stat_module.S_ISLNK(est.st_mode):
                    yield entry.path, name, est
            stack.extend((d, depth + 1) for d in reversed(subdirs))

    def _scan_local(self, scope: SearchScope, path: str, hit: SearchHit) -> None:
        try:
            with open(path, "rb") as fh:
                snippet = scan_stream(fh.read, self.matcher, self.limits.max_content_bytes,
                                      self.cancel)
        except OSError as exc:
            self.error(f"{path}: {exc.strerror or exc}")
            return
        except _Stop:
            self.summary.cancelled = True
            raise
        if snippet is not None:
            hit.snippet = snippet
            self.emit(scope, hit)

    def _flush_rg(self, scope: SearchScope, pending: list[tuple[str, SearchHit]]) -> None:
        """Search *pending* with rg. When rg cannot run or refuses the
        pattern, the rest of the batch is searched here and rg is not used
        again in this run."""
        batch = list(pending)
        pending.clear()
        by_path = dict(batch)
        argv = [self.rg, "--no-config", "--text", "--no-messages", "--max-count", "1",
                "--with-filename", "--null", "--no-heading", "--no-line-number",
                "--color", "never", "--encoding", "none", "--max-columns", "4096",
                "--max-columns-preview", "--no-ignore", "--hidden"]
        argv.append("--case-sensitive" if self.q.case_sensitive else "--ignore-case")
        if not self.q.contains_is_regex:
            argv.append("--fixed-strings")
        argv += ["--regexp", self.q.contains, "--"]
        argv += [path for path, _hit in batch]
        try:
            tool = _ToolProcess(argv, self.cancel)
        except OSError as exc:
            self.error(f"rg could not start ({exc}); searching without it")
            self.rg = None
            for path, hit in batch:
                self._scan_local(scope, path, hit)
            return
        with tool:
            for path, line in _parse_rg(tool.chunks()):
                hit = by_path.pop(path, None)
                if hit is None:
                    continue
                hit.snippet = self.matcher.snippet_for_line(line)
                self.emit(scope, hit)
        self.check()
        if tool.returncode == 2 and "regex" in tool.stderr.lower():
            # A pattern rg's engine does not take (look-around, back
            # references): Python searches what rg could not.
            self.rg = None
            for path, hit in batch:
                if path in by_path:
                    self._scan_local(scope, path, hit)

    # -- other backends ---------------------------------------------------
    def run_backend(self, scope: SearchScope) -> None:
        backend = scope.backend
        self.summary.engines[scope.label] = "walk"
        root = scope.root or (backend.home() if hasattr(backend, "home") else "/")
        stack: list[tuple[str, int]] = [(root, 0)]
        visited: set[str] = set()
        while stack:
            self.check()
            path, depth = stack.pop()
            if path in visited:
                continue
            visited.add(path)
            try:
                items = backend.list_dir(path)
            except Exception as exc:  # noqa: BLE001 - one folder never ends a remote search
                self.error(f"{_backend_name(backend)}: {path}: {exc}")
                continue
            subdirs = []
            for item in items:
                self.check()
                name = getattr(item, "name", "")
                if name in ("", ".", ".."):
                    continue
                if self.ignored(name):
                    continue
                if not self.q.include_hidden and (
                    name.startswith(".") or getattr(item, "attr_hidden", False)
                ):
                    continue
                if not self.visit():
                    return
                full = _join(backend, path, name)
                if getattr(item, "is_dir", False):
                    if getattr(item, "is_link", False):
                        continue  # never followed: no loops
                    if self.q.max_depth < 0 or depth < self.q.max_depth:
                        subdirs.append(full)
                    continue
                self._remote_file(scope, full, name, item)
            stack.extend((d, depth + 1) for d in reversed(subdirs))

    def _remote_file(self, scope: SearchScope, path: str, name: str, item) -> None:
        backend = scope.backend
        size = int(getattr(item, "size", 0) or 0)
        mtime = _to_epoch(getattr(item, "modified", None))
        self.seen(path)
        searched_inside = False
        if self.q.search_archives and not getattr(item, "is_link", False):
            family = archive_kind(name)
            if family:
                searched_inside = True
                if size > self.limits.max_remote_archive_bytes:
                    self.skip("archive_too_large")
                else:
                    self._archive_file(scope, path, family, mtime,
                                       opener=lambda: backend.open_read(path))
        if not self.passes(name, size, mtime):
            return
        if searched_inside and self.matcher is not None:
            return  # its members were searched; the container is no content hit
        shown = self.categories(classify_name(name, path))
        if shown is None:
            return
        hit = SearchHit(backend_label=_backend_name(backend), path=path, size=size, mtime=mtime,
                        category=shown)
        if self.matcher is not None:
            try:
                handle = backend.open_read(path)
            except Exception as exc:  # noqa: BLE001
                self.error(f"{path}: {exc}")
                return
            try:
                snippet = scan_stream(handle.read, self.matcher, self.limits.max_content_bytes,
                                      self.cancel)
            except _Stop:
                self.summary.cancelled = True
                raise
            except Exception as exc:  # noqa: BLE001 - a read error skips the file
                self.error(f"{path}: {exc}")
                return
            finally:
                try:
                    handle.close()
                except Exception as exc:  # noqa: BLE001
                    log.debug("find files: close(%s) raised: %s", path, exc)
            if snippet is None:
                return
            hit.snippet = snippet
        self.emit(scope, hit)

    # -- archives ---------------------------------------------------------
    def _archive_file(self, scope: SearchScope, display: str, family: str, mtime: float, *,
                      local_path: str | None = None,
                      opener: Callable[[], Any] | None = None) -> None:
        """Search the members of one archive file: *local_path* is read in
        place, a remote one is copied (bounded) through *opener* first."""
        self.summary.archives += 1
        ctx = _ArchiveCtx(scope=scope, display=display, mtime=mtime)
        name = display.replace("\\", "/").rsplit("/", 1)[-1]
        try:
            if local_path is not None:
                if family in ("7z", "rar"):
                    self._listing_only(ctx, local_path, [])
                    return
                with open(local_path, "rb") as fh:
                    self._members(ctx, fh, family, name, [], 1, local_path=local_path)
                return
            with tempfile.TemporaryDirectory(prefix="axross-find-") as tmp:
                local = os.path.join(tmp, "archive" + os.path.splitext(name)[1].lower())
                if family == "tar":
                    local = os.path.join(tmp, "archive" + _tar_suffix(name))
                # A backend's read handle need not be a context manager:
                # read() and close() are all the API promises. Its errors
                # need not be OSErrors either (a protocol library's own
                # exception): like a content read, any of them skips this
                # archive, never the run.
                try:
                    src = opener()
                except Exception as exc:  # noqa: BLE001 - one archive, not the run
                    self.error(f"{display}: {exc}")
                    return
                try:
                    with open(local, "wb") as dst:
                        copied = 0
                        while True:
                            chunk = _read_capped(src, _CHUNK, self.cancel)
                            if not chunk:
                                break
                            copied += len(chunk)
                            if copied > self.limits.max_remote_archive_bytes:
                                self.skip("archive_too_large")
                                return
                            dst.write(chunk)
                except _Stop:
                    raise
                except Exception as exc:  # noqa: BLE001 - one archive, not the run
                    self.error(f"{display}: {exc}")
                    return
                finally:
                    close = getattr(src, "close", None)
                    if close is not None:
                        try:
                            close()
                        except Exception as exc:  # noqa: BLE001
                            log.debug("find files: close(%s) raised: %s", display, exc)
                if family in ("7z", "rar"):
                    self._listing_only(ctx, local, [])
                    return
                with open(local, "rb") as fh:
                    self._members(ctx, fh, family, name, [], 1, local_path=local)
        except _StopArchive:
            return
        except _ARCHIVE_ERRORS as exc:
            self.error(f"{display}: {exc}")

    def _members(self, ctx: _ArchiveCtx, fh, family: str, name: str, chain: list[str],
                 level: int, *, local_path: str | None = None) -> None:
        if family == "zip":
            self._zip_members(ctx, fh, chain, level)
        elif family == "tar":
            if local_path is not None:
                with AR.open_tar_archive(local_path) as tf:
                    self._tar_members(ctx, tf, chain, level)
            else:
                with tarfile.open(fileobj=fh, mode="r:*") as tf:
                    self._tar_members(ctx, tf, chain, level)
        elif family == "single":
            self._single_member(ctx, fh, name, chain, level)
        else:
            self.skip("no_content")  # 7z / rar nested in another archive

    def _zip_members(self, ctx: _ArchiveCtx, fh, chain: list[str], level: int) -> None:
        declared = AR.zip_declared_entries(fh)
        if declared is not None and (
            declared[0] > _ZIP_DIRECTORY_HARD_CAP or declared[1] > _ZIP_DIRECTORY_MAX_BYTES
        ):
            self.skip("archive_members")
            self.error(f"{ctx.display}: zip directory with {declared[0]} entries not opened")
            return
        with zipfile.ZipFile(fh) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                def read(n: int, info=info) -> bytes:
                    AR.check_bomb_ratio(info.file_size, info.compress_size, info.filename)
                    with zf.open(info) as member:
                        return _read_capped(member, n, self.cancel)

                mtime = _zip_epoch(info.date_time)
                self._member(ctx, info.filename, int(info.file_size), mtime, read, chain, level)

    def _tar_members(self, ctx: _ArchiveCtx, tf: tarfile.TarFile, chain: list[str],
                     level: int) -> None:
        seen_bytes = 0
        for ti in tf:
            self.check()
            if not ti.isreg():
                # Folder, link and device headers are members too: a tar of
                # endless folder entries compresses to almost nothing, and
                # tarfile keeps every header it reads in its member list.
                ctx.members += 1
                if ctx.members > self.limits.max_archive_members:
                    self.skip("archive_members")
                    raise _StopArchive
                continue
            seen_bytes += max(0, int(ti.size))
            if seen_bytes > self.limits.max_archive_total_bytes:
                self.skip("archive_budget")
                raise _StopArchive

            def read(n: int, ti=ti) -> bytes:
                member = tf.extractfile(ti)
                if member is None:
                    return b""
                with member:
                    return _read_capped(member, n, self.cancel)

            self._member(ctx, ti.name, int(ti.size), float(ti.mtime or 0), read, chain, level)

    def _single_member(self, ctx: _ArchiveCtx, fh, name: str, chain: list[str],
                       level: int) -> None:
        member_name = AR.strip_archive_extension(name) or "data"
        cap = self.limits.max_member_bytes
        state: dict = {}

        def read(n: int) -> bytes:
            if "data" not in state:
                fh.seek(0)
                with _single_reader(fh, name) as stream:
                    state["data"] = _read_capped(stream, cap + 1, self.cancel)
            return state["data"][:n]

        size = -1
        needs_size = self.q.min_size >= 0 or self.q.max_size >= 0
        if needs_size:
            data = self._member_bytes(ctx, read, cap + 1)
            if data is None:
                return
            size = len(data) if len(data) <= cap else -1
            if size < 0:
                return  # its size is unknown: a size filter cannot say yes
        self._member(ctx, member_name, max(size, 0), ctx.mtime, read, chain, level,
                     size_known=size >= 0 or not needs_size)

    def _listing_only(self, ctx: _ArchiveCtx, local_path: str, chain: list[str]) -> None:
        for entry in AR.list_archive(local_path):
            if entry.is_dir:
                continue
            self._member(ctx, entry.name, int(entry.size), float(entry.mtime or ctx.mtime), None,
                         chain, 1)

    def _member_bytes(self, ctx: _ArchiveCtx, read, n: int) -> bytes | None:
        try:
            data = read(n)
        except AR.UnsafeArchive:
            self.skip("bomb")
            return None
        except RuntimeError as exc:  # zipfile: "File is encrypted, password required"
            if "encrypt" in str(exc).lower() or "password" in str(exc).lower():
                self.skip("encrypted")
            else:
                self.error(f"{ctx.display}: {exc}")
            return None
        except (OSError, EOFError, ValueError, NotImplementedError, zipfile.BadZipFile,
                tarfile.TarError, zlib.error, lzma.LZMAError) as exc:
            self.error(f"{ctx.display}: {exc}")
            return None
        ctx.total += len(data)
        if ctx.total > self.limits.max_archive_total_bytes:
            self.skip("archive_budget")
            raise _StopArchive
        return data

    def _member(self, ctx: _ArchiveCtx, member_name: str, size: int, mtime: float, read,
                chain: list[str], level: int, *, size_known: bool = True) -> None:
        self.check()
        ctx.members += 1
        if ctx.members > self.limits.max_archive_members:
            self.skip("archive_members")
            raise _StopArchive
        clean = _clean_member(member_name)
        base = clean.rsplit("/", 1)[-1]
        if not base:
            return
        member_chain = [*chain, clean]
        display = ctx.display + "!/" + "!/".join(member_chain)
        self.seen(display)
        nested = archive_kind(base) if read is not None else None
        opened = False
        if nested and nested not in ("7z", "rar") and level < self.limits.max_archive_depth:
            opened = True
            data = self._member_bytes(ctx, read, self.limits.max_member_bytes + 1)
            if data is not None and len(data) > self.limits.max_member_bytes:
                self.skip("too_large")
            elif data is not None:
                self.summary.archives += 1
                try:
                    self._members(ctx, io.BytesIO(data), nested, base, member_chain, level + 1)
                except _ARCHIVE_ERRORS as exc:
                    self.error(f"{display}: {exc}")
        if not self.passes(base, size, mtime) or not size_known and (
            self.q.min_size >= 0 or self.q.max_size >= 0
        ):
            return
        if opened and self.matcher is not None:
            return  # a nested archive: its members were searched instead
        shown = self.categories(classify_name(base, clean))
        if shown is None:
            return
        snippet = ""
        if self.matcher is not None:
            if read is None:
                self.skip("no_content")
                return
            data = self._member_bytes(ctx, read, self.limits.max_content_bytes)
            if data is None:
                return
            found = scan_stream(io.BytesIO(data).read, self.matcher,
                                self.limits.max_content_bytes, self.cancel)
            if found is None:
                return
            snippet = found
        self.emit(ctx.scope, SearchHit(
            backend_label=_backend_name(ctx.scope.backend),
            path=display,
            size=size,
            mtime=mtime,
            snippet=snippet,
            category=shown,
            archive_path=ctx.display,
            member="!/".join(member_chain),
        ))

    # -- metadata index ---------------------------------------------------
    def run_index(self, db_path) -> None:
        from core import metadata_index as MX

        self.summary.engines["Index"] = "index"
        if self.matcher is not None:
            self.skip("index_content")
            return
        for entry in MX.iter_entries(db_path=db_path, cancel=self.cancel):
            self.check()
            if entry.is_dir:
                continue
            self.seen(entry.path)
            parts = [p for p in entry.path.replace("\\", "/").split("/") if p]
            if any(self.ignored(p) for p in parts) or (
                not self.q.include_hidden and any(p.startswith(".") for p in parts)
            ):
                continue
            mtime = entry.modified.timestamp() if entry.modified is not None else 0.0
            if not self.passes(entry.name, entry.size, mtime):
                continue
            shown = self.categories(classify_name(entry.name, entry.path))
            if shown is None:
                continue
            scope = self._index_scopes.get(entry.backend_id)
            if scope is None:
                scope = SearchScope(None, "", label=entry.backend_id, kind="index")
                self._index_scopes[entry.backend_id] = scope
            self.emit(scope, SearchHit(backend_label=f"Index: {entry.backend_id}",
                                       path=entry.path, size=entry.size, mtime=mtime,
                                       category=shown))
        self.check()


def _clean_member(name: str) -> str:
    """A member name for display: ``/`` separators, no leading ``./`` or
    ``/`` (GNU tar writes ``./docs/a.txt``), no trailing ``/``."""
    clean = name.replace("\\", "/").rstrip("/")
    while clean.startswith("./"):
        clean = clean[2:]
    return clean.lstrip("/")


def _tar_suffix(name: str) -> str:
    lower = name.lower()
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tgz", ".tbz2", ".txz", ".tzst"):
        if lower.endswith(ext):
            return ext
    return ".tar"


def _zip_epoch(date_time) -> float:
    try:
        return time.mktime((*date_time, 0, 0, -1))
    except (OverflowError, ValueError, TypeError):
        return 0.0


def _backend_name(backend) -> str:
    return getattr(backend, "name", "") or type(backend).__name__


def _join(backend, path: str, name: str) -> str:
    if hasattr(backend, "join"):
        return backend.join(path, name)
    return f"{path.rstrip('/')}/{name}"


def _relative(path: str, root: str, real_root: str) -> str | None:
    for base in (root, real_root):
        prefix = base.rstrip(os.sep) + os.sep
        if path.startswith(prefix):
            return path[len(prefix):]
    return None


def run_search(
    scopes: list[SearchScope],
    query: SearchQuery,
    *,
    on_hit: HitCallback,
    cancel: Callable[[], bool] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
    limits: SearchLimits | None = None,
    use_tools: bool = True,
    use_index: bool = False,
    index_db=None,
    use_sift: bool = True,
    accept: HitFilter | None = None,
) -> SearchSummary:
    """Search every scope in turn (then the metadata index when
    *use_index*), handing each hit to ``on_hit(scope, hit)`` at once.

    Raises ``ValueError`` for an invalid query or limits - before any
    folder is read. Everything else (a folder that cannot be listed, a
    damaged archive) lands in the summary's ``errors`` and the search
    goes on. ``progress(scanned, found, current_path)`` reports headway.
    ``accept(scope, hit)``, when given, decides before a hit is counted:
    a hit it refuses is neither handed on nor counted against ``max_hits``.
    """
    query.validate()
    limits = limits or SearchLimits()
    limits.validate()
    run = _Run(query, limits, on_hit, cancel or (lambda: False), progress, use_tools, use_sift,
               accept)
    started = time.monotonic()
    try:
        for scope in scopes:
            if _is_local(scope.backend):
                run.run_local(scope)
            else:
                run.run_backend(scope)
        if use_index:
            run.run_index(index_db)
    except _Stop:
        pass
    run.summary.elapsed_s = time.monotonic() - started
    return run.summary


def collect_hits(backend, query: SearchQuery, *, max_hits: int,
                 max_content_bytes: int) -> list[SearchHit]:
    """The hits of *query* on *backend* below ``query.roots`` (default:
    its home) as a list - :func:`core.search_federation._generic_adapter`."""
    roots = query.roots or [backend.home() if hasattr(backend, "home") else "/"]
    label = _backend_name(backend)
    hits: list[SearchHit] = []

    def keep(_scope: SearchScope, hit: SearchHit) -> None:
        hit.backend_label = label
        hits.append(hit)

    limits = SearchLimits(max_hits=max_hits, max_content_bytes=max_content_bytes,
                          max_visited=MAX_GENERIC_VISITED)
    run_search([SearchScope(backend, root) for root in roots], query, on_hit=keep,
               limits=limits)
    return hits


# ---------------------------------------------------------------------------
# Saved searches (Smart Folders)
# ---------------------------------------------------------------------------

SAVED_SEARCH_VERSION = 1
_MAX_SAVED_SCOPES = 32
_MAX_SAVED_TEXT = 4096
_SAVED_TEXT = ("name", "regex", "contains")
_SAVED_BOOL = ("contains_is_regex", "case_sensitive", "search_archives", "include_hidden")
_SAVED_INT = ("min_size", "max_size", "max_depth")
_SAVED_FLOAT = ("modified_after", "modified_before")


def _checked_tag(tag) -> str:
    """A saved search's tag filter: "" (none) or a tag name (core.tags)."""
    from core.tags import MAX_NAME

    if not isinstance(tag, str) or len(tag) > MAX_NAME or any(ord(c) < 32 for c in tag):
        raise ValueError(f"tag must be a tag name of at most {MAX_NAME} characters")
    return tag


def saved_search_to_dict(query: SearchQuery, scopes: list[dict], *,
                         use_index: bool = False, tag: str = "") -> dict:
    """*query*, the folders (``backend_name`` / ``profile_name`` / ``path``
    each) and the index switch as plain JSON data - what a Smart Folder
    stores in ``bookmarks.json``."""
    query.validate()
    data: dict = {"version": SAVED_SEARCH_VERSION}
    for key in (*_SAVED_TEXT, *_SAVED_BOOL, *_SAVED_INT, *_SAVED_FLOAT):
        data[key] = getattr(query, key)
    data["categories"] = list(query.categories)
    data["skip_noise_folders"] = bool(query.ignore_dirs)
    data["use_index"] = bool(use_index)
    data["tag"] = _checked_tag(tag)
    data["scopes"] = [_checked_scope(scope) for scope in scopes]
    return data


def _checked_scope(scope) -> dict:
    if not isinstance(scope, dict):
        raise ValueError("scopes must be a list of folders")
    out = {}
    for key, default in (("backend_name", "Local"), ("profile_name", ""), ("path", None)):
        value = scope.get(key, default)
        if not isinstance(value, str) or len(value) > _MAX_SAVED_TEXT:
            raise ValueError(f"scopes[].{key} must be a string")
        out[key] = value
    return out


def saved_search_from_dict(data) -> tuple[SearchQuery, list[dict], dict]:
    """``(query, scopes, {"use_index": bool, "tag": str})`` from a saved search.

    Raises ``ValueError`` naming the field when the data is damaged (a
    hand-edited or foreign bookmarks.json). Keys this version does not
    know are ignored; missing keys take the query defaults."""
    if not isinstance(data, dict):
        raise ValueError("a saved search must be a mapping")
    if data.get("version", SAVED_SEARCH_VERSION) != SAVED_SEARCH_VERSION:
        raise ValueError(f"unsupported saved search version: {data.get('version')!r}")
    kwargs: dict = {}
    for key in _SAVED_TEXT:
        value = data.get(key, "")
        if not isinstance(value, str) or len(value) > _MAX_SAVED_TEXT:
            raise ValueError(f"{key} must be a string of at most {_MAX_SAVED_TEXT} characters")
        kwargs[key] = value
    for key in _SAVED_BOOL:
        if key in data:
            if not isinstance(data[key], bool):
                raise ValueError(f"{key} must be true or false")
            kwargs[key] = data[key]
    for key in _SAVED_INT:
        if key in data:
            if not isinstance(data[key], int) or isinstance(data[key], bool):
                raise ValueError(f"{key} must be an integer")
            kwargs[key] = data[key]
    for key in _SAVED_FLOAT:
        if key in data:
            value = data[key]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"{key} must be a number")
            kwargs[key] = float(value)
    categories = data.get("categories", [])
    if not isinstance(categories, list):
        raise ValueError("categories must be a list of category ids")
    kwargs["categories"] = tuple(categories)
    skip_noise = data.get("skip_noise_folders", True)
    if not isinstance(skip_noise, bool):
        raise ValueError("skip_noise_folders must be true or false")
    if not skip_noise:
        kwargs["ignore_dirs"] = ()
    query = SearchQuery(**kwargs)
    query.validate()
    raw_scopes = data.get("scopes", [])
    if not isinstance(raw_scopes, list) or len(raw_scopes) > _MAX_SAVED_SCOPES:
        raise ValueError(f"scopes must be a list of at most {_MAX_SAVED_SCOPES} folders")
    scopes = [_checked_scope(scope) for scope in raw_scopes]
    use_index = data.get("use_index", False)
    if not isinstance(use_index, bool):
        raise ValueError("use_index must be true or false")
    return query, scopes, {"use_index": use_index, "tag": _checked_tag(data.get("tag", ""))}


def describe_saved_search(data) -> str:
    """One line for a tooltip: what a saved search looks for and where.
    Never raises: a damaged search says so."""
    try:
        query, scopes, options = saved_search_from_dict(data)
    except ValueError as exc:
        return f"damaged search ({exc})"
    from core.file_categories import label

    parts = []
    if query.name:
        parts.append(f"name {query.name}")
    if query.regex:
        parts.append(f"name regex {query.regex}")
    if query.categories:
        parts.append(", ".join(label(c) for c in query.categories))
    if query.contains:
        parts.append(f"containing {query.contains!r}")
    if query.search_archives:
        parts.append("inside archives")
    where = [s["path"] if s["backend_name"] == "Local" else f"{s['backend_name']}:{s['path']}"
             for s in scopes]
    if options["use_index"]:
        where.append("the index")
    text = " · ".join(parts) or "every file"
    return f"{text} in {', '.join(where)}" if where else text


__all__ = [
    "MAX_ERRORS",
    "SAVED_SEARCH_VERSION",
    "SearchLimits",
    "SearchScope",
    "SearchSummary",
    "archive_kind",
    "collect_hits",
    "describe_saved_search",
    "find_tool",
    "run_search",
    "saved_search_from_dict",
    "saved_search_to_dict",
    "scan_stream",
]
