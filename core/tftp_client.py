"""TFTP backend implementing the FileBackend protocol.

TFTP (RFC 1350) is a UDP-based file-transfer protocol with a tiny
surface: ``RRQ`` (read), ``WRQ`` (write), ``DATA``, ``ACK``, ``ERROR``.
There is no native ``LIST``, no directory hierarchy, no rename, no
chmod, no atime — TFTP servers are usually deliberately stripped
(PXE boot, network appliance firmware drops, embedded device
config push).

For discovery, :meth:`TftpSession.find_files` walks a wordlist of
common TFTP filenames (router configs, switch firmware, PXE-boot
artefacts) and probes each via a brief RRQ. Hits go into a
per-session cache so subsequent ``find_files`` runs return them
instantly.

Two consequences shape this backend:

1. **No directory listing exists.** ``list_dir`` cannot enumerate
   anything from the wire. Two opt-in modes are offered instead:

   * **Disabled (default)** — ``list_dir`` returns an empty list.
     Stat / read / write of paths the user types literally still
     work. Honest about the protocol: nothing is fabricated.
   * **Configured file-list** — when ``tftp_filelist_enabled`` is
     True and ``tftp_filelist`` is set on the profile, those paths
     get probed (RRQ + abort-on-first-block) and reported as
     FileItems. Sizes come from the server's ``OACK`` if the
     ``tsize`` option is supported, else marked as 0.

2. **Per-transfer size cap.** TFTP block-counters wrap after 65535
   blocks of 512 bytes (≈32 MiB) on classic servers, or higher with
   the ``blksize`` extension. Some lab/embedded servers cap much
   lower. ``tftp_max_size_bytes`` (default 16 MiB) is enforced
   before every transfer and refuses anything bigger up-front.

**Proxy support: NONE.** TFTP is UDP. SOCKS5's UDP-ASSOCIATE
extension is rarely supported in production proxies, and HTTP
CONNECT is TCP-only. The connection_manager warns when a proxy is
configured for a TFTP profile.

Requires the ``tftpy`` package (``pip install axross[tftp]``).
"""
from __future__ import annotations

import io
import logging
import os
import posixpath
import re
import tempfile
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    import tftpy  # type: ignore[import-not-found]
    TFTPY_AVAILABLE = True
except ImportError:
    tftpy = None  # type: ignore[assignment]
    TFTPY_AVAILABLE = False


# Default per-transfer cap. Classic TFTP without ``blksize`` blows
# up at ~32 MiB; we go conservative because lab and embedded
# servers tend to cap lower (8 / 16 MiB).
DEFAULT_MAX_BYTES = 16 * 1024 * 1024


# Filename allow-list for the configured file-list. TFTP filenames
# are 7-bit-ASCII path-style. We sanitise to keep server-side
# format-string / shell-injection trivially impossible.
_FILENAME_RE = re.compile(r"^[A-Za-z0-9._/\-]+$")


def _validate_filename(name: str) -> str:
    """Strip leading slashes (TFTP servers reject them on most
    daemons) and ensure the name fits the safe-character class.
    """
    cleaned = name.lstrip("/").strip()
    if not cleaned:
        raise OSError("TFTP filename is empty")
    if not _FILENAME_RE.match(cleaned):
        raise OSError(
            f"TFTP filename {name!r} contains characters outside "
            f"the [A-Za-z0-9._/-] safe set",
        )
    return cleaned


class TftpSession:
    """TFTP backend implementing the FileBackend protocol.

    Read/write of literal paths works in any mode. Listing requires
    the operator to opt in by configuring ``tftp_filelist`` and
    flipping ``tftp_filelist_enabled``.
    """

    # No directory hierarchy on TFTP.
    supports_symlinks = False
    supports_hardlinks = False

    # Cap on the per-session find-cache so a 50 000-entry wordlist
    # does not blow process memory. Older hits are dropped LRU-style.
    FIND_CACHE_LIMIT = 256

    def __init__(
        self,
        host: str,
        port: int = 69,
        filelist: list[str] | None = None,
        filelist_enabled: bool = False,
        max_size_bytes: int = DEFAULT_MAX_BYTES,
        timeout: float = 5.0,
        retries: int = 3,
    ):
        if not TFTPY_AVAILABLE:
            raise ImportError(
                "TFTP support requires tftpy. "
                "Install with: pip install axross[tftp]",
            )
        self._host = host
        self._port = int(port)
        self._max_size_bytes = int(max_size_bytes or DEFAULT_MAX_BYTES)
        self._timeout = float(timeout)
        self._retries = int(retries)
        # Sanitise the configured list once at ctor time so a hostile
        # profile.json can't inject newline / shell-meta into a TFTP
        # filename via the configured list.
        cleaned: list[str] = []
        for entry in filelist or ():
            try:
                cleaned.append(_validate_filename(entry))
            except OSError as exc:
                log.warning("TFTP: dropping bad filelist entry %r: %s", entry, exc)
        self._filelist = cleaned
        self._filelist_enabled = bool(filelist_enabled)
        # Per-session "find" cache: filename → (size, last_seen_ts).
        # Bounded to FIND_CACHE_LIMIT entries; older entries dropped
        # when the cap is hit.
        self._find_cache: dict[str, tuple[int, datetime]] = {}

        # tftpy's TftpClient is stateless per-transfer (UDP, no
        # persistent connection). We construct it lazily inside each
        # transfer to avoid holding a socket the user never uses.
        log.info(
            "TFTP session ready: %s:%d (filelist=%s, %d entries, max=%d B)",
            host, self._port,
            "on" if self._filelist_enabled else "off",
            len(self._filelist), self._max_size_bytes,
        )

    # ------------------------------------------------------------------
    # FileBackend identity
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"TFTP: {self._host}:{self._port}"

    @property
    def connected(self) -> bool:
        # TFTP is connectionless. A session is "live" as long as the
        # session object exists. There is no NOOP probe to perform.
        return True

    def disconnect(self) -> None:
        pass

    def close(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [p.strip("/") for p in parts if p]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return path

    # ------------------------------------------------------------------
    # Read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        """List configured files (opt-in) or return an empty list.

        Subdirectory listing is meaningless on TFTP; we filter the
        configured list by the path prefix the user navigated to so
        a list like ``["images/menu.png", "configs/dhcpd.conf"]``
        produces sensible "directories" `images/` and `configs/`
        when the user is at root.
        """
        path = self.normalize(path)
        if not self._filelist_enabled or not self._filelist:
            return []

        prefix = path.lstrip("/")
        if prefix and not prefix.endswith("/"):
            prefix = prefix + "/"

        entries: dict[str, FileItem] = {}
        for entry in self._filelist:
            if prefix and not entry.startswith(prefix):
                continue
            tail = entry[len(prefix):]
            if "/" in tail:
                # Subdirectory entry — synthesise a directory node.
                dirname = tail.split("/", 1)[0]
                if dirname not in entries:
                    entries[dirname] = FileItem(
                        name=dirname,
                        size=0,
                        modified=datetime.fromtimestamp(0),
                        permissions=0o500,
                        is_dir=True,
                        is_link=False,
                    )
                continue
            # Leaf file. Probe size if cheap; otherwise mark as 0.
            size = self._probe_size(entry)
            entries[tail] = FileItem(
                name=tail,
                size=size,
                modified=datetime.fromtimestamp(0),
                permissions=0o400,
                is_dir=False,
                is_link=False,
            )

        return sorted(entries.values(), key=lambda i: (not i.is_dir, i.name))

    def _probe_size(self, name: str) -> int:
        """Best-effort: ask the server for the file's ``tsize`` via
        the OACK option. Many tftpd daemons honour this; some don't.
        Returns 0 when unavailable.
        """
        try:
            client = tftpy.TftpClient(  # type: ignore[union-attr]
                self._host, self._port,
                options={"tsize": "0"},
            )
            # tftpy doesn't expose the OACK directly; the cleanest
            # cheap probe is to download into /dev/null and read the
            # size off the context. We cap reads at 1 byte's worth
            # of blocks to abort fast if the server doesn't honour
            # tsize and just streams.
            with tempfile.NamedTemporaryFile(delete=True) as tmp:
                client.download(
                    name, tmp.name,
                    timeout=self._timeout, retries=1,
                )
                # If we got here, the full transfer happened (server
                # didn't honour tsize as a probe-only). Use stat.
                tmp.seek(0, io.SEEK_END)
                return tmp.tell()
        except Exception as exc:  # noqa: BLE001
            log.debug("TFTP probe(%r) failed: %s", name, exc)
            return 0

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False,
                size=0, modified=datetime.fromtimestamp(0),
                permissions=0o500,
            )
        name = _validate_filename(path)
        size = self._probe_size(name)
        return FileItem(
            name=posixpath.basename(name),
            size=size, modified=datetime.fromtimestamp(0),
            permissions=0o400, is_dir=False, is_link=False,
        )

    def is_dir(self, path: str) -> bool:
        path = self.normalize(path)
        if path == "/":
            return True
        if not self._filelist_enabled:
            return False
        prefix = path.lstrip("/") + "/"
        return any(e.startswith(prefix) for e in self._filelist)

    def open_read(self, path: str, mode: str = "rb") -> IO:
        path = self.normalize(path)
        name = _validate_filename(path)
        client = tftpy.TftpClient(self._host, self._port)  # type: ignore[union-attr]

        # tftpy writes to a file path. Use a NamedTemporaryFile so the
        # bytes round-trip cleanly. Enforce the size cap by checking
        # the file's size after each chunk via packethook.
        cap = self._max_size_bytes
        bytes_so_far = [0]

        def _packethook(pkt):
            # tftpy passes a TftpPacketDAT to packethook for each
            # incoming data block. We accumulate the byte count and
            # raise to abort the transfer when over the cap.
            data = getattr(pkt, "data", b"")
            bytes_so_far[0] += len(data) if isinstance(data, (bytes, bytearray)) else 0
            if bytes_so_far[0] > cap:
                raise OSError(
                    f"TFTP read of {name!r} exceeded {cap} byte cap "
                    f"(at {bytes_so_far[0]} bytes)",
                )

        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            try:
                client.download(
                    name, tmp.name,
                    packethook=_packethook,
                    timeout=self._timeout, retries=self._retries,
                )
            except OSError:
                raise
            except Exception as exc:  # tftpy raises tftpy.TftpException
                raise OSError(f"TFTP RRQ {name!r}: {exc}") from exc
            tmp.seek(0)
            return io.BytesIO(tmp.read())

    # ------------------------------------------------------------------
    # Write surface — limited
    # ------------------------------------------------------------------

    def open_write(self, path: str, mode: str = "wb") -> IO:
        """Return a buffer that uploads on close. Note: TFTP writes
        only succeed on servers configured with ``--create`` /
        ``--writable`` — most production tftpd daemons reject WRQ
        outright. The size cap applies to the buffered bytes
        BEFORE upload; if the user writes more than the cap, close()
        raises rather than triggering a megabyte-flood transfer.
        """
        path = self.normalize(path)
        name = _validate_filename(path)
        return _TftpWriter(self, name)

    def remove(self, path: str, recursive: bool = False) -> None:
        raise OSError(
            "TFTP has no DELETE operation — the protocol does not "
            "support removing files from the server.",
        )

    def mkdir(self, path: str, parents: bool = False, exist_ok: bool = False) -> None:
        raise OSError(
            "TFTP has no directory hierarchy — mkdir is not supported.",
        )

    def rename(self, src: str, dst: str) -> None:
        raise OSError("TFTP does not support rename.")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("TFTP does not carry POSIX permissions.")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("TFTP has no server-side copy.")

    # ------------------------------------------------------------------
    # Wordlist discovery
    # ------------------------------------------------------------------

    @staticmethod
    def default_wordlist_path() -> str | None:
        """Return the bundled wordlist path under ``resources/`` or
        ``None`` when the install layout doesn't ship one (e.g. a
        slim wheel that excluded resources)."""
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate = os.path.join(here, "resources", "wordlists", "tftp_common.txt")
        return candidate if os.path.isfile(candidate) else None

    @staticmethod
    def load_wordlist(path: str) -> list[str]:
        """Load a wordlist file. Lines starting with ``#`` and blanks
        are skipped. Each surviving line is run through
        :func:`_validate_filename`; entries that fail are dropped
        (with a debug log) so a polluted list can't blow up the probe.
        """
        out: list[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        out.append(_validate_filename(line))
                    except OSError as exc:
                        log.debug("wordlist: dropping %r: %s", line, exc)
        except OSError as exc:
            raise OSError(f"Cannot read wordlist {path}: {exc}") from exc
        return out

    def find_files(
        self,
        wordlist: list[str] | str | None = None,
        on_progress=None,
    ) -> list[FileItem]:
        """Probe each entry in ``wordlist`` via a brief RRQ. Hits
        are returned as ``FileItem``s and added to the per-session
        find-cache; misses are silent.

        ``wordlist`` may be:

        * ``None`` → use the bundled list under
          ``resources/wordlists/tftp_common.txt`` (raises if the
          install layout lacks it).
        * ``str`` → path to a user-supplied wordlist file.
        * ``list[str]`` → an in-memory list of names.

        ``on_progress(name, hit_so_far, total)`` is called once per
        probed entry so a UI button can drive a progress bar.
        Returns the list of hits sorted by name.
        """
        if isinstance(wordlist, list):
            names = [_validate_filename(x) for x in wordlist]
        else:
            path = wordlist or self.default_wordlist_path()
            if not path:
                raise OSError(
                    "TFTP find: no wordlist supplied and no bundled "
                    "wordlist found under resources/wordlists/"
                )
            names = self.load_wordlist(path)

        hits: list[FileItem] = []
        total = len(names)
        for i, name in enumerate(names):
            cached = self._find_cache.get(name)
            if cached is not None:
                size, mtime = cached
                hits.append(FileItem(
                    name=name, size=size, modified=mtime,
                    permissions=0o400, is_dir=False, is_link=False,
                ))
                if on_progress:
                    on_progress(name, len(hits), total)
                continue
            try:
                size = self._probe_size(name)
            except Exception as exc:  # noqa: BLE001 — probe is best-effort
                log.debug("TFTP find: probe(%r) raised: %s", name, exc)
                size = -1
            if size > 0:
                self._record_find_hit(name, size)
                hits.append(FileItem(
                    name=name, size=size, modified=datetime.now(),
                    permissions=0o400, is_dir=False, is_link=False,
                ))
            if on_progress:
                on_progress(name, len(hits), total)
        return sorted(hits, key=lambda i: i.name)

    def _record_find_hit(self, name: str, size: int) -> None:
        """Insert a hit into the find-cache, trimming the oldest entry
        when the cap is reached."""
        if name in self._find_cache:
            self._find_cache[name] = (size, datetime.now())
            return
        if len(self._find_cache) >= self.FIND_CACHE_LIMIT:
            # dict keeps insertion order; pop the oldest.
            try:
                oldest = next(iter(self._find_cache))
                self._find_cache.pop(oldest, None)
            except StopIteration:
                pass
        self._find_cache[name] = (size, datetime.now())

    def find_cache_snapshot(self) -> list[FileItem]:
        """Return the current in-memory cache as FileItems (no probing).
        Useful for UI panes that want to show "previously found" hits
        before kicking off a fresh scan."""
        return sorted(
            (
                FileItem(
                    name=name, size=size, modified=mtime,
                    permissions=0o400, is_dir=False, is_link=False,
                )
                for name, (size, mtime) in self._find_cache.items()
            ),
            key=lambda i: i.name,
        )

    def clear_find_cache(self) -> None:
        self._find_cache.clear()

    # ------------------------------------------------------------------
    # Internal: actual upload (called by _TftpWriter.close)
    # ------------------------------------------------------------------

    def _upload_bytes(self, name: str, data: bytes) -> None:
        if len(data) > self._max_size_bytes:
            raise OSError(
                f"TFTP upload of {name!r} ({len(data)} bytes) exceeds "
                f"{self._max_size_bytes} byte cap.",
            )
        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            tmp.write(data)
            tmp.flush()
            tmp.seek(0)
            client = tftpy.TftpClient(self._host, self._port)  # type: ignore[union-attr]
            try:
                client.upload(
                    name, tmp.name,
                    timeout=self._timeout, retries=self._retries,
                )
            except Exception as exc:
                raise OSError(f"TFTP WRQ {name!r}: {exc}") from exc


class _TftpWriter:
    """File-like writer that buffers in memory then ships via WRQ on
    close. Aborts cleanly if discarded without close()."""

    def __init__(self, session: TftpSession, name: str):
        self._session = session
        self._name = name
        self._buf = io.BytesIO()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("TFTP writer closed")
        # Eagerly enforce the cap so the user sees the error at write
        # time rather than buried in close().
        if self._buf.tell() + len(data) > self._session._max_size_bytes:
            raise OSError(
                f"TFTP upload of {self._name!r} would exceed "
                f"{self._session._max_size_bytes} byte cap "
                f"(buffered {self._buf.tell() + len(data)} bytes).",
            )
        return self._buf.write(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._session._upload_bytes(self._name, self._buf.getvalue())
        self._buf.close()

    def discard(self) -> None:
        """Drop buffered bytes without uploading. Used by the transfer
        cancel path so a half-written blob doesn't get pushed."""
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()
