"""NNTP backend implementing the FileBackend protocol.

Built on :mod:`core.nntp_lib` (our own Python-3.13-safe NNTP impl).
Treats Usenet as a filesystem::

    /                                — list of newsgroups (LIST ACTIVE)
    /<group>/                        — directory; list_dir lazy-pages OVER N-M
    /<group>/<msgno>_<subject>.eml   — one article (RFC 5322 / Usenet bytes)

Write surface is **POST** (creating an article in a postable group).
Symlinks, chmod, rename are refused. Recursive delete is refused
(deleting articles is not a generic NNTP operation).

Authentication:

* ``use_tls=True`` + port 563 → implicit-TLS (RFC 4642)
* ``use_tls=False`` + ``starttls=True`` → upgrade in-band on port 119
* ``username`` + ``password`` → AUTHINFO USER/PASS (RFC 4643)
"""
from __future__ import annotations

import io
import logging
import posixpath
import re
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


# Cap how many articles list_dir paginates in one go. Big groups can
# hold millions of messages; we expose the most-recent N by default
# so the UI doesn't choke. Override via ``window`` ctor arg.
DEFAULT_WINDOW = 200

# Sanitise subjects for filenames.
_FILENAME_BAD = re.compile(r'[/\\:*?"<>|\x00-\x1f]')
_MSG_PATH_RE = re.compile(r"^/(?P<group>[^/]+)/(?P<msgno>\d+)_[^/]*\.eml$")


def _sanitize(name: str, max_len: int = 80) -> str:
    cleaned = _FILENAME_BAD.sub("_", name).strip(". ")
    if not cleaned:
        cleaned = "untitled"
    return cleaned[:max_len]


class NntpSession:
    """NNTP backend implementing the FileBackend protocol."""

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str,
        port: int = 0,
        username: str = "",
        password: str = "",
        use_tls: bool = True,
        starttls: bool = False,
        group_prefix: str = "",
        window: int = DEFAULT_WINDOW,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        from core.nntp_lib import (
            DEFAULT_PORT,
            DEFAULT_TLS_PORT,
            NntpAuthRequired,
            NntpClient,
        )
        from core.proxy import ProxyConfig

        self._host = host
        if port:
            self._port = int(port)
        else:
            self._port = DEFAULT_TLS_PORT if (use_tls and not starttls) else DEFAULT_PORT
        self._use_tls = bool(use_tls or starttls)
        self._starttls = bool(starttls)
        self._username = username
        self._group_prefix = group_prefix
        self._window = max(1, int(window))
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host, port=int(proxy_port or 0),
            username=proxy_username, password=proxy_password,
        )

        # Connect + auth.
        try:
            self._client = NntpClient(
                host=host, port=self._port,
                use_tls=use_tls, starttls=starttls,
                proxy_config=self._proxy,
            )
        except Exception as exc:
            raise OSError(f"Cannot connect to NNTP {host}:{self._port}: {exc}") from exc
        try:
            self._client.mode_reader()
            if username:
                self._client.authinfo(username, password)
        except NntpAuthRequired as exc:
            raise OSError(f"NNTP requires auth: {exc}") from exc
        except Exception:
            self._client.quit()
            raise

        # Per-group cache: group → (count, low, high)
        self._group_info_cache: dict[str, tuple[int, int, int]] = {}
        # Per-group OVER cache: group → list of records (most recent window)
        self._group_over_cache: dict[str, list[dict]] = {}
        log.info("NNTP session ready: %s@%s:%d", username or "(anon)", host, self._port)

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        scheme = "NNTPS" if self._use_tls else "NNTP"
        who = self._username or "anon"
        return f"{scheme}: {who}@{self._host}:{self._port}"

    @property
    def connected(self) -> bool:
        return self._client is not None

    def close(self) -> None:
        if getattr(self, "_client", None) is not None:
            self._client.quit()
            self._client = None  # type: ignore[assignment]

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path) or "/"

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        if path == "/":
            return self._list_groups()
        # /<group> — list articles
        parts = path.strip("/").split("/")
        if len(parts) != 1:
            raise OSError(f"NNTP list({path}): nesting beyond /<group> is not supported")
        return self._list_articles(parts[0])

    def _list_groups(self) -> list[FileItem]:
        items: list[FileItem] = []
        for group, high, low, status in self._client.list_groups(self._group_prefix):
            items.append(FileItem(
                name=group, is_dir=True, is_link=False,
                size=0, modified=datetime.fromtimestamp(0),
                permissions=0o555 if status == "y" else 0o550,
            ))
        return items

    def _ensure_group(self, group: str) -> tuple[int, int, int]:
        info = self._group_info_cache.get(group)
        if info is not None:
            return info
        info = self._client.select_group(group)
        self._group_info_cache[group] = info
        return info

    def _list_articles(self, group: str) -> list[FileItem]:
        try:
            count, low, high = self._ensure_group(group)
        except Exception as exc:
            raise OSError(f"NNTP GROUP {group}: {exc}") from exc
        # Most-recent window: [max(low, high - window + 1) .. high].
        if high < low:
            return []
        win_low = max(low, high - self._window + 1)
        records = list(self._client.over(win_low, high))
        self._group_over_cache[group] = records
        items: list[FileItem] = []
        from core.nntp_lib import parse_overview_date
        for rec in records:
            subject_safe = _sanitize(rec.get("subject", ""))
            name = f"{rec['msgno']}_{subject_safe}.eml"
            items.append(FileItem(
                name=name, is_dir=False, is_link=False,
                size=int(rec.get("bytes") or 0),
                modified=parse_overview_date(rec.get("date", "")),
                permissions=0o444,
            ))
        return items

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False,
                size=0, modified=datetime.fromtimestamp(0), permissions=0o555,
            )
        parts = path.strip("/").split("/")
        if len(parts) == 1:
            # Group node
            return FileItem(
                name=parts[0], is_dir=True, is_link=False,
                size=0, modified=datetime.fromtimestamp(0), permissions=0o555,
            )
        m = _MSG_PATH_RE.match(path)
        if not m:
            raise OSError(f"NNTP stat({path}): not a recognised group/article path")
        group = m.group("group")
        msgno = int(m.group("msgno"))
        # Find in cached overview if possible.
        for rec in self._group_over_cache.get(group, []):
            if rec.get("msgno") == msgno:
                from core.nntp_lib import parse_overview_date
                return FileItem(
                    name=posixpath.basename(path), is_dir=False, is_link=False,
                    size=int(rec.get("bytes") or 0),
                    modified=parse_overview_date(rec.get("date", "")),
                    permissions=0o444,
                )
        # Fallback: cheap HEAD to confirm existence.
        try:
            self._ensure_group(group)
            head = self._client.head(msgno)
        except Exception as exc:
            raise OSError(f"NNTP HEAD {group}/{msgno}: {exc}") from exc
        return FileItem(
            name=posixpath.basename(path), is_dir=False, is_link=False,
            size=len(head), modified=datetime.fromtimestamp(0),
            permissions=0o444,
        )

    def is_dir(self, path: str) -> bool:
        path = self.normalize(path)
        return path == "/" or "/" not in path.strip("/")

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def open_read(self, path: str) -> IO[bytes]:
        m = _MSG_PATH_RE.match(self.normalize(path))
        if not m:
            raise OSError(f"NNTP read({path}): not a group/article path")
        group = m.group("group")
        msgno = int(m.group("msgno"))
        try:
            self._ensure_group(group)
            blob = self._client.article(msgno)
        except Exception as exc:
            raise OSError(f"NNTP ARTICLE {group}/{msgno}: {exc}") from exc
        return io.BytesIO(blob)

    # ------------------------------------------------------------------
    # FileBackend — write surface (POST)
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if append:
            raise OSError("NNTP POST does not support append")
        # The write target encodes the destination group via the path:
        # /<group>/draft.eml  → POST to <group>. We require the writer
        # to provide a fully-formed RFC 5322 article in the body.
        norm = self.normalize(path)
        parts = norm.strip("/").split("/")
        if len(parts) != 2:
            raise OSError("NNTP write must target /<group>/<filename>.eml")
        group = parts[0]
        return _NntpPoster(self._client, group)

    def remove(self, path: str, recursive: bool = False) -> None:
        # NNTP has no client-side DELE. Some servers expose CANCEL-style
        # control messages, but those are policy-bound; refuse cleanly.
        raise OSError("NNTP does not expose a generic article-delete primitive")

    def mkdir(self, path: str) -> None:
        raise OSError("NNTP groups are server-managed — mkdir is not supported")

    def rename(self, src: str, dst: str) -> None:
        raise OSError("NNTP does not support rename")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("NNTP carries no POSIX permissions")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("NNTP has no server-side copy primitive")

    def readlink(self, path: str) -> str:
        raise OSError("NNTP has no symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("NNTP has no version history")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return ""

    # ------------------------------------------------------------------
    # NNTP-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    @staticmethod
    def _no_crlf(label: str, value: str) -> None:
        """F33: refuse CR/LF in any caller-supplied string that lands
        in an NNTP command line. The wire layer in ``nntp_lib._send_line``
        also refuses these, but checking at the public API gives a
        clearer error and rejects BEFORE any session state changes
        (e.g. before a partial GROUP select)."""
        if "\r" in value or "\n" in value:
            raise ValueError(
                f"NNTP {label} must not contain CR/LF "
                f"(would smuggle a second NNTP command). F33."
            )

    def groups_list(self, prefix: str = "") -> list[dict]:
        """``LIST ACTIVE [<prefix>*]`` — return every (or every-prefix-
        matching) newsgroup the server publishes.

        ``prefix=""`` enumerates the full list — careful, public Usenet
        servers carry 100k+ groups and this materialises the whole
        thing. Pass a prefix like ``"de.comp."`` to scope.

        Returns one dict per group ``{name, low, high, status, count}``
        where ``status`` is ``y``/``n``/``m`` and ``count`` is the
        server-estimated article count (``high-low+1``).
        """
        self._no_crlf("group prefix", prefix)
        out: list[dict] = []
        for name, high, low, status in self._client.list_groups(prefix):
            out.append({
                "name": name,
                "low": low,
                "high": high,
                "status": status,
                "count": max(0, high - low + 1),
            })
        return out

    def xover(self, group: str, low: int | None = None,
              high: int | None = None,
              *, max_records: int = 5000) -> list[dict]:
        """``OVER`` (RFC 3977 §8.3) — overview header records for
        ``low..high`` in ``group``. Falls back to legacy ``XOVER``
        automatically (handled by nntp_lib).

        ``low`` / ``high`` default to the group's current low/high
        watermarks (returns every article). Capped at ``max_records``
        — a packed group can return tens of thousands.

        Returns dicts with ``msgno / subject / from / date /
        message_id / references / bytes / lines``.
        """
        self._no_crlf("group", group)
        count, lo, hi = self._client.select_group(group)
        if low is None:
            low = lo
        if high is None:
            high = hi
        out: list[dict] = []
        for rec in self._client.over(low, high):
            out.append(rec)
            if len(out) >= max_records:
                break
        return out

    def article_headers(self, group: str, msg_no: int) -> dict[str, str]:
        """``HEAD`` — return only the headers of one article, parsed
        into a dict ``{header_name_lower: value}``. Multi-line headers
        are unfolded; repeated headers (``Received:``) keep only the
        last value (use ``raw_head`` for the unparsed bytes)."""
        self._no_crlf("group", group)
        # Switch group + fetch HEAD via the wire-lib.
        self._client.select_group(group)
        raw = self._client.head(int(msg_no))
        return _parse_headers(raw)

    def raw_head(self, group: str, msg_no: int) -> bytes:
        """Bytes-level escape hatch — the unparsed ``HEAD`` response
        for callers that need every duplicate header line."""
        self._no_crlf("group", group)
        self._client.select_group(group)
        return self._client.head(int(msg_no))


def _parse_headers(raw: bytes) -> dict[str, str]:
    """Parse RFC 5322 headers out of ``raw`` (bytes ending at the
    blank-line separator). Multi-line headers are unfolded; the
    last value wins on a duplicate name (matches Python's
    ``email.message.Message.__getitem__`` behaviour)."""
    text = raw.decode("utf-8", errors="replace")
    out: dict[str, str] = {}
    cur_name: str | None = None
    cur_val: list[str] = []
    for line in text.split("\n"):
        line = line.rstrip("\r")
        if not line:
            break
        if line[:1] in (" ", "\t") and cur_name is not None:
            cur_val.append(line.lstrip())
            continue
        if cur_name is not None:
            out[cur_name] = " ".join(cur_val).strip()
        if ":" in line:
            name, _, val = line.partition(":")
            cur_name = name.strip().lower()
            cur_val = [val.lstrip()]
        else:
            cur_name = None
            cur_val = []
    if cur_name is not None:
        out[cur_name] = " ".join(cur_val).strip()
    return out


# ---------------------------------------------------------------------------
# Writer: buffer + POST on close
# ---------------------------------------------------------------------------

class _NntpPoster:
    def __init__(self, client, group: str):
        self._client = client
        self._group = group
        self._buf = io.BytesIO()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("writer closed")
        return self._buf.write(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        article = self._buf.getvalue()
        # Auto-add Newsgroups header if missing — most submission flows
        # forget it.
        if b"\nNewsgroups:" not in article and not article.startswith(b"Newsgroups:"):
            article = (
                f"Newsgroups: {self._group}\r\n".encode("utf-8") + article
            )
        else:
            # Header already present — warn loudly when it disagrees with
            # the path target so a typo doesn't quietly post into the
            # wrong group.
            self._warn_on_group_disagreement(article)
        self._client.post(article)
        self._buf.close()

    def _warn_on_group_disagreement(self, article: bytes) -> None:
        """Emit a WARNING when the in-body ``Newsgroups:`` header lists
        groups that don't include the path-target group. The post
        proceeds either way (the header is the wire authority), but
        the operator gets a heads-up."""
        # Parse only the headers section. Body comes after the first
        # blank line (CRLF CRLF or LF LF).
        head_end = article.find(b"\r\n\r\n")
        if head_end == -1:
            head_end = article.find(b"\n\n")
        head_block = article[:head_end] if head_end != -1 else article
        for raw_line in head_block.splitlines():
            if raw_line[:11].lower() == b"newsgroups:":
                value = raw_line[11:].decode("utf-8", "replace").strip()
                groups = {g.strip() for g in value.split(",") if g.strip()}
                if self._group not in groups:
                    log.warning(
                        "NNTP POST: path target %r is not in the article's "
                        "Newsgroups header (%r) — posting will go to the "
                        "header's groups, not the path",
                        self._group, value,
                    )
                return

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
