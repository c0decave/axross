"""A mail project: a folder with imported messages, each analysed.

Import from .eml and Outlook .msg files, Outlook .pst / .ost data files
(core.pst: every message rebuilt as .eml), mbox files, Maildir folders, any
folder of them (recursively), and from an IMAP / POP3 backend folder
(messages listed as .eml). Each message is kept as it came, under its
SHA-256 (``messages/<sha>.eml|.msg``; one message imported twice is one
message), its analysis as ``reports/<sha>.json`` (core.mail_analyse), and
a row in ``index.sqlite`` for listing, sorting and searching. The folder
is self-contained: an Agent tab given it read-only (with the "Mail
analyst" prompt) needs nothing but file tools; ``PROJECT.md`` says what is
where.

Bounded: a message larger than core.mail_message.MAX_MESSAGE is skipped
and logged, an import stops after ``limit`` messages, symlinks are not
followed out of an imported folder, nothing in a message is run.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import logging
import mailbox
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.mail_analyse import Finding, analyse
from core.mail_message import MAX_MESSAGE, MailMessage, parse_any

log = logging.getLogger(__name__)

MAIL_SUFFIXES = {".eml", ".msg"}
PST_SUFFIXES = {".pst", ".ost"}
MBOX_SUFFIXES = {".mbox", ".mbx", ".mbs"}

_README = """# Mail project

Made by axross. Every imported message is analysed offline (no lookups, nothing run).

- `messages/<sha256>.eml` / `.msg` - each message exactly as imported (named by its SHA-256)
- `reports/<sha256>.json` - its analysis: summary (from, to, subject, date, attachments),
  findings (severity info / warn / high, area, text), Received hops, SPF/DKIM/DMARC as
  recorded, links with notes, attachments with detected type; `score` 0-100 for sorting
- `index.sqlite` - table `messages` (sha256, source, kind, subject, sender, recipients,
  date, size, score, high, warn) and `imports` (when, what, counts)
- `index.csv` - the same rows as CSV
"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    sha256 TEXT PRIMARY KEY, source TEXT, kind TEXT, subject TEXT, sender TEXT,
    recipients TEXT, date TEXT, size INTEGER, score INTEGER, high INTEGER, warn INTEGER,
    message_id TEXT, imported REAL);
CREATE TABLE IF NOT EXISTS imports (
    at REAL, what TEXT, added INTEGER, known INTEGER, skipped INTEGER, errors TEXT);
"""


@dataclass
class ImportResult:
    added: int = 0
    known: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def line(self) -> str:
        text = f"{self.added} new, {self.known} already there"
        if self.skipped:
            text += f", {self.skipped} skipped"
        if self.errors:
            text += f", {len(self.errors)} could not be read"
        return text


class MailProject:
    """*dns*: also check SPF / DKIM / DMARC against live DNS (core.mail_dns) -
    off unless asked, the lookups show which domains are looked at; a
    callable ``(name, rtype) -> [text]`` replaces the resolver (tests)."""

    def __init__(self, folder: str | os.PathLike, *, dns=False):
        self.dns = dns
        self.folder = Path(folder)
        (self.folder / "messages").mkdir(parents=True, exist_ok=True)
        (self.folder / "reports").mkdir(exist_ok=True)
        readme = self.folder / "PROJECT.md"
        if not readme.exists():
            readme.write_text(_README, encoding="utf-8")
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.folder / "index.sqlite"), check_same_thread=False)
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- adding ------------------------------------------------------------------

    def add_bytes(self, data: bytes, source: str, name: str = "") -> str | None:
        """Parse, keep, analyse and index one message; its SHA-256, or None
        when it was already there."""
        msg = parse_any(data, name, source)
        sha = msg.sha256
        with self._lock:
            if self._db.execute("SELECT 1 FROM messages WHERE sha256=?", (sha,)).fetchone():
                return None
        suffix = ".msg" if msg.kind == "msg" else ".eml"
        target = self.folder / "messages" / f"{sha}{suffix}"
        if not target.exists():
            tmp = target.with_suffix(".part")
            tmp.write_bytes(data)
            os.replace(tmp, target)
        report = analyse(msg)
        dns_result = None
        if self.dns:
            from core import mail_dns

            lookup = self.dns if callable(self.dns) else mail_dns._lookup_default
            try:
                found, dns_result = mail_dns.dns_check(msg, lookup)
                report.findings.extend(found)
            except Exception as exc:  # noqa: BLE001 - no DNS: the offline analysis stands
                report.findings.append(Finding("info", "dns", f"DNS checks failed: {exc}"[:300]))
        rep = report.to_dict()
        if dns_result is not None:
            rep["dns"] = dns_result
        (self.folder / "reports" / f"{sha}.json").write_text(json.dumps(rep, indent=1, default=str),
                                                             encoding="utf-8")
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sha, source, msg.kind, msg.subject, msg.from_, ", ".join(msg.to + msg.cc),
                 msg.date.isoformat() if msg.date else "", msg.size, report.score,
                 sum(f.severity == "high" for f in report.findings),
                 sum(f.severity == "warn" for f in report.findings), msg.message_id, time.time()))
            self._db.commit()
        return sha

    def _add(self, data: bytes, source: str, name: str, result: ImportResult) -> None:
        if len(data) > MAX_MESSAGE:
            result.skipped += 1
            result.errors.append(f"{source}: larger than {MAX_MESSAGE} bytes")
            return
        try:
            sha = self.add_bytes(data, source, name)
        except Exception as exc:  # noqa: BLE001 - one broken message must not end the import
            result.errors.append(f"{source}: {type(exc).__name__}: {exc}"[:300])
            return
        if sha is None:
            result.known += 1
        else:
            result.added += 1

    def import_paths(self, paths: list[str], *, limit: int = 100_000, cancel=None) -> ImportResult:
        """.eml / .msg files, mbox files, Maildir folders and folders of them."""
        result = ImportResult()

        def full() -> bool:
            return result.added + result.known >= limit or (cancel is not None and cancel())

        for raw in paths:
            for kind, path in _walk(Path(raw)):
                if full():
                    break
                if kind == "file":
                    try:
                        if path.stat().st_size > MAX_MESSAGE:
                            result.skipped += 1
                            result.errors.append(f"{path}: larger than {MAX_MESSAGE} bytes")
                            continue
                        self._add(path.read_bytes(), str(path), path.name, result)
                    except OSError as exc:
                        result.errors.append(f"{path}: {exc}")
                elif kind == "pst":
                    self._import_pst(path, result, full)
                elif kind == "mbox":
                    self._import_mailbox(mailbox.mbox(str(path), create=False), str(path), result, full)
                elif kind == "maildir":
                    self._import_mailbox(mailbox.Maildir(str(path), create=False), str(path), result, full)
        self._log(", ".join(map(str, paths)), result)
        return result

    def _import_pst(self, path: Path, result: ImportResult, full) -> None:
        """Each message of an Outlook data file, rebuilt as .eml (core.pst)."""
        import struct
        import zlib

        from core.pst import PstError, PstFile, to_eml

        try:
            pst = PstFile(path)
        except (PstError, OSError, struct.error, zlib.error) as exc:
            result.errors.append(f"{path}: {exc}")
            return
        with pst:
            for msg in pst.messages():
                if full():
                    return
                label = f"{path}#{msg.folder}/{msg.nid:#x}"
                if "error" in msg.props:
                    result.errors.append(f"{label}: {msg.props['error']}")
                    continue
                try:
                    data = to_eml(msg, str(path))
                except Exception as exc:  # noqa: BLE001 - one message the rebuild cannot take
                    result.errors.append(f"{label}: {type(exc).__name__}: {exc}"[:300])
                    continue
                self._add(data, label, "", result)

    def _import_mailbox(self, box, label: str, result: ImportResult, full) -> None:
        try:
            keys = list(box.iterkeys())
        except (OSError, mailbox.Error) as exc:
            result.errors.append(f"{label}: {exc}")
            return
        for n, key in enumerate(keys):
            if full():
                return
            try:
                data = box.get_bytes(key)
            except (OSError, mailbox.Error, KeyError) as exc:
                result.errors.append(f"{label}#{n}: {exc}")
                continue
            self._add(data, f"{label}#{n + 1}", "", result)

    def import_backend(self, backend, folder: str = "/", *, recursive: bool = True,
                       limit: int = 100_000, cancel=None) -> ImportResult:
        """The .eml messages an IMAP / POP3 / Exchange backend lists in *folder*."""
        result = ImportResult()
        stack = [folder]
        while stack and result.added + result.known < limit and not (cancel and cancel()):
            current = stack.pop()
            try:
                items = backend.list_dir(current)
            except OSError as exc:
                result.errors.append(f"{current}: {exc}")
                continue
            for item in items:
                path = backend.join(current, item.name)
                if item.is_dir:
                    if recursive:
                        stack.append(path)
                    continue
                if not item.name.lower().endswith((".eml", ".msg")):
                    continue
                if item.size > MAX_MESSAGE:
                    result.skipped += 1
                    continue
                try:
                    with backend.open_read(path) as f:
                        data = f.read(MAX_MESSAGE + 1)
                except OSError as exc:
                    result.errors.append(f"{path}: {exc}")
                    continue
                self._add(data, f"{getattr(backend, 'name', 'backend')}:{path}", item.name, result)
                if result.added + result.known >= limit:
                    break
        self._log(f"{getattr(backend, 'name', 'backend')}:{folder}", result)
        return result

    def _log(self, what: str, result: ImportResult) -> None:
        with self._lock:
            self._db.execute("INSERT INTO imports VALUES (?,?,?,?,?,?)",
                             (time.time(), what[:2000], result.added, result.known, result.skipped,
                              json.dumps(result.errors[:200])))
            self._db.commit()
        self.write_csv()

    # --- reading -------------------------------------------------------------------

    @staticmethod
    def _where(search: str) -> tuple[str, list]:
        if not search:
            return "", []
        return (" WHERE subject LIKE ? OR sender LIKE ? OR recipients LIKE ? OR source LIKE ?",
                [f"%{search}%"] * 4)

    def count(self, *, search: str = "") -> int:
        """How many messages :meth:`messages` would list without its limit."""
        where, args = self._where(search)
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM messages" + where, args).fetchone()[0])

    def messages(self, *, order: str = "score", search: str = "", limit: int = 1000) -> list[dict]:
        """At most *limit* messages (see :meth:`count` for how many there are)."""
        column = {"score": "score DESC, date DESC", "date": "date DESC", "sender": "sender",
                  "subject": "subject"}.get(order, "score DESC")
        where, args = self._where(search)
        sql = ("SELECT sha256, source, kind, subject, sender, recipients, date, size, score, high, warn "
               "FROM messages" + where)
        sql += f" ORDER BY {column} LIMIT ?"
        args.append(int(limit))
        keys = ("sha256", "source", "kind", "subject", "sender", "recipients", "date", "size", "score",
                "high", "warn")
        with self._lock:
            return [dict(zip(keys, row)) for row in self._db.execute(sql, args)]

    def report(self, sha: str) -> dict:
        if not sha.isalnum():
            raise ValueError("not a message id")
        return json.loads((self.folder / "reports" / f"{sha}.json").read_text(encoding="utf-8"))

    def message(self, sha: str) -> MailMessage:
        if not sha.isalnum():
            raise ValueError("not a message id")
        for suffix in (".eml", ".msg"):
            path = self.folder / "messages" / f"{sha}{suffix}"
            if path.exists():
                return parse_any(path.read_bytes(), path.name, str(path))
        raise FileNotFoundError(sha)

    def write_csv(self) -> Path:
        out = io.StringIO()
        rows = self.messages(limit=10**9)
        writer = csv.DictWriter(out, fieldnames=list(rows[0]) if rows else ["sha256"])
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in row.items()})
        path = self.folder / "index.csv"
        path.write_text(out.getvalue(), encoding="utf-8")
        return path


def _walk(root: Path):
    """('file' | 'mbox' | 'maildir', path) for everything importable under root."""
    if root.is_symlink():
        return
    if root.is_file():
        suffix = root.suffix.lower()
        if suffix in MAIL_SUFFIXES:
            yield "file", root
        elif suffix in PST_SUFFIXES:
            yield "pst", root
        elif suffix in MBOX_SUFFIXES or _looks_like_mbox(root):
            yield "mbox", root
        return
    if not root.is_dir():
        return
    if all((root / d).is_dir() for d in ("cur", "new", "tmp")):
        yield "maildir", root
        return
    with contextlib.suppress(OSError):
        for child in sorted(root.iterdir()):
            yield from _walk(child)


def _looks_like_mbox(path: Path) -> bool:
    if path.suffix:
        return False
    try:
        with open(path, "rb") as f:
            return f.read(5) == b"From "
    except OSError:
        return False
