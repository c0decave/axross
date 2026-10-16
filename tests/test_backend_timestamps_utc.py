"""Every backend's ``FileItem.modified`` names the same instant on the same clock.

The contract (``models/file_item.py``): a naive ``modified`` is local wall
clock time — what ``datetime.fromtimestamp`` yields and what LocalFS, SFTP,
SMB and the pane's date column use — and an aware one is converted to local
wall clock time on construction.

Several backends broke it by handing over a *naive UTC* value: WebDAV
(``Last-Modified ... GMT``), Google Drive (``Z`` stripped), Azure Blob and
Files (``tzinfo`` stripped), Dropbox (the SDK parses ``...Z`` naive), FTP
MLSD / MDTM (RFC 3659: UTC), WinRM (``Z`` stripped), MongoDB (BSON dates
decode naive UTC) and IMAP (the ``INTERNALDATE`` zone was dropped). On any
machine east of UTC the remote file then looked hours older than it was:
"newer wins" overwrote the newer remote copy with the older local one.
The DB backends also wrote naive local ``datetime.now()`` into columns the
server reads as UTC (Mongo BSON, Postgres TIMESTAMPTZ in a UTC session).

Every test runs with ``TZ=Europe/Berlin`` (UTC+2 in July).
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.sync import ConflictPolicy, plan_sync  # noqa: E402
from core.tree_compare import ComparedEntry, Status, compare_trees  # noqa: E402
from models.file_item import FileItem  # noqa: E402

#: The remote file's real modification instant: 11:00 in Berlin.
REMOTE_UTC = datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc)
REMOTE_LOCAL = datetime(2026, 7, 1, 11, 0, 0)
#: The local copy was saved at 10:30 Berlin time — half an hour BEFORE the
#: remote one, so "newer wins" must take the remote copy.
LOCAL_OLDER = datetime(2026, 7, 1, 10, 30, 0)


@pytest.fixture
def berlin():
    old = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Berlin"
    time.tzset()
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()


def _newer_wins_direction(remote: FileItem) -> str:
    local = FileItem(name="f.txt", size=1, modified=LOCAL_OLDER)
    entry = ComparedEntry("f.txt", Status.DIFFERS, "differs", local, remote)
    plan = plan_sync([entry], policy=ConflictPolicy.NEWER_WINS)
    assert not plan.conflicts, plan.conflicts
    return plan.actions[0].direction


# --------------------------------------------------------------------------
# The contract itself
# --------------------------------------------------------------------------


def test_happy_aware_modified_becomes_local_wall_clock(berlin):
    item = FileItem(name="f", modified=REMOTE_UTC)
    assert item.modified == REMOTE_LOCAL
    assert item.modified.tzinfo is None
    assert item.modified.timestamp() == REMOTE_UTC.timestamp()


def test_happy_newer_wins_orders_local_against_an_aware_remote(berlin):
    # Used to be a "cannot compare" conflict: the offset of a naive local
    # value IS known — it is the machine's own.
    assert _newer_wins_direction(FileItem(name="f.txt", size=2, modified=REMOTE_UTC)) == "to_left"


def test_happy_same_instant_on_both_sides_compares_equal(berlin, tmp_path):
    class _Flat:
        def __init__(self, item):
            self.item = item

        def list_dir(self, path):
            return [self.item]

        def join(self, *parts):
            return "/".join(parts)

    local = FileItem(name="f.txt", size=5, modified=REMOTE_LOCAL)
    remote = FileItem(name="f.txt", size=5, modified=REMOTE_UTC)
    entries = compare_trees(_Flat(local), "/", _Flat(remote), "/", hash_limit=0)
    assert [(e.rel_path, e.status) for e in entries] == [("f.txt", Status.SAME)]


def test_sad_naive_value_is_left_alone(berlin):
    assert FileItem(name="f", modified=LOCAL_OLDER).modified == LOCAL_OLDER


def test_edge_accessed_and_created_follow_the_same_rule(berlin):
    item = FileItem(name="f", accessed=REMOTE_UTC, created=REMOTE_UTC)
    assert (item.accessed, item.created) == (REMOTE_LOCAL, REMOTE_LOCAL)


def test_edge_out_of_range_aware_value_does_not_crash(berlin):
    # datetime.max in UTC is past datetime.max in UTC+2.
    item = FileItem(name="f", modified=datetime.max.replace(tzinfo=timezone.utc))
    assert item.modified.tzinfo is None


def test_edge_non_datetime_modified_is_left_alone(berlin):
    assert FileItem(name="f", modified=1.5).modified == 1.5  # type: ignore[arg-type]


def test_edge_dst_change_is_respected(berlin):
    winter = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    assert FileItem(name="f", modified=winter).modified == datetime(2026, 1, 1, 10, 0)


# --------------------------------------------------------------------------
# WebDAV — end to end against a local PROPFIND server
# --------------------------------------------------------------------------


def _dav_server(lastmod: str):
    body = (
        '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">'
        "<d:response><d:href>/dav/</d:href><d:propstat><d:prop>"
        "<d:resourcetype><d:collection/></d:resourcetype></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        "<d:response><d:href>/dav/f.txt</d:href><d:propstat><d:prop>"
        "<d:displayname>f.txt</d:displayname><d:resourcetype/>"
        "<d:getcontentlength>2</d:getcontentlength>"
        f"<d:getlastmodified>{lastmod}</d:getlastmodified>"
        "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        "</d:multistatus>"
    ).encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_PROPFIND(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(207)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.parametrize(
    "lastmod",
    ["Wed, 01 Jul 2026 09:00:00 GMT", "2026-07-01T09:00:00Z", "2026-07-01T11:00:00+02:00"],
)
def test_webdav_listing_reports_the_real_instant(berlin, lastmod):
    pytest.importorskip("defusedxml")
    from core.webdav_client import WebDavSession

    srv = _dav_server(lastmod)
    try:
        s = WebDavSession(f"http://127.0.0.1:{srv.server_address[1]}/dav")
        try:
            (item,) = [i for i in s.list_dir("/") if i.name == "f.txt"]
        finally:
            s.close()
    finally:
        srv.shutdown()
        srv.server_close()
    assert item.modified == REMOTE_LOCAL
    assert _newer_wins_direction(item) == "to_left"


def test_webdav_unparseable_date_stays_epoch(berlin):
    from core.webdav_client import _parse_http_date

    assert _parse_http_date("yesterday-ish") == datetime.fromtimestamp(0)


# --------------------------------------------------------------------------
# FTP — MLST / MDTM are UTC (RFC 3659 section 2.3)
# --------------------------------------------------------------------------


class _ScriptedFtp:
    """Control connection on a socketpair answering from a verb table."""

    def __init__(self, replies: dict[str, str]) -> None:
        self.replies = replies
        self.client_sock, self._srv = socket.socketpair()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        for raw in self._srv.makefile("rb"):
            line = raw.decode().rstrip("\r\n")
            verb, _, arg = line.partition(" ")
            reply = {"NOOP": "200 ok\r\n", **self.replies}.get(verb, "550 no\r\n")
            self._srv.sendall(reply.replace("{arg}", arg).encode())

    def session(self, has_mlsd: bool):
        from ftplib import FTP

        from core import ftp_client as FC

        ftp = FTP()
        ftp.sock = self.client_sock
        ftp.file = self.client_sock.makefile("r", encoding="utf-8")
        s = FC.FtpSession.__new__(FC.FtpSession)
        s._ftp = ftp
        s._host, s._username = "h", "u"
        s._has_mlsd = has_mlsd
        return s


def test_ftp_mlst_modify_fact_is_utc(berlin):
    srv = _ScriptedFtp(
        {"MLST": "250-x\r\n type=file;size=2;modify=20260701090000; {arg}\r\n250 End\r\n"}
    )
    item = srv.session(has_mlsd=True).stat("/f.txt")
    assert item.modified == REMOTE_LOCAL
    assert _newer_wins_direction(item) == "to_left"


def test_ftp_mdtm_fallback_is_utc(berlin):
    srv = _ScriptedFtp(
        {
            "SIZE": "213 2\r\n",
            "MDTM": "213 20260701090000\r\n",
            "PWD": '257 "/"\r\n',
            "CWD": "550 not a directory\r\n",
        }
    )
    item = srv.session(has_mlsd=False).stat("/f.txt")
    assert item.modified == REMOTE_LOCAL


def test_ftp_mlst_fractional_and_missing_modify(berlin):
    srv = _ScriptedFtp(
        {"MLST": "250-x\r\n type=file;size=2;modify=20260701090000.250; {arg}\r\n250 End\r\n"}
    )
    assert srv.session(has_mlsd=True).stat("/f.txt").modified == REMOTE_LOCAL
    srv = _ScriptedFtp({"MLST": "250-x\r\n type=file;size=2; {arg}\r\n250 End\r\n"})
    assert srv.session(has_mlsd=True).stat("/f.txt").modified == datetime.fromtimestamp(0)


# --------------------------------------------------------------------------
# Google Drive — RFC 3339 "...Z"
# --------------------------------------------------------------------------


def test_gdrive_stat_keeps_the_utc_zone(berlin):
    pytest.importorskip("googleapiclient")
    from core import gdrive_client as GC

    s = object.__new__(GC.GDriveSession)
    s._resolve_path = lambda path: "id1"
    s._get_metadata = lambda fid: {
        "name": "f.txt",
        "mimeType": "text/plain",
        "size": "2",
        "modifiedTime": "2026-07-01T09:00:00.000Z",
    }
    item = s.stat("/f.txt")
    assert item.modified == REMOTE_LOCAL
    assert _newer_wins_direction(item) == "to_left"


def test_gdrive_bad_timestamp_is_epoch(berlin):
    pytest.importorskip("googleapiclient")
    from core import gdrive_client as GC

    assert GC.GDriveSession._parse_time("garbage") == datetime.fromtimestamp(0)
    assert GC.GDriveSession._parse_time("") == datetime.fromtimestamp(0)


# --------------------------------------------------------------------------
# Azure Blob / Files — the SDK returns aware UTC; it used to be stripped
# --------------------------------------------------------------------------


def test_azure_blob_listing_and_stat_keep_the_zone(berlin):
    pytest.importorskip("azure.storage.blob")
    from core import azure_client as AC

    blob = SimpleNamespace(name="f.txt", size=2, last_modified=REMOTE_UTC)
    container = SimpleNamespace(
        walk_blobs=lambda name_starts_with="", delimiter="/": iter([blob]),
        get_blob_client=lambda key: SimpleNamespace(
            get_blob_properties=lambda: SimpleNamespace(size=2, last_modified=REMOTE_UTC)
        ),
    )
    s = object.__new__(AC.AzureBlobSession)
    s._container = container
    (listed,) = s.list_dir("/")
    assert listed.modified == REMOTE_LOCAL
    assert s.stat("/f.txt").modified == REMOTE_LOCAL
    assert _newer_wins_direction(listed) == "to_left"


def test_azure_files_listing_and_stat_keep_the_zone(berlin):
    pytest.importorskip("azure.storage.fileshare")
    from core import azure_client as AC

    file_props = {"size": 2, "last_modified": REMOTE_UTC}
    directory = SimpleNamespace(
        list_directories_and_files=lambda: iter(
            [{"name": "f.txt", "is_directory": False, "size": 2, "last_modified": REMOTE_UTC}]
        ),
        get_file_client=lambda name: SimpleNamespace(get_file_properties=lambda: file_props),
    )
    s = object.__new__(AC.AzureFilesSession)
    s._share = SimpleNamespace(get_directory_client=lambda path: directory)
    (listed,) = s.list_dir("/")
    assert listed.modified == REMOTE_LOCAL
    assert s.stat("/f.txt").modified == REMOTE_LOCAL


# --------------------------------------------------------------------------
# Dropbox — stone parses "...Z" into a naive datetime
# --------------------------------------------------------------------------


def test_dropbox_server_modified_is_utc(berlin):
    pytest.importorskip("dropbox")
    from dropbox.files import FileMetadata

    from core import dropbox_client as DC

    # Exactly what the SDK hands over: naive, in UTC.
    entry = FileMetadata(
        name="f.txt",
        id="id:1",
        client_modified=datetime(2026, 7, 1, 9, 0),
        server_modified=datetime(2026, 7, 1, 9, 0),
        rev="0123456789abc",
        size=2,
    )
    item = DC.DropboxSession._entry_to_item(entry)
    assert item.modified == REMOTE_LOCAL
    assert _newer_wins_direction(item) == "to_left"


# --------------------------------------------------------------------------
# WinRM — PowerShell LastWriteTimeUtc.ToString('o')
# --------------------------------------------------------------------------


def test_winrm_listing_row_is_utc(berlin):
    from core import winrm_client as WC

    item = WC.WinRMSession._parse_listing_row(
        {"Name": "f.txt", "Length": 2, "Mtime": "2026-07-01T09:00:00.0000000Z", "IsDir": False}
    )
    assert item.modified == REMOTE_LOCAL
    bad = WC.WinRMSession._parse_listing_row({"Name": "g", "Mtime": "not a date"})
    assert bad.modified == datetime.fromtimestamp(0)


# --------------------------------------------------------------------------
# IMAP — INTERNALDATE carries its own zone
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "internaldate", ["01-Jul-2026 11:00:00 +0200", "01-Jul-2026 05:00:00 -0400", "01-Jul-2026 09:00:00 +0000"]
)
def test_imap_stat_honours_the_internaldate_zone(berlin, internaldate):
    from core.imap_client import ImapSession

    fake = SimpleNamespace(
        uid=lambda *a: (
            "OK",
            [(f'1 (UID 7 RFC822.SIZE 2 INTERNALDATE "{internaldate}")'.encode(), b"")],
        )
    )
    s = object.__new__(ImapSession)
    s._parse_path = lambda path: ("INBOX", "7")
    s._mailbox_names = lambda: ["INBOX"]
    s._select_mailbox = lambda *a, **k: None
    s._ensure_connected = lambda: fake
    item = s.stat("/INBOX/7.eml")
    assert item.modified == REMOTE_LOCAL


# --------------------------------------------------------------------------
# MongoDB / Postgres / DB-FS writes
# --------------------------------------------------------------------------


def test_mongo_upload_date_is_read_as_utc(berlin):
    pytest.importorskip("pymongo")
    from core import mongo_fs_client as MC

    stored = SimpleNamespace(
        filename="/f.txt",
        metadata={"parent": "/", "mode": 0o644},
        upload_date=datetime(2026, 7, 1, 9, 0),  # BSON decodes naive UTC
        length=2,
    )
    s = object.__new__(MC.MongoFsSession)
    s._lock = threading.RLock()
    s._dirs = SimpleNamespace(find_one=lambda q: None, find=lambda q: [])
    s._fs = SimpleNamespace(find_one=lambda q: stored, find=lambda q: [stored])
    assert s.stat("/f.txt").modified == REMOTE_LOCAL
    (listed,) = s.list_dir("/")
    assert listed.modified == REMOTE_LOCAL


def test_db_fs_writes_an_aware_mtime(berlin):
    pytest.importorskip("psycopg")
    from core import postgres_fs_client as PG

    executed: list[tuple] = []

    class _Cur:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            executed.append((sql, params))

        def fetchone(self):
            return None

        def fetchall(self):
            return []

    s = object.__new__(PG.PostgresFsSession)
    s._lock = threading.RLock()
    s._conn = SimpleNamespace(cursor=lambda: _Cur())
    before = time.time()
    s.mkdir("/d")
    inserts = [p for sql, p in executed if sql.startswith("INSERT")]
    assert inserts, executed
    mtime = inserts[0][4]
    # A naive value is read by a TIMESTAMPTZ column in the SESSION zone —
    # whatever the server is configured with, not this machine's.
    assert mtime.tzinfo is not None
    assert abs(mtime.timestamp() - before) < 60
