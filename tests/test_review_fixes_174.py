"""Regression tests of the three whole-codebase reviews (2026-11-06, 0.15.174):
correctness, security, robustness. Each test names the defect it pins."""

from __future__ import annotations

import gzip
import json
import os
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


# -- trash: the only complete copy is never emptied unseen -----------------------------------


def test_sad_a_move_that_could_not_remove_its_source_still_gets_its_sidecar(tmp_path, monkeypatch):
    """Across devices the copy succeeded, the source was only partly removed:
    the trash holds the only complete copy. Without its sidecar the Trash
    window did not list it and Empty Trash deleted it."""
    from core import server_ops
    from core import trash as T
    from core.local_fs import LocalFS

    fs = LocalFS()
    src = tmp_path / "photos"
    src.mkdir()
    (src / "a.jpg").write_bytes(b"jpeg")
    root = tmp_path / "trash"

    def half_move(backend, path, dst, *a, **k):
        import shutil

        shutil.copytree(path, dst)
        raise OSError("moved, but the source could not be removed completely")

    monkeypatch.setattr(server_ops, "server_side_move", half_move)
    with pytest.raises(OSError):
        T.trash(fs, str(src), root=str(root))
    entries = T.list_trash(fs, root=str(root))
    assert len(entries) == 1 and entries[0].original_path == str(src)


def test_sad_empty_trash_keeps_data_the_trash_window_does_not_show(tmp_path):
    from core import trash as T
    from core.local_fs import LocalFS

    fs = LocalFS()
    root = tmp_path / "trash"
    (tmp_path / "f.txt").write_text("x")
    T.trash(fs, str(tmp_path / "f.txt"), root=str(root))
    orphan = root / ("0" * 32)
    orphan.write_text("the only copy")
    assert len(T.list_trash(fs, root=str(root))) == 1
    assert T.empty_trash(fs, root=str(root)) == 1
    assert orphan.read_text() == "the only copy"


# -- state files: broken ones set aside, unreadable ones not written over -----------------------


def test_happy_read_for_merge_of_a_missing_file_is_empty(tmp_path):
    from core.json_store import read_for_merge

    assert read_for_merge(tmp_path / "none.json") == {}


@pytest.mark.parametrize("text", ["{ trailing,", "[1, 2]", "\xff\xfe"])
def test_sad_a_broken_store_is_set_aside_not_lost(tmp_path, text):
    from core.json_store import read_for_merge

    store = tmp_path / "settings.json"
    store.write_bytes(text.encode("latin-1"))
    assert read_for_merge(store) == {}
    assert not store.exists()
    kept = list(tmp_path.glob("settings.json.unreadable-*"))
    assert len(kept) == 1 and kept[0].read_bytes() == text.encode("latin-1")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_sad_an_unreadable_store_is_an_error_and_stays(tmp_path):
    from core.json_store import read_for_merge

    store = tmp_path / "settings.json"
    store.write_text('{"keep": 1}')
    store.chmod(0)
    try:
        with pytest.raises(OSError):
            read_for_merge(store)
    finally:
        store.chmod(0o600)
    assert json.loads(store.read_text()) == {"keep": 1}


def test_sad_a_setting_written_into_a_broken_file_keeps_the_rest(tmp_path, monkeypatch):
    from core import open_limits as OL

    path = tmp_path / "settings.json"
    path.write_text('{"transfer_parallel": 3, "mode": "x",}')  # a trailing comma
    monkeypatch.setattr(OL, "SETTINGS_PATH", path)
    OL.write_setting("max_open_mb", 64)
    assert json.loads(path.read_text()) == {"max_open_mb": 64}
    kept = list(tmp_path.glob("settings.json.unreadable-*"))
    assert len(kept) == 1 and '"mode": "x"' in kept[0].read_text()


def test_sad_the_scheduler_does_not_save_over_a_store_it_cannot_read(tmp_path, monkeypatch):
    from core import scheduler as S

    store = S.JobStore(tmp_path / "jobs.json") if hasattr(S, "JobStore") else None
    if store is None:
        pytest.skip("no JobStore")
    (tmp_path / "jobs.json").write_text("[]")

    def unreadable(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", unreadable)
    with pytest.raises(OSError):
        store.update(lambda jobs: jobs)


# -- dates: the locale does not decide them -------------------------------------------------------


def test_happy_ls_dates_do_not_depend_on_the_locale(monkeypatch):
    import time as _time

    from core.telnet_client import _parse_ls_date

    # strptime's %b would follow LC_TIME; the table does not call it at all
    monkeypatch.setattr(_time, "strptime", lambda *a: (_ for _ in ()).throw(AssertionError))
    assert _parse_ls_date("Mar 16  2025").year == 2025
    assert _parse_ls_date("Dec 31  2024").month == 12
    leap = _parse_ls_date("Feb 29 10:00")
    assert (leap.month, leap.day) == (2, 29) and leap.year % 4 == 0
    assert _parse_ls_date("Foo 1 10:00").year == 1970


def test_happy_http_dates_parse_without_strptime():
    from core.webdav_client import _parse_http_date

    when = _parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT")
    assert (when.year, when.month, when.hour) == (2015, 10, 7) and when.utcoffset().total_seconds() == 0
    assert _parse_http_date("nonsense").year == 1970


def test_sad_a_time_no_datetime_holds_does_not_break_a_listing(tmp_path):
    from core.local_fs import LocalFS
    from models.file_item import local_time

    odd = tmp_path / "odd.txt"
    odd.write_text("x")
    try:
        os.utime(odd, (1e12, 1e12))   # the year 33658
    except (OverflowError, OSError):
        pytest.skip("the file system does not take that time")
    names = [i.name for i in LocalFS().list_dir(str(tmp_path))]
    assert names == ["odd.txt"]
    assert local_time(1e12).year == 1970 and local_time(0).year in (1969, 1970)


# -- WebDAV: names from the href, quota bounded, "absent" only on 404 ---------------------------


def test_sad_a_displayname_is_not_the_entry_name():
    from core import webdav_client as W

    client = W._WebDavClient("http://127.0.0.1:1/dav", "", "")
    payload = (b"<d:multistatus xmlns:d='DAV:'><d:response><d:href>/dav/old.txt</d:href>"
               b"<d:propstat><d:prop><d:displayname>../../new.txt</d:displayname>"
               b"<d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
               b"</d:response></d:multistatus>")
    entries = client._parse_propfind(payload)
    assert [e["name"] for e in entries if e["name"]] == ["old.txt"]


@pytest.mark.parametrize("status, absent", [(404, True), (410, True), (503, None), (403, None)])
def test_sad_only_not_found_is_absent(monkeypatch, status, absent):
    from core import webdav_client as W

    client = W._WebDavClient.__new__(W._WebDavClient)

    def info(path):
        raise W.WebDavRequestError(f"HTTP {status}", status=status)

    monkeypatch.setattr(client, "info", info)
    if absent:
        assert client.check("/f") is False
    else:
        with pytest.raises(OSError):
            client.check("/f")


# -- media player: a server's name stays inside the temporary folder ----------------------------


@pytest.mark.parametrize("name", ["../../escaped.mp3", "/etc/x.mp3", "a/b.mp3"])
def test_sad_a_remote_track_name_cannot_leave_the_temporary_folder(tmp_path, name):
    from resources.extensions import media_player as MP

    class Backend:
        def open_read(self, path):
            raise AssertionError("nothing may be read for an unsafe name")

    folder = tmp_path / "axross-media-x"
    folder.mkdir()
    with pytest.raises(OSError):
        MP.copy_remote(Backend(), "/remote/x", name, str(folder), 0)
    assert not list(tmp_path.rglob("escaped.mp3"))


# -- IMAP, POP3, http_probe ----------------------------------------------------------------------


@pytest.mark.parametrize("name, sent", [
    ("INBOX", '"INBOX"'),
    ("Sent Items", '"Sent Items"'),
    ("[Gmail]/Sent Mail", '"[Gmail]/Sent Mail"'),
    ('a"b\\c', '"a\\"b\\\\c"'),
    ("Entwürfe", '"Entw&APw-rfe"'),
])
def test_happy_mailbox_names_are_quoted(name, sent):
    from core.imap_client import _mailbox_arg

    assert _mailbox_arg(name) == sent


@pytest.mark.parametrize("encoding, packed", [
    ("gzip", gzip.compress(b"\0" * 20_000_000)),
    ("deflate", zlib.compress(b"\0" * 20_000_000)),
])
def test_sad_a_compression_bomb_decodes_only_to_the_cap(encoding, packed):
    from core.net_helpers import _decode_bounded

    assert len(_decode_bounded(packed, encoding, 4097)) == 4097


def test_sad_an_endless_pop3_listing_is_cut(monkeypatch):
    import poplib

    from core.pop3_client import Pop3Session

    lines = iter([b"+OK"] + [b"1 1000"] * 100)

    class Pop(poplib.POP3):
        def __init__(self):
            self.closed = False

        def _putcmd(self, line):
            pass

        def _getresp(self):
            return next(lines)

        def _getline(self):
            line = next(lines, b".")
            return line, len(line) + 2

        def close(self):
            self.closed = True

    session = Pop3Session.__new__(Pop3Session)
    session._pop = pop = Pop()
    with pytest.raises(OSError, match="exceeds"):
        session._long_capped(pop, "list", (), "LIST", 50)
    assert pop.closed and session._pop is None


# -- XMPP: no password without TLS, none in the log -----------------------------------------------


def test_happy_xmpp_logs_in_only_with_mechanisms_that_need_tls():
    from core import chat_xmpp as X

    assert "LOGIN" not in X.SAFE_SASL_MECHANISMS
    assert all(m.startswith("SCRAM-") or m == "PLAIN" for m in X.SAFE_SASL_MECHANISMS)


def test_sad_sasl_stanzas_stay_out_of_the_log(caplog):
    import logging

    from core import chat_xmpp as X

    X.install_log_redaction()
    X.install_log_redaction()   # once
    target = logging.getLogger("slixmpp.xmlstream.xmlstream")
    assert sum(isinstance(f, X._SaslLogFilter) for f in target.filters) == 1
    with caplog.at_level(logging.DEBUG, logger="slixmpp.xmlstream.xmlstream"):
        target.debug("SEND: %s", "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>c2VjcmV0</auth>")
        target.debug("SEND: %s", "<message>hello</message>")
    text = caplog.text
    assert "c2VjcmV0" not in text and "not logged" in text and "hello" in text


# -- IRC: a nick at the length limit, a SCRAM server that proves nothing ---------------------------


def test_sad_scram_is_unverified_until_the_server_proves_it():
    from core.chat_irc import Scram, ScramError

    scram = Scram("user", "pass", nonce="abc")
    assert scram.verified is False
    with pytest.raises(ScramError):
        scram.verify(b"v=AAAA")
    assert scram.verified is False


# -- supply-chain gate: the build installs what was inspected -----------------------------------


def test_happy_a_reduced_lock_holds_only_the_inspected_archives():
    from security.dep_floor_audit import parse_lock
    from security.supply_chain_gate import GateError, reduce_lock

    a, b, c = "a" * 64, "b" * 64, "c" * 64
    text = (f"foo==1.0 ; sys_platform == 'linux' \\\n    --hash=sha256:{a} \\\n    --hash=sha256:{b}\n"
            f"bar==2.0 \\\n    --hash=sha256:{c}\n")
    reduced = reduce_lock(text, {("foo", "1.0"): {b}, ("bar", "2.0"): {c}})
    pins = {p.name: p for p in parse_lock(reduced)}
    assert pins["foo"].hashes == (b,) and pins["foo"].marker == "sys_platform == 'linux'"
    assert pins["bar"].hashes == (c,)
    with pytest.raises(GateError):
        reduce_lock(text, {("foo", "1.0"): {b}})   # bar: nothing inspected


# -- the agent: no writes to what runs code; approvals show what runs ---------------------------


@pytest.mark.parametrize("rel", [".config/axross/agent/settings.json", ".bashrc",
                                 ".config/autostart/x.desktop", ".ssh/authorized_keys"])
def test_sad_the_agent_does_not_change_places_that_run_code(tmp_path, monkeypatch, rel):
    from core import mcp_server as M

    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(PermissionError):
        M._refuse_protected(str(tmp_path / rel))
    with pytest.raises(PermissionError):
        M._refuse_protected(str(tmp_path / ".config"), entry=True)
    assert M._refuse_protected(str(tmp_path / "notes.txt")) == str(tmp_path / "notes.txt")


def test_happy_an_approval_shows_bidi_overrides_as_escapes():
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.agent_dock import _visible

    shown = _visible("rm -rf /tmp/x\u202egnp.txt\nnext")
    assert "\u202e" not in shown and "\\u202e" in shown and "\nnext" in shown


# -- names shown, archives, bookmarks -------------------------------------------------------------


def test_happy_a_name_with_a_bidi_override_is_shown_defused():
    pytest.importorskip("PyQt6.QtWidgets")
    from models.file_item import FileItem
    from models.file_table_model import COL_NAME, FileTableModel

    model = FileTableModel()
    shown = model.display_text(FileItem(name="report\u202efdp.exe"), COL_NAME)
    assert "\u202e" not in shown and shown.startswith("report")


def test_sad_a_dangling_link_is_a_taken_name(tmp_path):
    from core.archive import auto_suffix_dir

    os.symlink(tmp_path / "gone", tmp_path / "foo")
    assert auto_suffix_dir(str(tmp_path), "foo") == str(tmp_path / "foo-1")


def test_sad_a_bookmark_of_a_non_utf8_path_is_saved(tmp_path, monkeypatch):
    from core import bookmarks as B

    monkeypatch.setattr(B, "_bookmarks_file", lambda: tmp_path / "bookmarks.json")
    manager = B.BookmarkManager()
    name = "caf\udce9"
    manager.add(B.Bookmark(name="x", path=f"/data/{name}"))
    saved = json.loads((tmp_path / "bookmarks.json").read_text("utf-8"))
    assert f"/data/{name}" in json.dumps(saved, ensure_ascii=False)


# -- SMB: a junction is a link; each session its own connection ----------------------------------


def test_sad_a_recursive_delete_does_not_empty_a_junction_target(monkeypatch):
    pytest.importorskip("smbclient")
    from smb_fake_client import DirEntry, FakeSmbClient, make_session, smb_info

    from core import smb_client

    fake = FakeSmbClient()
    monkeypatch.setattr(smb_client, "smbclient", fake)
    junction = DirEntry("cache", smb_info(attrs=0x410, size=0))   # DIRECTORY | REPARSE_POINT
    fake.listings["\\\\h\\s\\proj"] = [junction]
    fake.listings["\\\\h\\s\\proj\\cache"] = [DirEntry("precious.dat")]
    session = make_session(fake)
    [item] = session.list_dir("/proj")
    assert item.is_dir and item.is_link
    session._rmdir_recursive("/proj")
    assert ("scandir", "\\\\h\\s\\proj\\cache") not in fake.calls
    assert ("remove", "\\\\h\\s\\proj\\cache\\precious.dat") not in fake.calls
    assert ("rmdir", "\\\\h\\s\\proj\\cache") in fake.calls


def test_sad_a_junction_named_for_removal_goes_as_the_link(monkeypatch):
    pytest.importorskip("smbclient")
    from smb_fake_client import FakeSmbClient, make_session

    from core import smb_client

    fake = FakeSmbClient()
    monkeypatch.setattr(smb_client, "smbclient", fake)
    fake.junctions.add("\\\\h\\s\\sub")
    make_session(fake).remove("/sub", recursive=True)
    assert fake.calls == [("rmdir", "\\\\h\\s\\sub")]


def test_happy_each_smb_session_has_its_own_connection_pool():
    pytest.importorskip("smbclient")
    from core.smb_client import SmbSession

    a, b = SmbSession.__new__(SmbSession), SmbSession.__new__(SmbSession)
    for s in (a, b):
        s._port, s._connections = 445, {}
    assert a._kw["connection_cache"] is not b._kw["connection_cache"]


# -- windows put into the dock bar still ask about their edits on quit -----------------------


def test_sad_a_docked_window_with_edits_is_asked_on_quit():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget

    from ui import viewer_window as VW
    from ui import window_dock_bar as DB

    app = QApplication.instance() or QApplication([])
    main = QMainWindow()
    DB.install(main)

    asked = []

    class Editor(QWidget):
        def closeEvent(self, event):
            asked.append(self.isVisible())
            event.ignore()   # "Cancel": keep it open

    from PyQt6.QtCore import Qt

    editor = Editor(main, Qt.WindowType.Window)
    VW.show_independent(editor)
    main.window_dock_bar.dock(editor)
    assert not editor.isVisible()
    assert VW.close_independent_windows(main) is False
    assert asked == [True]   # asked - and shown again, so the user sees which one
    main.deleteLater()
    app.processEvents()
