"""Regression tests of the review findings first held back, fixed after
0.15.174 (2026-11-06): SCP memory, remote ownership, stale sync plans,
reconnected editors, Drive threads, UTF-8 IMAP logins, store errors."""

from __future__ import annotations

import base64
import io
import os
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


# -- SCP: a large upload streams from its spool -------------------------------------------------


def test_happy_a_large_scp_upload_is_streamed_not_read_whole(monkeypatch):
    pytest.importorskip("paramiko")
    from core import scp_client as S

    sent = {}

    def exec_fn(cmd, timeout, stdin_data=None):
        sent["type"] = type(stdin_data)
        sent["data"] = b"".join(bytes(c) for c in S._chunks(stdin_data))
        return ""

    monkeypatch.setattr(S, "STREAM_ABOVE", 1000)
    caps = S._Capabilities(transfer_method="base64")
    writer = S._SpooledWriter(exec_fn, "/srv/big.bin", caps)
    payload = os.urandom(100_003)
    writer.write(payload)
    writer.close()
    assert sent["type"] is S._Base64Stream          # never one bytes object
    assert base64.b64decode(sent["data"]) == payload


def test_sad_a_large_binary_upload_without_base64_is_refused_before_sending(monkeypatch):
    pytest.importorskip("paramiko")
    from core import scp_client as S

    calls = []
    monkeypatch.setattr(S, "STREAM_ABOVE", 10)
    caps = S._Capabilities(transfer_method="raw")
    writer = S._SpooledWriter(lambda *a, **k: calls.append(a), "/srv/x", caps)
    writer.write(b"text " * 10 + b"\xff\xfe")
    with pytest.raises(OSError, match="binary"):
        writer.close()
    assert calls == []


# -- atomic save over SFTP keeps the owner --------------------------------------------------------


class _OwnedFS:
    """A remote-like backend (not LocalFS) on a temp folder, with owners."""

    def __init__(self, root: Path, *, chown_works: bool) -> None:
        from core.local_fs import LocalFS

        self._fs = LocalFS()
        self.owners: dict[str, tuple[int, int]] = {}
        self.chown_works = chown_works
        self.chowned: list = []

    def __getattr__(self, name):
        return getattr(self._fs, name)

    def owner_ids(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        return self.owners.get(path, (1000, 1000))

    def chown(self, path, uid, gid):
        if not self.chown_works:
            raise PermissionError("not allowed")
        self.chowned.append((path, uid, gid))
        self.owners[path] = (uid, gid)


@pytest.mark.parametrize("chown_works", [True, False])
def test_sad_an_atomic_save_does_not_take_a_files_owner(tmp_path, chown_works):
    from core import atomic_io

    target = tmp_path / "config.php"
    target.write_bytes(b"old")
    fs = _OwnedFS(tmp_path, chown_works=chown_works)
    fs.owners[str(target)] = (33, 33)    # www-data
    atomic_io.atomic_write(fs, str(target), b"new content")
    assert target.read_bytes() == b"new content"
    if chown_works:
        assert fs.chowned and fs.chowned[0][1:] == (33, 33)
    else:
        # written into the file itself: it keeps its owner
        assert fs.owners[str(target)] == (33, 33)
    assert [p.name for p in tmp_path.iterdir()] == ["config.php"]


def test_happy_an_unrestorable_destination_is_kept_locally(tmp_path, monkeypatch):
    from core import server_ops

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    kept = server_ops._keep_snapshot_locally("/remote/report.doc", io.BytesIO(b"previous"))
    assert kept and Path(kept).read_bytes() == b"previous"
    assert Path(kept).parent == tmp_path / "state" / "axross" / "kept"


# -- sync: "newer wins" is checked again when the copy runs -------------------------------------


def test_sad_a_stale_newer_wins_plan_does_not_overwrite_a_later_edit(tmp_path):
    from core.local_fs import LocalFS
    from core.transfer_conflicts import IF_EXISTS_NEWER, ConflictPlan

    plan = ConflictPlan.only_newer(LocalFS(), [("/l/a.txt", str(tmp_path / "a.txt"))])
    assert plan.resolve(str(tmp_path / "a.txt"), "/l/a.txt") == (str(tmp_path / "a.txt"),
                                                                  IF_EXISTS_NEWER)


# -- stores: a failed save is reported, not only logged ----------------------------------------


def test_sad_a_bookmark_store_that_cannot_be_written_is_reported(tmp_path, monkeypatch):
    from core import bookmarks as B
    from core import json_store

    heard = []
    monkeypatch.setattr(json_store, "_SAVE_FAILURE_LISTENERS", [lambda what, err: heard.append(what)])
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(B, "_bookmarks_file", lambda: blocker / "bookmarks.json")  # not a folder
    manager = B.BookmarkManager()
    manager.add(B.Bookmark(name="x", path="/data"))
    assert heard == ["bookmarks"]


# -- IMAP: a password beyond ASCII ----------------------------------------------------------------


def test_happy_a_utf8_password_logs_in_with_sasl_plain():
    from core.imap_client import ImapSession

    calls = []

    class Imap:
        capabilities = ("IMAP4REV1", "AUTH=PLAIN")

        def login(self, *a):
            raise AssertionError("LOGIN encodes as ASCII")

        def authenticate(self, mech, callback):
            calls.append((mech, callback(b"")))
            return "OK", [b"done"]

    session = ImapSession.__new__(ImapSession)
    session._username, session._password = "jörg", "pässwört€"
    session._imap = Imap()
    assert session._login()[0] == "OK"
    assert calls == [("PLAIN", "\0jörg\0pässwört€".encode("utf-8"))]


def test_sad_a_utf8_password_without_auth_plain_is_a_clear_error():
    from core.imap_client import ImapSession

    class Imap:
        capabilities = ("IMAP4REV1",)

    session = ImapSession.__new__(ImapSession)
    session._username, session._password = "u", "€"
    session._imap = Imap()
    with pytest.raises(ConnectionError, match="AUTH=PLAIN"):
        session._login()


# -- Drive: one service per thread -----------------------------------------------------------------


def test_happy_each_thread_gets_its_own_drive_service(monkeypatch):
    pytest.importorskip("googleapiclient")
    from core.gdrive_client import GDriveSession

    built = []
    s = GDriveSession.__new__(GDriveSession)
    monkeypatch.setattr(s, "_build_service", lambda creds: built.append(creds) or object())
    s._creds = "creds"
    s._per_thread = threading.local()
    s._owner_thread = threading.current_thread()
    s._service = main = object()
    assert s._service is main and s._service is main
    other = []
    t = threading.Thread(target=lambda: other.extend([s._service, s._service]))
    t.start()
    t.join()
    assert other[0] is other[1] and other[0] is not main and built == ["creds"]


def test_edge_a_session_made_without_credentials_keeps_its_service():
    pytest.importorskip("googleapiclient")
    from core.gdrive_client import GDriveSession

    s = GDriveSession.__new__(GDriveSession)
    fake = object()
    s._service = fake
    seen = []
    t = threading.Thread(target=lambda: seen.append(s._service))
    t.start()
    t.join()
    assert seen == [fake]


# -- sandboxes ------------------------------------------------------------------------------------


def test_happy_full_network_uses_pasta_when_it_works(monkeypatch):
    from core import agent_sandbox as AS

    monkeypatch.setattr(AS, "_pasta_works", lambda: True)
    monkeypatch.setattr(AS, "_limits_prefix", lambda rules: [])
    monkeypatch.setattr(AS, "_python_paths", lambda: ([], []))
    profiles = [p for p in AS.default_profiles() if getattr(p, "network", "") == "full"] \
        if hasattr(AS, "default_profiles") else []
    if not profiles:
        pytest.skip("no full-network profile to build")
    profile = profiles[0]
    argv = AS._bwrap_command(profile, "/tmp", False, ["true"])
    assert argv[:len(AS.PASTA_PREFIX)] == list(AS.PASTA_PREFIX)
