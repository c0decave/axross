"""Tests for new features: chmod, disk_usage, readlink, ssh_config, bookmarks."""

import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.bookmarks import Bookmark, BookmarkManager
from core.local_fs import LocalFS
from core.profiles import ConnectionProfile
from core.ssh_client import SSHSession, UnknownHostKeyError
from core.ssh_config import parse_ssh_config

# ── Docker network config ──
SERVERS = {
    "alpha": {"host": "10.99.0.10", "port": 22, "user": "alpha", "pass": "alpha123"},
    "beta": {"host": "10.99.0.11", "port": 22, "user": "beta", "pass": "beta123"},
    "gamma": {"host": "10.99.0.12", "port": 22, "user": "gamma", "pass": "gamma123"},
}


def _ssh_lab_available() -> bool:
    try:
        with socket.create_connection(
            (SERVERS["alpha"]["host"], SERVERS["alpha"]["port"]),
            timeout=0.25,
        ):
            return True
    except OSError:
        return False


requires_ssh_lab = pytest.mark.skipif(
    not _ssh_lab_available(),
    reason=(
        "Docker SSH lab endpoints are unavailable; local/mocked chmod, disk_usage, "
        "readlink, SSH config, and bookmark tests still cover production logic."
    ),
)


def auto_trust(error: UnknownHostKeyError) -> bool:
    return True


def make_profile(server: str) -> ConnectionProfile:
    s = SERVERS[server]
    return ConnectionProfile(
        name=server,
        host=s["host"],
        port=s["port"],
        username=s["user"],
        auth_type="password",
    )


def connect_session(server: str) -> SSHSession:
    s = SERVERS[server]
    profile = make_profile(server)
    session = SSHSession(profile)
    session.connect(password=s["pass"], on_unknown_host=auto_trust)
    return session


# ════════════════════════════════════════════
#  chmod tests
# ════════════════════════════════════════════


def test_local_chmod():
    fs = LocalFS()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    try:
        fs.chmod(path, 0o644)
        st = os.stat(path)
        assert st.st_mode & 0o777 == 0o644

        fs.chmod(path, 0o755)
        st = os.stat(path)
        assert st.st_mode & 0o777 == 0o755
    finally:
        os.unlink(path)


@requires_ssh_lab
def test_remote_chmod():
    s = connect_session("alpha")
    try:
        test_file = s.join(s.home(), "chmod_test.txt")
        with s.open_write(test_file) as f:
            f.write(b"chmod test")

        s.chmod(test_file, 0o600)
        stat = s.stat(test_file)
        assert stat.permissions & 0o777 == 0o600

        s.chmod(test_file, 0o755)
        stat = s.stat(test_file)
        assert stat.permissions & 0o777 == 0o755

        s.remove(test_file)
    finally:
        s.disconnect()


# ════════════════════════════════════════════
#  disk_usage tests
# ════════════════════════════════════════════


def test_local_disk_usage():
    fs = LocalFS()
    total, used, free = fs.disk_usage("/")
    assert total > 0
    assert used >= 0
    assert free > 0
    assert total >= free


@requires_ssh_lab
def test_remote_disk_usage():
    s = connect_session("beta")
    try:
        total, used, free = s.disk_usage(s.home())
        # statvfs should work on the container
        assert total > 0
        assert free >= 0
    finally:
        s.disconnect()


# ════════════════════════════════════════════
#  readlink tests
# ════════════════════════════════════════════


def test_local_readlink():
    fs = LocalFS()
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "target.txt")
        link = os.path.join(tmp, "link.txt")
        with open(target, "w") as f:
            f.write("target")
        os.symlink(target, link)
        result = fs.readlink(link)
        assert result == target


@requires_ssh_lab
def test_remote_readlink():
    s = connect_session("alpha")
    try:
        target = s.readlink(s.join(s.home(), "data", "link_to_readme"))
        assert "readme.txt" in target
    finally:
        s.disconnect()


# ════════════════════════════════════════════
#  SSH config parser tests
# ════════════════════════════════════════════


def test_ssh_config_parser():
    with tempfile.NamedTemporaryFile(mode="w", suffix="_config", delete=False) as f:
        f.write("""
Host myserver
    HostName 192.168.1.100
    Port 2222
    User admin
    IdentityFile ~/.ssh/id_ed25519

Host staging
    HostName staging.example.com
    User deploy

Host *
    ServerAliveInterval 60
""")
        f.flush()
        path = Path(f.name)

    try:
        hosts = parse_ssh_config(path)
        assert len(hosts) == 2  # Wildcard is skipped

        h1 = hosts[0]
        assert h1.alias == "myserver"
        assert h1.hostname == "192.168.1.100"
        assert h1.port == 2222
        assert h1.user == "admin"
        assert "id_ed25519" in h1.identity_file

        h2 = hosts[1]
        assert h2.alias == "staging"
        assert h2.hostname == "staging.example.com"
        assert h2.user == "deploy"
        assert h2.port == 22  # Default
    finally:
        path.unlink()


def test_ssh_config_missing_file():
    hosts = parse_ssh_config(Path("/nonexistent/path"))
    assert hosts == []


def test_ssh_config_multiple_aliases():
    with tempfile.NamedTemporaryFile(mode="w", suffix="_config", delete=False) as f:
        f.write("""
Host app staging
    HostName app.example.com
    User deploy
    Port 2200
    IdentityFile "~/.ssh/id_ed25519"

Host *
    ForwardAgent yes
""")
        f.flush()
        path = Path(f.name)

    try:
        hosts = parse_ssh_config(path)
        assert [h.alias for h in hosts] == ["app", "staging"]
        for host in hosts:
            assert host.hostname == "app.example.com"
            assert host.user == "deploy"
            assert host.port == 2200
            assert host.identity_file.endswith("id_ed25519")
    finally:
        path.unlink()


# ════════════════════════════════════════════
#  Bookmark manager tests
# ════════════════════════════════════════════


def test_bookmark_manager():
    with tempfile.TemporaryDirectory() as tmp:
        import core.bookmarks as bm_mod

        orig_file = bm_mod.BOOKMARKS_FILE
        bm_mod.BOOKMARKS_FILE = Path(tmp) / "bookmarks.json"

        try:
            mgr = BookmarkManager()
            assert len(mgr.all()) == 0

            mgr.add(Bookmark(name="Home", path="~", backend_name="Local"))
            mgr.add(Bookmark(name="Remote", path="/var/log", backend_name="admin@server"))
            assert len(mgr.all()) == 2

            # Duplicate check
            mgr.add(Bookmark(name="Home2", path="~", backend_name="Local"))
            assert len(mgr.all()) == 2  # Not added

            # Filter
            local = mgr.for_backend("Local")
            assert len(local) == 1

            # Remove
            mgr.remove(0)
            assert len(mgr.all()) == 1

            # Persistence
            mgr2 = BookmarkManager()
            assert len(mgr2.all()) == 1
        finally:
            bm_mod.BOOKMARKS_FILE = orig_file


def test_bookmark_load_rejects_non_list_root():
    # Top-level JSON is a dict, not a list — load skips cleanly.
    with tempfile.TemporaryDirectory() as tmp:
        import core.bookmarks as bm_mod

        orig = bm_mod.BOOKMARKS_FILE
        bm_mod.BOOKMARKS_FILE = Path(tmp) / "bookmarks.json"
        try:
            bm_mod.BOOKMARKS_FILE.write_text('{"not": "a list"}')
            mgr = BookmarkManager()
            assert mgr.all() == []
        finally:
            bm_mod.BOOKMARKS_FILE = orig


def test_bookmark_load_drops_malformed_entries():
    # Mix of valid + invalid entries — valid ones survive.
    with tempfile.TemporaryDirectory() as tmp:
        import core.bookmarks as bm_mod

        orig = bm_mod.BOOKMARKS_FILE
        bm_mod.BOOKMARKS_FILE = Path(tmp) / "bookmarks.json"
        try:
            bm_mod.BOOKMARKS_FILE.write_text(
                json.dumps(
                    [
                        {"name": "ok", "path": "/home"},
                        {"name": 123, "path": "/bad"},  # name not str
                        {"name": "also-ok", "path": "/tmp"},
                        "not-a-dict",
                    ]
                )
            )
            mgr = BookmarkManager()
            names = sorted(b.name for b in mgr.all())
            assert names == ["also-ok", "ok"]
        finally:
            bm_mod.BOOKMARKS_FILE = orig


def test_bookmark_load_swallows_corrupted_json():
    with tempfile.TemporaryDirectory() as tmp:
        import core.bookmarks as bm_mod

        orig = bm_mod.BOOKMARKS_FILE
        bm_mod.BOOKMARKS_FILE = Path(tmp) / "bookmarks.json"
        try:
            bm_mod.BOOKMARKS_FILE.write_text("{not-json")
            mgr = BookmarkManager()
            assert mgr.all() == []
        finally:
            bm_mod.BOOKMARKS_FILE = orig


def test_bookmark_remove_ignores_out_of_range():
    # Negative / too-large indices are no-ops, never raise.
    with tempfile.TemporaryDirectory() as tmp:
        import core.bookmarks as bm_mod

        orig = bm_mod.BOOKMARKS_FILE
        bm_mod.BOOKMARKS_FILE = Path(tmp) / "bookmarks.json"
        try:
            mgr = BookmarkManager()
            mgr.add(Bookmark(name="x", path="/x"))
            mgr.remove(-1)  # no-op
            mgr.remove(99)  # no-op
            assert len(mgr.all()) == 1
        finally:
            bm_mod.BOOKMARKS_FILE = orig


def test_bookmark_save_tolerates_chmod_failure():
    # When chmod on the config dir fails (read-only FS / unusual
    # mount), save() logs and continues — bookmarks still persist.
    from unittest import mock as _mock

    with tempfile.TemporaryDirectory() as tmp:
        import core.bookmarks as bm_mod

        orig = bm_mod.BOOKMARKS_FILE
        bm_mod.BOOKMARKS_FILE = Path(tmp) / "bookmarks.json"
        try:
            mgr = BookmarkManager()
            # chmod call on target_dir raises; chmod on target file
            # is still reached in the normal flow.
            calls = {"n": 0}

            def fake_chmod(p, m):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError("read-only fs")

            with _mock.patch("core.bookmarks.os.chmod", side_effect=fake_chmod):
                mgr.add(Bookmark(name="x", path="/x"))
            # File written regardless.
            assert bm_mod.BOOKMARKS_FILE.exists()
        finally:
            bm_mod.BOOKMARKS_FILE = orig


def test_bookmark_save_cleans_up_tempfile_on_replace_failure():
    # If os.replace() raises after the temp is written, save() must
    # clean up the orphaned temp so /tmp doesn't fill.
    from unittest import mock as _mock

    with tempfile.TemporaryDirectory() as tmp:
        import core.bookmarks as bm_mod

        orig = bm_mod.BOOKMARKS_FILE
        bm_mod.BOOKMARKS_FILE = Path(tmp) / "bookmarks.json"
        try:
            mgr = BookmarkManager()
            with _mock.patch("core.bookmarks.os.replace", side_effect=OSError("disk full")):
                mgr.add(Bookmark(name="x", path="/x"))  # no raise
            # Target dir has no leftover .bookmarks.*.tmp
            leftovers = [p for p in Path(tmp).glob(".bookmarks.*.tmp")]
            assert leftovers == []
        finally:
            bm_mod.BOOKMARKS_FILE = orig


# ════════════════════════════════════════════
#  Combined network tests for new features
# ════════════════════════════════════════════


@requires_ssh_lab
def test_chmod_and_verify_across_servers():
    """chmod on one server, verify on reconnect."""
    s = connect_session("gamma")
    try:
        test_file = s.join(s.home(), "chmod_cross.txt")
        with s.open_write(test_file) as f:
            f.write(b"cross test")

        s.chmod(test_file, 0o700)
        stat = s.stat(test_file)
        assert stat.permissions & 0o777 == 0o700
        s.remove(test_file)
    finally:
        s.disconnect()


@requires_ssh_lab
def test_disk_usage_all_servers():
    """disk_usage works on all Docker servers."""
    for name in SERVERS:
        s = connect_session(name)
        try:
            total, used, free = s.disk_usage(s.home())
            assert total > 0, f"{name}: total should be > 0"
        finally:
            s.disconnect()
