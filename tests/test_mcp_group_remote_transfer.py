"""MCP capability groups ``remote`` and ``transfer``.

remote: remote_profiles (no secrets), remote_open (a saved profile becomes
an extra backend every tool can address with ``backend``), remote_close,
list_backends. Credentials come from the keyring only when the profile
stores them; anything that would need a prompt fails with a clear error.

transfer: transfer_copy / transfer_move between backends (mutating),
optionally resumable.

Remote ends are a RamFS profile (in-process memory) and the in-process
paramiko SFTP server from tests/sftp_testkit.py; no keyring is touched.
"""

from __future__ import annotations

import base64
import json
import os
import threading

import pytest

from core import credentials
from core import mcp_server as M
from core import profiles as P
from core import security_mode
from core.local_fs import LocalFS
from core.profiles import ConnectionProfile
from tests import mcp_group_testkit as T

PW = "sftp-password-must-not-leak"
SAS = "SAS-TOKEN-must-not-leak"


@pytest.fixture(autouse=True)
def _no_keyring(monkeypatch):
    # core.credentials would swap the null keyring for SecretService; the
    # tests must never reach a real keyring.
    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)


@pytest.fixture(autouse=True)
def _fresh_connections():
    # One ConnectionManager per registry; close what a test left open.
    yield
    from core import mcp_groups

    for registry in list(mcp_groups.RemoteRegistry._live):
        registry.close_all()


def _write_profiles(path, profiles: list[dict]) -> None:
    path.write_text(json.dumps({p["name"]: p for p in profiles}))


@pytest.fixture
def saved(tmp_path, monkeypatch):
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    ram = ConnectionProfile(name="ram1", protocol="ramfs").to_dict()
    ram2 = ConnectionProfile(name="ram2", protocol="ramfs").to_dict()
    prod = ConnectionProfile(name="prod", protocol="ramfs", production=True).to_dict()
    drive = ConnectionProfile(name="drive", protocol="gdrive").to_dict()
    legacy = ConnectionProfile(name="old-ftp", protocol="ftp", host="127.0.0.1", port=1).to_dict()
    azure = ConnectionProfile(name="az", protocol="azure_blob", username="acct").to_dict()
    azure["azure_sas_token"] = SAS
    profiles = [ram, ram2, prod, drive, legacy, azure]
    _write_profiles(path, profiles)
    return path, profiles


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    r.mkdir()
    (r / "a.txt").write_bytes(b"alpha bytes\n")
    (r / "dir").mkdir()
    (r / "dir" / "x.txt").write_text("x\n")
    (r / "dir" / "sub").mkdir()
    (r / "dir" / "sub" / "y.txt").write_text("y\n")
    (tmp_path / "outside.txt").write_text("outside\n")
    return r


def _remote(root, write=False, extra=()):
    return T.build(root, {"remote", *extra}, allow_write=write)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# -- remote: gating and listing ---------------------------------------------------


def test_happy_remote_tools_without_write(root, saved):
    tools = _remote(root)
    assert {"remote_profiles", "remote_open", "remote_close", "list_backends"} <= set(tools)
    assert "write_file" not in tools
    assert tools["list_backends"].group == "remote"
    assert "backend" in tools["list_dir"].schema["properties"]
    assert "backend" not in tools["remote_profiles"].schema["properties"]


def test_happy_profiles_are_listed_without_secrets(root, saved):
    out = T.call(_remote(root), "remote_profiles", {})
    by_name = {p["name"]: p for p in out["profiles"]}
    assert set(by_name) == {"ram1", "ram2", "prod", "drive", "old-ftp", "az"}
    assert by_name["ram1"]["protocol"] == "ramfs" and by_name["ram1"]["openable"] is True
    assert by_name["drive"]["openable"] is False and "browser" in by_name["drive"]["reason"]
    assert by_name["prod"]["production"] is True
    text = json.dumps(out)
    assert SAS not in text and "sas" not in text.lower()
    allowed = {"name", "protocol", "host", "port", "username", "auth_type", "store_password",
               "production", "open_as", "openable", "reason"}
    assert all(set(p) <= allowed for p in out["profiles"])


def test_edge_no_profiles_file(root, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "PROFILES_FILE", tmp_path / "none.json")
    assert T.call(_remote(root), "remote_profiles", {}) == {"profiles": []}


# -- remote_open / addressing ------------------------------------------------------


def test_happy_open_and_address_a_profile(root, saved):
    tools = _remote(root, write=True)
    opened = T.call(tools, "remote_open", {"profile": "ram1"})
    bid = opened["backend"]
    assert bid == "profile:ram1" and opened["protocol"] == "ramfs" and opened["writable"] is True
    backends = {b["id"]: b for b in T.call(tools, "list_backends", {})}
    assert backends["local"]["is_default"] is True and backends["local"]["remote"] is False
    assert backends[bid]["remote"] is True and backends[bid]["profile"] == "ram1"
    # Remote paths are not confined to --mcp-root ...
    T.call(tools, "write_file", {"backend": bid, "path": "/note.txt", "content_b64": _b64(b"hi")})
    got = T.call(tools, "read_file", {"backend": bid, "path": "/note.txt"})
    assert base64.b64decode(got["content_b64"]) == b"hi"
    assert [e["name"] for e in T.call(tools, "list_dir", {"backend": bid, "path": "/"})] == ["note.txt"]
    # ... the local backend still is.
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "read_file", {"backend": "local", "path": str(root.parent / "outside.txt")})
    assert "escapes" in err.value.message


def test_edge_open_twice_reuses_the_backend(root, saved):
    tools = _remote(root)
    first = T.call(tools, "remote_open", {"profile": "ram1"})
    second = T.call(tools, "remote_open", {"profile": "ram1"})
    assert first["backend"] == second["backend"] and second["reused"] is True


def test_happy_close_forgets_the_backend(root, saved):
    tools = _remote(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    assert T.call(tools, "remote_close", {"backend": bid}) == {"backend": bid, "closed": True}
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "list_dir", {"backend": bid, "path": "/"})
    assert "unknown backend" in err.value.message
    with pytest.raises(T.RpcError):
        T.call(tools, "remote_close", {"backend": bid})


def test_sad_unknown_profile_and_bad_args(root, saved):
    tools = _remote(root)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "remote_open", {"profile": "nope"})
    assert "nope" in err.value.message
    for args in ({}, {"profile": ""}, {"profile": 1}, {"profile": "ram1", "url": "sftp://x"}):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "remote_open", args)
        assert err.value.code == M.ERR_INVALID_PARAMS


def test_sad_oauth_profile_is_refused_before_connecting(root, saved, monkeypatch):
    from core.connection_manager import ConnectionManager

    monkeypatch.setattr(ConnectionManager, "connect", lambda *a, **k: pytest.fail("connected"))
    with pytest.raises(T.RpcError) as err:
        T.call(_remote(root), "remote_open", {"profile": "drive"})
    assert "interactive" in err.value.message


def test_sad_paranoid_mode_refuses_legacy_protocols(root, saved):
    security_mode.set_policy("paranoid")
    try:
        with pytest.raises(T.RpcError) as err:
            T.call(_remote(root), "remote_open", {"profile": "old-ftp"})
        assert "paranoid" in err.value.message
    finally:
        security_mode.set_policy("normal")


def test_sad_a_profile_that_opens_the_local_disk_is_refused(root, saved, monkeypatch):
    from core.connection_manager import ConnectionManager

    monkeypatch.setattr(ConnectionManager, "connect", lambda self, *a, **k: LocalFS())
    with pytest.raises(T.RpcError) as err:
        T.call(_remote(root), "remote_open", {"profile": "ram1"})
    assert "--mcp-root" in err.value.message
    assert [b["id"] for b in T.call(_remote(root), "list_backends", {})] == ["local"]


def test_sad_production_profile_is_read_only_over_mcp(root, saved, caplog):
    T.capture_audit(caplog)
    tools = _remote(root, write=True)
    opened = T.call(tools, "remote_open", {"profile": "prod"})
    assert opened["production"] is True and opened["writable"] is False
    assert T.call(tools, "list_dir", {"backend": opened["backend"], "path": "/"}) == []
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "mkdir", {"backend": opened["backend"], "path": "/x"})
    assert "production" in err.value.message
    assert any("tool=mkdir outcome=refused" in ln for ln in T.audit_lines(caplog))


def test_edge_backends_are_scoped_per_http_session(root, saved):
    tools = _remote(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"}, session_id="A")["backend"]
    T.call(tools, "list_dir", {"backend": bid, "path": "/"}, session_id="A")
    with pytest.raises(T.RpcError):
        T.call(tools, "list_dir", {"backend": bid, "path": "/"}, session_id="B")
    assert [b["id"] for b in T.call(tools, "list_backends", {}, session_id="B")] == ["local"]


def test_edge_open_backend_cap(root, saved, monkeypatch):
    from core import mcp_groups

    monkeypatch.setattr(mcp_groups, "MAX_REMOTE_BACKENDS", 1)
    tools = _remote(root)
    T.call(tools, "remote_open", {"profile": "ram1"})
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "remote_open", {"profile": "ram2"})
    assert "remote_close" in err.value.message


def test_sad_archive_tools_refuse_a_remote_backend(root, saved):
    tools = _remote(root, write=True, extra=("archive",))
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "archive_list", {"backend": bid, "path": "/x.zip"})
    assert "local backend" in err.value.message


# -- SFTP: credentials from the keyring, never a prompt ----------------------------


@pytest.fixture
def sftp(tmp_path, monkeypatch, saved):
    pytest.importorskip("paramiko")
    from tests.sftp_testkit import SftpServer, _host_key

    served = tmp_path / "served"
    served.mkdir()
    (served / "remote.txt").write_text("over sftp\n")
    server = SftpServer(str(served))
    path, profiles = saved
    profile = ConnectionProfile(
        name="sftp1", protocol="sftp", host="127.0.0.1", port=server.port, username="u",
        auth_type="password", store_password=True,
    ).to_dict()
    nopw = dict(profile, name="sftp-nopw", store_password=False)
    _write_profiles(path, [*profiles, profile, nopw])
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    try:
        yield server, home, _host_key()
    finally:
        server.close()


def _trust(home, server, key) -> None:
    line = f"[127.0.0.1]:{server.port} {key.get_name()} {key.get_base64()}\n"
    (home / ".ssh" / "known_hosts").write_text(line)


def test_sad_sftp_without_a_stored_password_fails_clearly(root, sftp):
    server, home, key = sftp
    _trust(home, server, key)
    with pytest.raises(T.RpcError) as err:
        T.call(_remote(root), "remote_open", {"profile": "sftp-nopw"})
    assert "password" in err.value.message and "GUI" in err.value.message


def test_sad_sftp_unknown_host_key_is_refused_not_prompted(root, sftp, monkeypatch):
    monkeypatch.setattr(ConnectionProfile, "get_password", lambda self: PW)
    with pytest.raises(T.RpcError) as err:
        T.call(_remote(root), "remote_open", {"profile": "sftp1"})
    assert "host key" in err.value.message and PW not in err.value.message
    assert not (sftp[1] / ".ssh" / "known_hosts").exists()  # nothing was trusted


def test_happy_sftp_with_keyring_password_and_known_host(root, sftp, monkeypatch, caplog):
    server, home, key = sftp
    _trust(home, server, key)
    monkeypatch.setattr(ConnectionProfile, "get_password", lambda self: PW)
    T.capture_audit(caplog)
    tools = _remote(root)
    opened = T.call(tools, "remote_open", {"profile": "sftp1"})
    listing = T.call(tools, "list_dir", {"backend": opened["backend"], "path": "/"})
    assert [e["name"] for e in listing] == ["remote.txt"]
    assert PW not in json.dumps(opened) + json.dumps(listing)
    assert not any(PW in ln for ln in T.audit_lines(caplog))


# -- transfer -------------------------------------------------------------------


def _tr(root, write=True):
    return T.build(root, {"remote", "transfer"}, allow_write=write)


def test_happy_transfer_tools_only_with_write(root, saved):
    assert not {"transfer_copy", "transfer_move"} & set(_tr(root, write=False))
    tools = _tr(root)
    assert "backend" not in tools["transfer_copy"].schema["properties"]
    assert {"src_backend", "dst_backend"} <= set(tools["transfer_copy"].schema["properties"])


def test_happy_copy_a_file_to_a_remote_and_back(root, saved, caplog):
    T.capture_audit(caplog)
    tools = _tr(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    out = T.call(tools, "transfer_copy", {"src": str(root / "a.txt"), "dst_backend": bid, "dst": "/a.txt"})
    assert out["copied"] == 1 and out["entries"][0]["action"] == "copied"
    back = T.call(tools, "transfer_copy", {"src_backend": bid, "src": "/a.txt", "dst": str(root / "b.txt")})
    assert back["copied"] == 1
    assert (root / "b.txt").read_bytes() == b"alpha bytes\n"
    lines = T.audit_lines(caplog)
    assert any("tool=transfer_copy outcome=ok" in ln and "copied=1" in ln for ln in lines)


def test_happy_copy_a_tree_and_skip_existing(root, saved):
    tools = _tr(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    args = {"src": str(root / "dir"), "dst_backend": bid, "dst": "/dir"}
    first = T.call(tools, "transfer_copy", args)
    assert first["copied"] == 2
    names = {e["name"] for e in T.call(tools, "walk", {"backend": bid, "path": "/dir"})["entries"]}
    assert names == {"x.txt", "sub", "y.txt"}
    again = T.call(tools, "transfer_copy", args)
    assert again["copied"] == 0 and {e["reason"] for e in again["entries"]} == {"exists"}
    forced = T.call(tools, "transfer_copy", {**args, "overwrite": True})
    assert forced["copied"] == 2


def test_edge_tree_copy_caps_files(root, saved):
    tools = _tr(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    out = T.call(tools, "transfer_copy", {"src": str(root / "dir"), "dst_backend": bid, "dst": "/d", "max_files": 1})
    assert out["copied"] == 1 and out["truncated"] is True


def test_happy_move_from_remote_to_local(root, saved):
    tools = _tr(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    T.call(tools, "write_file", {"backend": bid, "path": "/m.txt", "content_b64": _b64(b"moved")})
    out = T.call(tools, "transfer_move", {"src_backend": bid, "src": "/m.txt", "dst": str(root / "m.txt")})
    assert out["bytes"] == 5
    assert (root / "m.txt").read_bytes() == b"moved"
    assert T.call(tools, "list_dir", {"backend": bid, "path": "/"}) == []


def test_sad_transfer_confinement_and_refusals(root, saved):
    tools = _tr(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"})["backend"]
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "transfer_copy", {"src": str(root.parent / "outside.txt"), "dst_backend": bid, "dst": "/o"})
    assert "escapes" in err.value.message
    T.call(tools, "write_file", {"backend": bid, "path": "/r.txt", "content_b64": _b64(b"r")})
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "transfer_copy", {"src_backend": bid, "src": "/r.txt", "dst": str(root.parent / "planted.txt")})
    assert "escapes" in err.value.message
    assert not (root.parent / "planted.txt").exists()
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "transfer_copy", {"src": str(root / "a.txt"), "dst_backend": "profile:nope", "dst": "/a"})
    assert "unknown backend" in err.value.message
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "transfer_move", {"src": str(root / "dir"), "dst_backend": bid, "dst": "/dir"})
    assert "file" in err.value.message
    assert (root / "dir").is_dir()
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "transfer_copy", {"src": str(root / "a.txt"), "dst": str(root)})
    assert "root" in err.value.message


def test_sad_transfer_to_a_production_profile(root, saved):
    tools = _tr(root)
    bid = T.call(tools, "remote_open", {"profile": "prod"})["backend"]
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "transfer_copy", {"src": str(root / "a.txt"), "dst_backend": bid, "dst": "/a"})
    assert "production" in err.value.message


class _CancelAfter(threading.Event):
    """An event that reads as set from the *n*-th is_set() call on."""

    def __init__(self, n: int) -> None:
        super().__init__()
        self.calls = 0
        self.n = n

    def is_set(self) -> bool:
        self.calls += 1
        return self.calls >= self.n or super().is_set()


def test_happy_resumable_copy_resumes_after_a_cancel(root, saved):
    big = os.urandom(9 * 1024 * 1024)  # three 4 MiB segments
    (root / "big.bin").write_bytes(big)
    tools = _tr(root)
    args = {"src": str(root / "big.bin"), "dst": str(root / "copy.bin"), "resumable": True}
    with pytest.raises(M.CancelledError):
        T.run_handler(tools, "transfer_copy", args, cancel=_CancelAfter(4))
    assert 0 < (root / "copy.bin").stat().st_size < len(big)
    out = T.call(tools, "transfer_copy", args)
    entry = out["entries"][0]
    assert entry["action"] == "copied" and entry["resumed_segments"] >= 1
    assert (root / "copy.bin").read_bytes() == big


# -- an ended HTTP session closes its connections -------------------------------------


def test_happy_ending_a_session_closes_its_profiles(root, saved):
    from core import mcp_groups

    tools = _remote(root)
    bid = T.call(tools, "remote_open", {"profile": "ram1"}, session_id="S1")["backend"]
    T.call(tools, "remote_open", {"profile": "ram2"}, session_id="S2")
    assert mcp_groups.RemoteRegistry.close_session("S1") == 1
    with pytest.raises(T.RpcError):
        T.call(tools, "list_dir", {"backend": bid, "path": "/"}, session_id="S1")
    assert [b["id"] for b in T.call(tools, "list_backends", {}, session_id="S2")][-1] == "profile:ram2"


def test_edge_closing_an_unknown_session_is_a_no_op(root, saved):
    from core import mcp_groups

    _remote(root)
    assert mcp_groups.RemoteRegistry.close_session("never-opened") == 0


@pytest.mark.parametrize("how", ["drop", "evict"])
def test_happy_http_session_end_releases_remote_backends(how, monkeypatch):
    from core import mcp_groups
    from core import mcp_http

    ended: list[str] = []
    monkeypatch.setattr(
        mcp_groups.RemoteRegistry, "close_session", staticmethod(lambda sid: ended.append(sid) or 0)
    )
    sessions = mcp_http._SessionRegistry(idle_seconds=0.0 if how == "evict" else 60.0)
    sess = sessions.create()
    if how == "drop":
        assert sessions.drop(sess.session_id) is True
    else:
        assert sessions.evict_idle() == [sess.session_id]
    assert ended == [sess.session_id]
