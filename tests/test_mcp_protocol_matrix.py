"""The MCP server reaches every protocol axross registers.

Two routes exist, and every registered protocol takes exactly one:

* **Saved profile** (``core.profiles.VALID_PROTOCOLS``): ``remote_open``
  connects it through the GUI's ConnectionManager and every file tool
  addresses it as ``profile:<name>``. The four browser sign-in protocols
  are refused with that reason, the legacy ones in the paranoid mode.
* **URL only** (no connection dialog, so no saved profile can name them):
  the script tools (``--mcp-allow-scripts``) open them with
  ``axross.open_url``.

The backend classes are replaced by a RAM-backed fake that records how it
was built, so the matrix runs offline and shows the whole MCP path:
profile -> keyring password -> ConnectionManager branch -> backend ->
file tools. The live lab run proves the real backends behind it.
"""

from __future__ import annotations

import base64
import json

import pytest

from core import backend_registry as R
from core import connection_manager as CM
from core import credentials
from core import mcp_groups
from core import profiles as P
from core import security_mode
from core.profiles import VALID_PROTOCOLS, ConnectionProfile, password_needed
from core.ram_fs import RamFsSession
from tests import mcp_group_testkit as T

#: Registered protocols without a saved profile; reached over MCP only by
#: the script tools' axross.open_url. Each with a URL that names it.
URL_ONLY = {
    "exchange": "exchange://mail.example.test",
    "git": "git+https://git.example.test/repo.git",
    "ldap": "ldap://ldap.example.test",
    "mongodb": "mongodb://db.example.test",
    "postgres": "postgres://db.example.test/vault",
    "redis": "redis://cache.example.test",
    "rsh": "rsh://host.example.test",
    "slp": "slp://directory.example.test",
    "sqlite": "sqlite:////nonexistent/vault.db",
    "wmi": "wmi://win.example.test",
}


def _registered() -> set[str]:
    return {b.protocol_id for b in R.all_backends()}


class _Fake(RamFsSession):
    """Stands in for every backend class: a working RAM file system that
    remembers how the ConnectionManager built and connected it."""

    made: list = []

    def __init__(self, *args, **kwargs):
        super().__init__(label="fake")
        self.init_args, self.init_kwargs = args, kwargs
        self.connect_kwargs: dict = {}
        _Fake.made.append(self)

    def connect(self, *args, **kwargs):
        self.connect_kwargs = kwargs


@pytest.fixture
def fake_backends(monkeypatch, tmp_path):
    _Fake.made = []
    monkeypatch.setattr(CM, "load_backend_class", lambda proto: _Fake)
    monkeypatch.setattr(CM, "_session_class", lambda name: _Fake)
    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)
    monkeypatch.setattr(ConnectionProfile, "get_password", lambda self: f"pw-{self.protocol}")
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    profiles = {
        f"p-{proto}": ConnectionProfile(
            name=f"p-{proto}", protocol=proto, host="203.0.113.5", username="user",
            store_password=True,
        ).to_dict()
        for proto in VALID_PROTOCOLS
    }
    path.write_text(json.dumps(profiles))
    root = tmp_path / "root"
    root.mkdir()
    yield T.build(root, {"remote"}, allow_write=True)
    for registry in list(mcp_groups.RemoteRegistry._live):
        registry.close_all()


def _round_trip(tools, bid: str) -> bytes:
    data = base64.b64encode(b"over mcp\n").decode()
    T.call(tools, "write_file", {"backend": bid, "path": "/matrix.txt", "content_b64": data})
    names = [e["name"] for e in T.call(tools, "list_dir", {"backend": bid, "path": "/"})]
    assert "matrix.txt" in names
    got = T.call(tools, "read_file", {"backend": bid, "path": "/matrix.txt"})
    return base64.b64decode(got["content_b64"]) if isinstance(got, dict) else got


# --- the two routes cover the registry ----------------------------------------


def test_edge_every_registered_protocol_has_exactly_one_route():
    registered = _registered()
    assert VALID_PROTOCOLS <= registered
    assert set(URL_ONLY) <= registered
    assert not VALID_PROTOCOLS & set(URL_ONLY)
    assert registered == VALID_PROTOCOLS | set(URL_ONLY), (
        "a new protocol needs a route: a saved profile, or an entry in URL_ONLY"
    )


def test_edge_every_profile_protocol_has_a_connection_branch(fake_backends):
    # Without a branch, ConnectionManager raises "Unsupported protocol".
    manager = CM.ConnectionManager()
    for proto in sorted(VALID_PROTOCOLS):
        profile = ConnectionProfile(name=f"b-{proto}", protocol=proto, host="203.0.113.5")
        session = manager._create_session(profile, "pw", "", None)
        assert isinstance(session, _Fake), proto


# --- route 1: saved profiles ----------------------------------------------------


@pytest.mark.parametrize("proto", sorted(VALID_PROTOCOLS - mcp_groups.INTERACTIVE_PROTOCOLS))
def test_happy_remote_open_reaches_the_protocol(fake_backends, proto):
    tools = fake_backends
    opened = T.call(tools, "remote_open", {"profile": f"p-{proto}"})
    bid = opened["backend"]
    assert bid == f"profile:p-{proto}" and opened["protocol"] == proto
    backend = _Fake.made[-1]
    profile = P.ProfileManager().get(f"p-{proto}")
    if password_needed(profile):
        handed = {**backend.init_kwargs, **backend.connect_kwargs}
        assert f"pw-{proto}" in handed.values(), f"{proto}: the stored password never arrived"
    assert _round_trip(tools, bid) == b"over mcp\n"


@pytest.mark.parametrize("proto", sorted(mcp_groups.INTERACTIVE_PROTOCOLS))
def test_sad_browser_sign_in_protocols_are_refused_with_the_reason(fake_backends, proto):
    with pytest.raises(T.RpcError) as info:
        T.call(fake_backends, "remote_open", {"profile": f"p-{proto}"})
    assert "browser" in str(info.value) and _Fake.made == []


@pytest.mark.parametrize("proto", sorted(security_mode.LEGACY_PROTOCOLS & VALID_PROTOCOLS))
def test_sad_paranoid_mode_refuses_the_legacy_protocols(fake_backends, monkeypatch, proto):
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    with pytest.raises(T.RpcError) as info:
        T.call(fake_backends, "remote_open", {"profile": f"p-{proto}"})
    assert proto in str(info.value) and _Fake.made == []


def test_edge_remote_profiles_says_why_each_one_cannot_open(fake_backends):
    rows = {r["protocol"]: r for r in T.call(fake_backends, "remote_profiles", {})["profiles"]}
    assert set(rows) == VALID_PROTOCOLS
    for proto, row in rows.items():
        assert row["openable"] is (proto not in mcp_groups.INTERACTIVE_PROTOCOLS), proto
        assert bool(row["reason"]) is (not row["openable"]), proto


# --- route 2: URL only, through the script tools ----------------------------------


@pytest.mark.parametrize("proto", sorted(URL_ONLY))
def test_happy_open_url_reaches_the_url_only_protocol(monkeypatch, proto):
    from core import scripting

    monkeypatch.setattr(R, "load_backend_class", lambda p: _Fake)
    _Fake.made = []
    backend = scripting.open_url(URL_ONLY[proto], proxy_type="none")
    assert isinstance(backend, _Fake) and len(_Fake.made) == 1


def test_happy_the_script_tools_carry_open_url(tmp_path):
    from core import scripting

    tools = T.build(tmp_path, set(), allow_scripts=True)
    assert {"script_run", "script_write"} <= set(tools)
    assert callable(getattr(scripting, "open_url", None))
