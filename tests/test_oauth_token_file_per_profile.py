"""Every Google Drive / Dropbox / OneDrive profile keeps its own token file.

All profiles of a cloud protocol shared one token file
(``~/.config/axross/gdrive_token.json``, ``dropbox_token.json``,
``onedrive_token.json``): ConnectionManager passed no ``token_file``, so
a second profile - another OAuth client, another account - loaded the
first profile's token and opened the first account. Now the manager
hands each profile a file of its own, a token whose client id is not
the profile's is refused, and the legacy shared file is adopted (moved)
only when it belongs to the profile's client id.

No network: the OAuth flows, the SDK clients and MSAL are stubbed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.connection_manager import ConnectionManager
from core.profiles import ConnectionProfile

_FUTURE = "2099-01-01T00:00:00Z"


@pytest.fixture
def token_dir(tmp_path, monkeypatch):
    """HOME in tmp_path: the token files live in tmp_path/.config/axross."""
    monkeypatch.setenv("HOME", str(tmp_path))
    d = tmp_path / ".config" / "axross"
    d.mkdir(parents=True)
    return d


def _connect(profile: ConnectionProfile):
    return ConnectionManager()._create_session(profile, "", "", None)


def _own_files(token_dir: Path, stem: str) -> list[Path]:
    """The per-profile files ``<stem>.<name>-<hash>.json``, not the legacy one."""
    return sorted(
        p
        for p in token_dir.iterdir()
        if p.name.startswith(stem + ".") and p.name != stem + ".json"
    )


# ---------------------------------------------------------------------------
# Google Drive
# ---------------------------------------------------------------------------


def _gdrive_token(client_id: str, token: str) -> str:
    from core import gdrive_client as G

    return json.dumps(
        {
            "token": token,
            "refresh_token": "r-" + token,
            "client_id": client_id,
            "client_secret": "s",
            "token_uri": "https://oauth2.googleapis.com/token",
            "scopes": list(G._SCOPES),
            "expiry": _FUTURE,
        }
    )


@pytest.fixture
def gdrive(monkeypatch):
    pytest.importorskip("googleapiclient")
    from core import gdrive_client as G

    used: list[tuple[str, str]] = []
    flows: list[str] = []
    monkeypatch.setattr(
        G.GDriveSession,
        "_build_service",
        lambda self, creds: used.append((creds.client_id, creds.token)) or object(),
    )

    class _Flow:
        def __init__(self, client_id):
            self.client_id = client_id
            self.oauth2session = None

        def run_local_server(self, port=0):
            flows.append(self.client_id)
            return G.Credentials.from_authorized_user_info(
                json.loads(_gdrive_token(self.client_id, "fresh-" + self.client_id))
            )

    monkeypatch.setattr(
        G.InstalledAppFlow,
        "from_client_config",
        classmethod(lambda cls, cfg, scopes: _Flow(cfg["installed"]["client_id"])),
    )
    return used, flows


def _gprofile(name: str, client_id: str) -> ConnectionProfile:
    return ConnectionProfile(
        name=name, protocol="gdrive", gdrive_client_id=client_id, gdrive_client_secret="s"
    )


def test_sad_gdrive_second_profile_does_not_open_the_first_account(token_dir, gdrive):
    used, flows = gdrive
    legacy = token_dir / "gdrive_token.json"
    legacy.write_text(_gdrive_token("work-client", "ACCOUNT-A"))
    _connect(_gprofile("personal", "personal-client"))
    assert used == [("personal-client", "fresh-personal-client")]
    assert flows == ["personal-client"]
    # The other account's token stays where it was, untouched.
    assert json.loads(legacy.read_text())["token"] == "ACCOUNT-A"
    (own,) = _own_files(token_dir, "gdrive_token")
    assert json.loads(own.read_text())["client_id"] == "personal-client"


def test_happy_gdrive_legacy_token_of_the_same_client_is_adopted_once(token_dir, gdrive):
    used, flows = gdrive
    legacy = token_dir / "gdrive_token.json"
    legacy.write_text(_gdrive_token("work-client", "ACCOUNT-A"))
    _connect(_gprofile("work", "work-client"))
    assert used == [("work-client", "ACCOUNT-A")]
    assert flows == []
    assert not legacy.exists()
    (own,) = _own_files(token_dir, "gdrive_token")
    assert json.loads(own.read_text())["token"] == "ACCOUNT-A"
    assert oct(own.stat().st_mode & 0o777) == oct(0o600)
    # A second profile of the same client finds no legacy file any more.
    _connect(_gprofile("work2", "work-client"))
    assert flows == ["work-client"]
    # The first profile keeps its token across connects.
    _connect(_gprofile("work", "work-client"))
    assert used[-1] == ("work-client", "ACCOUNT-A")


def test_sad_gdrive_own_token_of_another_client_id_is_refused(token_dir, gdrive):
    used, flows = gdrive
    _connect(_gprofile("p", "client-1"))
    (own,) = _own_files(token_dir, "gdrive_token")
    # The profile now names another OAuth client: its old token is not used.
    _connect(_gprofile("p", "client-2"))
    assert used[-1] == ("client-2", "fresh-client-2")
    assert flows == ["client-1", "client-2"]
    assert json.loads(own.read_text())["client_id"] == "client-2"


def test_edge_gdrive_names_that_look_alike_get_distinct_files(token_dir, gdrive):
    for name in ("a b", "a_b", "../evil", "ä"):
        _connect(_gprofile(name, "c-" + name))
    files = _own_files(token_dir, "gdrive_token")
    assert len(files) == 4
    assert all(f.parent == token_dir for f in files)
    assert not (token_dir.parent / "evil").exists()


# ---------------------------------------------------------------------------
# Dropbox
# ---------------------------------------------------------------------------


@pytest.fixture
def dropbox_stub(monkeypatch):
    pytest.importorskip("dropbox")
    from core import dropbox_client as D

    built: list[dict] = []
    flows: list[str] = []

    class _Dbx:
        def __init__(self, **kw):
            built.append(kw)

        def users_get_current_account(self):
            return None

    monkeypatch.setattr(D.dropbox, "Dropbox", _Dbx)
    monkeypatch.setattr(D.DropboxSession, "_apply_session_overrides", lambda self, dbx: None)

    def flow(self):
        flows.append(self._app_key)
        self._save_tokens("fresh-" + self._app_key, "rfresh-" + self._app_key)
        self._dbx = _Dbx(oauth2_access_token="fresh-" + self._app_key)

    monkeypatch.setattr(D.DropboxSession, "_run_oauth_flow", flow)
    return built, flows


def _dprofile(name: str, app_key: str) -> ConnectionProfile:
    return ConnectionProfile(
        name=name, protocol="dropbox", dropbox_app_key=app_key, dropbox_app_secret=""
    )


def test_sad_dropbox_legacy_token_without_app_key_is_not_used(token_dir, dropbox_stub):
    built, flows = dropbox_stub
    legacy = token_dir / "dropbox_token.json"
    legacy.write_text(json.dumps({"access_token": "ACCOUNT-A", "refresh_token": "RA"}))
    _connect(_dprofile("personal", "app-B"))
    assert flows == ["app-B"]
    assert all(kw.get("oauth2_access_token") != "ACCOUNT-A" for kw in built)
    assert json.loads(legacy.read_text())["access_token"] == "ACCOUNT-A"


def test_happy_dropbox_own_token_is_reused_and_carries_the_app_key(token_dir, dropbox_stub):
    built, flows = dropbox_stub
    _connect(_dprofile("p", "app-A"))
    (own,) = _own_files(token_dir, "dropbox_token")
    assert json.loads(own.read_text())["app_key"] == "app-A"
    _connect(_dprofile("p", "app-A"))
    assert flows == ["app-A"]
    assert built[-1]["oauth2_refresh_token"] == "rfresh-app-A"


def test_edge_dropbox_legacy_token_of_the_same_app_is_adopted(token_dir, dropbox_stub):
    built, flows = dropbox_stub
    legacy = token_dir / "dropbox_token.json"
    legacy.write_text(
        json.dumps({"access_token": "A", "refresh_token": "RA", "app_key": "app-A"})
    )
    _connect(_dprofile("work", "app-A"))
    assert flows == []
    assert built[-1]["oauth2_refresh_token"] == "RA"
    assert not legacy.exists()
    # Another app key with its own file: the token of app-A is refused.
    (own,) = _own_files(token_dir, "dropbox_token")
    _connect(_dprofile("work", "app-Z"))
    assert flows == ["app-Z"]
    assert json.loads(own.read_text())["app_key"] == "app-Z"


# ---------------------------------------------------------------------------
# OneDrive (MSAL keys every token by client id; the cache file is per profile)
# ---------------------------------------------------------------------------


@pytest.fixture
def msal_stub(monkeypatch):
    pytest.importorskip("msal")
    from core import onedrive_client as O

    seen: list[tuple[str, str]] = []

    class _App:
        def __init__(self, client_id, authority=None, token_cache=None, proxies=None):
            self.client_id, self.cache = client_id, token_cache
            seen.append((client_id, token_cache.serialize()))

        def get_accounts(self):
            return []

        def acquire_token_interactive(self, scopes, redirect_uri=None):
            self.cache.deserialize(json.dumps(_msal_cache(self.client_id)))
            self.cache.has_state_changed = True
            return {"access_token": "t-" + self.client_id}

    monkeypatch.setattr(O.msal, "PublicClientApplication", _App)
    return seen


def _msal_cache(client_id: str) -> dict:
    return {
        "RefreshToken": {
            "k": {"credential_type": "RefreshToken", "client_id": client_id, "secret": "x"}
        }
    }


def _oprofile(name: str, client_id: str) -> ConnectionProfile:
    return ConnectionProfile(name=name, protocol="onedrive", onedrive_client_id=client_id)


def test_sad_onedrive_second_profile_starts_with_an_empty_cache(token_dir, msal_stub):
    legacy = token_dir / "onedrive_token.json"
    legacy.write_text(json.dumps(_msal_cache("client-A")))
    _connect(_oprofile("personal", "client-B"))
    client_id, cache = msal_stub[-1]
    assert client_id == "client-B"
    assert "client-A" not in cache
    assert legacy.exists()


def test_happy_onedrive_legacy_cache_of_the_same_client_is_adopted(token_dir, msal_stub):
    legacy = token_dir / "onedrive_token.json"
    legacy.write_text(json.dumps(_msal_cache("client-A")))
    _connect(_oprofile("work", "client-A"))
    assert "client-A" in msal_stub[-1][1]
    assert not legacy.exists()
    (own,) = _own_files(token_dir, "onedrive_token")
    assert "client-A" in own.read_text()


def test_edge_onedrive_unreadable_legacy_cache_is_left_alone(token_dir, msal_stub):
    legacy = token_dir / "onedrive_token.json"
    legacy.write_text("{not json")
    _connect(_oprofile("work", "client-A"))
    assert legacy.read_text() == "{not json"
    assert msal_stub[-1][1] in ("{}", "")
    (own,) = _own_files(token_dir, "onedrive_token")
    assert "client-A" in own.read_text()
