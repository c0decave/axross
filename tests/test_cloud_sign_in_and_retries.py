"""OneDrive, Dropbox and Google Drive once the sign-in is gone, and four
retries that reported the wrong thing.

Before:

* OneDrive: when the refresh token was revoked or had expired, every
  Graph request - from whichever thread made it: the health check, a
  transfer, the MCP server - fell back to the browser login, opened a
  browser tab per request and waited for it without any limit; MSAL's own
  token requests had no time-out either. The retry after a 401 sent the
  same cached token Graph had just refused.
* An expired or revoked sign-in read "Permission denied ... ask its owner
  for access" (OneDrive, Dropbox) or as raw ``invalid_grant`` text with
  EIO (Google Drive) - nothing said to sign in again.
* Dropbox ``name`` asked the server for the account on every read - the
  file pane reads it for every row it paints - and turned into "Dropbox"
  when that call failed, which moved the pane's tags to another key.
* A Dropbox connect that met a 5xx or a 429 raised the SDK's own error.
* A Dropbox mkdir or copy that worked but was answered with a 5xx was
  retried and reported as "already exists".
* One 503 on OneDrive's createUploadSession failed a large upload.
* Google Drive: listings iterated the path cache while another thread
  filled it ("dictionary changed size during iteration"); share_revoke
  let the raw HttpError out.
* OneDrive refused names with ``: * ? " < > | \\`` with Graph's raw JSON.
"""

from __future__ import annotations

import errno
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fake_dropbox as FD  # noqa: E402
import fake_gdrive as FG  # noqa: E402
import fake_onedrive as FO  # noqa: E402
from core import cloud_http, user_errors  # noqa: E402


@pytest.fixture(autouse=True)
def _no_pauses(monkeypatch):
    monkeypatch.setattr(cloud_http, "_sleep", lambda _s: None)


# ------------------------------------------------------------------ OneDrive


class _RevokedApp:
    """msal.PublicClientApplication whose refresh token was revoked:
    acquire_token_silent answers None."""

    def __init__(self, token=None):
        self.token = token
        self.interactive = []
        self.silent = []

    def get_accounts(self):
        return [{"username": "u"}]

    def acquire_token_silent(self, scopes, account, **kw):
        self.silent.append(kw)
        return {"access_token": self.token} if self.token else None

    def acquire_token_interactive(self, **kw):
        self.interactive.append(threading.current_thread().name)
        return None


class _Cache:
    has_state_changed = False


def _onedrive(graph=None, app=None):
    s = FO.make_session(graph)
    for stub in ("_ensure_token", "_acquire_token", "_refresh_token"):
        del s.__dict__[stub]  # the real token code
    s._app = app or _RevokedApp()
    s._cache = _Cache()
    s._scopes = ["Files.ReadWrite.All"]
    s._proxies = {}
    s._token_file = "/nonexistent"
    return s


def test_sad_the_health_check_never_opens_the_browser_login(monkeypatch):
    import core.onedrive_client as OD

    monkeypatch.setattr(OD, "install_clean_webbrowser", lambda: None)
    s = _onedrive()
    seen = []
    t = threading.Thread(target=lambda: seen.append(s.connected), name="conn-health")
    t.start()
    t.join()
    assert seen == [False]
    assert s._app.interactive == []


def test_sad_a_revoked_sign_in_says_sign_in_again(monkeypatch):
    import core.onedrive_client as OD

    monkeypatch.setattr(OD, "install_clean_webbrowser", lambda: None)
    s = _onedrive()
    with pytest.raises(PermissionError) as info:
        s.list_dir("/")
    assert s._app.interactive == []
    text = user_errors.describe(info.value, "/")
    assert "sign-in to OneDrive expired or was revoked" in text and "owner" not in text


def test_happy_a_401_is_retried_with_a_fresh_token_not_the_cached_one():
    graph = FO.FakeGraph()
    sent = []
    real_get = graph.get

    def get(url, headers=None, **kw):
        sent.append(headers.get("Authorization"))
        if len(sent) == 1:
            return FO.Resp(401, {"error": {"code": "InvalidAuthenticationToken"}})
        return real_get(url, headers=headers, **kw)

    graph.get = get
    app = _RevokedApp(token="FRESH")
    s = _onedrive(graph, app)
    s._access_token = "STALE"
    s._ensure_token = lambda: None
    s.list_dir("/")
    assert sent == ["Bearer STALE", "Bearer FRESH"]
    assert app.silent[-1].get("force_refresh") is True


def test_sad_a_second_401_is_the_sign_in_not_a_missing_right():
    graph = FO.FakeGraph()
    graph.get = lambda url, headers=None, **kw: FO.Resp(401, {"error": {"code": "x"}})
    s = _onedrive(graph, _RevokedApp(token="T"))
    with pytest.raises(cloud_http.CloudSignInExpired):
        s.stat("/a")


def test_happy_msal_and_the_browser_login_have_time_outs(monkeypatch, tmp_path):
    import core.onedrive_client as OD

    built = {}

    class App(_RevokedApp):
        def __init__(self, client_id, **kw):
            super().__init__()
            built.update(kw)

        def get_accounts(self):
            return []

        def acquire_token_interactive(self, **kw):
            built["interactive"] = kw
            return {"access_token": "T"}

    monkeypatch.setattr(OD.msal, "PublicClientApplication", App)
    monkeypatch.setattr(OD, "install_clean_webbrowser", lambda: None)
    OD.OneDriveSession(client_id="cid", token_file=str(tmp_path / "tok.json"))
    assert built["timeout"] == OD.GRAPH_TIMEOUT
    assert built["interactive"]["timeout"] == OD.INTERACTIVE_LOGIN_TIMEOUT


def test_happy_one_503_on_create_upload_session_is_retried(monkeypatch):
    graph = FO.FakeGraph()
    real_post = graph.post
    calls = []

    def post(url, headers=None, **kw):
        calls.append(url)
        if url.endswith("createUploadSession") and len(
                [c for c in calls if c.endswith("createUploadSession")]) == 1:
            return FO.Resp(503, {"error": {"code": "serviceNotAvailable"}})
        return real_post(url, headers=headers, **kw)

    graph.post = post
    s = FO.make_session(graph)
    import io

    s._upload_in_session("/big.bin", io.BytesIO(b"x" * 1000), 1000)
    assert len([c for c in calls if c.endswith("createUploadSession")]) == 2


@pytest.mark.parametrize("name", ["a:b.txt", "what?.txt", "pipe|x", 'q"uote', "back\\slash"])
def test_sad_a_name_onedrive_refuses_is_said_in_words(name):
    graph = FO.FakeGraph()
    s = FO.make_session(graph)
    with pytest.raises(OSError) as info:
        s.mkdir("/" + name)
    assert info.value.errno == errno.EINVAL
    assert "OneDrive" in user_errors.describe(info.value)
    assert "Graph API" not in user_errors.describe(info.value)


# ------------------------------------------------------------------ Dropbox


class _Acct:
    class name:  # noqa: N801 - the SDK's shape
        display_name = "Alice"


def test_happy_the_dropbox_name_is_read_once_not_per_paint():
    fake = FD.FakeDropbox()
    calls = []

    def account():
        calls.append(1)
        if len(calls) > 1:
            raise ConnectionError("network down")
        return _Acct()

    fake.users_get_current_account = account
    s = FD.make_session(fake)
    s._display_name = s._account_display_name()
    names = {s.name for _ in range(20)}
    assert names == {"Alice (Dropbox)"}
    assert len(calls) == 1


def test_sad_a_revoked_dropbox_token_says_sign_in_again():
    from dropbox.auth import AuthError as AuthErrorUnion
    from dropbox.exceptions import AuthError

    fake = FD.FakeDropbox()

    def boom(*a, **k):
        raise AuthError("rid", AuthErrorUnion.invalid_access_token)

    fake.files_list_folder = boom
    s = FD.make_session(fake)
    with pytest.raises(PermissionError) as info:
        s.list_dir("/docs")
    text = user_errors.describe(info.value, "/docs")
    assert "sign-in to Dropbox" in text and "owner" not in text


def test_sad_a_dropbox_connect_that_meets_a_5xx_is_an_oserror(monkeypatch, tmp_path):
    from dropbox.exceptions import InternalServerError

    import core.dropbox_client as DC

    def failing_auth(self):
        raise InternalServerError("rid", 503, "<html>upstream</html>")

    monkeypatch.setattr(DC.DropboxSession, "_authenticate", failing_auth)
    with pytest.raises(OSError) as info:
        DC.DropboxSession(app_key="k", token_file=str(tmp_path / "t.json"))
    assert info.value.errno in (errno.EAGAIN, errno.EIO)
    assert "InternalServerError(" not in user_errors.describe(info.value)


def _done_then_5xx(monkeypatch, fake, route):
    from dropbox.exceptions import InternalServerError

    real = getattr(fake, route)
    state = {"first": True}

    def flaky(*a, **k):
        result = real(*a, **k)
        if state["first"]:
            state["first"] = False
            raise InternalServerError("rid", 503, "Service Unavailable")
        return result

    monkeypatch.setattr(fake, route, flaky)


def test_happy_a_mkdir_done_by_the_try_a_5xx_answered_is_done(monkeypatch):
    fake = FD.FakeDropbox()
    s = FD.make_session(fake)
    _done_then_5xx(monkeypatch, fake, "files_create_folder_v2")
    s.mkdir("/newdir")
    assert s.is_dir("/newdir")


def test_happy_a_copy_done_by_the_try_a_5xx_answered_is_done(monkeypatch):
    fake = FD.FakeDropbox()
    s = FD.make_session(fake)
    with s.open_write("/a.txt") as fh:
        fh.write(b"data")
    _done_then_5xx(monkeypatch, fake, "files_copy_v2")
    s.copy("/a.txt", "/b.txt")
    with s.open_read("/b.txt") as fh:
        assert fh.read() == b"data"


def test_sad_a_mkdir_onto_a_file_after_a_5xx_still_says_exists(monkeypatch):
    fake = FD.FakeDropbox()
    s = FD.make_session(fake)
    with s.open_write("/taken") as fh:
        fh.write(b"x")
    from dropbox.exceptions import InternalServerError

    real = fake.files_create_folder_v2
    state = {"first": True}

    def flaky(*a, **k):
        if state["first"]:
            state["first"] = False
            raise InternalServerError("rid", 503, "Service Unavailable")
        return real(*a, **k)

    monkeypatch.setattr(fake, "files_create_folder_v2", flaky)
    with pytest.raises(FileExistsError):
        s.mkdir("/taken")


def test_happy_a_long_dropbox_folder_pages_more_than_twice(monkeypatch):
    monkeypatch.setattr(FD, "PAGE", 2)
    fake = FD.FakeDropbox()
    s = FD.make_session(fake)
    for n in range(7):
        with s.open_write(f"/f{n}") as fh:
            fh.write(b"x")
    assert sorted(i.name for i in s.list_dir("/")) == [f"f{n}" for n in range(7)]


# ------------------------------------------------------------------ Google Drive


def test_sad_a_revoked_google_sign_in_says_sign_in_again():
    from google.auth.exceptions import RefreshError

    drive = FG.FakeDrive()

    def boom(*a, **k):
        raise RefreshError("invalid_grant: Token has been expired or revoked.",
                           {"error": "invalid_grant"})

    drive._list = boom
    s = FG.make_session(drive)
    with pytest.raises(PermissionError) as info:
        s.list_dir("/")
    assert "sign-in to Google Drive" in user_errors.describe(info.value, "/")


def test_sad_share_revoke_fails_as_an_oserror():
    from googleapiclient.errors import HttpError

    drive = FG.FakeDrive()
    s = FG.make_session(drive)
    with s.open_write("/doc.txt") as fh:
        fh.write(b"x")

    class Resp(dict):
        status = 404
        reason = "Not Found"

    class Perms:
        def delete(self, **kw):
            class Req:
                def execute(self, **kw):
                    raise HttpError(Resp(), b'{"error": {"message": "Permission not found"}}')

            return Req()

    drive.permissions = lambda: Perms()
    with pytest.raises(OSError):
        s.share_revoke("/doc.txt", "perm-1")

