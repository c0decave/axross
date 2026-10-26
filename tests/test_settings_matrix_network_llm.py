"""Every setting really works, part 2: Network & Proxy beyond the proxy
type, and every field of an LLM profile.

Operator: *„alle bereiche der tools plus neue matrix tests auch bei den
einstellungen. wir brauchen eine saubere abdeckung aller hauptfeatures.“*
The rows run the four steps of tests/test_settings_matrix.py (set through
the page's real widgets -> OK -> stored -> a fresh load shows it -> the
effect; the default again; Cancel writes nothing; a hand-edited value falls
back). The effects are real: a connection through a fake SOCKS5, HTTP or
HTTPS proxy, a PAC file deciding, a request of the agent to a recording
LLM server, a recording sent to its transcription endpoint.

``SECRETS`` are the password fields (the proxy password, an LLM API key):
typed, a secret goes to the keyring and is never shown again; left empty,
the stored one stays (check_secret).
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core import llm_profiles as LP
from core import proxy_settings as PS
from core.proxy import create_proxy_socket
from tests import test_settings_matrix as SMX
from tests.proxy_testkit import FakeSocks5Server, allow_loopback_proxy
from tests.test_settings_matrix import ctx  # noqa: F401 - the fixture of the matrix

APP = SMX.APP
Row, Secret = SMX.Row, SMX.Secret
TARGET = ("db.internal", 5432)
#: What hand-edited values read as when the whole entry is dropped.
MISSING = "<missing>"
#: The running test's context: shown() gets the dialog only, and the rows'
#: values name the test's server and files by markers (ROOT, CA, PAC).
_CURRENT: dict = {}


def _ctx():
    return _CURRENT["ctx"]


# ---------------------------------------------------------------------------
# Network & Proxy
# ---------------------------------------------------------------------------


def _write_proxy(ctx, **fields) -> None:
    data = SMX._read_json(ctx.stores.proxy) or {}
    data.update(fields)
    ctx.stores.proxy.write_text(json.dumps(data))
    PS._PAC_CACHE.clear()


def _edit_proxy(key):
    return lambda c, v: _write_proxy(c, **{key: v})


def _seed_socks(ctx, **extra) -> None:
    """The default proxy: the fake SOCKS5 of the matrix (no login)."""
    _write_proxy(ctx, proxy_type="socks5", host="127.0.0.1", port=ctx.socks.port, **extra)


def _resolve(host=TARGET[0], port=TARGET[1]):
    return PS.resolve("default", None, host, port).config


def _talk(cfg, port=None) -> bytes:
    """A connection to db.internal:5432 through *cfg* (on *port* when
    given): the echo server's banner."""
    import dataclasses

    if port is not None:
        cfg = dataclasses.replace(cfg, port=port)
    with allow_loopback_proxy():
        sock = create_proxy_socket(cfg, *TARGET, timeout=5)
    try:
        return sock.recv(3)
    finally:
        sock.close()


def _routes(ctx) -> dict:
    return {TARGET: ("127.0.0.1", ctx.echo.port)}


def _page(dialog):
    return dialog.page("network")


# -- authentication (HTTP / HTTPS proxies) ------------------------------------


def _seed_http_with_login(ctx) -> None:
    _write_proxy(ctx, proxy_type="http", host="127.0.0.1", port=ctx.socks.port, username="alice")


def set_auth(ctx, dialog, value) -> None:
    from ui.network_proxy_dialog import AUTH_CHOICES

    _page(dialog)._auth.setCurrentIndex([v for _l, v in AUTH_CHOICES].index(value))


def shown_auth(dialog) -> str:
    from ui.network_proxy_dialog import AUTH_CHOICES

    page = _page(dialog)
    return AUTH_CHOICES[page._auth.currentIndex()][1] if page._auth.isEnabled() else ""


def stored_auth(ctx) -> str:
    from core.proxy import parse_proxy_type

    kind = PS.load().proxy_type
    return "" if kind == "none" else parse_proxy_type(kind)[1]


def effect_auth(ctx, win, value) -> None:
    """The scheme the proxy asks for is the one the connection answers:
    Basic (also "automatic" with a username) or NTLM. A proxy type edited
    into something unknown is no proxy at all (core.proxy_settings)."""
    from tests.proxy_http_testkit import FakeHttpProxy

    cfg = _resolve()
    if PS.load().proxy_type == "none":
        assert value == "" and cfg is None
        return
    assert cfg.proxy_type == ("http+" + value if value else "http")
    PS.set_session_password("s3cret")
    cfg = _resolve()
    if value == "ntlm":  # the fake's NTLM store knows the user in its domain
        import dataclasses

        cfg = dataclasses.replace(cfg, username="DOM\\alice")
        ctx.monkeypatch.setenv("NTLM_USER_FILE", "")  # the fake points it at its store
    proxy = SMX.keep_open(ctx, FakeHttpProxy(_routes(ctx), auth=value if value == "ntlm"
                                             else "basic", users={"alice": "s3cret"}))
    assert _talk(cfg, proxy.port) == b"HI\n"
    assert proxy.legs[-1] == ("ntlm" if value == "ntlm" else "basic"), proxy.legs


# -- username / keyring choice ---------------------------------------------------


def effect_username(ctx, win, value) -> None:
    """With a username the SOCKS5 login carries it (and the password typed
    for this session); without one no login is offered."""
    cfg = _resolve()
    assert cfg.username == value
    if not value:
        assert _talk(cfg) == b"HI\n"
        return
    PS.set_session_password("pw")
    socks = SMX.keep_open(ctx, FakeSocks5Server(routes=_routes(ctx), username=value,
                                                password="pw"))
    assert _talk(_resolve(), socks.port) == b"HI\n"
    assert socks.auth_seen == [(value, "pw")]


def effect_store_password(ctx, win, value) -> None:
    """Which password a connection takes: the keyring's (Save password in
    keyring) or the one typed for this session."""
    ctx.stores.proxy_passwords["pw"] = "from-keyring"
    PS.set_session_password("from-session")
    assert _resolve().password == ("from-keyring" if value else "from-session")


# -- CA file of an HTTPS proxy -------------------------------------------------------


def _seed_https_proxy(ctx) -> None:
    from tests.proxy_http_testkit import FakeHttpProxy, TestPki

    pki = TestPki()
    ctx.extras["pki"] = pki
    ctx.extras["ca_file"] = pki.ca_file
    proxy = SMX.keep_open(ctx, FakeHttpProxy(_routes(ctx), tls=pki.issue("127.0.0.1")))
    _write_proxy(ctx, proxy_type="https", host="127.0.0.1", port=proxy.port)


def set_ca(ctx, dialog, value) -> None:
    _page(dialog)._ca_file.setText(ctx.extras["ca_file"] if value == "CA" else value)


def _as_ca(ctx, text: str) -> str:
    return "CA" if text and text == ctx.extras.get("ca_file") else text


def effect_ca(ctx, win, value) -> None:
    """The HTTPS proxy's certificate verifies against the CA file; without
    it the system store refuses the test CA."""
    cfg = _resolve()
    assert _as_ca(ctx, cfg.ca_file) == value
    if value:
        assert _talk(cfg) == b"HI\n"
    else:
        with pytest.raises((ConnectionError, OSError)):
            _talk(cfg)


# -- PAC script ---------------------------------------------------------------------


def _seed_pac(ctx) -> None:
    pac = ctx.tmp_path / "proxy.pac"
    pac.write_text(
        "function FindProxyForURL(url, host) {\n"
        f'  if (host == "{TARGET[0]}") return "SOCKS5 127.0.0.1:{ctx.socks.port}";\n'
        '  return "DIRECT";\n}\n'
    )
    ctx.extras["pac"] = str(pac)


def set_pac(ctx, dialog, value) -> None:
    _page(dialog)._pac.setText(ctx.extras["pac"] if value == "PAC" else value)


def _as_pac(ctx, text: str) -> str:
    return "PAC" if text and text == ctx.extras.get("pac") else text


def effect_pac(ctx, win, value) -> None:
    """The PAC file decides: db.internal through the SOCKS5 it names, any
    other host directly; without one there is no default proxy."""
    if not value:
        assert _resolve() is None and _resolve("other.example", 443) is None
        return
    cfg = _resolve()
    assert (cfg.proxy_type, cfg.host, cfg.port) == ("socks5", "127.0.0.1", ctx.socks.port)
    assert _talk(cfg) == b"HI\n"
    assert _resolve("other.example", 443) is None
    assert PS.resolve("default", None, "other.example", 443).source == "pac"


# -- bypass list ----------------------------------------------------------------------


def effect_bypass(ctx, win, value) -> None:
    """A host on the list connects directly, every other one through the proxy."""
    db_direct = value != list(PS.DEFAULT_BYPASS)  # both lists of the row name db.internal
    assert (_resolve() is None) is db_direct
    assert (_resolve("localhost", 22) is None) is (not db_direct)
    if not db_direct:
        assert _talk(_resolve()) == b"HI\n"


def _net_row(row_id, widget, values, default, set_ui, shown, stored, write_bad, bad, effect,
             setup, bad_effect=None):
    return Row(row_id, "network", f"proxy.json {row_id.removeprefix('proxy_')}", values,
               default, set_ui, shown, stored, write_bad, bad, effect,
               widgets=(f"network.{widget}",), setup=setup, bad_effect=bad_effect)


NETWORK_ROWS = [
    _net_row("proxy_auth", "_auth", ("ntlm", "basic"), "", set_auth, shown_auth, stored_auth,
             lambda c, v: _write_proxy(c, proxy_type=v), ("http+bogus", 5, None),
             effect_auth, _seed_http_with_login, bad_effect=SMX.refused_unknown_proxy_type),
    _net_row("proxy_username", "_username", ("alice",), "",
             lambda c, d, v: _page(d)._username.setText(v),
             lambda d: _page(d)._username.text(), lambda c: PS.load().username,
             _edit_proxy("username"), (5, None, ["alice"]), effect_username, _seed_socks),
    _net_row("proxy_store_password", "_store_pw", (True,), False,
             lambda c, d, v: _page(d)._store_pw.setChecked(v),
             lambda d: _page(d)._store_pw.isChecked(), lambda c: PS.load().store_password,
             _edit_proxy("store_password"), ("yes", 1, None), effect_store_password,
             lambda c: _seed_socks(c, username="alice")),
    _net_row("proxy_ca_file", "_ca_file", ("CA",), "", set_ca,
             lambda d: _as_ca(_ctx(), _page(d)._ca_file.text()),
             lambda c: _as_ca(c, PS.load().ca_file), _edit_proxy("ca_file"), (5, None, ["x"]),
             effect_ca, _seed_https_proxy),
    _net_row("proxy_pac_url", "_pac", ("PAC",), "", set_pac,
             lambda d: _as_pac(_ctx(), _page(d)._pac.text()),
             lambda c: _as_pac(c, PS.load().pac_url), _edit_proxy("pac_url"), (5, None),
             effect_pac, _seed_pac),
    _net_row("proxy_bypass", "_bypass", (["db.internal"], ["*.internal", "10.0.0.0/8"]),
             list(PS.DEFAULT_BYPASS),
             lambda c, d, v: _page(d)._bypass.setPlainText("\n".join(v)),
             lambda d: _page(d).collect().bypass, lambda c: PS.load().bypass,
             _edit_proxy("bypass"), ("db.internal", 5, None), effect_bypass, _seed_socks),
]


# ---------------------------------------------------------------------------
# LLM profiles
# ---------------------------------------------------------------------------


class RecordingLLM:
    """An LLM server over a real socket that records every request:
    ``/chat/completions`` (OpenAI), Ollama's ``/api/tags`` and ``/api/ps``,
    ``/models`` and ``/audio/transcriptions``."""

    def __init__(self, *, loaded=("model-a:latest", "model-b:latest")) -> None:
        self.requests: list[tuple[str, str, dict, bytes]] = []
        self.loaded = list(loaded)
        self.delay = 0.0
        #: Messages the next chat requests answer with (a tool call, ...);
        #: then "done".
        self.replies: list[dict] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _answer(self, method: str) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                fake.requests.append((method, self.path, {k.lower(): v for k, v in
                                                          self.headers.items()}, body))
                path = self.path.rstrip("/")
                if method == "POST" and path.endswith("/chat/completions"):
                    time.sleep(fake.delay)
                    message = (fake.replies.pop(0) if fake.replies
                               else {"role": "assistant", "content": "done"})
                    finish = "tool_calls" if message.get("tool_calls") else "stop"
                    data = {"id": "r1", "choices": [{"index": 0, "finish_reason": finish,
                                                     "message": message}]}
                elif method == "POST" and path.endswith("/audio/transcriptions"):
                    data = {"text": "heard on the server"}
                elif path.endswith("/api/tags"):
                    data = {"models": [{"name": "model-a", "model": "model-a"}]}
                elif path.endswith("/api/ps"):
                    data = {"models": [{"name": n, "model": n} for n in fake.loaded]}
                elif path.endswith("/models"):
                    data = {"data": [{"id": "model-a"}]}
                else:
                    data = None
                raw = json.dumps(data or {"error": "no such endpoint"}).encode()
                self.send_response(200 if data is not None else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass  # the client gave up (its timeout)

            def do_GET(self):  # noqa: N802
                self._answer("GET")

            def do_POST(self):  # noqa: N802
                self._answer("POST")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def paths(self, method: str, suffix: str = "") -> list[str]:
        return [p for m, p, _h, _b in self.requests if m == method and p.endswith(suffix)]

    def chats(self) -> list[dict]:
        return [json.loads(b) for m, p, _h, b in self.requests
                if m == "POST" and p.endswith("/chat/completions")]

    def last_chat(self) -> dict:
        return self.chats()[-1]


def _seed_llm(ctx, *, loaded=None, **fields) -> RecordingLLM:
    """llm.json with the active profile "rec" (LLMProfile's defaults but
    for *fields*; endpoint and model point at a new RecordingLLM)."""
    server = SMX.keep_open(ctx, RecordingLLM(**({"loaded": loaded} if loaded else {})))
    ctx.extras["llm"] = server
    profile = {"name": "rec", "endpoint": server.url, "model": "model-a", **fields}
    profile = {k: (v.replace("ROOT", server.url) if isinstance(v, str) else v)
               for k, v in profile.items()}
    ctx.stores.llm.write_text(json.dumps({"profiles": [profile], "active": "rec"}))
    return server


def _rooted(ctx, value):
    server = ctx.extras.get("llm")
    return value.replace("ROOT", server.url) if isinstance(value, str) and server else value


def _unrooted(ctx, value):
    server = ctx.extras.get("llm")
    return value.replace(server.url, "ROOT") if isinstance(value, str) and server else value


def _stored_profile(ctx, field):
    profile = LP.LLMSettings.load().profile("rec")
    return MISSING if profile is None else _unrooted(ctx, getattr(profile, field))


def _edit_profile(ctx, field, value) -> None:
    data = json.loads(ctx.stores.llm.read_text())
    data["profiles"][0][field] = value
    ctx.stores.llm.write_text(json.dumps(data))


def _agent_tab(ctx, win):
    dock = win._agent_dock
    dock.refresh_profiles()
    return dock.new_tab(folder=str(ctx.tmp_path))


def _ask_agent(ctx, win):
    """One task of a new Agent tab, the way its Send runs it (core.agent,
    the tab's own config): the request the LLM server got."""
    from core import agent as A

    tab = _agent_tab(ctx, win)
    profile = tab.profile()
    assert profile is not None and profile.name == "rec"
    config = tab._config(profile, mode=tab.session.mode)
    return A.Agent(config, confirm=lambda *a: True).run("say done")


def effect_provider(ctx, win, value) -> None:
    """The provider decides where the model list is asked: Ollama's own
    /api/tags, the OpenAI API's /v1/models."""
    from core import agent as A

    server = ctx.extras["llm"]
    profile = _agent_tab(ctx, win).profile()
    assert profile.provider == value
    assert A.list_models(profile, "") == ["model-a"]
    assert server.requests[-1][1] == ("/api/tags" if value == "ollama" else "/v1/models")


def effect_endpoint(ctx, win, value) -> None:
    from core import agent as A

    server = ctx.extras["llm"]
    if not value:  # the provider's default endpoint; nothing reaches the server
        profile = _agent_tab(ctx, win).profile()
        assert A.chat_url(profile) == LP.DEFAULT_ENDPOINTS["ollama"] + "/v1/chat/completions"
        return
    result = _ask_agent(ctx, win)
    assert result.answer == "done"
    assert server.paths("POST")[-1] == value.replace("ROOT", "") + "/v1/chat/completions"


def _chat_effect(field, key):
    def effect(ctx, win, value) -> None:
        assert _ask_agent(ctx, win).answer == "done"
        assert ctx.extras["llm"].last_chat()[key] == value

    return effect


def effect_timeout(ctx, win, value) -> None:
    """A server slower than the timeout is given up; within it, it answers."""
    from core import agent as A

    server = ctx.extras["llm"]
    if value == 1:
        server.delay = 1.6
        with pytest.raises(A.AgentError):
            _ask_agent(ctx, win)
        server.delay = 0.0
    else:
        assert _ask_agent(ctx, win).answer == "done"
    assert _agent_tab(ctx, win).profile().timeout == float(value)


def effect_model_load(ctx, win, value) -> None:
    """Ollama has another model loaded: asking ours would evict it - only
    with "May load a model" is it asked."""
    from core import agent as A

    server = ctx.extras["llm"]
    before = len(server.paths("POST", "/chat/completions"))
    if value:
        assert _ask_agent(ctx, win).answer == "done"
        assert len(server.paths("POST", "/chat/completions")) == before + 1
    else:
        with pytest.raises(A.AgentError, match="not loaded"):
            _ask_agent(ctx, win)
        assert len(server.paths("POST", "/chat/completions")) == before


def _hear(ctx, win):
    """A recording handed to the Agent dock's voice for recognition: (text
    recognised, notices); waits until it is through."""
    voice = win._agent_dock.voice
    _agent_tab(ctx, win)
    heard, notices = [], []
    voice.transcribed.connect(heard.append)
    voice.notice.connect(notices.append)
    try:
        voice._transcribe(b"\x00\x01" * 16000)
        end = time.time() + 10
        while time.time() < end and voice._state == "transcribing":
            APP.processEvents()
            time.sleep(0.01)
        APP.processEvents()
    finally:
        voice.transcribed.disconnect(heard.append)
        voice.notice.disconnect(notices.append)
    return heard, notices


def effect_stt_engine(ctx, win, value) -> None:
    """Server: the recording goes to the profile's transcription endpoint.
    Local: it never leaves the machine (here without the voice packages)."""
    server = ctx.extras["llm"]
    win._agent_dock.voice._packages = lambda: (False, False)
    before = len(server.paths("POST", "/audio/transcriptions"))
    heard, notices = _hear(ctx, win)
    sent = len(server.paths("POST", "/audio/transcriptions")) - before
    if value == "server":
        assert (sent, heard) == (1, ["heard on the server"]), notices
    else:
        assert sent == 0 and not heard
        assert any("voice packages" in n for n in notices), notices


def effect_stt_endpoint(ctx, win, value) -> None:
    server = ctx.extras["llm"]
    heard, notices = _hear(ctx, win)
    assert heard == ["heard on the server"], notices
    assert server.paths("POST")[-1] == value.replace("ROOT", "") + "/audio/transcriptions"


def effect_stt_model(ctx, win, value) -> None:
    """The local model the recognition would load: not downloaded here, the
    voice names it."""
    from core import voice_models as VM

    voice = win._agent_dock.voice
    voice._packages = lambda: (False, True)
    voice._model_ready = lambda model: False
    _heard, notices = _hear(ctx, win)
    title = VM.whisper_model(value).title
    assert any(title in n and "not downloaded" in n for n in notices), notices


def _set_llm_widget(attr, how):
    def set_ui(ctx, dialog, value) -> None:
        widget = getattr(dialog.page("llm"), attr)
        value = _rooted(ctx, value)
        if how == "text":
            widget.setText(value)
        elif how == "edit":
            widget.setEditText(value)
        elif how == "combo_text":
            widget.setCurrentText(value)
        elif how == "data":
            SMX._combo_data(widget, value)
        elif how == "check":
            widget.setChecked(value)
        else:
            from PyQt6.QtWidgets import QSpinBox

            widget.setValue(int(value) if isinstance(widget, QSpinBox) else value)

    return set_ui


def _shown_llm_widget(attr, how):
    def shown(dialog):
        widget = getattr(dialog.page("llm"), attr)
        value = {"text": lambda: widget.text(), "edit": lambda: widget.currentText(),
                 "combo_text": lambda: widget.currentText(),
                 "data": lambda: widget.currentData(), "check": lambda: widget.isChecked(),
                 "value": lambda: widget.value()}[how]()
        return _unrooted(_ctx(), value)

    return shown


def _llm_row(field, attr, how, values, bad, effect, *, seed=None, loaded=None, shown_as=None):
    default = getattr(LP.LLMProfile(name="x"), field)
    seed = {field: default, **(seed or {})}

    def setup(ctx) -> None:
        _seed_llm(ctx, loaded=loaded, **seed)

    def stored(ctx):
        value = _stored_profile(ctx, field)
        return shown_as(value) if shown_as and value != MISSING else value

    shown = _shown_llm_widget(attr, how)
    return Row(f"llm_{field}", "llm", f"llm.json profiles[].{field}", values, default,
               _set_llm_widget(attr, how),
               (lambda d: shown_as(shown(d))) if shown_as else shown,
               stored, lambda c, v: _edit_profile(c, field, v), bad, effect,
               widgets=(f"llm.{attr}",), setup=setup)


LLM_ROWS = [
    _llm_row("provider", "provider_combo", "combo_text", ("lmstudio", "openai"), (5, None),
             effect_provider, seed={"endpoint": "ROOT"}),
    _llm_row("endpoint", "endpoint_edit", "text", ("ROOT", "ROOT/alt"), (5, None, ["x"]),
             effect_endpoint),
    _llm_row("model", "model_combo", "edit", ("model-b",), (5, None, ["model-b"]),
             _chat_effect("model", "model")),
    _llm_row("temperature", "temperature_spin", "value", (0.7, 1.5), ("hot", True, None),
             _chat_effect("temperature", "temperature")),
    _llm_row("timeout", "timeout_spin", "value", (1, 60), ("slow", True, None),
             effect_timeout, shown_as=lambda v: int(v)),
    _llm_row("max_output_tokens", "max_tokens_spin", "value", (512,), ("many", True, 2.5),
             _chat_effect("max_output_tokens", "max_tokens")),
    _llm_row("allow_model_load", "load_check", "check", (True,), ("yes", 1, None),
             effect_model_load, loaded=("other:latest",)),
    _llm_row("stt_engine", "stt_engine_combo", "data", ("server",), (5, None, "cloud"),
             effect_stt_engine),
    _llm_row("stt_endpoint", "stt_endpoint_edit", "text", ("ROOT/stt",), (5, ["x"]),
             effect_stt_endpoint, seed={"stt_engine": "server"}),
    _llm_row("stt_model", "stt_model_combo", "edit", ("small",), (5, "gigantic"),
             effect_stt_model),
]

ROWS = NETWORK_ROWS + LLM_ROWS


# ---------------------------------------------------------------------------
# The matrix of this file
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _current_ctx(ctx):
    _CURRENT["ctx"] = ctx
    yield
    _CURRENT.clear()


ROW_PARAMS = [pytest.param(row, id=row.id) for row in ROWS]


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_set_store_reload_effect(ctx, row) -> None:
    SMX.check_set_store_reload_effect(ctx, row)


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_hand_edited_value_falls_back(ctx, row) -> None:
    SMX.check_hand_edited_value_falls_back(ctx, row)


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------


class _MemoryKeyring:
    """The system keyring as a dict (keyring's backend protocol)."""

    priority = 1

    def __init__(self) -> None:
        self.data: dict = {}

    def get_password(self, service, user):
        return self.data.get((service, user))

    def set_password(self, service, user, password):
        self.data[(service, user)] = password

    def delete_password(self, service, user):
        from keyring.errors import PasswordDeleteError

        if self.data.pop((service, user), None) is None:
            raise PasswordDeleteError(user)


@pytest.fixture
def memory_keyring(monkeypatch):
    import keyring
    from keyring.backend import KeyringBackend

    from core import credentials as C

    backend = type("MatrixKeyring", (_MemoryKeyring, KeyringBackend), {})()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    monkeypatch.setattr(C, "_keyring_checked", True)
    monkeypatch.setattr(C, "_keyring_usable", True)
    monkeypatch.setattr(C, "_keyring_backend_id", "matrix.memory")
    yield backend
    keyring.set_keyring(previous)


def check_secret(ctx, secret, values=("first-secret", "second-secret")) -> None:
    """Cancel keeps the keyring; typed -> OK -> in the keyring, in no file,
    a fresh dialog shows an empty field, the credential is used; an empty
    field changes nothing; a new value replaces it."""
    ctx.stores.close_windows()
    secret.setup(ctx)
    SMX._start(ctx, closed=True)
    before = ctx.stores.files()
    dialog = ctx.dialog()
    secret.type_in(ctx, dialog, values[0])
    dialog.reject()
    assert ctx.stores.files() == before and secret.kept(ctx) == ""
    for value in values:
        dialog = ctx.dialog()
        secret.type_in(ctx, dialog, value)
        assert dialog.dirty_page_ids() == [secret.page]
        assert dialog.apply(), dialog.error_text()
        assert secret.kept(ctx) == value
        for path in ctx.stores.config.rglob("*"):
            if path.is_file():
                assert value not in path.read_text(errors="replace"), path
        fresh = ctx.dialog()
        assert secret.field(fresh) == ""  # never shown again
        assert fresh.dirty_page_ids() == []  # an empty field is no change
        assert fresh.apply() and secret.kept(ctx) == value  # and keeps the stored one
        secret.effect(ctx, ctx.win, value)


def _type_proxy_password(ctx, dialog, value) -> None:
    _page(dialog)._password.setText(value)


def _effect_proxy_password(ctx, win, value) -> None:
    socks = SMX.keep_open(ctx, FakeSocks5Server(routes=_routes(ctx), username="alice",
                                                password=value))
    assert _talk(_resolve(), socks.port) == b"HI\n"
    assert socks.auth_seen[-1] == ("alice", value)


def _type_api_key(ctx, dialog, value) -> None:
    dialog.page("llm").key_edit.setText(value)


def _effect_api_key(ctx, win, value) -> None:
    assert _ask_agent(ctx, win).answer == "done"
    headers = [h for m, p, h, _b in ctx.extras["llm"].requests
               if m == "POST" and p.endswith("/chat/completions")]
    assert headers[-1].get("authorization") == f"Bearer {value}"


SECRETS = [
    Secret("proxy_password", "network", ("network._password",),
           lambda c: _seed_socks(c, username="alice", store_password=True),
           _type_proxy_password, lambda c: c.stores.proxy_passwords.get("pw", ""),
           lambda d: _page(d)._password.text(), _effect_proxy_password),
    Secret("llm_api_key", "llm", ("llm.key_edit",), lambda c: _seed_llm(c),
           _type_api_key, lambda c: LP.get_api_key("rec"),
           lambda d: d.page("llm").key_edit.text(), _effect_api_key),
]


@pytest.mark.parametrize("secret", [pytest.param(s, id=s.id) for s in SECRETS])
def test_secret_goes_to_the_keyring_and_is_used(ctx, memory_keyring, secret) -> None:
    check_secret(ctx, secret)


def test_proxy_password_without_the_keyring_lives_for_this_session_only(ctx) -> None:
    """Edge: Save password in keyring off - the typed password is used by
    this run's connections, and neither the keyring nor a file holds it."""
    _seed_socks(ctx, username="alice")
    dialog = ctx.dialog()
    _page(dialog)._password.setText("only-now")
    assert dialog.apply()
    assert ctx.stores.proxy_passwords == {} and PS.session_password() == "only-now"
    assert "only-now" not in ctx.stores.proxy.read_text()
    _effect_proxy_password(ctx, ctx.win, "only-now")


def test_llm_api_key_without_a_keyring_says_so_and_keeps_the_profile(ctx) -> None:
    """Sad: no usable keyring - the profile is saved, the key is not, and
    the page says why."""
    _seed_llm(ctx)
    dialog = ctx.dialog()
    dialog.page("llm").key_edit.setText("lost-key")
    assert dialog.apply()
    assert any("could not be stored" in text for _kind, text in ctx.stores.messages)
    assert LP.LLMSettings.load().profile("rec") is not None
    assert "lost-key" not in ctx.stores.llm.read_text()


# ---------------------------------------------------------------------------
# Sad and edge cases of the pages
# ---------------------------------------------------------------------------


def test_network_page_refuses_a_missing_ca_file_and_saves_nothing(ctx) -> None:
    _seed_socks(ctx)
    before = ctx.stores.proxy.read_text()
    dialog = ctx.dialog()
    _page(dialog)._ca_file.setText(str(ctx.tmp_path / "no-such-ca.pem"))
    assert not dialog.apply()
    assert "does not exist" in dialog.error_text()
    assert ctx.stores.proxy.read_text() == before


def test_network_page_refuses_a_pac_location_that_is_no_file_or_http(ctx) -> None:
    dialog = ctx.dialog()
    _page(dialog)._pac.setText("ftp://proxy.example/proxy.pac")
    assert not dialog.apply()
    assert "PAC location" in dialog.error_text()
    assert not ctx.stores.proxy.exists()


def test_llm_page_refuses_an_endpoint_that_is_no_url(ctx) -> None:
    _seed_llm(ctx)
    before = ctx.stores.llm.read_text()
    dialog = ctx.dialog()
    dialog.page("llm").endpoint_edit.setText("ftp://model.example")
    assert not dialog.apply()
    assert "http(s) URL" in dialog.error_text()
    assert ctx.stores.llm.read_text() == before


def test_llm_profile_with_an_unknown_provider_is_left_out_and_logged(ctx, caplog) -> None:
    """Edge: a hand-edited provider no server speaks drops that profile
    only (the others load); the dock then has no active profile."""
    _seed_llm(ctx)
    data = json.loads(ctx.stores.llm.read_text())
    data["profiles"].append({"name": "other", "provider": "ollama"})
    data["profiles"][0]["provider"] = "gpt-cloud"
    ctx.stores.llm.write_text(json.dumps(data))
    settings = LP.LLMSettings.load()
    assert [p.name for p in settings.profiles] == ["other"]
    assert settings.active == ""


# ---------------------------------------------------------------------------
# Cross effects
# ---------------------------------------------------------------------------


def test_cross_a_pac_proxy_takes_the_authentication_of_the_proxy_type(ctx) -> None:
    """PAC x Authentication: the PAC file names an HTTP proxy, the type
    "HTTP CONNECT + NTLM" gives it the NTLM scheme."""
    pac = ctx.tmp_path / "http.pac"
    pac.write_text('function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:3128"; }\n')
    dialog = ctx.dialog()
    page = _page(dialog)
    SMX._combo_data(page._type, "http")
    page._host.setText("127.0.0.1")
    set_auth(ctx, dialog, "ntlm")
    page._pac.setText(str(pac))
    assert dialog.apply(), dialog.error_text()
    cfg = _resolve()
    assert (cfg.proxy_type, cfg.host, cfg.port) == ("http+ntlm", "127.0.0.1", 3128)


def test_cross_the_bypass_list_wins_over_the_pac_file(ctx) -> None:
    _seed_pac(ctx)
    dialog = ctx.dialog()
    page = _page(dialog)
    page._pac.setText(ctx.extras["pac"])
    page._bypass.setPlainText("db.internal")
    assert dialog.apply(), dialog.error_text()
    assert PS.resolve("default", None, *TARGET).source == "bypass"


def test_cross_a_remote_llm_endpoint_asks_for_consent_before_anything_is_sent(ctx) -> None:
    """Endpoint x consent edge: a local endpoint needs no consent; switched
    to a remote host, the agent refuses until it is given - nothing is sent."""
    from core import agent as A

    _seed_llm(ctx)
    dialog = ctx.dialog()
    dialog.page("llm").endpoint_edit.setText("https://llm.example.com/v1")
    assert dialog.apply()
    profile = _agent_tab(ctx, ctx.win).profile()
    assert profile.needs_consent()
    with pytest.raises(A.AgentError, match="no consent"):
        A.Agent(_agent_tab(ctx, ctx.win)._config(profile, mode="ask")).run("hi")
    assert ctx.extras["llm"].chats() == []
