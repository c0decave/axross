"""The agent harness in a sandbox: bubblewrap, podman or docker.

Configured, the agent - its loop and every tool it runs - lives in a
process of its own inside a sandbox. The sandbox has no network at all:
the model's requests go over the worker's stdin/stdout to axross, which
sends them to the profile's server and nowhere else, keeps the API key
and asks for the consent. A sandbox profile picks one of four
levels - lax (the host's network), normal and high (allowed hosts only,
through axross), paranoid (the LLM only, nothing writable) - and extra
folders, read-only or read-write.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_loop import _call, _Fake  # noqa: E402


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake():
    servers = []

    def make(*replies):
        server = _Fake(replies)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def _config(server_url, root, **cfg):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server_url, model="tiny")
    return A.AgentConfig(profile=profile, root=str(root), **cfg)


def _pairs(argv, flag):
    """The (source, dest) pairs of a repeated two-argument flag."""
    return [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == flag]


def _bwrap_works() -> bool:
    if not shutil.which("bwrap"):
        return False
    probe = subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
                           capture_output=True, timeout=20)
    return probe.returncode == 0


needs_bwrap = pytest.mark.skipif(
    not _bwrap_works(), reason="bubblewrap cannot create a sandbox here"
)


# -- happy ---------------------------------------------------------------------


def test_happy_bubblewrap_has_no_network_and_only_the_folder_from_home(tmp_path):
    settings = SB.SandboxProfile(engine="bubblewrap", level="normal")
    argv = SB.sandbox_command(settings, str(tmp_path), writable=True)
    argv = argv[argv.index("bwrap"):]  # after the limits (systemd-run or prlimit)
    for flag in ("--unshare-all", "--die-with-parent", "--new-session", "--clearenv"):
        assert flag in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert (str(tmp_path), str(tmp_path)) in _pairs(argv, "--bind")
    home = str(Path.home())
    mounted = [src for flag in ("--bind", "--ro-bind") for src, _ in _pairs(argv, flag)]
    assert not any(src == home or home.startswith(src + os.sep) and src != "/" for src in mounted)
    assert "/" not in mounted


def test_happy_podman_runs_without_network_capabilities_or_a_writable_image(tmp_path):
    settings = SB.SandboxProfile(
        engine="podman", level="normal", image="localhost/axross-agent:test"
    )
    argv = SB.sandbox_command(settings, str(tmp_path), writable=True)
    assert argv[:4] == ["podman", "run", "--rm", "-i"]
    for flag in ("--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--read-only", "--userns=keep-id"):
        assert flag in argv
    assert f"{tmp_path}:{tmp_path}:rw" in argv
    assert argv[-1] == "localhost/axross-agent:test"


def test_happy_docker_runs_as_the_user(tmp_path):
    settings = SB.SandboxProfile(engine="docker", level="normal", image="axross-agent:x")
    argv = SB.sandbox_command(settings, str(tmp_path), writable=False)
    assert argv[:4] == ["docker", "run", "--rm", "-i"]
    assert f"--user={os.getuid()}:{os.getgid()}" in argv
    assert not any(a.startswith("--userns") for a in argv)
    assert f"{tmp_path}:{tmp_path}:ro" in argv


def test_happy_the_relay_answers_a_sandboxed_read(fake, tmp_path):
    (tmp_path / "notes.txt").write_text("buy milk")
    server = fake({"tool_calls": [_call("read_file", {"path": str(tmp_path / "notes.txt"),
                                                       "encoding": "text"})]},
                  {"content": "It says: buy milk."})
    events = []
    agent = SB.SandboxedAgent(_config(server.url, tmp_path), None,
                              on_event=events.append, command=SB.worker_argv())
    try:
        result = agent.run("What is in notes.txt?")
    finally:
        agent.close()
    assert result.answer == "It says: buy milk." and result.stopped == "answered"
    assert result.calls == [{"name": "read_file", "outcome": "ok"}]
    assert "buy milk" in server.requests[1]["messages"][-1]["content"]
    assert [e["type"] for e in events if e["type"] != "connection"] == \
        ["tool_call", "tool_result", "assistant"]
    # axross sends the worker's requests, so axross says how they went (the lamp).
    assert [e["state"] for e in events if e["type"] == "connection"] == \
        ["trying", "connected", "trying", "connected"]


def test_happy_a_change_waits_for_the_hosts_yes(fake, tmp_path):
    server = fake({"tool_calls": [_call("write_file", {"path": str(tmp_path / "todo.txt"),
                                                        "content": "renew the domain"})]},
                  {"content": "Written."})
    asked = []
    agent = SB.SandboxedAgent(_config(server.url, tmp_path, allow_write=True),
                              None,
                              confirm=lambda n, a: asked.append((n, a)) or True,
                              command=SB.worker_argv())
    try:
        result = agent.run("Write todo.txt")
    finally:
        agent.close()
    assert asked and asked[0][0] == "write_file"
    assert (tmp_path / "todo.txt").read_text() == "renew the domain"
    assert result.calls == [{"name": "write_file", "outcome": "ok"}]


# -- sad -----------------------------------------------------------------------


def test_sad_the_api_key_never_enters_the_sandbox(fake, tmp_path, monkeypatch):
    server = fake({"content": "ok"})
    sent: list[dict] = []
    real = SB.SandboxedAgent._send

    def spy(self, message):
        sent.append(message)
        return real(self, message)

    monkeypatch.setattr(SB.SandboxedAgent, "_send", spy)
    agent = SB.SandboxedAgent(_config(server.url, tmp_path, api_key="sk-secret-123"),
                              None, command=SB.worker_argv())
    try:
        agent.run("hi")
    finally:
        agent.close()
    assert "sk-secret-123" not in json.dumps(sent)
    assert server.headers[0].get("Authorization") == "Bearer sk-secret-123"


def test_sad_no_means_nothing_changes(fake, tmp_path):
    server = fake(
        {"tool_calls": [_call("write_file", {"path": str(tmp_path / "x.txt"), "content": "x"})]},
        {"content": "Not written."},
    )
    agent = SB.SandboxedAgent(_config(server.url, tmp_path, allow_write=True),
                              None, confirm=lambda n, a: False,
                              command=SB.worker_argv())
    try:
        result = agent.run("write x")
    finally:
        agent.close()
    assert not (tmp_path / "x.txt").exists()
    assert result.calls == [{"name": "write_file", "outcome": "declined"}]


def test_sad_a_worker_that_dies_is_an_agent_error(tmp_path):
    agent = SB.SandboxedAgent(
        _config("http://127.0.0.1:9/v1", tmp_path),
        None,
        command=[sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"],
    )
    with pytest.raises(A.AgentError, match="boom"):
        agent.run("hi")
    agent.close()


def test_sad_an_engine_that_is_not_installed_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(SB.shutil, "which", lambda name: None)
    agent = SB.SandboxedAgent(_config("http://127.0.0.1:9/v1", tmp_path),
                              SB.SandboxProfile(engine="podman"))
    with pytest.raises(A.AgentError, match="podman is not installed"):
        agent.run("hi")
    agent.close()


def test_sad_a_broken_profile_entry_takes_safe_defaults():
    profile = SB.SandboxProfile.from_dict(
        {
            "name": "x",
            "engine": "chroot",
            "level": "yolo",
            "image": 5,
            "hosts": ["db:5432", "nope", "*:22", "db:5432"],
            "mounts": [
                {"path": "relative", "mode": "rw"},
                {"path": "/srv/data", "mode": "rw"},
                {"path": "/srv/data", "mode": "ro"},
            ],
        }
    )
    assert (profile.engine, profile.level, profile.image) == ("auto", "normal", SB.DEFAULT_IMAGE)
    assert profile.hosts == ("db:5432",)
    assert profile.mounts == (("/srv/data", True),)
    assert SB.SandboxProfile.from_dict({"engine": "podman"}) is None
    assert SB.SandboxProfile.from_dict("not a dict") is None


# -- edge ----------------------------------------------------------------------


def test_edge_paranoid_mounts_nothing_writable_and_tightens_limits(tmp_path):
    for engine in ("bubblewrap", "podman", "docker"):
        settings = SB.SandboxProfile(engine=engine, level="paranoid", image="img")
        argv = SB.sandbox_command(settings, str(tmp_path), writable=True)
        if engine == "bubblewrap":
            assert _pairs(argv, "--bind") == []
            assert (str(tmp_path), str(tmp_path)) in _pairs(argv, "--ro-bind")
            assert "--disable-userns" in argv
        else:
            assert f"{tmp_path}:{tmp_path}:ro" in argv
            assert not any(a.endswith(":rw") for a in argv)
            assert "--ipc=none" in argv and "--memory=1g" in argv and "--pids-limit=64" in argv
    assert not SB.writes_allowed(SB.SandboxProfile(engine="podman", level="paranoid"))
    assert SB.writes_allowed(SB.SandboxProfile(engine="podman", level="normal"))


def test_edge_the_sandbox_offers_no_remote_or_exec_groups():
    groups = SB.allowed_groups(frozenset({"metadata", "remote", "exec", "archive"}))
    assert groups == frozenset({"metadata", "archive"})


def test_edge_cancel_reaches_the_worker(fake, tmp_path):
    started = threading.Event()
    release = threading.Event()

    def confirm(name, args):
        started.set()
        release.wait(10)
        return False

    server = fake(
        {"tool_calls": [_call("write_file", {"path": str(tmp_path / "y.txt"), "content": "y"})]},
        {"tool_calls": [_call("list_dir", {"path": str(tmp_path)})]},
        {"content": "never"},
    )
    cancel = threading.Event()
    agent = SB.SandboxedAgent(_config(server.url, tmp_path, allow_write=True),
                              None, confirm=confirm, cancel=cancel,
                              command=SB.worker_argv())
    out = {}
    thread = threading.Thread(target=lambda: out.setdefault("r", agent.run("go")))
    thread.start()
    assert started.wait(30)
    cancel.set()
    release.set()
    thread.join(30)
    agent.close()
    assert out["r"].stopped == "cancelled"
    assert len(server.requests) == 1


def _probe_sandbox(engine, tmp_path, python, env=None):
    """Run a probe in the sandbox of *engine* on both levels: network,
    home, the folder (read, write) and /tmp."""
    listener = socket.socket()
    listener.bind(("0.0.0.0", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    secret = Path.home() / "agent-sandbox-probe.txt"
    probe = (
        "import socket, os, sys, pathlib\n"
        "out = {}\n"
        "s = socket.socket()\n"
        "s.settimeout(2)\n"
        f"try:\n    s.connect(('127.0.0.1', {port})); out['net'] = 'open'\n"
        "except OSError as e:\n    out['net'] = 'closed'\n"
        f"out['home'] = os.path.exists({str(secret)!r})\n"
        f"root = pathlib.Path({str(tmp_path)!r})\n"
        "out['read'] = (root / 'in.txt').read_text()\n"
        "try:\n    (root / 'out.txt').write_text('x'); out['write'] = 'ok'\n"
        "except OSError:\n    out['write'] = 'refused'\n"
        "pathlib.Path('/tmp/scratch').write_text('t'); out['tmp'] = 'ok'\n"
        "print(__import__('json').dumps(out))\n"
    )
    (tmp_path / "in.txt").write_text("visible")
    secret.write_text("private")
    results = {}
    try:
        for level in ("normal", "paranoid"):
            settings = SB.SandboxProfile(engine=engine, level=level)
            argv = SB.sandbox_command(settings, str(tmp_path), writable=True,
                                      inner=[python, "-c", probe])
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, env=env)
            assert proc.returncode == 0, proc.stderr
            results[level] = json.loads(proc.stdout.strip().splitlines()[-1])
            (tmp_path / "out.txt").unlink(missing_ok=True)
    finally:
        secret.unlink()
        listener.close()
    for level in ("normal", "paranoid"):
        assert results[level]["net"] == "closed"
        assert results[level]["home"] is False
        assert results[level]["read"] == "visible"
        assert results[level]["tmp"] == "ok"
    assert results["normal"]["write"] == "ok"
    assert results["paranoid"]["write"] == "refused"


def _engine_env() -> dict:
    """The environment with the user's real home: rootless podman keeps
    its images there, and the tests run with a scratch HOME."""
    import pwd

    env = {
        k: v for k, v in os.environ.items() if not k.startswith("XDG_") or k == "XDG_RUNTIME_DIR"
    }
    env["HOME"] = pwd.getpwuid(os.getuid()).pw_dir
    return env


def _image_present(engine: str) -> bool:
    if not shutil.which(engine):
        return False
    probe = subprocess.run([engine, "image", "inspect", SB.DEFAULT_IMAGE], capture_output=True,
                           timeout=60, env=_engine_env())
    return probe.returncode == 0


@needs_bwrap
def test_edge_inside_bubblewrap_there_is_no_network_no_home_and_paranoid_is_read_only(tmp_path):
    _probe_sandbox("bubblewrap", tmp_path, sys.executable)


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_edge_inside_a_container_there_is_no_network_no_home_and_paranoid_is_read_only(
    engine, tmp_path
):
    if not _image_present(engine):
        pytest.skip(f"no {SB.DEFAULT_IMAGE} for {engine} (scripts/axross-podman.sh agent-image)")
    _probe_sandbox(engine, tmp_path, "python", env=_engine_env())


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_edge_a_containered_agent_reaches_the_model_only_through_axross(
    engine, fake, tmp_path, monkeypatch
):
    if not _image_present(engine):
        pytest.skip(f"no {SB.DEFAULT_IMAGE} for {engine} (scripts/axross-podman.sh agent-image)")
    for key, value in _engine_env().items():
        monkeypatch.setenv(key, value)
    (tmp_path / "notes.txt").write_text("renew the domain")
    server = fake({"tool_calls": [_call("read_file", {"path": str(tmp_path / "notes.txt"),
                                                       "encoding": "text"})]},
                  {"content": "renew the domain"})
    agent = SB.SandboxedAgent(_config(server.url, tmp_path),
                              SB.SandboxProfile(engine=engine, level="paranoid"))
    try:
        result = agent.run("read notes.txt")
    finally:
        agent.close()
    assert result.calls == [{"name": "read_file", "outcome": "ok"}]
    assert "renew the domain" in server.requests[1]["messages"][-1]["content"]


@needs_bwrap
def test_edge_a_bubblewrapped_agent_reaches_the_model_only_through_axross(fake, tmp_path):
    (tmp_path / "notes.txt").write_text("renew the domain")
    server = fake({"tool_calls": [_call("read_file", {"path": str(tmp_path / "notes.txt"),
                                                       "encoding": "text"})]},
                  {"content": "renew the domain"})
    agent = SB.SandboxedAgent(_config(server.url, tmp_path),
                              SB.SandboxProfile(engine="bubblewrap", level="paranoid"))
    try:
        result = agent.run("read notes.txt")
    finally:
        agent.close()
    assert result.calls == [{"name": "read_file", "outcome": "ok"}]
    assert "renew the domain" in server.requests[1]["messages"][-1]["content"]


# -- levels, folders and allowed hosts ---------------------------------------------


@pytest.mark.parametrize("engine", ["bubblewrap", "podman", "docker"])
def test_happy_lax_keeps_the_network_and_the_others_drop_it(engine, tmp_path):
    for level, networked in (
        ("lax", True),
        ("normal", False),
        ("high", False),
        ("paranoid", False),
    ):
        argv = SB.sandbox_command(SB.SandboxProfile(engine=engine, level=level, image="img"),
                                  str(tmp_path), writable=False)
        if engine == "bubblewrap":
            assert ("--share-net" in argv) is networked, level
            assert "--unshare-all" in argv
        else:
            assert ("--network=none" in argv) is not networked, level


@pytest.mark.parametrize("engine", ["bubblewrap", "podman", "docker"])
def test_happy_extra_folders_are_mounted_as_the_level_allows(engine, tmp_path):
    ro, rw = tmp_path / "ro", tmp_path / "rw"
    ro.mkdir()
    rw.mkdir()
    for level, rw_kept in (("lax", True), ("normal", True), ("high", False), ("paranoid", False)):
        profile = SB.SandboxProfile(engine=engine, level=level, image="img",
                                    mounts=((str(ro), False), (str(rw), True)))
        argv = SB.sandbox_command(profile, str(tmp_path / "work"), writable=True)
        if engine == "bubblewrap":
            assert (str(ro), str(ro)) in _pairs(argv, "--ro-bind")
            assert ((str(rw), str(rw)) in _pairs(argv, "--bind")) is rw_kept, level
        else:
            assert f"{ro}:{ro}:ro" in argv
            assert (f"{rw}:{rw}:rw" in argv) is rw_kept, level
            assert (f"{rw}:{rw}:ro" in argv) is not rw_kept, level


def test_sad_allowed_hosts_count_only_where_the_level_has_an_allowlist():
    hosts = ("db.example:5432",)
    assert SB.SandboxProfile(level="normal", hosts=hosts).allows("DB.example", 5432)
    assert not SB.SandboxProfile(level="normal", hosts=hosts).allows("db.example", 5433)
    assert not SB.SandboxProfile(level="normal", hosts=hosts).allows("other", 5432)
    assert SB.SandboxProfile(level="high", hosts=hosts).allows("db.example", 5432)
    assert not SB.SandboxProfile(level="paranoid", hosts=hosts).allows("db.example", 5432)
    assert SB.SandboxProfile(level="lax").allows("anything", 1)


def test_sad_a_missing_extra_folder_is_named(tmp_path):
    profile = SB.SandboxProfile(engine="bubblewrap", mounts=((str(tmp_path / "gone"), False),))
    agent = SB.SandboxedAgent(_config("http://127.0.0.1:9/v1", tmp_path), profile)
    if not SB.available("bubblewrap"):
        pytest.skip("bubblewrap is not installed")
    with pytest.raises(A.AgentError, match="gone"):
        agent.run("hi")
    agent.close()


def test_edge_a_restored_conversation_gets_the_workers_system_message(fake, tmp_path):
    # A session saved with another folder: the worker tells the model the
    # folder it works in now, not the one in the stored system message.
    import json

    server = fake({"content": "ok"})
    history = [{"role": "system", "content": 'old rules, root "/elsewhere"'},
               {"role": "user", "content": "earlier"}, {"role": "assistant", "content": "yes"}]
    agent = SB.SandboxedAgent(_config(server.url, tmp_path),
                              lambda: SB.SandboxProfile(engine="bubblewrap", level="lax"),
                              command=SB.worker_argv(), history=history)
    try:
        agent.run("now")
    finally:
        agent.close()
    sent = server.requests[0]["messages"]
    assert sent[0]["role"] == "system"
    assert json.dumps(str(tmp_path)) in sent[0]["content"]
    assert "/elsewhere" not in sent[0]["content"]
    assert [m["role"] for m in sent] == ["system", "user", "assistant", "user"]


def test_edge_a_changed_profile_starts_a_new_sandbox_that_keeps_the_conversation(fake, tmp_path):
    server = fake({"content": "first"}, {"content": "second"})
    profile = {"now": SB.SandboxProfile(engine="bubblewrap", level="lax")}
    # The plain worker process stands in for the sandbox: the restart is what is tested.
    agent = SB.SandboxedAgent(_config(server.url, tmp_path), lambda: profile["now"],
                              command=SB.worker_argv())
    try:
        agent.run("one")
        first_proc = agent._proc
        profile["now"] = SB.SandboxProfile(engine="bubblewrap", level="paranoid")
        agent.run("two")
        assert agent._proc is not first_proc
    finally:
        agent.close()
    sent = server.requests[1]["messages"]
    assert [m["content"] for m in sent if m["role"] == "user"] == ["one", "two"]
    assert any(m["role"] == "assistant" and m["content"] == "first" for m in sent)


@needs_bwrap
def test_edge_a_running_sandbox_drops_a_removed_host_at_the_next_connection(tmp_path):
    """Allowed hosts end to end: a bubblewrapped bridge (no network of its
    own) reaches an allowed host only through axross's relay, and a host
    removed from the profile is refused at once."""
    from core.agent_net import HostRelay

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]

    def echo():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            data = conn.recv(100)
            conn.sendall(b"echo:" + data)
            conn.close()

    threading.Thread(target=echo, daemon=True).start()
    probe = f"""
import json, socket, sys, threading
sys.path.insert(0, {str(Path(SB.__file__).resolve().parent.parent)!r})
from core.agent_worker import _Channel
from core.agent_net import WorkerBridge
channel = _Channel(sys.stdin, sys.stdout)
channel.bridge = WorkerBridge(channel.request, channel.send, ["db.internal:{port}"])
channel.bridge.install()
threading.Thread(target=channel.serve, daemon=True).start()
out = {{}}
for attempt in ("first", "second"):
    try:
        s = socket.create_connection(("db.internal", {port}), timeout=5)
        s.sendall(attempt.encode())
        out[attempt] = s.recv(100).decode()
    except OSError as e:
        out[attempt] = "refused"
    result = {{"type": "probe", "attempt": attempt, "out": out[attempt]}}
    sys.stdout.write(json.dumps(result) + "\\n")
    sys.stdout.flush()
try:
    socket.create_connection(("127.0.0.1", {port}), timeout=2)
    out["direct"] = "open"
except OSError:
    out["direct"] = "closed"
sys.stdout.write(json.dumps({{"type": "done", "out": out}}) + "\\n")
sys.stdout.flush()
"""
    profile = SB.SandboxProfile(engine="bubblewrap", level="normal", hosts=(f"db.internal:{port}",))
    argv = SB.sandbox_command(profile, str(tmp_path), writable=False,
                              inner=[sys.executable, "-c", probe])
    proc = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    lock = threading.Lock()

    def send(message):
        with lock:
            proc.stdin.write((json.dumps(message) + "\n").encode())
            proc.stdin.flush()

    allowed = {"hosts": {("db.internal", port)}}
    relay = HostRelay(send, lambda h, p: (h, p) in allowed["hosts"])
    # The relay opens a real connection: the test resolves the name for it.
    real_connect = socket.create_connection

    def connect(address, *a, **k):
        host, p = address
        return real_connect(("127.0.0.1" if host == "db.internal" else host, p), *a, **k)

    results = {}
    try:
        socket.create_connection = connect
        for raw in proc.stdout:
            message = json.loads(raw)
            kind = message.get("type")
            if kind == "tcp_open":
                try:
                    stream = relay.open(message["host"], message["port"])
                    send({"type": "answer", "id": message["id"], "value": {"stream": stream}})
                except (OSError, ValueError) as exc:
                    send({"type": "answer", "id": message["id"], "error": str(exc)})
            elif kind == "tcp_data":
                relay.write(message["stream"], message["data"])
            elif kind == "tcp_close":
                relay.close(message["stream"])
            elif kind == "probe":
                results[message["attempt"]] = message["out"]
                if message["attempt"] == "first":
                    allowed["hosts"] = set()  # the user removed the host
            elif kind == "done":
                results["direct"] = message["out"]["direct"]
                break
    finally:
        socket.create_connection = real_connect
        relay.close_all()
        proc.stdin.close()
        proc.wait(timeout=10)
        server.close()
    errors = proc.stderr.read().decode(errors="replace")
    assert results.get("first") == "echo:first", errors
    assert results["second"] in ("refused", "")
    assert results["direct"] == "closed"


# -- hardening (independent review of the agent program) -------------------------


def test_sad_bubblewrap_mounts_no_start_folder_and_no_foreign_source_tree(tmp_path, monkeypatch):
    """sys.path holds the start folder ('' or $HOME with python -m) and
    editable installs (.pth): none of them may reach the sandbox - only the
    interpreter's own folders and its site-packages."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    foreign = tmp_path / "other-project" / "src"
    foreign.mkdir(parents=True)
    monkeypatch.chdir(home)
    monkeypatch.setattr(sys, "path", ["", str(home), str(foreign), *sys.path])
    mounts, pythonpath = SB._python_paths()
    for bad in (str(home), str(foreign), os.getcwd()):
        assert bad not in mounts and bad not in pythonpath
    import site

    venv_site = [p for p in site.getsitepackages() if p.startswith(sys.prefix)]
    assert all(p in mounts or any(p.startswith(m + os.sep) for m in mounts) for p in venv_site)


def test_edge_a_frozen_build_mounts_only_its_own_files(tmp_path, monkeypatch):
    exe_dir = tmp_path / "home"
    exe_dir.mkdir()
    exe = exe_dir / "axross"
    exe.write_text("")
    (exe_dir / ".ssh").mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)
    (tmp_path / "bundle").mkdir()
    mounts, _pythonpath = SB._python_paths()
    assert str(exe_dir) not in mounts
    assert str(exe) in mounts and str(tmp_path / "bundle") in mounts


def test_edge_an_interpreter_installed_into_home_does_not_mount_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    lib = home / "lib" / "python3.12"
    (lib / "site-packages").mkdir(parents=True)
    (home / ".ssh").mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    for name in ("prefix", "base_prefix", "exec_prefix", "base_exec_prefix"):
        monkeypatch.setattr(sys, name, str(home))
    monkeypatch.setattr(sys, "path", [str(lib), str(lib / "site-packages"), str(home)])
    mounts, _pythonpath = SB._python_paths()
    assert str(home) not in mounts
    assert str(lib) in mounts and str(lib / "site-packages") in mounts


_HUGE_LINE_WORKER = """
import sys
sys.stdin.buffer.readline(); sys.stdin.buffer.readline()
chunk = b"x" * 65536
for _ in range(int(sys.argv[1])):
    sys.stdout.buffer.write(chunk)
sys.stdout.buffer.flush()
import time; time.sleep(30)
"""

_DEAF_WORKER = """
import json, sys, time
port = int(sys.argv[1])
sys.stdin.buffer.readline(); sys.stdin.buffer.readline()
opened = {"type": "tcp_open", "id": 1, "host": "127.0.0.1", "port": port}
sys.stdout.write(json.dumps(opened) + "\\n")
sys.stdout.flush()
time.sleep(60)
"""


def test_sad_a_worker_line_over_the_limit_ends_the_worker(tmp_path, monkeypatch):
    """A broken or subverted worker cannot make axross buffer an endless line."""
    script = tmp_path / "huge.py"
    script.write_text(_HUGE_LINE_WORKER)
    monkeypatch.setattr(SB, "MAX_LINE", 1 << 20)
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
                           root=str(tmp_path))
    agent = SB.SandboxedAgent(
        config, None, command=[sys.executable, str(script), "64"]
    )  # 4 MiB, no newline
    with pytest.raises(A.AgentError, match="too long"):
        agent.run("hi")
    assert agent._proc is None
    agent.close()


def test_sad_closing_never_hangs_on_a_worker_that_stopped_reading(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        try:
            conn.sendall(b"x" * (16 << 20))
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    script = tmp_path / "deaf.py"
    script.write_text(_DEAF_WORKER)
    profile = SB.SandboxProfile(name="N", level="normal", hosts=(f"127.0.0.1:{port}",))
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
                           root=str(tmp_path))
    agent = SB.SandboxedAgent(
        config, lambda: profile, command=[sys.executable, str(script), str(port)]
    )
    threading.Thread(target=lambda: _ignore(agent.run, "hi"), daemon=True).start()
    import time

    time.sleep(3)
    proc = agent._proc
    done = threading.Event()
    threading.Thread(target=lambda: (agent.close(), done.set()), daemon=True).start()
    assert done.wait(10), "close() hung on a worker that stopped reading"
    assert proc is not None and proc.poll() is not None
    srv.close()


def _ignore(fn, *args):
    try:
        fn(*args)
    except Exception:  # noqa: BLE001 - the run ends with the worker
        pass


def test_happy_bubblewrap_applies_the_levels_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "_user_scope_works", lambda: True)
    argv = SB.sandbox_command(
        SB.SandboxProfile(engine="bubblewrap", level="paranoid"), str(tmp_path), writable=False
    )
    rules = SB.RULES["paranoid"]
    assert argv[:2] == ["systemd-run", "--user"]
    assert f"MemoryMax={SB._bytes(rules.memory)}" in argv and f"TasksMax={rules.pids}" in argv
    assert f"CPUQuota={int(rules.cpus) * 100}%" in argv
    i = argv.index("--tmpfs")
    assert argv[i - 2:i] == ["--size", str(SB._bytes(rules.tmp_size))] and argv[i + 1] == "/tmp"


def test_edge_without_a_user_manager_memory_is_limited_by_prlimit(tmp_path, monkeypatch):
    monkeypatch.setattr(SB, "_user_scope_works", lambda: False)
    argv = SB.sandbox_command(
        SB.SandboxProfile(engine="bubblewrap", level="high"), str(tmp_path), writable=False
    )
    assert argv[0] == "prlimit" and f"--as={SB._bytes(SB.RULES['high'].memory)}" in argv
    assert "bwrap" in argv


@needs_bwrap
def test_happy_a_paranoid_bubblewrap_tmp_is_small(tmp_path):
    argv = SB.sandbox_command(
        SB.SandboxProfile(engine="bubblewrap", level="paranoid"),
        str(tmp_path),
        writable=False,
        inner=["/bin/sh", "-c", "df -B1 /tmp | tail -1"],
    )
    out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    size = int(out.stdout.split()[1])
    assert size <= SB._bytes(SB.RULES["paranoid"].tmp_size)
