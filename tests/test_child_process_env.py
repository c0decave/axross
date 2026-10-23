"""Every child process gets the environment its program needs.

Reproduced 2026-10-22 with dist/axross-full 0.13.22: a PyInstaller one-file
build points LD_LIBRARY_PATH at its extraction folder, and a host program
started with the inherited environment resolves ITS libraries against the
bundled ones - ``bash -c true`` ended with "symbol lookup error ...
rl_trim_arg_from_keyseq" (rc 127), ``ffprobe -version`` with "GLIBCXX_3.4.32
not found". core.subprocess_env had the fix; these call sites did not use it.

Here the bundle is simulated: LD_LIBRARY_PATH points at a fake extraction
folder and no LD_LIBRARY_PATH_ORIG exists (nothing was set before launch).
Wherever the call site takes the program from its caller, a real child
reports what it saw; where the program is fixed (systemd-run, podman,
mount) the call is recorded instead.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402

FAKE_BUNDLE = "/tmp/_MEIfake"
#: A child that prints the LD_LIBRARY_PATH it was given.
PROBE_CODE = "import os, sys; sys.stdout.write(os.environ.get('LD_LIBRARY_PATH', '<unset>'))"
PROBE = [sys.executable, "-c", PROBE_CODE]


@pytest.fixture
def bundle_env(monkeypatch):
    """The environment of a frozen one-file process started without an
    LD_LIBRARY_PATH of its own."""
    monkeypatch.setenv("LD_LIBRARY_PATH", FAKE_BUNDLE)
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)


@pytest.fixture
def probe_script(tmp_path):
    """An executable file that writes the LD_LIBRARY_PATH it saw to stdout
    (for call sites that take a program path, not an argv)."""
    path = tmp_path / "probe-tool"
    path.write_text(f"#!{sys.executable}\n{PROBE_CODE}\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


class Recorder:
    """Stands in for subprocess.run where the program is fixed."""

    def __init__(self, stdout=""):
        self.calls: list[tuple[list, dict]] = []
        self._stdout = stdout

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))

        class Done:
            returncode = 0
            stdout = self._stdout
            stderr = ""

        return Done()


def _extension(name: str):
    path = EX.bundled_dir() / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"childenv_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# -- core ----------------------------------------------------------------------------------


def test_sad_loop_mount_runs_host_tools_without_the_bundle_path(bundle_env):
    from core import loop_mount

    assert loop_mount.run_command(PROBE).stdout == "<unset>"


def test_sad_agent_sandbox_probes_systemd_run_without_the_bundle_path(bundle_env, monkeypatch):
    from core import agent_sandbox

    rec = Recorder()
    monkeypatch.setattr(agent_sandbox.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(agent_sandbox.subprocess, "run", rec)
    agent_sandbox._user_scope_works.cache_clear()
    try:
        assert agent_sandbox._user_scope_works() is True
    finally:
        agent_sandbox._user_scope_works.cache_clear()
    (argv, kwargs), = rec.calls
    assert argv[0] == "systemd-run"
    assert "env" in kwargs and "LD_LIBRARY_PATH" not in kwargs["env"]
    assert kwargs["env"].get("PATH") == os.environ.get("PATH")


def test_sad_agent_sandbox_removes_a_container_without_the_bundle_path(bundle_env, monkeypatch):
    from core import agent_sandbox

    rec = Recorder()
    monkeypatch.setattr(agent_sandbox.subprocess, "run", rec)
    sandbox = object.__new__(agent_sandbox.SandboxedAgent)
    sandbox._container = ("podman", "axross-agent-test")

    class Gone:
        pid = 2**22 + 12345  # no such process group

        def kill(self):
            pass

    sandbox._kill(Gone())
    (argv, kwargs), = rec.calls
    assert argv[1:] == ["rm", "-f", "axross-agent-test"]
    assert "env" in kwargs and "LD_LIBRARY_PATH" not in kwargs["env"]


def test_edge_a_users_own_library_path_reaches_host_tools(monkeypatch):
    """The value saved before launch comes back - only the bundle's goes."""
    from core import loop_mount

    monkeypatch.setenv("LD_LIBRARY_PATH", f"{FAKE_BUNDLE}:/opt/mine")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/opt/mine")
    assert loop_mount.run_command(PROBE).stdout == "/opt/mine"


def test_sad_an_rsync_dry_run_gets_the_session_env_not_the_inherited_one(bundle_env, tmp_path,
                                                                       monkeypatch):
    """dry_run passed no env at all: besides the loader path it lost the
    daemon password and the proxy (RSYNC_CONNECT_PROG) that every other
    rsync call of the session gets from _build_env, and it handed rsync the
    whole environment that _build_env deliberately trims (docs/OPSEC.md #9)."""
    from core.rsync_client import RsyncSession

    fake = tmp_path / "rsync"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "print('>f+++++++++ ' + '|'.join(os.environ.get(k, '-') for k in "
        "('LD_LIBRARY_PATH', 'RSYNC_PASSWORD', 'AXROSS_SECRET_PROBE')))\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("AXROSS_SECRET_PROBE", "leaked")
    session = object.__new__(RsyncSession)
    session._rsync_bin = str(fake)
    session._host, session._port, session._module = "backup.example.invalid", 873, "data"
    session._username, session._password, session._ssh_mode = "ci", "pw", False
    session._proxy = None
    result = session.dry_run("/docs", str(tmp_path / "dest"))
    assert result["files"] == ["-|pw|-"]


# -- workers: axross itself, reusing this process's extraction folder ----------------------


def _read_worker(proc) -> str:
    out = proc.stdout.read().decode()
    proc.wait(timeout=10)
    return out


def test_happy_the_analysis_worker_keeps_the_bundle_path(bundle_env, tmp_path):
    """The frozen worker's bootloader does not set LD_LIBRARY_PATH again;
    without the inherited one it loads the host's libssl/libstdc++ into
    the bundled interpreter (measured with dist/axross-full 0.13.22)."""
    from core.analysis_worker import AnalysisWorker

    worker = AnalysisWorker(tmp_path, command=PROBE)
    assert _read_worker(worker._start()) == FAKE_BUNDLE


def test_happy_the_voice_worker_keeps_the_bundle_path(bundle_env):
    from core.voice_worker import VoiceWorker

    assert _read_worker(VoiceWorker(command=PROBE)._start()) == FAKE_BUNDLE


def test_edge_a_worker_is_never_told_to_extract_the_bundle_again(monkeypatch):
    from core.voice_worker import VoiceWorker

    code = "import os, sys; sys.stdout.write(os.environ.get('PYINSTALLER_RESET_ENVIRONMENT', '-'))"
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "1")
    assert _read_worker(VoiceWorker(command=[sys.executable, "-c", code])._start()) == "-"


# -- ProxyCommand ---------------------------------------------------------------------------


def test_sad_a_proxy_command_runs_without_the_bundle_path(bundle_env):
    from core.ssh_client import CleanEnvProxyCommand

    import shlex

    proxy = CleanEnvProxyCommand(shlex.join(PROBE))
    try:
        proxy.settimeout(10)
        # recv waits for exactly this many bytes (or the timeout).
        assert proxy.recv(len(b"<unset>")) == b"<unset>"
    finally:
        proxy.close()


def test_edge_the_proxy_command_keeps_paramikos_interface():
    """paramiko's send/recv/close use exactly these attributes; a paramiko
    release that adds one shows up here, not as an AttributeError on a
    jump host."""
    import paramiko

    from core.ssh_client import CleanEnvProxyCommand

    ours = CleanEnvProxyCommand("true")
    theirs = paramiko.ProxyCommand("true")
    try:
        assert isinstance(ours, paramiko.ProxyCommand)
        assert sorted(vars(ours)) == sorted(vars(theirs))
        assert ours.cmd == ["true"] and ours.timeout is None
    finally:
        ours.process.wait(timeout=10)
        theirs.process.wait(timeout=10)


def test_sad_a_missing_proxy_program_raises_like_paramiko():
    from core.ssh_client import CleanEnvProxyCommand

    with pytest.raises(OSError):
        CleanEnvProxyCommand("/nonexistent/axross-proxy-probe")


def _proxy_profile(marker: Path, protocol: str):
    from core.profiles import ConnectionProfile

    # An SSH-1.0 banner ends the handshake at once ("Incompatible
    # version") instead of after paramiko's banner timeout.
    code = (f"import os, sys; open({str(marker)!r}, 'w')"
            ".write(os.environ.get('LD_LIBRARY_PATH', '<unset>')); "
            "sys.stdout.write('SSH-1.0-probe\\r\\n'); sys.stdout.flush()")
    import shlex

    return ConnectionProfile(
        name="jump", protocol=protocol, host="build.example.invalid", username="ci",
        proxy_command=shlex.join([sys.executable, "-c", code]),
    )


@pytest.mark.parametrize("protocol", ["sftp", "scp"])
def test_sad_an_ssh_session_starts_its_proxy_command_without_the_bundle_path(
        bundle_env, tmp_path, protocol):
    from core.scp_client import SCPSession
    from core.ssh_client import SSHSession

    marker = tmp_path / "seen"
    session = (SSHSession if protocol == "sftp" else SCPSession)(_proxy_profile(marker, protocol))
    with pytest.raises(Exception):  # noqa: B017 - the probe is no SSH server
        session.connect(password="pw")
    deadline = time.monotonic() + 10
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert marker.read_text() == "<unset>"


def _ssh_lab_up() -> bool:
    import socket

    try:
        with socket.create_connection(("10.99.0.10", 22), timeout=0.25):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _ssh_lab_up(), reason="SSH lab (ssh-alpha 10.99.0.10) not running; "
                    "podman-compose -p axlab -f tests/docker/docker-compose.yml up -d ssh-alpha")
def test_e2e_an_sftp_session_runs_through_a_clean_proxy_command(bundle_env, tmp_path):
    """The whole path against the lab: the jump process gets a clean
    environment and paramiko's send/recv carry a real SFTP session over it."""
    import shlex

    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    marker = tmp_path / "seen"
    code = (f"import os; open({str(marker)!r}, 'w').write(os.environ.get('LD_LIBRARY_PATH', "
            "'<unset>')); os.execvp('nc', ['nc', '10.99.0.10', '22'])")
    profile = ConnectionProfile(
        name="lab", protocol="sftp", host="10.99.0.10", port=22, username="alpha",
        proxy_command=shlex.join([sys.executable, "-c", code]),
    )
    session = SSHSession(profile)
    session.connect(password="alpha123", on_unknown_host=lambda err: True)
    try:
        assert session.connected
        assert "etc" in {item.name for item in session.list_dir("/")}
    finally:
        session.close()
    assert marker.read_text() == "<unset>"


# -- bundled extensions ---------------------------------------------------------------------


def test_sad_forensic_tools_run_without_the_bundle_path(bundle_env):
    forensic = _extension("forensic_tools")
    assert forensic._run(PROBE) == "<unset>"


def test_sad_forensic_extract_runs_icat_without_the_bundle_path(bundle_env, monkeypatch,
                                                                 probe_script, tmp_path):
    forensic = _extension("forensic_tools")
    monkeypatch.setattr(forensic, "need", lambda tool: probe_script)
    entry = forensic.parse_fls("r/r 12:\tnotes.txt\n")[0]
    out = tmp_path / "out"
    out.mkdir()
    written = forensic.extract(str(tmp_path / "disk.img"), [entry], str(out))
    assert [Path(p).read_text() for p in written] == ["<unset>"]


def test_sad_virtualbox_runs_vboxmanage_without_the_bundle_path(bundle_env):
    vbox = _extension("virtualbox")
    assert vbox.run(PROBE) == "<unset>"


def test_sad_backup_tools_run_without_the_bundle_path(bundle_env):
    repos = _extension("backup_repos")
    assert repos._run(PROBE, {"RESTIC_PASSWORD": "pw"}) == "<unset>"


def test_edge_backup_tools_still_get_the_password_and_lose_overriding_settings(bundle_env,
                                                                              monkeypatch):
    repos = _extension("backup_repos")
    monkeypatch.setenv("RESTIC_REPOSITORY", "/elsewhere")
    code = ("import os, sys; sys.stdout.write(os.environ.get('RESTIC_PASSWORD', '-') + '|' + "
            "os.environ.get('RESTIC_REPOSITORY', '-'))")
    assert repos._run([sys.executable, "-c", code], {"RESTIC_PASSWORD": "pw"}) == "pw|-"


def test_sad_drives_overview_runs_mount_without_the_bundle_path(bundle_env, monkeypatch):
    drives = _extension("drives_overview")
    rec = Recorder(stdout="/dev/disk1s1 on / (apfs, local, journaled)\n")
    monkeypatch.setattr(drives.sys, "platform", "darwin")
    monkeypatch.setitem(sys.modules, "psutil", None)  # the fallback without psutil
    monkeypatch.setattr(drives.shutil, "which", lambda name: "/sbin/mount")
    monkeypatch.setattr(drives.subprocess, "run", rec)
    assert [d.mount for d in drives.list_drives()] == ["/"]
    (argv, kwargs), = rec.calls
    assert argv == ["/sbin/mount"]
    assert "env" in kwargs and "LD_LIBRARY_PATH" not in kwargs["env"]
