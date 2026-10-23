"""Open Terminal Here / Open External Terminal Here.

* Local pane: the embedded terminal dock opens a fresh local shell in the
  folder; the external entry starts the user's terminal emulator there
  (argument list, no shell, detached, cwd set).
* SSH / SCP pane: the dock opens a shell on the pane's own transport and
  ``cd``s into the remote folder, quoted with ``shlex.quote``.
* Every other remote protocol has no shell: the entry is disabled and its
  tooltip says why.

No test here ever starts a terminal emulator: ``subprocess.Popen`` is
replaced wherever the launcher would call it.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import terminal_here as TH  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from ui import file_pane as FP  # noqa: E402
from ui.file_pane import FilePaneWidget  # noqa: E402
from ui.terminal_widget import (  # noqa: E402
    LocalTerminalSession,
    SSHTerminalSession,
    TerminalDock,
)

APP = QApplication.instance() or QApplication([])

EMBEDDED = "Open Terminal Here"
EXTERNAL = "Open External Terminal Here"
HAS_PROC = Path("/proc/self/cwd").exists()


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------


class FakeChannel:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def get_pty(self, **_kw) -> None:
        pass

    def invoke_shell(self) -> None:
        pass

    def sendall(self, data) -> None:
        self.sent.append(bytes(data))

    def recv_ready(self) -> bool:
        return False

    def recv(self, _n) -> bytes:
        return b""

    def resize_pty(self, **_kw) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    def __init__(self, active: bool = True) -> None:
        self.active = active
        self.channels: list[FakeChannel] = []

    def is_active(self) -> bool:
        return self.active

    def open_session(self) -> FakeChannel:
        channel = FakeChannel()
        self.channels.append(channel)
        return channel


class SshLikeRam(RamFsSession):
    """A RamFS that carries an SSH transport, as SSHSession / SCP do."""

    def __init__(self, transport: FakeTransport) -> None:
        super().__init__(label="ssh-like")
        self._fake_transport = transport

    @property
    def transport(self) -> FakeTransport:
        return self._fake_transport


class FakePopen:
    calls: list[tuple[list[str], dict]] = []

    def __init__(self, argv, **kwargs) -> None:
        FakePopen.calls.append((list(argv), kwargs))
        self.pid = 4242

    def wait(self, timeout=None) -> int:
        return 0


@pytest.fixture()
def popen(monkeypatch):
    FakePopen.calls = []
    monkeypatch.setattr(TH.subprocess, "Popen", FakePopen)
    return FakePopen


def _which_only(*names):
    table = {n: f"/usr/bin/{n}" for n in names}
    return lambda name: table.get(name)


def _wait(predicate, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _cwd_becomes(pid: int, expected: str, timeout: float = 3.0) -> bool:
    """The forked child chdirs right before execve; poll for it."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if os.readlink(f"/proc/{pid}/cwd") == expected:
                return True
        except OSError:
            pass
        time.sleep(0.02)
    return False


def _pane(backend, path: str):
    widget = FilePaneWidget(backend)
    widget.resize(600, 400)
    widget.show()
    APP.processEvents()
    widget.navigate(path)
    APP.processEvents()
    return widget


def _close(widget) -> None:
    widget.close()
    widget.deleteLater()
    APP.processEvents()


def _action(widget, text):
    return next((a for a in widget._build_context_menu().actions() if a.text().replace("&", "") == text), None)


# --------------------------------------------------------------------------
# core: finding and starting an external terminal
# --------------------------------------------------------------------------


def test_happy_terminal_env_wins(monkeypatch):
    monkeypatch.setattr(TH.shutil, "which", _which_only("kitty", "xterm"))
    assert TH.find_terminal({"TERMINAL": "kitty"}) == ["/usr/bin/kitty"]


def test_happy_terminal_env_with_arguments(monkeypatch):
    monkeypatch.setattr(TH.shutil, "which", _which_only("wezterm"))
    assert TH.find_terminal({"TERMINAL": "wezterm --config-file x"}) == [
        "/usr/bin/wezterm",
        "--config-file",
        "x",
    ]


def test_happy_falls_back_to_the_known_list_in_order(monkeypatch):
    monkeypatch.setattr(TH.shutil, "which", _which_only("konsole", "xterm"))
    assert TH.find_terminal({}) == ["/usr/bin/konsole"]
    monkeypatch.setattr(TH.shutil, "which", _which_only("xterm", "x-terminal-emulator"))
    assert TH.find_terminal({}) == ["/usr/bin/x-terminal-emulator"]


@pytest.mark.parametrize(
    "name, expected_tail",
    [
        ("gnome-terminal", ["--working-directory=/srv/a b"]),
        ("konsole", ["--workdir", "/srv/a b"]),
        ("xfce4-terminal", ["--working-directory=/srv/a b"]),
        ("alacritty", ["--working-directory", "/srv/a b"]),
        ("kitty", ["--directory", "/srv/a b"]),
        ("foot", ["--working-directory=/srv/a b"]),
        ("wezterm", ["start", "--cwd", "/srv/a b"]),
        ("xterm", []),
        ("x-terminal-emulator", []),
    ],
)
def test_happy_each_emulator_gets_its_working_directory_flag(name, expected_tail):
    argv = TH.terminal_command([f"/usr/bin/{name}"], "/srv/a b")
    assert argv == [f"/usr/bin/{name}"] + expected_tail


def test_happy_launch_uses_argv_cwd_and_detaches(tmp_path, monkeypatch, popen):
    monkeypatch.setattr(TH.shutil, "which", _which_only("alacritty"))
    folder = tmp_path / "it's a dir"
    folder.mkdir()
    argv = TH.launch_external_terminal(str(folder), environ={})
    assert argv == ["/usr/bin/alacritty", "--working-directory", str(folder)]
    (called, kwargs), = popen.calls
    assert called == argv
    assert kwargs["cwd"] == str(folder)
    assert kwargs.get("start_new_session") is True
    assert not kwargs.get("shell")
    assert kwargs["stdin"] == TH.subprocess.DEVNULL


def test_sad_no_terminal_found_is_a_clear_error(tmp_path, monkeypatch, popen):
    monkeypatch.setattr(TH.shutil, "which", lambda name: None)
    with pytest.raises(TH.TerminalLaunchError) as err:
        TH.launch_external_terminal(str(tmp_path), environ={"TERMINAL": "nope"})
    assert "$TERMINAL" in str(err.value)
    assert popen.calls == []


def test_sad_vanished_folder_is_refused_before_launch(tmp_path, monkeypatch, popen):
    monkeypatch.setattr(TH.shutil, "which", _which_only("xterm"))
    with pytest.raises(TH.TerminalLaunchError) as err:
        TH.launch_external_terminal(str(tmp_path / "gone"), environ={})
    assert "no longer a folder" in str(err.value)
    assert popen.calls == []


def test_sad_emulator_that_fails_to_start(tmp_path, monkeypatch):
    monkeypatch.setattr(TH.shutil, "which", _which_only("xterm"))

    def broken(*_a, **_k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(TH.subprocess, "Popen", broken)
    with pytest.raises(TH.TerminalLaunchError) as err:
        TH.launch_external_terminal(str(tmp_path), environ={})
    assert "xterm" in str(err.value)


def test_edge_file_path_opens_its_folder(tmp_path, monkeypatch, popen):
    monkeypatch.setattr(TH.shutil, "which", _which_only("xterm"))
    f = tmp_path / "a.txt"
    f.write_text("x")
    TH.launch_external_terminal(str(f), environ={})
    assert popen.calls[0][1]["cwd"] == str(tmp_path)


def test_edge_launch_reaps_the_child_without_blocking(tmp_path, monkeypatch):
    monkeypatch.setattr(TH.shutil, "which", _which_only("xterm"))
    waited = []

    class SlowPopen(FakePopen):
        def wait(self, timeout=None):
            waited.append(True)
            time.sleep(0.5)
            return 0

    monkeypatch.setattr(TH.subprocess, "Popen", SlowPopen)
    started = time.monotonic()
    TH.launch_external_terminal(str(tmp_path), environ={})
    assert time.monotonic() - started < 0.4
    assert _wait(lambda: waited, timeout=2)


# --------------------------------------------------------------------------
# core: which panes have a shell, and the remote cd line
# --------------------------------------------------------------------------


def test_happy_shell_kinds():
    assert TH.shell_kind(LocalFS()) == TH.LOCAL
    assert TH.shell_kind(SshLikeRam(FakeTransport())) == TH.SSH


def test_sad_shell_kinds_without_a_shell():
    assert TH.shell_kind(RamFsSession()) == TH.NONE
    assert TH.shell_kind(SshLikeRam(FakeTransport(active=False))) == TH.NONE
    assert "no shell" in TH.no_shell_reason(RamFsSession())


def test_happy_remote_cd_with_spaces_and_quotes_round_trips():
    path = "/srv/my dir/it's \"here\" $HOME;rm -rf"
    line = TH.remote_cd_command(path)
    assert line.startswith(b" cd -- ") and line.endswith(b"\n")
    assert shlex.split(line.decode()) == ["cd", "--", path]


def test_sad_remote_cd_refuses_control_characters():
    for bad in ("/srv/a\nrm -rf ~", "/srv/\x03x", "/srv/\x1b[2J", ""):
        with pytest.raises(ValueError):
            TH.remote_cd_command(bad)


def test_edge_remote_cd_with_a_leading_dash():
    assert shlex.split(TH.remote_cd_command("-rf").decode()) == ["cd", "--", "-rf"]


# --------------------------------------------------------------------------
# terminal sessions and the dock
# --------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_PROC, reason="needs /proc to read a process' cwd")
def test_happy_local_session_starts_in_the_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELL", "/bin/sh")
    folder = tmp_path / "a dir 'q'"
    folder.mkdir()
    session = LocalTerminalSession(cwd=str(folder))
    try:
        session.start()
        assert _cwd_becomes(session._pid, str(folder))
    finally:
        session.close()


def test_happy_ssh_session_cds_after_history_suppression():
    transport = FakeTransport()
    session = SSHTerminalSession(transport, initial_dir="/srv/my dir/it's")
    session.start()
    sent = transport.channels[0].sent
    assert sent[0].startswith(b"unset HISTFILE")
    assert sent[-1] == TH.remote_cd_command("/srv/my dir/it's")


def test_edge_ssh_session_cds_without_history_suppression():
    transport = FakeTransport()
    SSHTerminalSession(transport, suppress_history=False, initial_dir="/x").start()
    assert transport.channels[0].sent == [TH.remote_cd_command("/x")]


def test_sad_ssh_session_with_a_bad_dir_sends_no_cd():
    transport = FakeTransport()
    session = SSHTerminalSession(transport, suppress_history=False, initial_dir="/a\nb")
    session.start()
    assert transport.channels[0].sent == []


@pytest.fixture()
def dock(monkeypatch):
    monkeypatch.setenv("SHELL", "/bin/sh")
    widget = TerminalDock()
    try:
        yield widget
    finally:
        widget.shutdown()
        widget.deleteLater()
        APP.processEvents()


@pytest.mark.skipif(not HAS_PROC, reason="needs /proc to read a process' cwd")
def test_happy_dock_opens_a_local_shell_in_the_folder(dock, tmp_path):
    label = dock.open_local_shell_at(str(tmp_path))
    assert label and dock._session_combo.currentText() == label
    tab = dock._tabs[label]
    assert tab.session is not None and tab.session.is_active
    assert _cwd_becomes(tab.session._pid, str(tmp_path))
    again = dock.open_local_shell_at(str(tmp_path))
    assert again and again != label  # a second request gets its own entry


def test_sad_dock_refuses_a_vanished_local_folder(dock, tmp_path):
    count = dock._session_combo.count()
    assert dock.open_local_shell_at(str(tmp_path / "gone")) is None
    assert dock._session_combo.count() == count
    assert "no longer a folder" in dock._status_label.text()


def test_happy_dock_opens_an_ssh_shell_in_the_remote_folder(dock):
    transport = FakeTransport()
    dock.add_ssh_session("box", transport)
    label = dock.open_ssh_shell_at("box", transport, "/srv/my dir")
    assert label and "box" in label
    assert transport.channels[-1].sent[-1] == TH.remote_cd_command("/srv/my dir")
    # disconnecting the host removes the extra entry and closes its shell
    dock.remove_ssh_session("box")
    labels = [dock._session_combo.itemText(i) for i in range(dock._session_combo.count())]
    assert not any("box" in t for t in labels)
    assert transport.channels[-1].closed


def test_sad_dock_ssh_with_control_characters_opens_nothing(dock):
    transport = FakeTransport()
    assert dock.open_ssh_shell_at("box", transport, "/srv/a\nb") is None
    assert transport.channels == []
    assert "control character" in dock._status_label.text()


# --------------------------------------------------------------------------
# the pane's context menu
# --------------------------------------------------------------------------


@pytest.fixture()
def local_pane(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / "sub dir").mkdir()
    widget = _pane(LocalFS(), str(tmp_path))
    widget.open_terminal_requested.connect(lambda d: None)  # a dock is listening
    try:
        yield widget
    finally:
        _close(widget)


def test_happy_local_pane_offers_both_entries_on_empty_space(local_pane):
    texts = [a.text().replace("&", "") for a in local_pane._build_context_menu().actions()]
    assert EMBEDDED in texts and EXTERNAL in texts
    assert _action(local_pane, EMBEDDED).isEnabled()


def test_happy_file_selected_opens_its_folder(local_pane, tmp_path):
    seen = []
    local_pane.open_terminal_requested.connect(seen.append)
    local_pane._restore_selection({"a.txt"}, "a.txt")
    _action(local_pane, EMBEDDED).trigger()
    assert seen == [str(tmp_path)]


def test_happy_folder_selected_opens_that_folder(local_pane, tmp_path):
    seen = []
    local_pane.open_terminal_requested.connect(seen.append)
    local_pane._restore_selection({"sub dir"}, "sub dir")
    _action(local_pane, EMBEDDED).trigger()
    assert seen == [str(tmp_path / "sub dir")]


def test_happy_external_entry_launches_in_the_folder(local_pane, tmp_path, monkeypatch, popen):
    monkeypatch.setattr(TH.shutil, "which", _which_only("xterm"))
    monkeypatch.delenv("TERMINAL", raising=False)
    _action(local_pane, EXTERNAL).trigger()
    assert popen.calls[0][0] == ["/usr/bin/xterm"]
    assert popen.calls[0][1]["cwd"] == str(tmp_path)


def test_sad_no_terminal_emulator_shows_a_message(local_pane, monkeypatch, popen):
    monkeypatch.setattr(TH.shutil, "which", lambda name: None)
    shown = []
    monkeypatch.setattr(FP.QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    _action(local_pane, EXTERNAL).trigger()
    assert shown and "terminal emulator" in shown[0]
    assert popen.calls == []


def test_sad_vanished_folder_shows_a_message_and_emits_nothing(local_pane, tmp_path, monkeypatch):
    seen, shown = [], []
    local_pane.open_terminal_requested.connect(seen.append)
    monkeypatch.setattr(FP.QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    local_pane._restore_selection({"sub dir"}, "sub dir")
    (tmp_path / "sub dir").rmdir()
    _action(local_pane, EMBEDDED).trigger()
    assert seen == []
    assert shown and "no longer a folder" in shown[0]


def test_sad_non_ssh_remote_entry_is_disabled_with_a_reason():
    ram = RamFsSession()
    widget = _pane(ram, "/")
    widget.open_terminal_requested.connect(lambda d: None)
    try:
        action = _action(widget, EMBEDDED)
        assert action is not None and not action.isEnabled()
        assert "no shell" in action.toolTip()
        assert _action(widget, EXTERNAL) is None
    finally:
        _close(widget)


def test_edge_ssh_pane_emits_the_remote_folder_with_spaces_and_quotes():
    backend = SshLikeRam(FakeTransport())
    backend.mkdir("/srv")
    backend.mkdir("/srv/it's a dir")
    widget = _pane(backend, "/srv/it's a dir")
    seen = []
    widget.open_terminal_requested.connect(seen.append)
    try:
        action = _action(widget, EMBEDDED)
        assert action.isEnabled()
        action.trigger()
        assert seen == ["/srv/it's a dir"]
    finally:
        _close(widget)


def test_edge_without_a_terminal_dock_the_entry_is_disabled(tmp_path):
    widget = _pane(LocalFS(), str(tmp_path))
    try:
        action = _action(widget, EMBEDDED)
        assert not action.isEnabled()
        assert action.toolTip()
    finally:
        _close(widget)


# --------------------------------------------------------------------------
# the main window routes the request to the dock
# --------------------------------------------------------------------------


@pytest.fixture()
def window(monkeypatch):
    from ui import main_window as MW

    monkeypatch.setenv("SHELL", "/bin/sh")
    home = Path(tempfile.mkdtemp())
    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    session = mock.patch.object(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    session.start()
    try:
        yield win
    finally:
        win._terminal_dock.shutdown()
        win.close()
        win.deleteLater()
        APP.processEvents()
        session.stop()
        shutil.rmtree(home, ignore_errors=True)


@pytest.mark.skipif(not HAS_PROC, reason="needs /proc to read a process' cwd")
def test_happy_main_window_opens_the_dock_in_the_local_folder(window, tmp_path):
    pane = window._panes[0]
    pane.navigate(str(tmp_path))
    APP.processEvents()
    _action(pane, EMBEDDED).trigger()
    dock = window._terminal_dock
    label = dock._session_combo.currentText()
    tab = dock._tabs[label]
    assert tab.session is not None and tab.session.is_active
    assert _cwd_becomes(tab.session._pid, str(tmp_path))


def test_happy_main_window_opens_an_ssh_shell_for_an_ssh_pane(window):
    transport = FakeTransport()
    backend = SshLikeRam(transport)
    backend.mkdir("/home")
    backend.mkdir("/home/me and you")
    pane = window._add_pane_to_splitter(window._root_splitter, backend)
    pane.navigate("/home/me and you")
    APP.processEvents()
    _action(pane, EMBEDDED).trigger()
    assert transport.channels, "no shell was opened on the pane's transport"
    assert transport.channels[-1].sent[-1] == TH.remote_cd_command("/home/me and you")


# --- round-2 verification: a working folder typed as ~/... (terminal bookmarks) ------


def _bash_cwd(line: bytes, home) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "--norc", "--noprofile", "-c", line.decode() + " pwd"],
        capture_output=True, text=True, env={"HOME": str(home), "PATH": os.environ["PATH"]},
        cwd=str(home.parent), timeout=10,
    )


def test_happy_remote_cd_expands_the_home_tilde(tmp_path):
    """A terminal bookmark's folder is typed by hand, and ~/ is how a shell
    user names the home folder: the remote shell must expand it, while the
    rest stays quoted."""
    home = tmp_path / "home"
    (home / "my dir").mkdir(parents=True)
    done = _bash_cwd(TH.remote_cd_command("~/my dir"), home)
    assert done.stdout.strip() == str(home / "my dir"), done
    done = _bash_cwd(TH.remote_cd_command("~"), home)
    assert done.stdout.strip() == str(home), done


def test_sad_the_part_after_the_tilde_stays_quoted(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    marker = tmp_path / "ran"
    done = _bash_cwd(TH.remote_cd_command(f"~/$(touch {marker})"), home)
    assert not marker.exists() and done.returncode == 0, done
    with pytest.raises(ValueError):
        TH.remote_cd_command("~/a\nrm -rf ~")


def test_edge_other_tilde_forms_stay_literal():
    """Only ~ and ~/... name the home folder here; ~user and a ~ inside a
    name are literal, as for every absolute path a pane sends."""
    for path in ("~other/x", "/srv/~/x", "~x"):
        assert shlex.split(TH.remote_cd_command(path).decode()) == ["cd", "--", path]
        assert b"'" in TH.remote_cd_command(path)
