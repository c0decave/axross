"""The local terminal runs on Windows through pywinpty's PtyProcess.

Windows has no ``pty`` module; ``LocalTerminalSession`` then starts the
shell (``COMSPEC``) in a ConPTY via ``winpty.PtyProcess``. The fake below
follows the API of pywinpty 3.1.0 as read from its wheel
(``winpty/ptyprocess.py``): ``spawn(argv, cwd, env, dimensions)``,
``read(size) -> str`` raising ``EOFError`` once closed, ``write(str)``,
``setwinsize(rows, cols)``, ``close(force)``, ``fileno()`` - a socket,
which ``select`` can wait on under Windows as well.
"""

from __future__ import annotations

import socket
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ui import terminal_widget as TW  # noqa: E402


class _FakePtyProcess:
    spawned: list[dict] = []

    def __init__(self) -> None:
        self._ours, self._theirs = socket.socketpair()
        self.pid = 4242
        self.written: list[str] = []
        self.sizes: list[tuple[int, int]] = []
        self.closed_with: bool | None = None

    @classmethod
    def spawn(cls, argv, cwd=None, env=None, dimensions=(24, 80)):
        inst = cls()
        cls.spawned.append(
            {"argv": argv, "cwd": cwd, "env": env, "dimensions": dimensions, "proc": inst}
        )
        return inst

    def emit(self, text: str) -> None:  # test helper: the shell prints
        self._theirs.sendall(text.encode("utf-8"))

    def hang_up(self) -> None:  # test helper: the shell exits
        self._theirs.close()

    def fileno(self) -> int:
        return self._ours.fileno()

    def read(self, size=1024) -> str:
        data = self._ours.recv(size)
        if not data:
            raise EOFError("Pty is closed")
        return data.decode("utf-8")

    def write(self, s: str) -> int:
        self.written.append(s)
        return len(s)

    def setwinsize(self, rows, cols) -> None:
        self.sizes.append((rows, cols))

    def close(self, force=False) -> None:
        self.closed_with = force
        self._ours.close()


@pytest.fixture
def windows(monkeypatch):
    """No pty module; a fake winpty module in its place."""
    monkeypatch.setitem(sys.modules, "pty", None)
    fake = types.ModuleType("winpty")
    fake.PtyProcess = _FakePtyProcess
    monkeypatch.setitem(sys.modules, "winpty", fake)
    monkeypatch.setenv("COMSPEC", r"C:\Windows\system32\cmd.exe")
    _FakePtyProcess.spawned = []
    yield
    for s in _FakePtyProcess.spawned:
        try:
            s["proc"]._theirs.close()
        except OSError:
            pass


def _started(cwd=None):
    session = TW.LocalTerminalSession(cwd=cwd)
    session.start()
    return session, _FakePtyProcess.spawned[-1]


# --- happy ----------------------------------------------------------------


def test_happy_the_shell_starts_in_a_conpty_in_the_folder(windows, tmp_path):
    session, spawned = _started(cwd=str(tmp_path))
    assert session.is_active
    assert spawned["argv"] == [r"C:\Windows\system32\cmd.exe"]
    assert spawned["cwd"] == str(tmp_path)
    assert spawned["env"]["TERM"] == "xterm"
    session.close()


def test_happy_output_reads_as_bytes_and_input_writes_as_text(windows):
    session, spawned = _started()
    spawned["proc"].emit("C:\\Users\\alex> ")
    assert session.read() == "C:\\Users\\alex> ".encode()
    session.write(b"dir\r\n")
    assert spawned["proc"].written == ["dir\r\n"]
    session.resize(40, 120)
    assert spawned["proc"].sizes == [(40, 120)]
    session.close()
    assert spawned["proc"].closed_with is True
    assert not session.is_active


# --- sad ------------------------------------------------------------------


def test_sad_without_pywinpty_the_refusal_names_it(monkeypatch):
    monkeypatch.setitem(sys.modules, "pty", None)
    monkeypatch.setitem(sys.modules, "winpty", None)
    with pytest.raises(OSError, match="pywinpty"):
        TW.LocalTerminalSession().start()


def test_sad_a_shell_that_exits_ends_the_session(windows):
    session, spawned = _started()
    spawned["proc"].hang_up()
    assert session.read() == b""
    assert not session.is_active
    session.close()  # closing an ended session is harmless


# --- edge -----------------------------------------------------------------


def test_edge_nothing_to_read_returns_empty_without_blocking(windows):
    session, _spawned = _started()
    assert session.read() == b""
    assert session.is_active
    session.close()


def test_edge_undecodable_input_is_replaced_not_raised(windows):
    session, spawned = _started()
    session.write(b"caf\xe9\r\n")
    assert spawned["proc"].written == ["caf\ufffd\r\n"]
    session.close()
