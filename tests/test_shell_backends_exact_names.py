"""Shell backends (Telnet, RSH, ADB; SCP shares the Telnet parser): paths
with control characters, and names with blanks or line breaks.

Review round 3 found:

* Telnet sends each command into the server's terminal. ``shlex.quote``
  protects against the shell, not against the line discipline in front
  of it: ``^U`` erased the quoted prefix of ``"report\\x15touch PWNED"``
  and the rest ran as a command of its own. Every Telnet, RSH and ADB
  operation now refuses a path with a C0 control character or DEL
  (``core.path_policy.refuse_control_chars``) before it builds a command.
* The ``ls -la`` parsers stripped each line and took ``\\s+`` before the
  name, so ``"report "`` and ``" notes"`` were listed as ``"report"`` and
  ``"notes"``: a delete of the listed entry removed ANOTHER file. A name
  with a line break was cut to its first line. The name is now exactly
  what follows the single space after the date, and a name with a line
  break keeps its other lines (listed, then refused where it is used).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.adb_client import AdbSession  # noqa: E402
from core.rsh_client import RshSession  # noqa: E402
from core.telnet_client import (  # noqa: E402
    TelnetSession,
    _Capabilities,
    _parse_ls_la,
    _ShellSession,
)

EVIL = "/tmp/report\x15touch PWNED #.txt"


class _RecordingShell:
    """A Telnet shell that answers every command with success."""

    def __init__(self, answer: str = "") -> None:
        self.sent: list[str] = []
        self.answer = answer

    def execute(self, cmd, timeout=30):
        self.sent.append(cmd)
        return self.answer, 0

    def execute_checked(self, cmd, timeout=30):
        self.sent.append(cmd)
        return self.answer


def _telnet(shell=None, caps=None) -> TelnetSession:
    s = object.__new__(TelnetSession)
    s._shell = shell or _RecordingShell()
    s._caps = caps or _Capabilities(has_readlink=True, has_chmod=True, has_df=True)
    s._connected = True
    s._transport = None
    s._ensure_connected = lambda: s._shell
    s._force_reconnect = lambda: s._shell
    return s


_TELNET_OPS = {
    "list_dir": lambda s, p: s.list_dir(p),
    "stat": lambda s, p: s.stat(p),
    "exists": lambda s, p: s.exists(p),
    "is_dir": lambda s, p: s.is_dir(p),
    "mkdir": lambda s, p: s.mkdir(p),
    "remove": lambda s, p: s.remove(p),
    "remove_recursive": lambda s, p: s.remove(p, recursive=True),
    "rename_src": lambda s, p: s.rename(p, "/tmp/ok"),
    "rename_dst": lambda s, p: s.rename("/tmp/ok", p),
    "copy_src": lambda s, p: s.copy(p, "/tmp/ok"),
    "copy_dst": lambda s, p: s.copy("/tmp/ok", p),
    "open_read": lambda s, p: s.open_read(p),
    "open_write": lambda s, p: s.open_write(p).close(),
    "chmod": lambda s, p: s.chmod(p, 0o644),
    "readlink": lambda s, p: s.readlink(p),
    "checksum": lambda s, p: s.checksum(p),
    "disk_usage": lambda s, p: s.disk_usage(p),
}


@pytest.mark.parametrize("op", sorted(_TELNET_OPS))
def test_sad_telnet_control_character_path_sends_no_command(op) -> None:
    """Every Telnet operation refused a ^U path only after the terminal
    had run its tail as a command - remove() above all."""
    shell = _RecordingShell()
    s = _telnet(shell)
    with pytest.raises(OSError, match="control characters"):
        _TELNET_OPS[op](s, EVIL)
    assert shell.sent == []


@pytest.mark.parametrize("char", ["\x03", "\x09", "\x0a", "\x0d", "\x16", "\x17", "\x7f"])
def test_sad_telnet_every_line_editing_character_is_refused(char) -> None:
    """^C, TAB (completion), LF, CR, ^V, ^W, DEL: not only ^U."""
    shell = _RecordingShell()
    with pytest.raises(OSError):
        _telnet(shell).remove(f"/tmp/a{char}b")
    assert shell.sent == []
    # Blanks and non-ASCII are no control characters.
    _telnet(shell).remove("/tmp/Grüße – ✓ report .txt")
    assert len(shell.sent) == 1 and "Grüße" in shell.sent[0]


def test_edge_refuse_control_chars_helper() -> None:
    """The one shared rule: C0 and DEL out, everything else (blanks,
    non-ASCII, a backslash) passes unchanged."""
    import errno

    from core.path_policy import refuse_control_chars

    assert refuse_control_chars("/a b/ü\\x.txt ") == "/a b/ü\\x.txt "
    with pytest.raises(OSError) as info:
        refuse_control_chars("/a\x00b", "X")
    assert info.value.errno == errno.EINVAL and "X:" in str(info.value)
    for code in list(range(32)) + [127]:
        with pytest.raises(OSError):
            refuse_control_chars(f"/a{chr(code)}b")


def test_sad_telnet_injection_on_a_real_terminal(tmp_path) -> None:
    """The repro of the finding: a local sh on a pseudo-terminal in
    canonical mode (what telnetd gives). remove() of a ^U name ran
    ``touch PWNED``; now it is refused and the shell runs nothing."""
    import pty
    import re
    import secrets
    import select
    import threading
    import time

    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - the child
        os.chdir(tmp_path)
        os.execv("/bin/sh", ["sh"])

    class PtyTransport:
        def send(self, data):
            raw = data.replace("\r\n", "\n").replace("\r", "\n")
            os.write(fd, (raw if raw.endswith("\n") else raw + "\n").encode())

        def read_until_re(self, pattern, timeout=30):
            end = time.monotonic() + timeout
            text = ""
            while time.monotonic() < end:
                ready, _, _ = select.select([fd], [], [], 0.2)
                if ready:
                    text += os.read(fd, 65536).decode("utf-8", "replace")
                    m = pattern.search(text)
                    if m:
                        return text, m
            raise TimeoutError("no marker")

    try:
        sh = object.__new__(_ShellSession)
        sh._transport = PtyTransport()
        sh._marker_id = secrets.token_hex(8)
        sh._seq = 0
        sh._lock = threading.RLock()
        sh._transport.send("stty -echo; PS1=''; PS2=''")
        time.sleep(0.3)
        s = _telnet(sh)
        with pytest.raises(OSError):
            s.remove(str(tmp_path / "report\x15touch PWNED #.txt"))
        out, code = sh.execute("echo alive", timeout=10)
        assert code == 0 and re.search("alive", out)
        assert not (tmp_path / "PWNED").exists()
    finally:
        os.kill(pid, 9)
        os.waitpid(pid, 0)


def test_sad_rsh_control_character_path_runs_nothing() -> None:
    """rsh refused only CR / LF / NUL."""
    s = RshSession.__new__(RshSession)
    with mock.patch.object(RshSession, "_run_status", return_value=(0, b"", b"")) as run:
        for call in (
            lambda: s.remove("/tmp/a\x15b"),
            lambda: s.rename("/tmp/a", "/tmp/a\x17b"),
            lambda: s.list_dir("/tmp/a\x16b"),
            lambda: s.open_write("/tmp/a\tb"),
        ):
            with pytest.raises(OSError, match="control characters"):
                call()
        assert run.call_count == 0


def test_sad_adb_control_character_path_runs_nothing() -> None:
    sent: list[str] = []
    s = AdbSession.__new__(AdbSession)
    s._shell = lambda cmd: sent.append(cmd) or ""
    for call in (
        lambda: s.remove("/sdcard/a\x15b"),
        lambda: s.rename("/sdcard/a\x15b", "/sdcard/c"),
        lambda: s.copy("/sdcard/a", "/sdcard/c\x15"),
        lambda: s.mkdir("/sdcard/a\x15b"),
        lambda: s.stat("/sdcard/a\x15b"),
        lambda: s.open_read("/sdcard/a\x15b"),
        lambda: s.open_write("/sdcard/a\x15b"),
    ):
        with pytest.raises(OSError, match="control characters"):
            call()
    assert sent == []


# --- names with blanks and line breaks ---------------------------------------


@pytest.fixture
def blank_tree(tmp_path):
    (tmp_path / "report").write_text("KEEP ME")
    (tmp_path / "report ").write_text("delete me")
    (tmp_path / " notes").write_text("n")
    return tmp_path


def _gnu_ls(folder, *flags: str, iso: bool = False) -> str:
    argv = ["ls", "-la", *flags]
    if iso:
        argv.append("--time-style=+%Y-%m-%d %H:%M")
    env = {"LC_ALL": "C", "QUOTING_STYLE": "literal", "TZ": "UTC0", "PATH": os.environ["PATH"]}
    return subprocess.run(
        [*argv, f"{folder}/"], capture_output=True, text=True, env=env, check=True
    ).stdout


def test_sad_shared_parser_keeps_blanks_around_names(blank_tree) -> None:
    """Telnet's and SCP's parser listed "report " as "report"."""
    names = sorted(i.name for i in _parse_ls_la(_gnu_ls(blank_tree)))
    assert names == [" notes", "report", "report "]


def test_sad_scp_delete_of_listed_entry_removes_that_entry(blank_tree) -> None:
    """The listed "report" of size 9 was "report " on disk; SCP's
    remove() of the listed name deleted the OTHER file, "report"."""
    from core.scp_client import SCPSession, _Capabilities as ScpCaps

    s = SCPSession.__new__(SCPSession)
    s._caps = ScpCaps()
    s._exec = lambda cmd, timeout=None: _gnu_ls(blank_tree)
    victim = next(i for i in s.list_dir(str(blank_tree)) if i.size == 9)
    assert victim.name == "report "


def test_sad_rsh_listing_keeps_blanks(blank_tree) -> None:
    s = RshSession.__new__(RshSession)
    out = _gnu_ls(blank_tree).encode()
    with mock.patch.object(RshSession, "_run_remote", return_value=out):
        names = sorted(i.name for i in s.list_dir(str(blank_tree)))
    assert names == [" notes", "report", "report "]


def test_sad_adb_listing_keeps_blanks(blank_tree) -> None:
    s = AdbSession.__new__(AdbSession)
    out = _gnu_ls(blank_tree, iso=True)
    s._shell = lambda cmd: out
    names = sorted(i.name for i in s.list_dir("/sdcard/x"))
    assert names == [" notes", "report", "report "]


def test_sad_rsh_stat_of_name_with_trailing_blank() -> None:
    """stat() matched the stripped name against the path: "unreadable"."""
    s = RshSession.__new__(RshSession)
    path = "/data/report "
    answer = f"-rw-r--r-- 1 u g 9 Jan  1  2020 {path}\n".encode()
    with mock.patch.object(RshSession, "_run_status", return_value=(0, answer, b"")):
        assert s.stat(path).name == "report "


def test_sad_telnet_answer_keeps_trailing_blanks() -> None:
    """_ShellSession.execute stripped the whole answer: the last name of
    a listing ("report ") lost its blank there even with a fixed parser."""
    import re
    import threading

    class Transport:
        def send(self, data):
            self.cmd = data

        def read_until_re(self, pattern, timeout=30):
            start = re.search(r"echo '([^']+)'", self.cmd).group(1)
            tag = start[len("__AXX_CMD_START_"):-2]
            text = f"{start}\nline one\n-rw-r--r-- 1 u g 9 Jan  1  2020 report \n__AXX_CMD_EXIT_{tag}_0__"
            return text, pattern.search(text)

    sh = object.__new__(_ShellSession)
    sh._transport = Transport()
    sh._marker_id = "abc"
    sh._seq = 0
    sh._lock = threading.RLock()
    out, code = sh.execute("ls")
    assert code == 0 and out.endswith("report ")


def test_edge_name_with_line_break_is_listed_whole_and_refused(tmp_path) -> None:
    """ "a\\nb" was listed as "a" (another file, or none); now it is
    listed whole and every Telnet operation on it is refused."""
    (tmp_path / "a\nb").write_text("x")
    (tmp_path / "a").write_text("other")
    (tmp_path / "z").write_text("z")
    items = _parse_ls_la(_gnu_ls(tmp_path))
    assert sorted(i.name for i in items) == ["a", "a\nb", "z"]
    shell = _RecordingShell()
    with pytest.raises(OSError):
        _telnet(shell).remove(str(tmp_path / "a\nb"))
    assert shell.sent == []
    s = RshSession.__new__(RshSession)
    with mock.patch.object(RshSession, "_run_remote", return_value=_gnu_ls(tmp_path).encode()):
        assert sorted(i.name for i in s.list_dir(str(tmp_path))) == ["a", "a\nb", "z"]


def test_happy_telnet_escaped_listing_round_trips(tmp_path) -> None:
    """With ``ls -b`` (escape style) every name comes back as it is on
    disk - blanks, a backslash, control characters, a link target."""
    for name in (" notes", "report ", "x\\y", "c\x15d", "tab\tx", "q?r", "ü→v"):
        (tmp_path / name).write_text("x")
    os.symlink("tar get ", tmp_path / "li nk")
    items = _parse_ls_la(_gnu_ls(tmp_path, "-b"), escaped=True)
    assert sorted(i.name for i in items) == sorted(os.listdir(tmp_path))
    link = next(i for i in items if i.name == "li nk")
    assert link.link_target == "tar get "


def test_happy_telnet_list_dir_runs_escaped_utc_ls(tmp_path) -> None:
    (tmp_path / "report ").write_text("x")
    calls: list[str] = []

    class Shell(_RecordingShell):
        def execute_checked(self, cmd, timeout=30):
            calls.append(cmd)
            return _gnu_ls(tmp_path, "-b")

    s = _telnet(Shell(), _Capabilities(has_ls_escape=True))
    assert [i.name for i in s.list_dir(str(tmp_path))] == ["report "]
    assert calls[0].startswith("TZ=UTC0 ls -lab ")
