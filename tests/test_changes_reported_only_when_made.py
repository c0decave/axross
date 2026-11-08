"""Changes reported as success that did not happen (review round 3).

* PJL: remove() of a missing file, of a folder with entries (with or
  without ``recursive``) sent FSDELETE, never read the answer and
  returned None - nothing was deleted. mkdir() returned normally when the
  firmware ignored FSMKDIR. Both check the device's listing afterwards.
* SLP: stat() never asked the directory agent - every name "existed",
  even with the network down.
* Telnet, RSH, ADB: ``rm -f`` said nothing about a path that was not
  there; remove() of a missing path "worked". FileNotFoundError now.
* Telnet: cp / mv / rm -rf ran under the 30 s command timeout and, on a
  timeout, were sent a second time after a reconnect - a long copy was
  reported failed while it was still running, then started again.
* Telnet / SCP stat: a ``|`` in a name broke the parse of GNU stat's
  ``%n|%s|...`` answer.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import ScriptedServer  # noqa: E402

from core import pjl_client as PJ  # noqa: E402

# -- PJL ---------------------------------------------------------------------

UEL = PJ.UEL
STATUS = b"@PJL INFO STATUS\r\nCODE=10001\r\n"
PROBE = b'@PJL INFO ID\r\n"HP LaserJet"\r\n' + STATUS + b"\x0c" + UEL
LISTINGS = {b"0:/": b"PJL TYPE=DIR\r\nreport.txt TYPE=FILE SIZE=5\r\n", b"0:/PJL": b"jobs TYPE=DIR\r\n"}


@pytest.fixture
def printer():
    """A device that refuses every FSDELETE (status 32xx, as for a
    missing file or a folder with entries) and changes nothing."""
    sent: list[bytes] = []

    def handle(conn):
        conn.settimeout(5)
        buf = b""
        while buf.count(UEL) < 2:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        sent.append(buf)
        if b"FSDELETE" in buf:
            conn.sendall(
                b'@PJL INFO STATUS\r\nCODE=32xx\r\nDISPLAY="FILE SYSTEM ERROR"\r\n'
                b"ONLINE=TRUE\r\n\x0c" + UEL
            )
            return
        if b"FSDIRLIST" not in buf:
            conn.sendall(PROBE)
            return
        name = buf.split(b'NAME="', 1)[1].split(b'"', 1)[0]
        conn.sendall(
            STATUS + b'@PJL FSDIRLIST NAME="' + name + b'" ENTRY=1\r\n'
            + LISTINGS.get(name, b"FILEERROR=3\r\n") + b"\x0c" + UEL
        )

    srv = ScriptedServer(handle)
    yield PJ.PjlSession("127.0.0.1", srv.port, timeout=1.0), sent
    srv.close()


def _deletes(sent) -> int:
    return sum(b"FSDELETE" in b for b in sent)


def test_sad_pjl_remove_of_a_missing_file_raises(printer) -> None:
    s, sent = printer
    with pytest.raises(FileNotFoundError):
        s.remove("/gone.txt")
    assert _deletes(sent) == 0


def test_sad_pjl_remove_of_a_folder_with_entries_raises(printer) -> None:
    s, sent = printer
    with pytest.raises(OSError) as info:
        s.remove("/PJL")
    assert "not empty" in str(info.value)
    assert _deletes(sent) == 0
    # recursive: the entries first; the device refusing them is an error
    with pytest.raises(OSError, match="still there"):
        s.remove("/PJL", recursive=True)
    assert b'NAME="0:/PJL/jobs"' in next(b for b in sent if b"FSDELETE" in b)


def test_sad_pjl_mkdir_ignored_by_the_firmware_raises(monkeypatch) -> None:
    s = PJ.PjlSession.__new__(PJ.PjlSession)
    s._safety_probed = True
    s._volume, s._host, s._port, s._proxy, s._timeout = "0:", "printer", 9100, None, 5

    class Sock:
        def close(self):
            pass

    monkeypatch.setattr(PJ, "_open_socket", lambda *a, **k: Sock())
    monkeypatch.setattr(PJ, "_send_pjl", lambda sock, cmd: None)
    monkeypatch.setattr(PJ, "_recv_until", lambda sock, uel, max_bytes=0: STATUS + UEL)
    monkeypatch.setattr(s, "stat", lambda path: (_ for _ in ()).throw(FileNotFoundError(path)))
    with pytest.raises(OSError, match="FSMKDIR"):
        s.mkdir("/newdir")


# -- SLP ---------------------------------------------------------------------


def _slp():
    from core import slp_client as S

    s = object.__new__(S.SlpSession)
    s._types_cache = ["service:printer"]
    s._urls_cache = {"service:printer": [("service:printer:lpr://h/q", 60)]}

    def unreachable(packet):
        raise OSError("network unreachable")

    s._query = unreachable
    return s


def test_sad_slp_stat_asks_the_directory_agent() -> None:
    s = _slp()
    for path in ("/no-such-type", "/service_printer/ghost.attrs", "/a/b/c"):
        assert s.exists(path) is False
        assert s.is_dir(path) is False
        with pytest.raises(FileNotFoundError):
            s.stat(path)
    listed = s.list_dir("/service_printer")[0].name
    assert s.exists(f"/service_printer/{listed}") and s.is_dir("/service_printer")


def test_sad_slp_exists_with_the_network_down_raises() -> None:
    s = _slp()
    s._types_cache = None
    s._scope = b"DEFAULT"
    with pytest.raises(OSError) as info:
        s.exists("/x")
    assert not isinstance(info.value, FileNotFoundError)


# -- Telnet / RSH / ADB: remove of a missing path -------------------------------


def _sh(cmd: str) -> tuple[str, int]:
    p = subprocess.run(
        ["sh", "-c", cmd + " 2>&1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30
    )
    return p.stdout.decode("utf-8", "replace"), p.returncode


class _LocalShell:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def execute(self, cmd, timeout=30):
        self.timeouts.append(timeout)
        return _sh(cmd)

    def execute_checked(self, cmd, timeout=30):
        out, code = self.execute(cmd, timeout)
        if code:
            from core.telnet_client import CommandFailed

            raise CommandFailed(out)
        return out


def _telnet(shell):
    from core.telnet_client import TelnetSession

    s = object.__new__(TelnetSession)
    s._shell = shell
    s._connected = True
    s._ensure_connected = lambda: s._shell
    s._force_reconnect = lambda: (_ for _ in ()).throw(AssertionError("sent a second time"))
    return s


def _rsh():
    from core.rsh_client import RshSession

    s = RshSession.__new__(RshSession)
    s._host = "h"

    def run_status(cmd, stdin=None, timeout=None):
        p = subprocess.run(["sh", "-c", cmd], capture_output=True, timeout=30)
        return p.returncode, p.stdout, p.stderr

    s._run_status = run_status
    return s


def _adb():
    from core.adb_client import AdbSession

    s = AdbSession.__new__(AdbSession)
    s._shell = lambda cmd: _sh(cmd)[0]
    return s


@pytest.mark.parametrize("make", [lambda: _telnet(_LocalShell()), _rsh, _adb],
                         ids=["telnet", "rsh", "adb"])
@pytest.mark.parametrize("recursive", [False, True], ids=["file", "recursive"])
def test_sad_shell_remove_of_a_missing_path_raises(tmp_path, make, recursive) -> None:
    s = make()
    with pytest.raises(FileNotFoundError):
        s.remove(str(tmp_path / "gone.txt"), recursive=recursive)
    (tmp_path / "here.txt").write_text("x")
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "f").write_text("x")
    s.remove(str(tmp_path / "here.txt"), recursive=recursive)
    assert not (tmp_path / "here.txt").exists()
    with pytest.raises(OSError):
        s.remove(str(tmp_path / "dir"), recursive=False)  # not empty
    s.remove(str(tmp_path / "dir"), recursive=True)
    assert not (tmp_path / "dir").exists()


# -- Telnet: long tree operations ----------------------------------------------


def test_sad_telnet_copy_move_delete_have_the_long_timeout(tmp_path) -> None:
    from core.telnet_client import CMD_TIMEOUT, TREE_OP_TIMEOUT

    shell = _LocalShell()
    s = _telnet(shell)
    (tmp_path / "a").write_text("x")
    s.copy(str(tmp_path / "a"), str(tmp_path / "b"))
    s.rename(str(tmp_path / "b"), str(tmp_path / "c"))
    s.remove(str(tmp_path / "c"), recursive=True)
    assert shell.timeouts == [TREE_OP_TIMEOUT] * 3
    assert TREE_OP_TIMEOUT > CMD_TIMEOUT


def test_sad_telnet_timed_out_copy_is_not_sent_again() -> None:
    class SlowShell:
        calls = 0

        def execute(self, cmd, timeout=30):
            SlowShell.calls += 1
            raise TimeoutError("no marker")

    s = _telnet(SlowShell())
    with pytest.raises(TimeoutError, match="may still be running"):
        s.copy("/big.iso", "/copy.iso")
    assert SlowShell.calls == 1


def test_sad_stat_of_a_name_with_a_pipe() -> None:
    from core.telnet_client import _parse_stat_gnu

    item = _parse_stat_gnu("/data/a|b.txt|5|1767268800|81a4|u|u|regular file")
    assert (item.name, item.size, item.owner, item.is_dir) == ("a|b.txt", 5, "u", False)
    with mock.patch("core.telnet_client.TelnetSession._exec_raw") as exec_:
        exec_.return_value = ("/x/p|q|7|1767268800|41ed|u|g|directory", 0)
        from core.telnet_client import TelnetSession, _Capabilities

        s = object.__new__(TelnetSession)
        s._caps = _Capabilities(has_stat_gnu=True)
        st = s.stat("/x/p|q")
    assert (st.name, st.is_dir, st.group) == ("p|q", True, "g")
