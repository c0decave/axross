"""Cisco IOS over Telnet (core.telnet_cisco) against a fake IOS line.

* A wrong password: IOS answers "% Login invalid" (or "% Bad passwords")
  and asks again; the session waited for a prompt until its 15 s time-out
  and said "did not answer in time". It is a refused login now, at once.
* The end of an answer was any line that LOOKED like a prompt
  (``\\nword#`` or ``\\nword>``) at the end of a read: output that paused
  right after such a line (a banner, a config line, a log message) came
  back cut short. The device's own prompt, learnt at login, ends it now.
* Two threads (a preview and a copy) sent their commands on the one line
  at the same time and read each other's answers: one command at a time.
* ``address_family`` is honoured ("ipv6" never reaches an IPv4 address).

Round 2: a line that is the device's OWN prompt (a banner or log line
"R1>") ended an answer that paused right after it; the rest came back as
the next command's answer, and every answer after it was the one before.
Each command is now followed by a marker command with a random word, and
the answer ends at the prompt in front of the marker's echo.
``clear counters`` asks "[confirm]" and waited for an Enter it never got
(300 s, then the line was closed); it is answered now.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from core.telnet_cisco import CiscoTelnetSession

VERSION = "Cisco IOS Software, C2960 Software, Version 15.0(2)SE\r\nR1 uptime is 1 day"
# A config whose output pauses right after a line that looks like a prompt.
CONFIG_PART1 = "Building configuration...\r\n!\r\nbanner motd ^C\r\nwelcome#"
CONFIG_PART2 = "\r\n^C\r\nhostname R1\r\nend"
# A log whose output pauses right after a line that IS the device's prompt.
LOG_PART1 = "Log Buffer (4096 bytes):\r\nbanner says:\r\nR1>"
LOG_PART2 = "\r\n*Mar  1 00:00:01: %SYS-5-CONFIG_I: Configured\r\nlast line"


class FakeIos:
    def __init__(self, password: str = "pw") -> None:
        self.password = password
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.commands: list[str] = []
        self.busy = threading.Lock()
        self.overlap = False
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        try:
            self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.listener.close()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _line(conn) -> str | None:
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                return None
            data += chunk
        return data.decode().strip()

    def _serve(self, conn) -> None:
        conn.settimeout(30)
        try:
            conn.sendall(b"\r\nUser Access Verification\r\n\r\nUsername: ")
            while True:
                if self._line(conn) is None:
                    return
                conn.sendall(b"Password: ")
                if self._line(conn) == self.password:
                    break
                conn.sendall(b"\r\n% Login invalid\r\n\r\nUsername: ")
            conn.sendall(b"\r\nR1>")
            while True:
                cmd = self._line(conn)
                if cmd is None:
                    return
                if not self.busy.acquire(blocking=False):
                    self.overlap = True
                    self.busy.acquire()
                try:
                    self.commands.append(cmd)
                    conn.sendall(cmd.encode() + b"\r\n")
                    if cmd == "show running-config":
                        conn.sendall(CONFIG_PART1.encode())
                        time.sleep(0.6)
                        conn.sendall(CONFIG_PART2.encode())
                    elif cmd == "show logging":
                        conn.sendall(LOG_PART1.encode())
                        time.sleep(0.6)
                        conn.sendall(LOG_PART2.encode())
                    elif cmd.startswith("clear counters"):
                        # Real IOS waits for Enter after [confirm].
                        conn.sendall(b'Clear "show interface" counters on all interfaces [confirm]')
                        if self._line(conn) is None:
                            return
                        conn.sendall(b"\r\n")
                    elif cmd == "show version":
                        time.sleep(0.2)
                        conn.sendall(VERSION.encode())
                    conn.sendall(b"\r\nR1>")
                finally:
                    self.busy.release()
        except OSError:
            return
        finally:
            conn.close()


@pytest.fixture
def ios():
    srv = FakeIos()
    yield srv
    srv.close()


def test_a_wrong_password_is_a_refused_login_not_a_time_out(ios):
    from core.user_errors import describe

    started = time.monotonic()
    with pytest.raises(PermissionError) as info:
        CiscoTelnetSession("127.0.0.1", ios.port, "admin", "wrong")
    assert time.monotonic() - started < 5.0
    assert "refused the login" in describe(info.value)


def test_output_pausing_after_a_prompt_like_line_is_read_to_its_end(ios):
    s = CiscoTelnetSession("127.0.0.1", ios.port, "admin", "pw")
    try:
        text = s.open_read("/show/running-config.txt").read().decode()
        assert text.rstrip().endswith("end"), text
        assert "hostname R1" in text
    finally:
        s.close()


def test_two_threads_never_share_the_line(ios):
    s = CiscoTelnetSession("127.0.0.1", ios.port, "admin", "pw")
    results: dict[int, object] = {}

    def read(i):
        try:
            results[i] = s.open_read("/show/version.txt").read().decode()
        except Exception as exc:  # noqa: BLE001
            results[i] = exc

    try:
        threads = [threading.Thread(target=read, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert not ios.overlap
        assert all(isinstance(r, str) and "uptime" in r for r in results.values()), results
    finally:
        s.close()


def test_ipv6_only_never_reaches_an_ipv4_address(ios):
    with pytest.raises(OSError):
        CiscoTelnetSession("127.0.0.1", ios.port, "admin", "pw", address_family="ipv6")
    s = CiscoTelnetSession("127.0.0.1", ios.port, "admin", "pw", address_family="ipv4")
    s.close()


def test_the_shell_telnet_session_honours_the_ip_version_too(ios):
    from core.telnet_client import TelnetSession

    with pytest.raises(OSError):
        TelnetSession("127.0.0.1", ios.port, "admin", "pw", address_family="ipv6")


def test_a_line_that_is_the_prompt_itself_does_not_end_the_answer(ios):
    s = CiscoTelnetSession("127.0.0.1", ios.port, "admin", "pw")
    try:
        log_text = s.open_read("/show/logging.txt").read().decode()
        assert log_text.rstrip().endswith("last line"), log_text
        # The line is still in step: the next answer is its own.
        version = s.open_read("/show/version.txt").read().decode()
        assert "uptime" in version and "last line" not in version, version
    finally:
        s.close()


def test_clear_counters_answers_the_confirm_question(ios):
    s = CiscoTelnetSession("127.0.0.1", ios.port, "admin", "pw")
    s._privileged = True  # the fake has no enable step
    s._timeout = 3.0
    import core.telnet_cisco as TC

    old = TC.SHOW_TIMEOUT
    TC.SHOW_TIMEOUT = 3.0
    try:
        started = time.monotonic()
        s.clear_counters()
        assert time.monotonic() - started < 3.0
        assert "uptime" in s.open_read("/show/version.txt").read().decode()
    finally:
        TC.SHOW_TIMEOUT = old
        s.close()
