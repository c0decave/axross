"""A fake telnet login shell for the telnet fuzz suite.

It speaks just enough of what core.telnet_client drives: a login prompt,
the shell probe, the prompt setup, and commands wrapped in the per-session
start / exit markers. ``outputs`` maps a command prefix to
``(text, exit_code)``, raw bytes (sent as they are, markers and all), or
``STALL`` (go silent).
"""

from __future__ import annotations

import re
import socket

from fuzz_testkit import ScriptedServer, recv_line, stall

STALL = object()

_WRAPPED = re.compile(
    r"^echo '(?P<start>__AXX_CMD_START_[0-9a-f]+__)'; (?P<cmd>.*) 2>&1; "
    r'echo "(?P<exit>__AXX_CMD_EXIT_[0-9a-f]+_)\$\?__"$'
)


class FakeTelnetShell:
    def __init__(self, outputs: dict | None = None, banner: bytes = b"") -> None:
        self.outputs: dict = {
            "command -v": ("/usr/bin/x", 0),
            "stat --format='%s' /": ("4096", 0),
            "uname -s": ("Linux", 0),
            "echo $0": ("bash", 0),
            "echo $HOME": ("/home/u", 0),
            "ls -la": (
                "total 8\n"
                "drwxr-xr-x 2 u u 4096 Jan  1 12:00 .\n"
                "drwxr-xr-x 3 u u 4096 Jan  1 12:00 ..\n"
                "-rw-r--r-- 1 u u 5 Jan  1 12:00 a.txt\n"
                "drwxr-xr-x 2 u u 4096 Mar 16  2025 sub dir",
                0,
            ),
            "stat --format='%n|%s|%Y|%f|%U|%G|%F'": (
                "/a.txt|5|1767268800|81a4|u|u|regular file",
                0,
            ),
            "base64 <": ("aGVsbG8=", 0),
            "test -d": ("", 1),
            "test -e": ("", 0),
            "df": ("Filesystem 1B-blocks Used Available Use% Mounted\n/dev/x 100 40 60 40% /", 0),
            **(outputs or {}),
        }
        self.banner = banner
        self.commands: list[str] = []
        self.server = ScriptedServer(self._handle)
        self.host, self.port = self.server.host, self.server.port

    def close(self) -> None:
        self.server.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _lookup(self, cmd: str):
        best = None
        for prefix, out in self.outputs.items():
            if cmd.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
                best = (prefix, out)
        return best[1] if best else ("", 0)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(20)
        conn.sendall(self.banner + b"login: ")
        recv_line(conn)
        conn.sendall(b"Password: ")
        recv_line(conn)
        conn.sendall(b"Welcome\r\n$ ")
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.commands.append(line)
            if "__AXROSS_SHELL_PROBE__" in line:
                conn.sendall(b"__AXROSS_SHELL_PROBE__/5.2/_/_/_/_\r\n")
                continue
            if line == "echo '__AXX_PROMPT__'":
                conn.sendall(b"__AXX_PROMPT__\r\n")
                continue
            m = _WRAPPED.match(line)
            if not m:
                continue
            out = self._lookup(m.group("cmd"))
            if out is STALL:
                stall(conn, 15)
                return
            if out is None:
                return
            if isinstance(out, bytes):
                conn.sendall(out)
                continue
            text, code = out
            conn.sendall(
                f"{m.group('start')}\r\n{text}\r\n{m.group('exit')}{code}__\r\n".encode(
                    "utf-8", "surrogateescape"
                )
            )
