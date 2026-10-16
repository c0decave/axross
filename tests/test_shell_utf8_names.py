"""SCP and Telnet list names outside ASCII as they are.

Lab matrix: a file "Grüße ü 名前 space.txt" uploaded fine but listed as
"Gr????e ?? ?????? space.txt" over SCP (BusyBox ls on Alpine replaces
every non-ASCII byte with "?" under LANG=C) and as
"'Gr'$'\\303\\274...'" over Telnet (GNU ls 9.1 on a terminal quotes in
shell-escape style under LANG=C). Both backends forced LANG=C LC_ALL=C
for parseable dates. C.UTF-8 keeps the same date and number format and
lets ls print the bytes; QUOTING_STYLE=literal turns GNU ls's quoting
off (BusyBox ignores it). Verified on the lab: both print the name.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import scp_client, telnet_client  # noqa: E402

NAME = "Grüße ü 名前 space.txt"
LS = (
    "total 4\n"
    "drwxr-xr-x    2 alpha    alpha         4096 Oct 16 14:33 .\n"
    f"-rw-r--r--    1 alpha    alpha           13 Oct 16 14:33 {NAME}\n"
)


def _scp(output=LS):
    s = scp_client.SCPSession.__new__(scp_client.SCPSession)
    s._caps = scp_client._Capabilities()
    s.commands = []

    def run(cmd, timeout=None):
        s.commands.append(cmd)
        return output

    s._exec = run
    return s


# --- happy ----------------------------------------------------------------


def test_happy_scp_lists_a_utf8_name():
    s = _scp()
    assert [i.name for i in s.list_dir("~")] == [NAME]


def test_happy_scp_asks_ls_for_utf8_output():
    s = _scp()
    s.list_dir("~")
    assert s.commands[0].startswith(telnet_client.SHELL_ENV + " ls -la ")


def test_happy_telnet_sets_the_same_environment():
    sent = []
    shell = telnet_client._ShellSession.__new__(telnet_client._ShellSession)
    shell._transport = type(
        "T",
        (),
        {
            "send": lambda self, cmd: sent.append(cmd),
            "read_until": lambda self, *a, **k: "",
            "read_some": lambda self, *a, **k: "",
        },
    )()
    shell._detect_remote_shell = lambda: "posix"
    shell._setup_prompt()
    assert f"export {telnet_client.SHELL_ENV} TERM=dumb" in sent


# --- sad ------------------------------------------------------------------


def test_sad_no_backend_forces_the_ascii_c_locale_any_more():
    for module in (scp_client, telnet_client):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "LANG=C LC_ALL=C" not in source, module.__name__


# --- edge -----------------------------------------------------------------


def test_edge_the_environment_keeps_english_dates():
    # C.UTF-8 formats dates like C ("Oct 16"): the parser stays valid.
    assert "C.UTF-8" in telnet_client.SHELL_ENV
    assert "QUOTING_STYLE=literal" in telnet_client.SHELL_ENV
    assert "LANG=C " not in telnet_client.SHELL_ENV + " "
