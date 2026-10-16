"""Telnet uploads stay in step with the shell, and one bad answer stays one.

Lab matrix, traced: a 3 MB upload sent the whole file as ONE line of
base64 (4 MB) in a heredoc through the interactive shell. Now and then
the terminal lost input: "base64: invalid input", exit 1, and even the
command's own start marker missing. The rest of the mangled input ran
later as commands of its own, and because every command of a session
waited for the same exit marker, the next commands read those answers:
an "echo ok" got "", an upload got the previous "ok", a read got another
file's base64 ("Incorrect padding") - until timeouts. The xxd path sent
one hex line twice as long.

Now base64 and hex go in 76-character lines and in heredocs of bounded
size (">" then ">>"), each command's exit marker carries its own
sequence number so a late answer is never taken for another command's,
and commands on one shell are serialized.
"""

from __future__ import annotations

import base64
import re
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as TC  # noqa: E402


class _Shell:
    """Records commands; answers rc 0."""

    def __init__(self):
        self.cmds: list[str] = []

    def execute_checked(self, cmd, timeout=None):
        self.cmds.append(cmd)
        return ""

    def execute(self, cmd, timeout=None):
        self.cmds.append(cmd)
        return "", 0


def _writer(method, append=False):
    caps = TC._Capabilities(transfer_method=method)
    shell = _Shell()
    w = TC._SpooledWriter(shell, "/tmp/f.bin", caps, append=append)
    return w, shell


def _heredoc_bodies(cmds):
    for cmd in cmds:
        lines = cmd.split("\n")
        yield lines[0], lines[1:-1]


# --- happy ----------------------------------------------------------------


@pytest.mark.parametrize("method", ["base64", "xxd"])
def test_happy_lines_are_short_and_decode_to_the_data(method):
    data = bytes(range(256)) * 2000  # 512 000 bytes
    w, shell = _writer(method)
    w.write(data)
    w.close()
    joined = b""
    for _head, body in _heredoc_bodies(shell.cmds):
        assert all(len(line) <= 76 for line in body), max(map(len, body))
        text = "".join(body)
        joined += base64.b64decode(text) if method == "base64" else bytes.fromhex(text)
    assert joined == data


@pytest.mark.parametrize("method", ["base64", "xxd"])
def test_happy_a_large_file_goes_in_bounded_heredocs(method):
    data = b"\x00" * (3 * 1024 * 1024)
    w, shell = _writer(method)
    w.write(data)
    w.close()
    assert len(shell.cmds) > 1
    assert all(len(c) <= TC.MAX_HEREDOC_CHARS + 200 for c in shell.cmds)
    heads = [c.split("\n", 1)[0] for c in shell.cmds]
    assert " > " in heads[0] and all(" >> " in h for h in heads[1:])


# --- sad ------------------------------------------------------------------


def test_sad_a_late_answer_is_never_taken_for_the_next_command():
    # The shell answers command 1 only after command 2 was sent: the
    # transport holds the late answer of 1 ahead of the answer of 2.
    shell = TC._ShellSession.__new__(TC._ShellSession)
    shell._marker_id = "abc"
    shell._cmd_start = f"{TC._CMD_START_PREFIX}abc__"
    shell._seq = 0
    shell._lock = threading.RLock()
    sent = []

    class _T:
        def send(self, text):
            sent.append(text)

        def read_until_re(self, pattern, timeout=None):
            text = ""
            for i, s in enumerate(sent, 1):
                start = re.search(r"echo '(__AXX_CMD_START_[^']+)'", s).group(1)
                exit_ = re.search(r'echo "(__AXX_CMD_EXIT_[^$]+)\$\?__"', s).group(1)
                text += f"{start}\nanswer {i}\n{exit_}0__\n"
            m = pattern.search(text)
            assert m, text
            return text, m

    shell._transport = _T()
    sent.append("echo '__AXX_CMD_START_abc_0__'; late 2>&1; echo \"__AXX_CMD_EXIT_abc_0_$?__\"")
    out, code = shell.execute("next")
    assert (out, code) == ("answer 2", 0)


# --- edge -----------------------------------------------------------------


def test_edge_append_keeps_appending_in_every_chunk():
    w, shell = _writer("base64", append=True)
    w.write(b"x" * (2 * TC.MAX_HEREDOC_CHARS))
    w.close()
    assert all(" >> " in c.split("\n", 1)[0] for c in shell.cmds)


def test_edge_an_empty_file_is_still_created():
    w, shell = _writer("base64")
    w.close()
    assert len(shell.cmds) == 1 and " > " in shell.cmds[0]


def test_edge_two_threads_never_interleave_on_one_shell():
    shell = TC._ShellSession.__new__(TC._ShellSession)
    shell._marker_id = "abc"
    shell._cmd_start = f"{TC._CMD_START_PREFIX}abc__"
    shell._seq = 0
    shell._lock = threading.RLock()
    inside = []
    overlap = []

    class _T:
        def send(self, text):
            inside.append(1)
            if len(inside) > 1:
                overlap.append(text)
            self.last = text

        def read_until_re(self, pattern, timeout=None):
            start = re.search(r"echo '(__AXX_CMD_START_[^']+)'", self.last).group(1)
            exit_ = re.search(r'echo "(__AXX_CMD_EXIT_[^$]+)\$\?__"', self.last).group(1)
            threading.Event().wait(0.01)
            text = f"{start}\nok\n{exit_}0__\n"
            inside.pop()
            return text, pattern.search(text)

    shell._transport = _T()
    threads = [threading.Thread(target=shell.execute, args=(f"c{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlap == []
