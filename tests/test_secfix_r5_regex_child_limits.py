"""Round-5 security: the regex matcher child has a CPU limit and ends with
its parent (core.regex_worker). Before, only RLIMIT_AS was set and a child
whose server was killed kept backtracking forever (orphaned, ppid 1)."""

from __future__ import annotations

import os
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core import regex_worker as R

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc and prctl")
posix_only = pytest.mark.skipif(os.name != "posix", reason="RLIMIT_CPU is POSIX")

_PARENT = r'''
import sys
sys.path.insert(0, {root!r})
from core import regex_worker as R
m = R.RegexMatcher(r"(a|aa)+$", seconds_per_text=3600)
print(m._proc.pid, flush=True)
m.matching_lines("a" * 60 + "b", 10)
'''


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"
    except OSError:
        return False


@linux_only
def test_happy_child_has_a_cpu_limit_and_still_matches():
    with R.RegexMatcher(r"b+", seconds_per_text=5) as m:
        limits = Path(f"/proc/{m._proc.pid}/limits").read_text()
        line = next(x for x in limits.splitlines() if x.startswith("Max cpu time"))
        assert "unlimited" not in line.split()[3], line
        assert m.matching_lines("a\nbb\nc\nb", 10) == [2, 4]


@linux_only
def test_sad_child_ends_when_the_parent_is_killed():
    root = str(Path(__file__).resolve().parents[1])
    parent = subprocess.Popen([sys.executable, "-c", _PARENT.format(root=root)],
                              stdout=subprocess.PIPE, text=True)
    child = int(parent.stdout.readline())
    try:
        time.sleep(1.0)
        assert _alive(child)
        parent.kill()
        parent.wait()
        deadline = time.monotonic() + 5
        while _alive(child) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not _alive(child), "the regex child outlived its parent"
    finally:
        try:
            os.kill(child, signal.SIGKILL)
        except OSError:
            pass
        parent.stdout.close()


@posix_only
def test_edge_cpu_limit_ends_a_spinning_child_without_any_parent_timer():
    # Parent pid 0 = no parent check; one CPU second per text.
    argv = [sys.executable, "-I", "-S", "-c", R._CHILD_SOURCE, "0", "1",
            str(R.ADDRESS_SPACE_LIMIT)]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    try:
        pat = rb"(a|aa)+$"
        text = b"a" * 80 + b"b"
        proc.stdin.write(struct.pack(">I", len(pat)) + pat)
        proc.stdin.write(struct.pack(">II", 10, len(text)) + text)
        proc.stdin.flush()
        rc = proc.wait(timeout=30)
        assert rc == -signal.SIGXCPU or rc == -signal.SIGKILL, rc
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_edge_worker_argv_carries_pid_and_cpu_budget():
    argv = R.worker_argv(7)
    assert argv[-3] == str(os.getpid())
    assert int(argv[-2]) >= 7
    assert argv[-1] == str(R.ADDRESS_SPACE_LIMIT)
