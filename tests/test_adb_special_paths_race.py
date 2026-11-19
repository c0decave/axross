"""Listings and stats of one ADB session in two threads at once.

Review 2026-11-18 (finding 11): the session's map of device nodes, FIFOs
and sockets was changed without a lock - stat() in one thread added to it
while list_dir() in another went through it ("RuntimeError: dictionary
changed size during iteration").
"""

from __future__ import annotations

import itertools
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.adb_client import AdbSession  # noqa: E402

N = 20000
DEV = "".join(f"crw-rw-rw- 1 root root 1, {i} 2024-01-01 00:00 n{i}\n" for i in range(N))


def _session() -> AdbSession:
    s = AdbSession.__new__(AdbSession)

    def shell(cmd):
        if cmd == "TZ=UTC0 ls -la /dev/":
            return DEV
        name = cmd.split()[-1]
        return f"crw-rw-rw- 1 root root 1, 3 2024-01-01 00:00 {name}\n"

    s._shell = shell
    return s


def test_sad_a_listing_and_stats_in_two_threads_do_not_collide():
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # switch threads often: the collision shows at once
    try:
        _run_collision_check()
    finally:
        sys.setswitchinterval(old)


def _run_collision_check():
    s = _session()
    errors: list[BaseException] = []
    counter = itertools.count()
    stop = time.monotonic() + 3

    def lister():
        while time.monotonic() < stop and not errors:
            try:
                s.list_dir("/dev")
            except BaseException as exc:  # noqa: BLE001 - the test looks at it
                errors.append(exc)

    def statter():
        while time.monotonic() < stop and not errors:
            try:
                s.stat(f"/dev/x{next(counter)}")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=lister), threading.Thread(target=statter),
               threading.Thread(target=statter)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(30)
    assert errors == []
