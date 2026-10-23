"""A hard crash leaves the Python stack of every thread in crash.log.

A segfault in Qt ended axross with "Segmentation fault (core dumped)" and
nothing else: --debug only adds log lines, and the last one says nothing
about what crashed. faulthandler writes the Python traceback of all
threads at the moment of the fatal signal; main.enable_crash_traces points
it at <log dir>/crash.log, after a header naming version and platform.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")


def _crash(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    code = textwrap.dedent(
        f"""
        import resource, sys
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core file for a test crash
        sys.path.insert(0, {str(ROOT)!r})
        import main
        from pathlib import Path
        main.LOG_DIR = Path({str(tmp_path / "logs")!r})
        """
    ) + textwrap.dedent(body)
    env = {**os.environ, "HOME": str(tmp_path), "QT_QPA_PLATFORM": "offscreen"}
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env
    )


# --- happy ----------------------------------------------------------------


def test_happy_a_segfault_leaves_every_threads_stack(tmp_path):
    r = _crash(
        tmp_path,
        """
        import faulthandler, threading, time
        main.enable_crash_traces()
        def media_worker():
            time.sleep(30)
        threading.Thread(target=media_worker, name="media-task", daemon=True).start()
        time.sleep(0.2)
        def open_media_viewer():
            faulthandler._sigsegv()
        open_media_viewer()
        """,
    )
    assert r.returncode != 0
    log = (tmp_path / "logs" / "crash.log").read_text(encoding="utf-8")
    assert "Segmentation fault" in log
    assert "open_media_viewer" in log  # the crashing thread
    assert "media_worker" in log  # and the others
    assert "axross " in log and sys.platform in log  # the header


# --- sad ------------------------------------------------------------------


def test_sad_an_unwritable_log_dir_does_not_stop_the_start(tmp_path):
    (tmp_path / "logs").write_text("a file where the directory should be")
    r = _crash(
        tmp_path,
        """
        print("path:", main.enable_crash_traces())
        """,
    )
    assert r.returncode == 0, r.stderr
    assert "path: None" in r.stdout


# --- edge -----------------------------------------------------------------


def test_edge_two_crashes_append_and_the_file_is_private(tmp_path):
    body = """
        import faulthandler
        main.enable_crash_traces()
        faulthandler._sigsegv()
        """
    _crash(tmp_path, body)
    _crash(tmp_path, body)
    path = tmp_path / "logs" / "crash.log"
    assert path.read_text(encoding="utf-8").count("Segmentation fault") == 2
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# --- a hang: SIGUSR1 writes the stacks, the process lives on ----------------
#
# Reported: axross-full showed no window; the last --debug line came from Qt
# Multimedia and then nothing. A hang leaves no crash trace. With SIGUSR1
# registered, `kill -USR1 <pid>` writes every thread's stack to crash.log
# and the process goes on.


def test_happy_sigusr1_writes_every_threads_stack_and_the_process_lives_on(tmp_path):
    r = _crash(
        tmp_path,
        """
        import os, signal, threading, time
        main.enable_crash_traces()
        def stuck_in_audio_setup():
            time.sleep(30)
        threading.Thread(target=stuck_in_audio_setup, name="audio", daemon=True).start()
        time.sleep(0.2)
        os.kill(os.getpid(), signal.SIGUSR1)
        time.sleep(0.2)
        print("still alive")
        """,
    )
    assert r.returncode == 0, r.stderr
    assert "still alive" in r.stdout
    text = (tmp_path / "logs" / "crash.log").read_text(encoding="utf-8")
    assert "stuck_in_audio_setup" in text
    assert "kill -USR1" in text  # the header says how to get the stacks


@pytest.mark.skipif(not hasattr(__import__("signal"), "SIGUSR1"), reason="no SIGUSR1")
def test_sad_without_a_crash_log_sigusr1_is_not_taken_over(tmp_path):
    import signal

    r = _crash(
        tmp_path,
        """
        import signal
        main.LOG_DIR = Path("/proc/forbidden/logs")
        print(main.enable_crash_traces())
        print(signal.getsignal(signal.SIGUSR1) == signal.SIG_DFL)
        """,
    )
    assert r.stdout.split() == ["None", "True"], (r.stdout, r.stderr)
    assert signal.SIGUSR1  # the platform has it


def test_edge_two_dumps_append_both(tmp_path):
    r = _crash(
        tmp_path,
        """
        import os, signal, time
        main.enable_crash_traces()
        def first_wait():
            os.kill(os.getpid(), signal.SIGUSR1); time.sleep(0.1)
        def second_wait():
            os.kill(os.getpid(), signal.SIGUSR1); time.sleep(0.1)
        first_wait(); second_wait()
        """,
    )
    assert r.returncode == 0, r.stderr
    text = (tmp_path / "logs" / "crash.log").read_text(encoding="utf-8")
    assert "first_wait" in text and "second_wait" in text
