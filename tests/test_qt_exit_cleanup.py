"""No segfault at interpreter exit from PyQt's own clean-up.

When the interpreter exits, PyQt6 (cleanup_on_exit, an atexit handler
registered by ``import PyQt6.QtCore``) walks sip's map of wrapped C++
objects and deletes every QObject Python still owns - from inside the walk
(sip_api_visit_wrappers). A destructor that calls back into Python there (a
``destroyed`` slot, a Python event filter getting the Destroy event of a
child) registers new wrappers; when that makes sip grow its map, the walk
goes on in the freed table and the process dies with SIGSEGV after all its
work was done. Measured: the main window opened and closed in a child
process crashed 24 of 200 runs like that (core dumps: sip_api_get_address <-
cleanup_qobject <- sip_api_visit_wrappers <- cleanup_on_exit).

core.qt_exit deletes those objects first, in an atexit handler that runs
before PyQt's, outside the walk. Every case runs in a child process: the
failure is a crash at exit.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

_PRELUDE = """
import atexit, gc, os, sys
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, {root!r})
"""

# 200 top-level objects Python owns; deleting the first one runs a Python
# slot that registers 3000 new wrappers - enough to make sip grow its map
# while PyQt's exit walk is still going over it.
_GROWS_THE_MAP = """
from PyQt6.QtCore import QCoreApplication, QObject
app = QCoreApplication.instance() or QCoreApplication([])
keep = []
def grow(*_):
    keep.extend(QObject() for _ in range(3000))
tops = [QObject() for _ in range(200)]
tops[0].destroyed.connect(grow)
"""

# Runs after core.qt_exit's handler and before PyQt's walk when registered
# between ``import PyQt6.QtCore`` and the import that installs the guard
# (atexit runs its handlers last in, first out).
_LEFT_FOR_PYQT = """
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QObject, QThread
def _left_for_pyqt():
    app = QCoreApplication.instance()
    left = []
    for o in gc.get_objects():
        if not issubclass(type(o), QObject) or o is app:
            continue
        if sip.isdeleted(o) or not sip.ispyowned(o):
            continue
        if isinstance(o, QThread) and o.isRunning():
            continue
        left.append(type(o).__name__)
    print("LEFT", len(left), sorted(set(left))[:10], flush=True)
atexit.register(_left_for_pyqt)
"""


def _run(body: str, *args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    script = textwrap.dedent(_PRELUDE).format(root=str(ROOT)) + textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", script, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
    )


def _left(stdout: str) -> int:
    lines = [line for line in stdout.splitlines() if line.startswith("LEFT ")]
    assert len(lines) == 1, stdout[-1500:]
    return int(lines[0].split()[1])


# --- control ----------------------------------------------------------------


def test_control_without_the_guard_pyqt_crashes_at_exit() -> None:
    """The reproduction really reproduces on this PyQt6/sip build."""
    done = _run(_GROWS_THE_MAP + "print('ok', flush=True)\n")
    assert "ok" in done.stdout, done.stderr[-1500:]
    if done.returncode == 0:
        pytest.skip("this PyQt6/sip build no longer crashes in its exit walk")
    assert done.returncode == -11, (done.returncode, done.stderr[-1500:])


# --- happy ------------------------------------------------------------------


def test_happy_with_the_guard_the_same_process_exits_cleanly() -> None:
    body = (
        _GROWS_THE_MAP
        + "from core import qt_exit\n"
        + "assert qt_exit.install_orderly_qt_exit() is True\n"
        + "print('ok', flush=True)\n"
    )
    for _ in range(3):
        done = _run(body)
        assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
        assert "ok" in done.stdout
        # The slot really ran (outside PyQt's walk): nothing hid the case.
        assert "Traceback" not in done.stderr, done.stderr[-1500:]


def test_happy_importing_ui_installs_the_guard() -> None:
    """Every process that builds axross widgets imports ui: the package
    installs the guard, so the test children and the app need no call."""
    body = (
        "from PyQt6 import QtCore\n"
        + _LEFT_FOR_PYQT
        + "import ui\n"
        + _GROWS_THE_MAP
        + "print('ok', flush=True)\n"
    )
    done = _run(body)
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    assert _left(done.stdout) == 0


def test_e2e_the_main_window_leaves_nothing_for_pyqts_exit_walk(tmp_path) -> None:
    """The cross-platform smoke test's steps: the window, its docks, models
    and workers are deleted before PyQt's walk, so none of their destructors
    (destroyed slots, Python event filters) runs inside it."""
    home = tmp_path / "home"
    home.mkdir()
    body = (
        f"os.environ.update(HOME={str(home)!r}, XDG_CONFIG_HOME={str(home / '.config')!r},"
        f" XDG_DATA_HOME={str(home / 'data')!r}, XDG_CACHE_HOME={str(home / 'cache')!r},"
        f" XDG_STATE_HOME={str(home / 'state')!r},"
        " PYTHON_KEYRING_BACKEND='keyring.backends.null.Keyring')\n"
        "import time\n"
        "from PyQt6 import QtCore\n"
        + _LEFT_FOR_PYQT
        + textwrap.dedent(
            """
            from PyQt6.QtWidgets import QApplication
            app = QApplication([])
            from ui.main_window import MainWindow
            win = MainWindow()
            win.show()
            end = time.monotonic() + 1.0
            while time.monotonic() < end:
                app.processEvents()
            assert win.isVisible() and win._panes, "no pane"
            win.close()
            app.processEvents()
            print("window ok", flush=True)
            """
        )
    )
    done = _run(body)
    assert done.returncode == 0, (done.returncode, done.stdout[-800:], done.stderr[-1500:])
    assert "window ok" in done.stdout
    assert _left(done.stdout) == 0


def test_e2e_a_script_that_leaves_qt_objects_exits_cleanly(tmp_path) -> None:
    """main.py --script: a script may build Qt objects of its own and leave
    them behind; the run reports the script's status, not a crash."""
    script = tmp_path / "grow.py"
    script.write_text(textwrap.dedent(_GROWS_THE_MAP) + "print('script ok', flush=True)\n")
    home = tmp_path / "home"
    home.mkdir()
    env = {
        **os.environ,
        "QT_QPA_PLATFORM": "offscreen",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / "data"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_STATE_HOME": str(home / "state"),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
    }
    env.pop("AXROSS_SECURITY_MODE", None)
    done = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--script", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=tmp_path,
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    assert "script ok" in done.stdout


def test_happy_objects_made_while_deleting_are_deleted_too() -> None:
    """A destructor's slot that builds a new object Python owns: the guard
    goes another round, so PyQt's walk does not find it either."""
    body = textwrap.dedent(
        """
        from PyQt6 import sip
        from PyQt6.QtCore import QCoreApplication, QObject
        app = QCoreApplication([])
        from core import qt_exit
        late = []
        first = QObject()
        first.destroyed.connect(lambda *_: late.append(QObject()))
        n = qt_exit.delete_python_owned_qobjects()
        print("late", len(late), sip.isdeleted(late[0]), "first", sip.isdeleted(first), n >= 2)
        """
    )
    done = _run(body)
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    assert "late 1 True first True True" in done.stdout, done.stdout


# --- sad --------------------------------------------------------------------


def test_sad_without_pyqt_installing_is_a_no_op() -> None:
    done = _run(
        """
        sys.modules["PyQt6"] = None  # import PyQt6 raises ImportError
        from core import qt_exit
        print("installed", qt_exit.install_orderly_qt_exit())
        print("deleted", qt_exit.delete_python_owned_qobjects())
        """
    )
    assert done.returncode == 0, done.stderr[-1500:]
    assert "installed False" in done.stdout
    assert "deleted 0" in done.stdout


def test_sad_a_running_thread_is_left_alone() -> None:
    """PyQt does not delete a running QThread either: destroying one aborts
    the process ("QThread: Destroyed while thread is still running")."""
    body = textwrap.dedent(
        """
        from PyQt6 import sip
        from PyQt6.QtCore import QCoreApplication, QThread
        app = QCoreApplication([])
        from core import qt_exit
        t = QThread()
        t.start()
        while not t.isRunning():
            pass
        qt_exit.delete_python_owned_qobjects()
        print("thread deleted", sip.isdeleted(t), flush=True)
        t.quit()
        t.wait()
        """
    )
    done = _run(body)
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    assert "thread deleted False" in done.stdout


def test_sad_only_if_loaded_does_not_import_qt() -> None:
    """The --script path asks for the guard only when the script used Qt:
    a headless script does not pay for importing PyQt6."""
    done = _run(
        """
        from core import qt_exit
        print("installed", qt_exit.install_orderly_qt_exit(only_if_loaded=True))
        print("qt loaded", "PyQt6.QtCore" in sys.modules)
        """
    )
    assert done.returncode == 0, done.stderr[-1500:]
    assert "installed False" in done.stdout
    assert "qt loaded False" in done.stdout


# --- edge -------------------------------------------------------------------


def test_edge_installing_twice_registers_one_handler() -> None:
    done = _run(
        """
        from PyQt6 import QtCore
        from core import qt_exit
        before = atexit._ncallbacks()
        first = qt_exit.install_orderly_qt_exit()
        second = qt_exit.install_orderly_qt_exit()
        print("added", atexit._ncallbacks() - before, first, second)
        """
    )
    assert done.returncode == 0, done.stderr[-1500:]
    assert "added 1 True True" in done.stdout


def test_edge_the_application_object_is_left_to_pyqt() -> None:
    """PyQt deletes the QApplication itself after its walk (outside it);
    the guard leaves it, so other atexit handlers still have it."""
    done = _run(
        """
        from PyQt6 import sip
        from PyQt6.QtCore import QCoreApplication, QObject
        app = QCoreApplication([])
        child = QObject(app)  # owned by its parent, not by Python
        loose = QObject()
        from core import qt_exit
        qt_exit.delete_python_owned_qobjects()
        print("app", sip.isdeleted(app), "child", sip.isdeleted(child),
              "loose", sip.isdeleted(loose))
        """
    )
    assert done.returncode == 0, done.stderr[-1500:]
    assert "app False child False loose True" in done.stdout


def test_edge_a_child_python_still_owns_goes_with_its_parent() -> None:
    """Top-level objects go first; a Python-owned object that its deleted
    parent took along is not deleted a second time."""
    done = _run(
        """
        from PyQt6 import sip
        from PyQt6.QtCore import QCoreApplication, QObject
        app = QCoreApplication([])
        parent = QObject()
        kid = QObject()
        kid.setParent(parent)
        sip.transferback(kid)  # Python owns it again, the parent stays
        from core import qt_exit
        print("owned", sip.ispyowned(kid), kid.parent() is parent)
        qt_exit.delete_python_owned_qobjects()
        print("parent", sip.isdeleted(parent), "kid", sip.isdeleted(kid))
        """
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    assert "owned True True" in done.stdout
    assert "parent True kid True" in done.stdout


# A direct connection runs the slot in the thread that emits ``destroyed``:
# the flag says whether the C++ object really went, wherever it lived.
_WORKER_IN_A_THREAD = """
import threading, time
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QObject, Qt, QThread
app = QCoreApplication([])
t = QThread()
worker = QObject()
worker.moveToThread(t)
gone = threading.Event()
worker.destroyed.connect(lambda *_: gone.set(), Qt.ConnectionType.DirectConnection)
t.start()
while not t.isRunning():
    time.sleep(0.01)
"""


def test_edge_an_object_of_a_finished_thread_is_released_not_destroyed() -> None:
    """sip.delete takes the wrapper out of sip's map and hands an object
    living in another thread to deleteLater; with that thread finished the
    C++ object is never destroyed. PyQt's walk no longer sees it, and the
    process exits cleanly."""
    done = _run(
        _WORKER_IN_A_THREAD
        + textwrap.dedent(
            """
            t.quit()
            t.wait()
            from core import qt_exit
            qt_exit.delete_python_owned_qobjects()
            end = time.monotonic() + 0.5
            while time.monotonic() < end:
                app.processEvents()
            print("unwrapped", sip.isdeleted(worker), "destroyed", gone.is_set(), flush=True)
            """
        )
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    assert "unwrapped True destroyed False" in done.stdout


def test_edge_an_object_of_a_running_thread_is_deleted_in_that_thread() -> None:
    done = _run(
        _WORKER_IN_A_THREAD
        + textwrap.dedent(
            """
            from core import qt_exit
            qt_exit.delete_python_owned_qobjects()
            print("destroyed", gone.wait(10), "thread", sip.isdeleted(t), flush=True)
            t.quit()
            t.wait()
            """
        )
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    assert "destroyed True thread False" in done.stdout
