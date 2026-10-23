"""A frozen axross gives every child process the environment it started with.

The one-file bootloader points LD_LIBRARY_PATH at the unpacked folder, and
PyInstaller's Qt hook points QT_PLUGIN_PATH and QML2_IMPORT_PATH there;
``_PYI_*`` variables describe this process's unpacking. Every child
inherited them - also those that third-party code (paramiko's
ProxyCommand, webbrowser, dulwich, Qt's own QProcess) starts, which no call
site can clean: in the real binary ``bash -c true`` died with "symbol lookup
error ... rl_trim_arg_from_keyseq" (our readline), ``ffprobe`` with
"libstdc++.so.6: version GLIBCXX_3.4.32 not found" (our libstdc++), and a
host Qt program would have loaded our Qt plugins.

subprocess_env.restore_loader_env runs once at the start of main(). glibc
reads LD_LIBRARY_PATH only when a process starts and Qt finds its plugins
through QLibraryInfo, so the running process keeps loading from the
bundle (measured in the binary: the TIFF plugin and libtiff.so.5 loaded
after the restore, 22 image formats and 11 media decoders without the Qt
variables).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.subprocess_env import clean_child_env, restore_loader_env  # noqa: E402

MEI = "/tmp/_MEIabc123"


def _frozen_env(**extra) -> dict:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/u",
        "LD_LIBRARY_PATH": MEI,
        "QT_PLUGIN_PATH": f"{MEI}/PyQt6/Qt6/plugins",
        "QML2_IMPORT_PATH": f"{MEI}/PyQt6/Qt6/qml",
        "_PYI_APPLICATION_HOME_DIR": MEI,
        "_PYI_ARCHIVE_FILE": "/opt/axross-full",
        "_PYI_PARENT_PROCESS_LEVEL": "1",
        "_PYI_LINUX_PROCESS_NAME": "axross-full",
    }
    env.update(extra)
    return env


def _points_into_bundle(env: dict) -> list[str]:
    return sorted(k for k, v in env.items() if MEI in v or k.startswith("_PYI_"))


# --- happy ----------------------------------------------------------------


def test_happy_nothing_points_into_the_bundle_afterwards():
    env = _frozen_env()
    restore_loader_env(env, bundle_dir=MEI)
    assert _points_into_bundle(env) == []
    assert env["PATH"] == "/usr/bin:/bin" and env["HOME"] == "/home/u"


def test_happy_the_users_own_values_come_back():
    env = _frozen_env(LD_LIBRARY_PATH_ORIG="/opt/mylib", LD_LIBRARY_PATH=f"{MEI}:/opt/mylib",
                      QT_PLUGIN_PATH=f"{MEI}/PyQt6/Qt6/plugins:/opt/myplugins")
    restore_loader_env(env, bundle_dir=MEI)
    assert env["LD_LIBRARY_PATH"] == "/opt/mylib"
    assert env["QT_PLUGIN_PATH"] == "/opt/myplugins"
    # clean_child_env later still hands the user's value on, not nothing.
    assert clean_child_env(env)["LD_LIBRARY_PATH"] == "/opt/mylib"


def test_happy_it_reports_what_it_changed():
    env = _frozen_env()
    changed = restore_loader_env(env, bundle_dir=MEI)
    assert set(changed) >= {"LD_LIBRARY_PATH", "QT_PLUGIN_PATH", "QML2_IMPORT_PATH",
                            "_PYI_APPLICATION_HOME_DIR"}


def test_happy_main_restores_before_any_mode_runs():
    # Workers start children too (the agent worker runs shell tools), so the
    # call comes first in main(), before the --*-worker branches.
    text = (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")
    body = text[text.index("def main() -> int:"):]
    assert body.index("restore_loader_env(") < body.index("--agent-worker")


# --- sad ------------------------------------------------------------------


def test_sad_outside_a_bundle_nothing_changes():
    env = {"LD_LIBRARY_PATH": "/opt/mylib", "QT_PLUGIN_PATH": "/opt/p", "PATH": "/bin"}
    assert restore_loader_env(env, bundle_dir=None) == []
    assert env == {"LD_LIBRARY_PATH": "/opt/mylib", "QT_PLUGIN_PATH": "/opt/p", "PATH": "/bin"}


def test_sad_a_users_value_that_does_not_point_into_the_bundle_stays():
    env = {"QT_PLUGIN_PATH": "/opt/p", "LD_LIBRARY_PATH": "/opt/l", "PATH": "/bin"}
    restore_loader_env(env, bundle_dir=MEI)
    assert env == {"QT_PLUGIN_PATH": "/opt/p", "LD_LIBRARY_PATH": "/opt/l", "PATH": "/bin"}


# --- edge -----------------------------------------------------------------


def test_edge_a_prefix_of_the_bundle_path_is_not_the_bundle():
    # "/tmp/_MEIabc1234" is another folder; only whole entries are removed.
    other = MEI + "4"
    env = {"LD_LIBRARY_PATH": f"{MEI}:{other}", "QT_PLUGIN_PATH": f"{MEI}/x:{other}/y"}
    restore_loader_env(env, bundle_dir=MEI)
    assert env == {"LD_LIBRARY_PATH": other, "QT_PLUGIN_PATH": f"{other}/y"}


def test_edge_running_twice_changes_nothing_more():
    env = _frozen_env(LD_LIBRARY_PATH_ORIG="/opt/mylib")
    restore_loader_env(env, bundle_dir=MEI)
    snapshot = dict(env)
    assert restore_loader_env(env, bundle_dir=MEI) == []
    assert env == snapshot


def test_edge_a_trailing_slash_on_the_bundle_dir():
    env = _frozen_env()
    restore_loader_env(env, bundle_dir=MEI + "/")
    assert _points_into_bundle(env) == []


def test_edge_os_environ_is_the_default_target(monkeypatch):
    from core import subprocess_env as SE

    monkeypatch.setattr(SE, "_STARTUP_VALUES", {})
    monkeypatch.setenv("QT_PLUGIN_PATH", f"{MEI}/PyQt6/Qt6/plugins")
    monkeypatch.setenv("_PYI_APPLICATION_HOME_DIR", MEI)
    restore_loader_env(bundle_dir=MEI)
    assert "QT_PLUGIN_PATH" not in os.environ and "_PYI_APPLICATION_HOME_DIR" not in os.environ


# --- the workers: axross itself, reusing the unpacked folder ---------------------
#
# The analysis and voice workers are this binary again. With the parent's
# _PYI_* and LD_LIBRARY_PATH a frozen child reuses the unpacked folder and
# loads the bundled libraries (measured: given a cleaned env it loaded the
# host's libssl and libstdc++ into the bundled interpreter; without _PYI_* it
# unpacks the whole bundle again). restore_loader_env removed exactly those
# at start, so worker_env puts the start values back.


def _start_frozen(monkeypatch, **extra):
    from core import subprocess_env as SE

    monkeypatch.setattr(SE, "_STARTUP_VALUES", {})
    for k in [k for k in os.environ if k.startswith("_PYI_") or k.startswith("LD_LIBRARY_PATH")
              or k in ("QT_PLUGIN_PATH", "QML2_IMPORT_PATH")]:
        monkeypatch.delenv(k)
    for k, v in _frozen_env(**extra).items():
        monkeypatch.setenv(k, v)
    restore_loader_env(bundle_dir=MEI)
    return SE


def test_happy_a_worker_gets_the_start_values_back(monkeypatch):
    SE = _start_frozen(monkeypatch)
    assert "LD_LIBRARY_PATH" not in os.environ  # host programs: clean
    env = SE.worker_env()
    assert env["LD_LIBRARY_PATH"] == MEI
    assert env["_PYI_APPLICATION_HOME_DIR"] == MEI and env["_PYI_ARCHIVE_FILE"] == "/opt/axross-full"
    assert env["QT_PLUGIN_PATH"] == f"{MEI}/PyQt6/Qt6/plugins"


def test_sad_from_the_source_tree_a_worker_gets_the_environment_as_it_is(monkeypatch):
    from core import subprocess_env as SE

    monkeypatch.setattr(SE, "_STARTUP_VALUES", {})
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/mylib")
    assert SE.worker_env()["LD_LIBRARY_PATH"] == "/opt/mylib"
    assert SE.worker_env() == {k: v for k, v in os.environ.items()
                               if k != "PYINSTALLER_RESET_ENVIRONMENT"}


def test_edge_only_os_environ_is_remembered(monkeypatch):
    # A restore on some other dict (a test, a child env being built) must not
    # change what the workers get.
    from core import subprocess_env as SE

    monkeypatch.setattr(SE, "_STARTUP_VALUES", {})
    restore_loader_env(_frozen_env(), bundle_dir=MEI)
    assert SE._STARTUP_VALUES == {}


def test_edge_an_explicit_env_is_taken_as_given(monkeypatch):
    SE = _start_frozen(monkeypatch)
    assert SE.worker_env({"PATH": "/bin"}) == {"PATH": "/bin"}


def test_edge_a_worker_never_gets_the_reset_marker(monkeypatch):
    SE = _start_frozen(monkeypatch)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "1")
    assert "PYINSTALLER_RESET_ENVIRONMENT" not in SE.worker_env()
