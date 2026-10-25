"""The GUI start imports neither optional SDKs nor paramiko.

Measured (CPU time, old vs new in alternation): start to a shown window
1.16-1.56 s before, 0.24-0.44 s after. paramiko alone was ~0.13 s, pulled
in by connection_manager and main_window although a fresh window shows a
local pane; SSH sessions are now imported on first use.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _run(code: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(ROOT), QT_QPA_PLATFORM="offscreen")
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().splitlines()[-1]


class StartupImportTest(unittest.TestCase):
    def test_a_shown_main_window_has_not_imported_paramiko(self) -> None:
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        got = _run(
            """
            import sys, tempfile, os
            os.environ["HOME"] = tempfile.mkdtemp()
            from core.backend_registry import init_registry
            init_registry()
            from PyQt6.QtWidgets import QApplication
            from ui.main_window import MainWindow
            app = QApplication([])
            w = MainWindow(); w.show(); app.processEvents()
            print("paramiko" in sys.modules, "boto3" in sys.modules)
            """
        )
        self.assertEqual(got, "False False")

    def test_connection_manager_import_does_not_load_ssh(self) -> None:
        got = _run(
            """
            import sys
            import core.connection_manager
            print("core.ssh_client" in sys.modules)
            """
        )
        self.assertEqual(got, "False")


def _start_imports(tmp: str) -> set[str]:
    """The modules a real ``main.py`` start imports up to a shown window
    (AXROSS_SMOKE_GUI_MS=0 quits right after), from ``-X importtime``."""
    home = Path(tmp)
    env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / "c"), XDG_DATA_HOME=str(home / "d"),
               XDG_CACHE_HOME=str(home / "k"), XDG_STATE_HOME=str(home / "s"),
               XDG_RUNTIME_DIR=str(home / "r"), QT_QPA_PLATFORM="offscreen",
               AXROSS_SMOKE_GUI_MS="0", PYTHONPATH=str(ROOT))
    (home / "r").mkdir(mode=0o700)
    out = subprocess.run([sys.executable, "-X", "importtime", "main.py", "--foreground"],
                         capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=120)
    assert "window shown" in out.stdout, (out.stdout, out.stderr[-2000:])
    return {line.rsplit("|", 1)[-1].strip() for line in out.stderr.splitlines()
            if line.startswith("import time:")}


class MainStartImportTest(unittest.TestCase):
    """2026-10-25 performance round: main.py imported paramiko (0.14 s with
    invoke and yaml) only to set its client banner - the main window needs
    no SSH until a connection opens."""

    def setUp(self) -> None:
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")

    def test_happy_a_real_start_does_not_import_paramiko(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            modules = _start_imports(tmp)
        self.assertIn("ui.main_window", modules)  # the scan saw the start
        self.assertFalse({"paramiko", "invoke"} & modules, sorted({"paramiko", "invoke"} & modules))


class BannerOnImportTest(unittest.TestCase):
    """The banner still reaches every Transport: set when paramiko loads."""

    def test_happy_paramiko_imported_later_gets_the_banner(self) -> None:
        got = _run(
            """
            import sys
            from core.client_identity import SSH_LOCAL_VERSION, banner_override_on_import
            banner_override_on_import()
            before = "paramiko" in sys.modules
            import paramiko
            print(before, paramiko.Transport._CLIENT_ID == SSH_LOCAL_VERSION.removeprefix("SSH-2.0-"))
            """
        )
        self.assertEqual(got, "False True")

    def test_happy_a_transport_made_through_net_helpers_sends_the_banner(self) -> None:
        got = _run(
            """
            import socket
            from core.client_identity import SSH_LOCAL_VERSION, banner_override_on_import
            banner_override_on_import()
            import paramiko  # as core.net_helpers.ssh_hostkey does
            a, b = socket.socketpair()
            print(paramiko.Transport(a).local_version == SSH_LOCAL_VERSION)
            a.close(); b.close()
            """
        )
        self.assertEqual(got, "True")

    def test_edge_already_imported_paramiko_is_patched_at_once_and_twice_is_one_hook(self) -> None:
        got = _run(
            """
            import sys, paramiko
            paramiko.Transport._CLIENT_ID = "paramiko_x"
            from core import client_identity as C
            C.banner_override_on_import(); C.banner_override_on_import()
            hooks = sum(isinstance(f, C._BannerOnImport) for f in sys.meta_path)
            print(paramiko.Transport._CLIENT_ID != "paramiko_x", hooks)
            """
        )
        self.assertEqual(got, "True 0")

    def test_edge_calling_twice_before_the_import_installs_one_hook(self) -> None:
        got = _run(
            """
            import sys
            from core import client_identity as C
            C.banner_override_on_import(); C.banner_override_on_import()
            print(sum(isinstance(f, C._BannerOnImport) for f in sys.meta_path))
            """
        )
        self.assertEqual(got, "1")

    def test_sad_without_paramiko_the_hook_changes_nothing(self) -> None:
        got = _run(
            """
            import sys
            from core import client_identity as C
            C.banner_override_on_import()
            sys.modules["paramiko"] = None  # as if it were not installed
            try:
                import paramiko.transport
            except ImportError:
                print("ImportError")
            """
        )
        self.assertEqual(got, "ImportError")

    def test_edge_other_imports_pass_the_hook_untouched(self) -> None:
        got = _run(
            """
            import sys
            from core import client_identity as C
            C.banner_override_on_import()
            import json, paramiko.util
            print(json.dumps([1]), type(paramiko.util.__loader__).__name__)
            """
        )
        self.assertEqual(got, "[1] SourceFileLoader")

    def test_edge_a_shared_loader_of_a_frozen_build_stays_untouched(self) -> None:
        """PyInstaller loads every module through one importer object: the
        hook must wrap it for paramiko.transport, never change it."""
        got = _run(
            """
            import sys, importlib.machinery
            from core import client_identity as C
            from core.client_identity import SSH_LOCAL_VERSION

            class Shared:  # one loader object for every module, as when frozen
                def __init__(self):
                    self.inner = {}
                def find_spec(self, name, path=None, target=None):
                    spec = importlib.machinery.PathFinder.find_spec(name, path)
                    if spec is None or not name.startswith("paramiko"):
                        return None
                    self.inner[name] = spec.loader
                    return importlib.machinery.ModuleSpec(name, self, origin=spec.origin,
                                                          is_package=spec.submodule_search_locations is not None)
                def create_module(self, spec):
                    return None
                def exec_module(self, module):
                    spec = module.__spec__
                    if spec.submodule_search_locations is not None:
                        module.__path__ = [spec.origin.rsplit("/", 1)[0]]
                    self.inner[spec.name].exec_module(module)

            shared = Shared()
            sys.meta_path.insert(0, shared)
            C.banner_override_on_import()  # in front of it
            run = Shared.exec_module
            import paramiko
            print(paramiko.Transport._CLIENT_ID == SSH_LOCAL_VERSION.removeprefix("SSH-2.0-"),
                  "exec_module" not in vars(shared), type(paramiko.util.__loader__) is Shared)
            """
        )
        self.assertEqual(got, "True True True")


class LazyFacadeTest(unittest.TestCase):
    def test_happy_import_axross_for_the_version_leaves_the_scripting_api_unloaded(self) -> None:
        got = _run(
            """
            import sys, axross
            print(bool(axross.__version__), "core.scripting" in sys.modules)
            """
        )
        self.assertEqual(got, "True False")

    def test_happy_names_resolve_and_star_import_works(self) -> None:
        got = _run(
            """
            import axross
            from core import scripting
            from axross import localfs
            ns = {}
            exec("from axross import *", ns)
            print(localfs is scripting.localfs, set(scripting.__all__) <= set(ns), "localfs" in dir(axross))
            """
        )
        self.assertEqual(got, "True True True")

    def test_sad_an_unknown_name_is_an_attribute_error(self) -> None:
        import axross

        with self.assertRaises(AttributeError):
            axross.no_such_helper  # noqa: B018


class LazySessionNamesTest(unittest.TestCase):
    def test_happy_the_session_classes_are_still_module_attributes(self) -> None:
        from core import connection_manager as cm
        from core.scp_client import SCPSession
        from core.ssh_client import SSHSession, UnknownHostKeyError

        self.assertIs(cm.SSHSession, SSHSession)
        self.assertIs(cm.SCPSession, SCPSession)
        self.assertIs(cm.UnknownHostKeyError, UnknownHostKeyError)

    def test_sad_unknown_names_still_raise_attribute_error(self) -> None:
        from core import connection_manager as cm

        with self.assertRaises(AttributeError):
            cm.NoSuchThing  # noqa: B018

    def test_edge_a_patched_class_is_the_one_used(self) -> None:
        import importlib

        from core.profiles import ConnectionProfile

        # The module mock.patch resolves (sys.modules): another test
        # re-imports connection_manager under patched sys.modules, which can
        # leave the ``core`` package attribute pointing at a different copy.
        cm = importlib.import_module("core.connection_manager")

        fake = mock.MagicMock()
        with mock.patch("core.connection_manager.SSHSession", return_value=fake) as cls:
            got = cm.ConnectionManager()._create_session(
                ConnectionProfile(name="x", protocol="sftp", host="h", username="u"), "", "", None
            )
        cls.assert_called_once()
        self.assertIs(got, fake)


class IsSshSessionTest(unittest.TestCase):
    def setUp(self) -> None:
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")

    def test_happy_an_ssh_session_is_recognised(self) -> None:
        from core.ssh_client import SSHSession
        from ui.main_window import _is_ssh_session

        self.assertTrue(_is_ssh_session(object.__new__(SSHSession)))

    def test_sad_other_backends_are_not(self) -> None:
        from core.local_fs import LocalFS
        from ui.main_window import _is_ssh_session

        self.assertFalse(_is_ssh_session(LocalFS()))
        self.assertFalse(_is_ssh_session(None))

    def test_edge_without_the_ssh_module_loaded_nothing_is_an_ssh_session(self) -> None:
        got = _run(
            """
            from ui.main_window import _is_ssh_session
            from core.local_fs import LocalFS
            print(_is_ssh_session(LocalFS()))
            """
        )
        self.assertEqual(got, "False")


if __name__ == "__main__":
    unittest.main()
