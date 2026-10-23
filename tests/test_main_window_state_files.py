"""The window's own state files (session.json, recents.json) never stop it.

Found in review: ``_read_json_file`` decodes the bytes as UTF-8 and the
callers caught only ``json.JSONDecodeError``. A session.json or
recents.json holding a non-UTF-8 byte raised UnicodeDecodeError out of
``MainWindow()``, so axross did not start at all until the user found and
deleted the file. "Restore Last Session" raised the same way, and a
session tree of the wrong shape failed half-way, after every open pane had
already been closed.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _destroy(win) -> None:
    """Delete *win* now. deleteLater alone waits for an event loop the tests
    never run: every leaked window was restyled by each later one's theme
    and its panes kept listing deleted temp dirs."""
    from PyQt6 import sip
    from PyQt6.QtCore import QCoreApplication, QEvent

    if win is None or sip.isdeleted(win):
        return
    win.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


class _WindowStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import main_window as MW

        self.MW = MW
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.session = self.home / "session.json"
        self.recents = self.home / "recents.json"
        for name, value in (("_SESSION_FILE", self.session), ("_RECENTS_FILE", self.recents)):
            patcher = mock.patch.object(MW.MainWindow, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.win = None

    def tearDown(self) -> None:
        if self.win is not None:
            from PyQt6.QtGui import QCloseEvent

            self.win.closeEvent(QCloseEvent())
            _destroy(self.win)

    def make_window(self):
        with mock.patch("pathlib.Path.home", return_value=self.home):
            self.win = self.MW.MainWindow()
        return self.win


class StartupTest(_WindowStateTest):
    def test_happy_readable_files_are_used(self) -> None:
        self.recents.write_text(json.dumps(["prod", "lab"]))
        self.session.write_text(json.dumps({"window": {"compact": False}}))
        win = self.make_window()
        self.assertEqual(win._recent_profiles, ["prod", "lab"])

    def test_sad_a_non_utf8_recents_file_does_not_stop_the_window(self) -> None:
        self.recents.write_bytes(b'["\xff"]')
        win = self.make_window()
        self.assertEqual(win._recent_profiles, [])

    def test_sad_a_non_utf8_session_file_does_not_stop_the_window(self) -> None:
        self.session.write_bytes(b'{"window": {"ui_theme": "\xff"}}')
        win = self.make_window()
        self.assertTrue(win._panes)

    def test_edge_wrong_json_shapes_do_not_stop_the_window(self) -> None:
        self.recents.write_text(json.dumps({"not": "a list"}))
        self.session.write_text(json.dumps([1, 2]))
        win = self.make_window()
        self.assertEqual(win._recent_profiles, [])


class RestoreTest(_WindowStateTest):
    def restore(self) -> list[str]:
        with mock.patch.object(self.MW.QMessageBox, "information") as info:
            self.win._restore_session()
        self.app.processEvents()
        return [str(c.args[2]) for c in info.call_args_list]

    def test_happy_a_saved_session_is_restored(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        win._save_session()
        self.assertEqual(self.restore(), [])
        self.assertEqual(len(win._panes), 2)

    def test_sad_a_non_utf8_session_is_reported_and_keeps_the_panes(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        panes = list(win._panes)
        self.session.write_bytes(b'{"splitter": "\xff"}')
        messages = self.restore()
        self.assertEqual(len(messages), 1)
        self.assertEqual(win._panes, panes)

    def test_sad_a_session_of_the_wrong_shape_keeps_the_open_panes(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        panes = list(win._panes)
        bad_pane = {"type": "pane", "local": True, "path": "/"}
        for data in (
            [1],
            {"splitter": [1]},
            {"splitter": {"type": "splitter", "children": [bad_pane, "x"]}},
            {"splitter": {"type": "splitter", "children": "abc"}},
            {"splitter": {"type": "splitter", "children": [{"type": "pane", "path": 5}]}},
            {"splitter": {"type": "splitter", "children": [bad_pane]}, "window": []},
        ):
            with self.subTest(data=data):
                self.session.write_text(json.dumps(data))
                messages = self.restore()
                self.assertEqual(len(messages), 1, messages)
                self.assertEqual(win._panes, panes)

    def test_edge_a_session_nested_beyond_any_real_layout_is_refused(self) -> None:
        """Deeper than the interpreter's recursion limit: restoring it raised
        RecursionError after the open panes were gone."""
        win = self.make_window()
        panes = list(win._panes)
        tree: dict = {"type": "pane", "local": True, "path": "/"}
        for _ in range(5000):
            tree = {"type": "splitter", "children": [tree]}
        self.session.write_text(json.dumps({"splitter": tree}))
        self.assertEqual(len(self.restore()), 1)
        self.assertEqual(win._panes, panes)


class SessionSaveTest(_WindowStateTest):
    """session.json is shared with core.i18n, which stores the language the
    user picked in window.language. Closing the window rewrote the file
    from scratch and dropped it, so the pick never survived the restart it
    asks for."""

    def close(self) -> None:
        from PyQt6.QtGui import QCloseEvent

        self.win.closeEvent(QCloseEvent())
        _destroy(self.win)
        self.win = None

    def test_happy_the_picked_language_survives_closing_the_window(self) -> None:
        from core.i18n import store_language, stored_language

        self.make_window()
        store_language("de", self.session)
        self.close()
        self.assertEqual(stored_language(self.session), "de")
        data = json.loads(self.session.read_text())
        self.assertIn("children", data["splitter"])
        self.assertIn("ui_theme", data["window"])

    def test_sad_an_unreadable_session_file_is_still_replaced_on_close(self) -> None:
        self.session.write_bytes(b'{"window": {"language": "de"')
        self.make_window()
        self.close()
        data = json.loads(self.session.read_text())
        self.assertIn("splitter", data)
        self.assertNotIn("language", data["window"])

    def test_edge_the_window_keys_are_its_own_not_the_old_files(self) -> None:
        self.session.write_text(
            json.dumps(
                {
                    "splitter": {"type": "splitter", "children": [{"type": "pane", "x": 1}]},
                    "window": {"language": "sv", "compact": True, "width": 1},
                    "theme": "old",
                }
            )
        )
        win = self.make_window()
        # Compact is read at start like the theme (test_compact_mode_persists);
        # what is saved is the window's state, here switched off again.
        self.assertTrue(win._compact_mode)
        win.set_compact_mode(False, store=False)
        self.close()
        data = json.loads(self.session.read_text())
        self.assertEqual(data["window"]["language"], "sv")
        self.assertFalse(data["window"]["compact"])
        self.assertGreater(data["window"]["width"], 1)
        self.assertNotIn({"type": "pane", "x": 1}, data["splitter"]["children"])


def _shape(widget):
    """The layout tree of *widget* as nested tuples: ("h"|"v", children) for
    a splitter, "file" / "term" / "placeholder" for a pane."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QSplitter

    from ui.disconnected_pane import DisconnectedPanePlaceholder
    from ui.file_pane import FilePaneWidget
    from ui.terminal_pane import TerminalPaneWidget

    if isinstance(widget, QSplitter):
        kind = "h" if widget.orientation() == Qt.Orientation.Horizontal else "v"
        return (kind, tuple(_shape(widget.widget(i)) for i in range(widget.count())))
    if isinstance(widget, FilePaneWidget):
        return "file"
    if isinstance(widget, TerminalPaneWidget):
        return "term"
    if isinstance(widget, DisconnectedPanePlaceholder):
        return "placeholder"
    return type(widget).__name__


def _local_pane(path: str, **extra) -> dict:
    return {"type": "pane", "local": True, "path": path, **extra}


class LayoutOnStartTest(_WindowStateTest):
    """The layout comes back on start: splitters, sizes, local paths,
    docks, geometry, theme. Remote panes come back as a placeholder and
    never connect by themselves."""

    def setUp(self) -> None:
        super().setUp()
        self.dirs = [self.home / name for name in ("alpha", "beta", "gamma")]
        for folder in self.dirs:
            folder.mkdir()

    def wait_for(self, condition, timeout: float = 5.0) -> bool:
        import time

        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if condition():
                return True
            time.sleep(0.01)
        return condition()

    def navigate(self, pane, path) -> None:
        pane.navigate_async(str(path))
        self.assertTrue(self.wait_for(lambda: pane.current_path == str(path)), pane.current_path)

    def write_session(self, splitter: dict, **window) -> None:
        self.session.write_text(json.dumps({"splitter": splitter, "window": window}))

    def start_window(self, *, show: bool = True, profiles: dict | None = None):
        """What main.py does: build the window, restore the layout, show it.
        Connecting is watched: no restore may reach it."""
        self.make_window()
        win = self.win
        self.connects = self.watch(mock.patch.object(win._connection_manager, "connect"))
        self.async_connects = self.watch(mock.patch.object(win, "_run_connect_async"))
        from PyQt6.QtWidgets import QInputDialog

        self.prompts = self.watch(mock.patch.object(QInputDialog, "getText"))
        self.dialogs = [
            self.watch(mock.patch.object(self.MW.QMessageBox, name))
            for name in ("information", "warning", "critical", "question")
        ]
        lookup = dict(profiles or {})
        self.watch(mock.patch.object(win._profile_manager, "get", side_effect=lookup.get))
        with mock.patch("pathlib.Path.home", return_value=self.home):
            self.restored = win.restore_layout_on_start()
        if show:
            win.show()
        self.app.processEvents()
        return win

    def close_window(self) -> None:
        from PyQt6.QtGui import QCloseEvent

        self.win.closeEvent(QCloseEvent())
        _destroy(self.win)
        self.win = None
        self.unwatch()

    def watch(self, patcher):
        """Start *patcher* until the window it watches is closed."""
        if not hasattr(self, "_watched"):
            self._watched = []
            self.addCleanup(self.unwatch)
        self._watched.append(patcher)
        return patcher.start()

    def unwatch(self) -> None:
        while getattr(self, "_watched", None):
            self._watched.pop().stop()

    def assert_no_dialog_and_no_connect(self) -> None:
        self.connects.assert_not_called()
        self.async_connects.assert_not_called()
        self.prompts.assert_not_called()
        for dialog in self.dialogs:
            dialog.assert_not_called()

    def assert_default_layout(self, win) -> None:
        self.assertEqual(_shape(win._root_splitter), ("h", ("file",)))
        self.assertEqual(win._pane_placeholders, [])
        self.assertEqual(win._terminal_panes, [])

    # --- happy -----------------------------------------------------------

    def test_happy_split_layout_sizes_and_local_paths_come_back(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.start_window()
        win.resize(1200, 700)
        win._split_pane(Qt.Orientation.Horizontal)
        win._split_pane(Qt.Orientation.Vertical)
        self.app.processEvents()
        for pane, folder in zip(win._panes, self.dirs):
            self.navigate(pane, folder)
        win._root_splitter.setSizes([300, 900])
        self.app.processEvents()
        shape = _shape(win._root_splitter)
        sizes = win._root_splitter.sizes()
        paths = [p.current_path for p in win._panes]
        self.close_window()

        win = self.start_window()
        self.assertTrue(self.restored)
        self.assertEqual(_shape(win._root_splitter), shape)
        self.assertTrue(
            self.wait_for(lambda: sorted(p.current_path for p in win._panes) == sorted(paths)),
            [p.current_path for p in win._panes],
        )
        restored = win._root_splitter.sizes()
        self.assertAlmostEqual(restored[0] / sum(restored), sizes[0] / sum(sizes), delta=0.05)
        self.assert_no_dialog_and_no_connect()

    def test_happy_docks_geometry_and_theme_come_back(self) -> None:
        win = self.start_window()
        win.resize(720, 720)
        self.app.processEvents()
        win._transfer_dock.hide()
        win._analysis_dock.show()
        win._apply_theme("hacker")
        self.app.processEvents()
        self.close_window()

        win = self.start_window()
        self.assertEqual((win.width(), win.height()), (720, 720))
        self.assertTrue(win._transfer_dock.isHidden())
        self.assertFalse(win._analysis_dock.isHidden())
        self.assertEqual(win._current_theme, "hacker")
        from ui import themes

        win._apply_theme(themes.DEFAULT_THEME)  # the stylesheet is process-wide

    def test_happy_a_remote_pane_comes_back_as_a_disconnected_placeholder(self) -> None:
        from core.profiles import ConnectionProfile

        prod = ConnectionProfile(name="prod", host="db.example", username="u", auth_type="agent")
        self.write_session(
            {
                "type": "splitter",
                "orientation": "horizontal",
                "sizes": [400, 800],
                "children": [
                    _local_pane(str(self.dirs[0]), active=True),
                    {"type": "pane", "profile": "prod", "path": "/srv/data", "target": True},
                ],
            }
        )
        win = self.start_window(profiles={"prod": prod})
        self.assertEqual(_shape(win._root_splitter), ("h", ("file", "placeholder")))
        placeholder = win._pane_placeholders[0]
        self.assertIn("Not connected — prod", placeholder.title_text())
        self.assertEqual(len(win._panes), 1)
        self.assertEqual(win._pane_profiles, {})
        self.assert_no_dialog_and_no_connect()

    def test_happy_reconnect_opens_the_profile_like_quick_connect_does(self) -> None:
        from core.local_fs import LocalFS
        from core.profiles import ConnectionProfile

        prod = ConnectionProfile(name="prod", host="db.example", username="u", auth_type="agent")
        remote_path = str(self.dirs[2])
        self.write_session(
            {
                "type": "splitter",
                "children": [
                    _local_pane(str(self.dirs[0])),
                    {
                        "type": "splitter",
                        "orientation": "vertical",
                        "children": [
                            _local_pane(str(self.dirs[1])),
                            {"type": "pane", "profile": "prod", "path": remote_path},
                        ],
                    },
                ],
            }
        )
        win = self.start_window(profiles={"prod": prod})
        self.assert_no_dialog_and_no_connect()
        placeholder = win._pane_placeholders[0]
        holder = placeholder.parent()
        # The existing connect path: _quick_connect_profile -> _run_connect_async.
        self.async_connects.side_effect = (
            lambda profile, pw, kp, on_success, on_failure: on_success(LocalFS())
        )
        placeholder.reconnect_button.click()
        self.app.processEvents()
        self.async_connects.assert_called_once()
        self.assertIs(self.async_connects.call_args.args[0], prod)
        self.assertEqual(win._pane_placeholders, [])
        self.assertEqual(_shape(win._root_splitter), ("h", ("file", ("v", ("file", "file")))))
        pane = holder.widget(1)
        self.assertIs(win._pane_profiles[pane], prod)
        self.assertTrue(self.wait_for(lambda: pane.current_path == remote_path))

    # --- sad -------------------------------------------------------------

    def test_sad_a_corrupt_session_file_keeps_the_default_layout_silently(self) -> None:
        for content in (b"{not json", b'{"splitter": "\xff"}', b"\x00" * 10):
            with self.subTest(content=content):
                self.session.write_bytes(content)
                win = self.start_window(show=False)
                self.assertFalse(self.restored)
                self.assert_default_layout(win)
                self.assert_no_dialog_and_no_connect()
                self.close_window()

    def test_sad_wrong_types_and_unknown_nodes_keep_the_default_layout(self) -> None:
        good = _local_pane(str(self.dirs[0]))
        for data in (
            [1],
            {"splitter": [good]},
            {"splitter": {"type": "splitter", "children": [good, {"type": "webview"}]}},
            {"splitter": {"type": "splitter", "children": [good, {"type": "terminal", "cwd": 5}]}},
            {"splitter": {"type": "splitter", "children": [{"type": "terminal", "profile": 7}]}},
            {"splitter": {"type": "splitter", "children": [{"type": "pane", "path": 5}]}},
            {"splitter": {"type": "splitter", "children": [good]}, "window": []},
            {"splitter": {"type": "splitter", "children": "abc"}},
        ):
            with self.subTest(data=data):
                self.session.write_text(json.dumps(data))
                win = self.start_window(show=False)
                self.assertFalse(self.restored)
                self.assert_default_layout(win)
                self.assert_no_dialog_and_no_connect()
                self.close_window()

    def test_sad_hostile_window_state_is_ignored_not_fatal(self) -> None:
        self.write_session(
            {"type": "splitter", "children": [good := _local_pane(str(self.dirs[0])), good]},
            geometry="!!!not base64!!!",
            dock_state="A" * 10,
            width=10**9,
            height="x",
        )
        win = self.start_window()
        self.assertTrue(self.restored)
        self.assertEqual(_shape(win._root_splitter), ("h", ("file", "file")))

    def test_sad_a_missing_profile_never_connects(self) -> None:
        self.write_session(
            {
                "type": "splitter",
                "children": [
                    _local_pane(str(self.dirs[0])),
                    {"type": "pane", "profile": "gone", "path": "/x"},
                ],
            }
        )
        win = self.start_window(profiles={})
        placeholder = win._pane_placeholders[0]
        self.assertIn("gone", placeholder.title_text())
        with mock.patch.object(win, "_quick_connect_profile") as quick:
            placeholder.reconnect_button.click()
            self.app.processEvents()
        quick.assert_not_called()
        self.assertIn(placeholder, win._pane_placeholders)
        self.assertIn("gone", win.statusBar().currentMessage())
        self.assert_no_dialog_and_no_connect()

    def test_sad_a_local_path_that_is_gone_falls_back_to_home(self) -> None:
        missing = self.home / "removed-since"
        self.write_session(
            {
                "type": "splitter",
                "children": [_local_pane(str(missing)), _local_pane(str(self.dirs[1]))],
            }
        )
        win = self.start_window()
        self.assertTrue(
            self.wait_for(
                lambda: [p.current_path for p in win._panes] == [str(self.home), str(self.dirs[1])]
            ),
            [p.current_path for p in win._panes],
        )
        self.assert_no_dialog_and_no_connect()

    def test_sad_switched_off_the_default_layout_starts(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.start_window()
        self.assertTrue(win.current_window_prefs().restore_layout_on_start)
        win._split_pane(Qt.Orientation.Horizontal)
        # The user switches it off (Edit > Settings > General).
        win.set_restore_on_start(False)
        stored = json.loads(self.session.read_text())
        self.assertIs(stored["window"]["restore_layout_on_start"], False)
        self.close_window()

        win = self.start_window()
        self.assertFalse(self.restored)
        self.assertFalse(win.current_window_prefs().restore_layout_on_start)
        self.assert_default_layout(win)
        # Switched back on, the next start restores again.
        win._split_pane(Qt.Orientation.Horizontal)
        win.set_restore_on_start(True)
        self.assertTrue(win.current_window_prefs().restore_layout_on_start)
        shape = _shape(win._root_splitter)
        self.close_window()
        win = self.start_window()
        self.assertTrue(self.restored)
        self.assertEqual(_shape(win._root_splitter), shape)

    def test_sad_a_non_bool_switch_value_keeps_the_default_on(self) -> None:
        self.write_session(
            {"type": "splitter", "children": [_local_pane(str(self.dirs[0]))] * 2},
            restore_layout_on_start="no",
        )
        win = self.start_window()
        self.assertTrue(win.current_window_prefs().restore_layout_on_start)
        self.assertTrue(self.restored)

    # --- edge ------------------------------------------------------------

    def test_edge_an_empty_tree_keeps_the_default_layout(self) -> None:
        for splitter in ({"type": "splitter", "children": []}, {}):
            with self.subTest(splitter=splitter):
                self.write_session(splitter)
                win = self.start_window(show=False)
                self.assertFalse(self.restored)
                self.assert_default_layout(win)
                self.close_window()

    def test_edge_a_single_pane_comes_back_on_its_folder(self) -> None:
        self.write_session({"type": "splitter", "children": [_local_pane(str(self.dirs[2]))]})
        win = self.start_window()
        self.assertEqual(_shape(win._root_splitter), ("h", ("file",)))
        self.assertTrue(self.wait_for(lambda: win._panes[0].current_path == str(self.dirs[2])))

    def test_edge_nesting_at_the_depth_bound_is_restored_one_deeper_is_not(self) -> None:
        bound = self.MW.MAX_SESSION_DEPTH

        def nested(levels: int) -> dict:
            tree: dict = _local_pane(str(self.dirs[0]))
            for _ in range(levels):
                tree = {"type": "splitter", "children": [tree]}
            return tree

        # The pane is one level below its innermost splitter.
        self.write_session(nested(bound - 1))
        win = self.start_window(show=False)
        self.assertTrue(self.restored)
        self.assertEqual(len(win._panes), 1)
        self.close_window()

        self.write_session(nested(bound))
        win = self.start_window(show=False)
        self.assertFalse(self.restored)
        self.assert_default_layout(win)

    def test_edge_the_node_count_is_bounded(self) -> None:
        bound = self.MW.MAX_SESSION_NODES
        leaf = _local_pane("/")
        at_bound = {"splitter": {"type": "splitter", "children": [leaf] * (bound - 1)}}
        beyond = {"splitter": {"type": "splitter", "children": [leaf] * bound}}
        self.assertEqual(self.MW._session_problem(at_bound), "")
        self.assertIn(str(bound), self.MW._session_problem(beyond))

    def test_edge_a_session_written_by_the_previous_version_still_restores(self) -> None:
        """0.10.10 wrote file panes only and width/height, no dock state,
        no geometry and no switch."""
        self.session.write_text(
            json.dumps(
                {
                    "window": {
                        "width": 1100,
                        "height": 820,
                        "ui_theme": "modern",
                        "compact": False,
                        "monochrome_icons": False,
                        "language": "en",
                    },
                    "splitter": {
                        "type": "splitter",
                        "orientation": "vertical",
                        "sizes": [300, 300],
                        "children": [
                            {"type": "pane", "path": str(self.dirs[0]), "active": True,
                             "target": False, "local": True},
                            {"type": "pane", "path": str(self.dirs[1]), "active": False,
                             "target": True, "local": True},
                        ],
                    },
                }
            )
        )
        win = self.start_window()
        self.assertTrue(self.restored)
        self.assertEqual(_shape(win._root_splitter), ("v", ("file", "file")))
        self.assertEqual((win.width(), win.height()), (1100, 820))
        self.assertIs(win._active_pane, win._panes[0])
        self.assertIs(win._target_pane, win._panes[1])

    def test_edge_paranoid_mode_restores_without_connecting_or_running_anything(self) -> None:
        from core import security_mode
        from core.profiles import ConnectionProfile

        before = security_mode.current_policy().name
        security_mode.set_policy("paranoid")
        self.addCleanup(security_mode.set_policy, before)
        prod = ConnectionProfile(name="prod", host="h", username="u", auth_type="agent")
        self.write_session(
            {
                "type": "splitter",
                "children": [
                    _local_pane(str(self.dirs[0])),
                    {"type": "pane", "profile": "prod", "path": "/srv"},
                    {"type": "terminal", "profile": "prod"},
                ],
            }
        )
        self.make_window()
        win = self.win
        with mock.patch.object(win.extension_host, "load_enabled") as load, \
                mock.patch.object(win.extension_host, "reload") as reload, \
                mock.patch.object(win._connection_manager, "connect") as connect, \
                mock.patch.object(win, "_run_connect_async") as connect_async, \
                mock.patch.object(win._profile_manager, "get", return_value=prod), \
                mock.patch("pathlib.Path.home", return_value=self.home):
            self.assertTrue(win.restore_layout_on_start())
        load.assert_not_called()
        reload.assert_not_called()
        connect.assert_not_called()
        connect_async.assert_not_called()
        self.assertTrue(security_mode.is_paranoid())
        self.assertEqual(_shape(win._root_splitter), ("h", ("file", "placeholder", "placeholder")))


class DeferredSplitTest(_WindowStateTest):
    """A split sizes its new splitter on the next event-loop pass. When the
    window was deleted before that pass, the closure ran on the deleted
    splitter and its RuntimeError, raised inside Qt, aborted the process."""

    def _run_pending(self) -> list:
        raised: list = []
        hook = sys.excepthook
        sys.excepthook = lambda *exc: raised.append(exc[1])
        try:
            self.app.processEvents()
        finally:
            sys.excepthook = hook
        return raised

    def test_sad_a_split_then_a_deleted_window_raises_nothing(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        from PyQt6.QtGui import QCloseEvent

        win.closeEvent(QCloseEvent())
        _destroy(win)
        self.win = None
        self.assertEqual(self._run_pending(), [])

    def test_happy_a_split_still_gets_equal_sizes(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win.resize(1000, 800)
        win.show()
        self.app.processEvents()
        win._split_pane(Qt.Orientation.Horizontal)
        self.assertEqual(self._run_pending(), [])
        sizes = win._active_pane.parent().sizes()
        self.assertEqual(len(sizes), 2)
        self.assertLessEqual(abs(sizes[0] - sizes[1]), 2, sizes)

    def test_edge_a_terminal_split_then_a_deleted_window_raises_nothing(self) -> None:
        win = self.make_window()
        win._embed_terminal_pane(None, "Local Shell", None, win._active_pane)
        from PyQt6.QtGui import QCloseEvent

        win.closeEvent(QCloseEvent())  # shuts the shell down
        _destroy(win)
        self.win = None
        self.assertEqual(self._run_pending(), [])


class MainEntryRestoresTheLayoutTest(unittest.TestCase):
    def test_happy_main_restores_the_layout_before_showing_the_window(self) -> None:
        import main as entry

        manager = mock.MagicMock()
        with mock.patch.object(sys, "argv", ["axross"]), \
                mock.patch.object(entry, "setup_logging"), \
                mock.patch.object(entry, "_install_excepthook"), \
                mock.patch.dict(os.environ, {"AXROSS_MCP": ""}), \
                mock.patch("core.i18n.install"), \
                mock.patch("core.client_identity.apply_paramiko_banner_override"), \
                mock.patch("core.tmpfs_detect.apply_tempdir_preference"), \
                mock.patch("core.backend_registry.init_registry"), \
                mock.patch("PyQt6.QtWidgets.QApplication", manager.app), \
                mock.patch("ui.main_window.MainWindow", manager.window):
            manager.app.return_value.exec.return_value = 0
            self.assertEqual(entry.main(), 0)
        window = manager.window.return_value
        names = [c[0] for c in window.method_calls if c[0] in ("restore_layout_on_start", "show")]
        self.assertEqual(names, ["restore_layout_on_start", "show"])


class ProfileImportTest(_WindowStateTest):
    def import_file(self, content: bytes):
        path = self.home / "import.json"
        path.write_bytes(content)
        from PyQt6.QtWidgets import QFileDialog

        with mock.patch.object(QFileDialog, "getOpenFileName", return_value=(str(path), "")), \
                mock.patch.object(self.MW.QMessageBox, "warning") as warning, \
                mock.patch.object(self.MW.QMessageBox, "information"):
            self.win._import_profiles_json()
        return warning

    def test_sad_a_non_utf8_import_file_is_reported(self) -> None:
        self.make_window()
        warning = self.import_file(b'{"x": "\xff"}')
        warning.assert_called_once()
        self.assertIn("Cannot read file", warning.call_args.args[2])

    def test_edge_a_non_object_import_file_is_reported(self) -> None:
        self.make_window()
        warning = self.import_file(b"[1]")
        warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
