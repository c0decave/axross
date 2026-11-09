"""The Arcade window: axross's own four games (core.arcade), drawn with
QPainter - a painted picker (ui/arcade_picker.py), then the game; arrows
/ WASD steer, Space jumps (Tilt Maze) or digs beside (Rockfall), P
pauses, Esc goes back to the picker, and Esc on the picker closes the
window. Every game opens with a short title intro (any key or a click
skips it). Best scores are kept in ~/.config/axross/arcade.json, the
levels reached in ~/.config/axross/arcade-progress.json.

The keys - why the window routes them: Qt gives a key to the focus
widget. When that was anything but the game (a button of the window's
corner after a click or Tab, a page that had just been swapped out), the
letters W A S D went nowhere - while an arrow key on a QAbstractButton
runs focusNextPrevChild() and so moved the focus back to the game: the
arrows "worked", WASD did not. Now the window filters every key event of
its QWindow - before Qt's focus dispatch - and hands it to the current
page's ``handle_key`` (a game view or the picker), wherever the focus is,
and gives that page the focus back. Forms (the level select, the Trail
Runner set-up) keep their keys; Esc there goes back. Keys with Ctrl, Alt
or Meta are left alone (shortcuts). When the window loses the keyboard,
the view forgets which keys were held - their releases go elsewhere.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from PyQt6.QtCore import QEvent, Qt
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from ui.arcade_chase_view import ChaseView
from ui.handbook import install_help_key
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

SCORES = Path.home() / ".config" / "axross" / "arcade.json"

GAMES = {
    "chase": ("Byte Chase", "Collect every bit of the maze; four daemons hunt you. A root key turns them "
              "for a while – catch them then. Arrows or WASD."),
    "tilt": ("Tilt Maze", "100 levels in 10 worlds on an isometric board: collect every bit, a root key "
             "turns the daemons, Space jumps over them and over pits; teleporters, the Hopper, boards "
             "that scroll. A world code opens a world you reached."),
    "rockfall": ("Rockfall", "40 caves in 5 worlds: dig for crystals, then reach the exit before the time "
                 "runs out. Rocks fall and roll, prisms split them into crystals, crawlers and seekers "
                 "hunt you. W A S D move, Space with a direction takes the cell beside you."),
    "trails": ("Trail Runner", "Riders leave walls behind them: make the others run into one first. Eight "
               "arenas or a tournament, 1-3 computer riders in three difficulties or two players on one "
               "keyboard, Space boosts while the energy lasts."),
}
#: Byte Chase's view under the name the window used for it
GameView = ChaseView
_MODIFIERS = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier | \
    Qt.KeyboardModifier.MetaModifier

PROGRESS = Path.home() / ".config" / "axross" / "arcade-progress.json"


def load_progress(path: Path = PROGRESS) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {k: int(v) for k, v in data.items() if isinstance(v, int) and 0 < v <= 1000}
    except (OSError, ValueError, RecursionError, AttributeError):
        return {}


def _write_json_atomically(path: Path, data: dict) -> None:
    """*data* to *path* through a temporary file and a rename: a crash or a
    full disk while writing leaves the old file, not a truncated one that
    the loaders read as "nothing" and the next save writes over."""
    import os
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_progress(game: str, level: int, path: Path = PROGRESS) -> None:
    """Keep the highest level *game* reached."""
    progress = load_progress(path)
    if level <= progress.get(game, 0):
        return
    progress[game] = level
    try:
        _write_json_atomically(path, progress)
    except OSError:
        pass


def load_scores(path: Path = SCORES) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {k: int(v) for k, v in data.items() if k in GAMES and isinstance(v, int)}
    except (OSError, ValueError, RecursionError, AttributeError):
        return {}


def save_score(game: str, score: int, path: Path = SCORES) -> bool:
    """Keep *score* when it beats the best; True when it did."""
    scores = load_scores(path)
    if score <= scores.get(game, 0):
        return False
    scores[game] = score
    try:
        _write_json_atomically(path, scores)
    except OSError:
        pass
    return True


class LevelSelect(QWidget):
    """Where a campaign game starts: level 1, the highest level reached, or
    the world a code opens."""

    def __init__(self, kind: str, *, reached: int, start, back, world_of, levels_per_world: int = 10):
        super().__init__()
        from ui.arcade_picker import ACCENTS
        from ui.arcade_trails_view import FORM_STYLE

        self.kind = kind
        self.setObjectName("arcadeForm")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setStyleSheet(FORM_STYLE)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        intro = QLabel(f"<h1 style='color:{ACCENTS.get(kind, '#e2e8f0')}'>{GAMES[kind][0]}</h1>"
                       f"<p>{tr(GAMES[kind][1])}</p>")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        first = QPushButton(tr("Start at level 1"))
        first.clicked.connect(lambda: start(kind, 1))
        layout.addWidget(first)
        self.cont = QPushButton(tr("Continue at level {n}").format(n=reached))
        self.cont.setEnabled(reached > 1)
        self.cont.clicked.connect(lambda: start(kind, reached))
        layout.addWidget(self.cont)
        row = QHBoxLayout()
        self.code = QLineEdit()
        self.code.setPlaceholderText(tr("world code"))
        self.code.setMaxLength(12)
        go = QPushButton(tr("Open World"))
        self.message = QLabel()

        def open_world():
            w = world_of(self.code.text())
            if w is None:
                self.message.setText(tr("That is not a world code."))
                return
            start(kind, w * levels_per_world + 1)
        go.clicked.connect(open_world)
        self.code.returnPressed.connect(open_world)
        row.addWidget(self.code)
        row.addWidget(go)
        layout.addLayout(row)
        layout.addWidget(self.message)
        b = QPushButton(tr("Back"))
        b.clicked.connect(back)
        layout.addWidget(b)
        layout.addWidget(QLabel(tr("Esc goes back")))
        layout.addStretch(1)
        for button in (first, self.cont, go, b):
            button.setAutoDefault(True)             # Enter presses the focused button, as Space does
        self.default_focus = self.cont if self.cont.isEnabled() else first


class ArcadeWindow(QWidget):
    def __init__(self, parent=None, *, scores: Path = SCORES, progress: Path = PROGRESS, audio=None):
        super().__init__(parent, Qt.WindowType.Window)
        set_window_icon(self, "gamepad")
        install_help_key(self, "arcade")  # F1: its handbook section (a window of its own)
        self.setWindowTitle(tr("Arcade"))
        self.resize(960, 680)
        self.scores_path = scores
        self.progress_path = progress
        if audio is None:
            from ui.arcade_audio import ArcadeAudio

            audio = ArcadeAudio(self)
        self.audio = audio
        self._key_window = None
        self.stack = QStackedWidget()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)
        from ui.arcade_picker import ArcadePicker

        self.picker = ArcadePicker({k: (name, tr(text)) for k, (name, text) in GAMES.items()},
                                   choose=self.choose, close_window=self.close, audio=audio)
        self.stack.addWidget(self.picker)
        self.view = None
        self._refresh_best()
        self.picker.setFocus()
        from ui.close_corner import add_close_corner

        # Feedback: the Arcade could not be closed - no _ [] x of its own.
        add_close_corner(self)

    # -- the keys ------------------------------------------------------------------------------

    def showEvent(self, event) -> None:  # noqa: N802 - Qt API
        super().showEvent(event)
        self._hook_keys()

    def _hook_keys(self) -> None:
        """Filter the keys of this window's QWindow (a new one after the
        window flags changed: the hook follows)."""
        handle = self.windowHandle()
        if handle is not None and handle is not self._key_window:
            handle.installEventFilter(self)
            self._key_window = handle

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt API
        # A filter keeps getting events while Python tears it down: an
        # exception here would end the process (PyQt6 aborts on one).
        try:
            if watched is not self.__dict__.get("_key_window"):
                return False
            kind = event.type()
            if kind in (QEvent.Type.KeyPress, QEvent.Type.KeyRelease):
                return self.route_key(event, kind == QEvent.Type.KeyPress)
        except Exception:  # noqa: BLE001 - see above
            log.exception("Arcade: a key could not be handled")
        return False

    def route_key(self, event, pressed: bool) -> bool:
        """Hand a key of the window to the current page; True when taken."""
        if event.modifiers() & _MODIFIERS:
            return False
        page = self.stack.currentWidget()
        handler = getattr(page, "handle_key", None)
        if handler is None:                       # a form: its keys are its own, Esc goes back
            if pressed and event.key() == Qt.Key.Key_Escape and page is not self.picker:
                self.back()
                return True
            return False
        if pressed and QApplication.focusWidget() is not page and page.isVisible():
            page.setFocus(Qt.FocusReason.OtherFocusReason)
        return bool(handler(event, pressed))

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt API
        if event.type() == QEvent.Type.ActivationChange and not self.isActiveWindow():
            release = getattr(self.view, "release_all", None)
            if callable(release):
                release()
        super().changeEvent(event)

    # -- the pages -----------------------------------------------------------------------------

    def _refresh_best(self) -> None:
        self.picker.best = load_scores(self.scores_path)
        self.picker.update()

    def _show(self, page: QWidget) -> QWidget:
        self.view = page
        self.stack.addWidget(page)
        self.stack.setCurrentWidget(page)
        # a game takes the keys itself; a form keeps the focus on its own first button
        target = page if hasattr(page, "handle_key") else (getattr(page, "default_focus", None) or page)
        target.setFocus(Qt.FocusReason.OtherFocusReason)
        best = load_scores(self.scores_path).get(getattr(page, "kind", ""), 0)
        if hasattr(page, "game"):
            page.best = best
        return page

    def choose(self, kind: str):
        """A campaign game asks where to start; the others start at once."""
        if kind == "trails":
            from ui.arcade_trails_view import TrailsSetup

            self.back()
            return self._show(TrailsSetup(start=self.start_trails, back=self.back))
        if kind not in ("tilt", "rockfall"):
            return self.start(kind)
        from core.arcade import rockfall_campaign as RCAMP
        from core.arcade import tilt_levels as TL

        self.back()
        reached = load_progress(self.progress_path).get(kind, 1)
        world_of, per = (TL.world_of, 10) if kind == "tilt" else (RCAMP.world_of, 8)
        return self._show(LevelSelect(kind, reached=reached, start=self.start_level, back=self.back,
                                      world_of=world_of, levels_per_world=per))

    def start_level(self, kind: str, level: int, intro: bool = True):
        from ui.arcade_rockfall_view import RockfallView
        from ui.arcade_tilt_view import TiltView

        self.back()

        def progress(level_now, score, done=False):
            save_progress(kind, level_now, self.progress_path)
            if done:
                save_score(kind, score, self.scores_path)
        view_class = TiltView if kind == "tilt" else RockfallView
        return self._show(view_class(level=level, audio=self.audio, on_exit=self.back, on_progress=progress,
                                     on_restart=lambda: self.start_level(kind, 1, intro=False), intro=intro))

    def start_trails(self, settings=None, intro: bool = True):
        from ui.arcade_trails_view import TrailsView

        self.back()

        def progress(_level, score, done=False):
            if done:
                save_score("trails", score, self.scores_path)
        return self._show(TrailsView(settings=settings, audio=self.audio, on_exit=self.back, on_progress=progress,
                                     on_restart=lambda: self.start_trails(settings, intro=False), intro=intro))

    def start(self, kind: str, seed: int | None = None, intro: bool = True):
        if kind == "trails":
            return self.start_trails(intro=intro)
        if kind in ("tilt", "rockfall"):
            return self.start_level(kind, 1, intro=intro)
        if kind != "chase":
            raise ValueError(kind)
        self.back()

        def progress(_level, score, done=False):
            if done:
                save_score("chase", score, self.scores_path)
        return self._show(ChaseView(seed=seed, audio=self.audio, on_exit=self.back, on_progress=progress,
                                    on_restart=lambda: self.start("chase", intro=False), intro=intro))

    def back(self) -> None:
        if self.view is not None:
            for name in ("timer", "tick_timer", "frame_timer"):
                t = getattr(self.view, name, None)
                if t is not None:
                    t.stop()
            shutdown = getattr(self.view, "shutdown", None)
            if callable(shutdown):
                shutdown()
            self.stack.removeWidget(self.view)
            self.view.deleteLater()
            self.view = None
        self.stack.setCurrentWidget(self.picker)
        self.picker.setFocus(Qt.FocusReason.OtherFocusReason)
        self._refresh_best()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
        self.back()
        self.audio.stop()
        super().closeEvent(event)
