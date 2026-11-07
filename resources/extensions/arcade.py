"""Arcade: axross's own four small games in a window of their own.

*Extensions → Arcade…* opens it:

* **Byte Chase** - collect every bit of a generated maze while four
  daemons hunt you (one tracks you, one cuts you off, one drifts, one
  patrols the corners); a root key turns them for a while.
* **Tilt Maze** - the same game on a board seen from the corner, with a
  jump over the daemons.
* **Rockfall** - dig through a generated cave for crystals; rocks fall and
  roll, crawlers follow the walls, the exit opens at the quota.
* **Trail Runner** - riders leave walls behind them; the last one moving
  wins the round, five rounds the match. Out of a round? Space or Enter
  goes straight to the next one.

Every game opens with a short title intro of its own (any key or a click
skips it) and a jingle; the music and every sound are synthesised
(core/arcade/sound.py) and mixed with little latency (ui/arcade_audio.py).
Arrows or W A S D steer wherever the window's focus is; Esc goes back to
the picker, and from the picker closes the window.

Every level is generated from a seed - nothing is copied from another
game, and the characters, names, art and tunes are axross's own. The rules
are core/arcade/, the window ui/arcade_window.py (picker
ui/arcade_picker.py, one view per game); best scores in
~/.config/axross/arcade.json.
"""

from __future__ import annotations

from PyQt6 import sip

EXTENSION = {
    "name": "Arcade",
    "version": "1.1",
    "description": "axross's own small games in a window: Byte Chase (a maze chase), Tilt Maze (the same "
    "on an isometric board, with a jump), Rockfall (dig for crystals under falling rocks) and Trail "
    "Runner (riders that leave walls) - generated levels, best scores kept.",
    "author": "axross",
}

#: The open window (one at a time), or None.
_WINDOW = None


def show_window(parent=None):
    global _WINDOW
    if _WINDOW is not None and not sip.isdeleted(_WINDOW):
        _WINDOW.show()
        _WINDOW.raise_()
        _WINDOW.activateWindow()
        return _WINDOW
    from ui.arcade_window import ArcadeWindow

    _WINDOW = ArcadeWindow(parent)
    _WINDOW.show()
    return _WINDOW


def activate(api):
    from core.i18n import tr

    api.add_menu_action(tr("Arcade…"), lambda: show_window(getattr(api, "window", None)), icon="gamepad")


def deactivate(api):
    global _WINDOW
    window, _WINDOW = _WINDOW, None
    if window is not None and not sip.isdeleted(window):
        window.close()
