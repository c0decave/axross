"""The Media Player as a program of its own: ``axross-media-player [FILE|URL ...]``.

The same player as axross's Media Player panel (resources/extensions/
media_player.py): playlists, equalizer, visualizations, its state in
~/.config/axross/media_player.json - in a window of its own. Local files and
folders, M3U playlists and http / https streams; files on axross's remote
connections stay a feature of axross itself.
"""

from __future__ import annotations

import sys

from ui.standalone_app import run, smoke_ms_from_env

NAME = "axross-media-player"
TITLE = "Media Player"


def background_runner(owner):
    """``run(work, on_done, on_error)`` as axross's extension host gives the
    panel: *work* on a thread of its own, the answer on the GUI thread
    (while *owner*, a QObject, lives). Without one the panel ran the audio
    probe - a child process, seconds per backend - and the checks of a
    restored playlist on the GUI thread: no window until they were done."""
    import threading

    from PyQt6.QtCore import QObject

    from core.thread_relay import GuiCall

    class _Deliver(QObject):
        def call(self, callback, value) -> None:
            callback(value)

    deliver = _Deliver(owner)
    relay = GuiCall(deliver.call)

    def run(work, on_done, on_error) -> None:
        def body() -> None:
            try:
                value = work()
            except Exception as exc:  # noqa: BLE001 - handed to on_error
                relay(on_error, exc)
                return
            relay(on_done, value)

        threading.Thread(target=body, name="axross-media-player-work", daemon=True).start()

    return run


def build(app, args: list[str]):
    """The window with the player; *args* are files, folders, playlists or
    stream URLs to add (and play the first of). Returns the shutdown."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QVBoxLayout, QWidget

    from core.i18n import tr
    from resources.extensions import media_player as MP
    from ui.close_corner import add_close_corner
    from ui.icon_provider import set_window_icon

    window = QWidget(None, Qt.WindowType.Window)
    window.setObjectName("axMediaPlayerApp")
    set_window_icon(window, "media-player")
    window.setWindowTitle(tr(TITLE))
    layout = QVBoxLayout(window)
    panel = MP.PlayerPanel(state_path=str(MP.state_file()), run_in_background=background_runner(window))
    layout.addWidget(panel)
    add_close_corner(window)
    panel.track_changed.connect(
        lambda title: window.setWindowTitle(f"{tr(TITLE)} - {title}" if title else tr(TITLE)))
    add_arguments(panel, args)
    window.resize(560, 720)
    window.show()
    window._ax_panel = panel   # noqa: SLF001 - kept with the window
    return panel.shutdown    # saves the list and position, stops the sound


def add_arguments(panel, args: list[str]) -> int:
    """Add what the command line named; play the first. Returns how many."""
    from resources.extensions import media_player as MP

    first = None
    count = 0
    files = [a for a in args if not MP.is_stream(a) and not a.startswith("-")]
    for arg in args:
        if MP.is_stream(arg) and panel.add_stream(arg):
            count += 1
            first = first or panel.playlist.item(panel.playlist.count() - 1)
    if files:
        found, skipped, truncated = MP.collect_local(files)
        item = panel.add_collected(found, skipped, truncated)
        count += len(found)
        first = first or item
    if first is not None:
        panel.play_item(first)
    return count


def main(argv: list[str] | None = None) -> int:
    return run(NAME, TITLE, "media-player", build, argv, smoke_ms=smoke_ms_from_env(),
               multimedia=True)


if __name__ == "__main__":
    sys.exit(main())
