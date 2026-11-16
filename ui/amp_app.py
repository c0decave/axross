"""axross-amp: the Media Player, the Audio Mixer and the Bluetooth connector
as one program of its own - ``axross-amp [FILE|FOLDER|URL ...]``.

The same panels as axross's (resources/extensions/media_player.py,
audio_mixer.py, bluetooth.py), each a tab of one window: the player with its
playlists, equalizer and visualizations; the mixer with a volume, mute and
output per source and the system's sound server; Bluetooth to find, pair and
connect headphones and speakers (BlueZ, or a USB stick driven directly). The
player's sound menu (*Audio Mixer…*) shows the mixer's tab. Their state is
axross's (``~/.config/axross``), so the program and axross share it.

The Bluetooth tab asks the system bus only when it is first shown, and the
mixer is built only then too: a start without them costs nothing.
"""

from __future__ import annotations

import sys

from ui.media_player_app import add_arguments, background_runner
from ui.standalone_app import run, smoke_ms_from_env

NAME = "axross-amp"
TITLE = "axross-amp"


class AmpWindow:
    """The window's parts (built by :func:`build`): ``window``, ``tabs``,
    ``player`` and - once their tab was shown - ``mixer`` and ``bluetooth``."""

    def __init__(self, app, args: list[str]) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

        from core.i18n import tr
        from resources.extensions import media_player as MP
        from ui.close_corner import add_close_corner
        from ui.icon_provider import icon, set_window_icon

        self.mixer = None
        self.bluetooth = None
        self.window = QWidget(None, Qt.WindowType.Window)
        self.window.setObjectName("axAmpApp")
        set_window_icon(self.window, "media-player")
        self.window.setWindowTitle(tr(TITLE))
        layout = QVBoxLayout(self.window)
        layout.setContentsMargins(4, 4, 4, 4)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        layout.addWidget(self.tabs)
        self.player = MP.PlayerPanel(state_path=str(MP.state_file()),
                                     run_in_background=background_runner(self.window),
                                     open_mixer=self.show_mixer)
        self.tabs.addTab(self.player, icon("media-player", 16), tr("Media Player"))
        # Placeholders: the mixer and Bluetooth are built when first shown.
        self._mixer_page = QWidget()
        QVBoxLayout(self._mixer_page).setContentsMargins(0, 0, 0, 0)
        self._bluetooth_page = QWidget()
        QVBoxLayout(self._bluetooth_page).setContentsMargins(0, 0, 0, 0)
        self.tabs.addTab(self._mixer_page, icon("mixer", 16), tr("Audio Mixer"))
        self.tabs.addTab(self._bluetooth_page, icon("bluetooth", 16), tr("Bluetooth"))
        self.tabs.currentChanged.connect(self._tab_shown)
        add_close_corner(self.window)
        self.player.track_changed.connect(
            lambda title: self.window.setWindowTitle(f"{tr(TITLE)} – {title}" if title else tr(TITLE)))
        add_arguments(self.player, args)
        self.window.resize(600, 760)
        self.window.show()
        self.window._ax_amp = self  # noqa: SLF001 - kept with the window

    def show_mixer(self) -> None:
        """The player's *Audio Mixer…*: the mixer's tab."""
        self.tabs.setCurrentWidget(self._mixer_page)

    def _tab_shown(self, index: int) -> None:
        page = self.tabs.widget(index)
        if page is self._mixer_page and self.mixer is None:
            from resources.extensions import audio_mixer as AM

            self.mixer = AM.MixerPanel(system_mixer=AM.make_system_mixer())
            page.layout().addWidget(self.mixer)
        elif page is self._bluetooth_page and self.bluetooth is None:
            from core import bluetooth_presence as BP
            from resources.extensions import bluetooth as BTX

            self.bluetooth = BTX.BluetoothHost(BTX.read_source(), panel_options={
                "presence_path": BP.default_path()})
            page.layout().addWidget(self.bluetooth)
            self.bluetooth.start()

    def shutdown(self) -> None:
        """Before the exit: the player saves its list and position and stops
        the sound; the mixer and Bluetooth let go of what they hold."""
        for part in (self.bluetooth, self.mixer):
            if part is not None:
                try:
                    part.shutdown()
                except RuntimeError:  # pragma: no cover - the widget is gone already
                    pass
        self.player.shutdown()


def build(app, args: list[str]):
    """The window; *args* are files, folders, playlists or stream URLs to add
    (and play the first of). Returns the shutdown."""
    return AmpWindow(app, args).shutdown


def main(argv: list[str] | None = None) -> int:
    return run(NAME, TITLE, "media-player", build, argv, smoke_ms=smoke_ms_from_env(),
               multimedia=True)


if __name__ == "__main__":
    sys.exit(main())
