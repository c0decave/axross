"""Where axross's sound goes: the saved audio settings as Qt devices and gains.

core.audio_settings stores the choice (``~/.config/axross/audio.json``);
this module turns it into what the players need:

* :func:`output_device` / :func:`input_device` - the QAudioDevice whose id
  is the saved (or a given) one, or None for "the system's default". A
  device that is no longer there is the default too, with one log line.
* :func:`output_gain` / :func:`input_gain` - the saved volumes as 0.0-1.0.
  The output gain scales every sound axross plays (the Media Player's own
  slider, the media preview, the voice); the input gain is the
  microphone's volume.
* :func:`publish` and :func:`notifier` - the Audio settings page publishes
  what it saved; running components listen to ``notifier().changed`` and
  apply it where Qt allows (a volume, an output's device), else on their
  next playback.

The rule of core.multimedia_probe holds here too: Qt's device lists are
asked for only after the probe answered ok, and "" (the system's default)
needs no list at all.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Callable

from core import multimedia_probe as MPROBE
from core.audio_settings import AudioSettings

log = logging.getLogger(__name__)

_settings: AudioSettings | None = None
#: (kind, id) already logged as missing; dropped again once it is found.
_missing_logged: set[tuple[str, str]] = set()
_notifier = None


def settings() -> AudioSettings:
    """The saved settings (read once, then what :func:`publish` was given)."""
    global _settings
    if _settings is None:
        try:
            _settings = AudioSettings.load()
        except Exception:  # noqa: BLE001 - a player must not fail on its settings
            log.warning("the audio settings could not be read", exc_info=True)
            _settings = AudioSettings()
    return _settings


def forget() -> None:
    """Read the settings file again on the next use (tests)."""
    global _settings
    _settings = None
    _missing_logged.clear()


def publish(saved: AudioSettings) -> None:
    """The Audio page saved *saved*: later reads see it and every listener
    of :func:`notifier` gets a copy of its own."""
    global _settings
    _settings = replace(saved)
    _missing_logged.clear()
    notifier().changed.emit(replace(saved))


def notifier():
    """The app-wide QObject whose ``changed(AudioSettings)`` fires when the
    audio settings were saved. Made on first use - from the GUI thread."""
    global _notifier
    if _notifier is None:
        from PyQt6.QtCore import QObject, pyqtSignal

        class _AudioNotifier(QObject):
            changed = pyqtSignal(object)

        _notifier = _AudioNotifier()
    return _notifier


def output_gain() -> float:
    return settings().output_volume / 100.0


def input_gain() -> float:
    return settings().input_volume / 100.0


def device_id(device) -> str:
    """QAudioDevice.id() as text - the id the settings store."""
    return bytes(device.id()).decode("utf-8", "replace")


def _probe_ok() -> bool:
    result = MPROBE.cached()
    return result is not None and result.ok


def find_device(wanted: str, lister: Callable[[], list], kind: str):
    """The device of *lister()* whose id is *wanted*; None (the system's
    default) for "", before the probe answered ok, and for an id that is
    not there - which is logged once until it is found again."""
    if not wanted or not _probe_ok():
        return None
    try:
        devices = list(lister())
    except Exception:  # noqa: BLE001 - the default plays rather than nothing
        log.warning("the %s devices could not be listed; using the system default", kind,
                    exc_info=True)
        return None
    for device in devices:
        if device_id(device) == wanted:
            _missing_logged.discard((kind, wanted))
            return device
    if (kind, wanted) not in _missing_logged:
        _missing_logged.add((kind, wanted))
        log.info("The audio %s %s is not connected; using the system default", kind, wanted)
    return None


def _outputs() -> list:
    from PyQt6.QtMultimedia import QMediaDevices

    return list(QMediaDevices.audioOutputs())


def _inputs() -> list:
    from PyQt6.QtMultimedia import QMediaDevices

    return list(QMediaDevices.audioInputs())


def output_device(wanted: str | None = None):
    """The output device for *wanted* (None: the saved one); None is the
    system's default."""
    return find_device(settings().output_device if wanted is None else wanted, _outputs,
                       "output")


def input_device(wanted: str | None = None):
    """The input device for *wanted* (None: the saved one); None is the
    system's default."""
    return find_device(settings().input_device if wanted is None else wanted, _inputs, "input")


__all__ = ["device_id", "find_device", "forget", "input_device", "input_gain", "notifier",
           "output_device", "output_gain", "publish", "settings"]
