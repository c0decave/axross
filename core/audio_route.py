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
    audio settings were saved. Made on first use - from the GUI thread.

    It is owned by C++ (sip.transferto), so main.py's exit clean-up
    (core.qt_exit.delete_python_owned_qobjects, which deletes every
    parentless Python-owned QObject) leaves it alone; one deleted all the
    same is made anew - a player connecting to it after that got
    "wrapped C/C++ object ... has been deleted"."""
    global _notifier
    from PyQt6 import sip

    if _notifier is None or sip.isdeleted(_notifier):
        from PyQt6.QtCore import QObject, pyqtSignal

        class _AudioNotifier(QObject):
            changed = pyqtSignal(object)

        made = _AudioNotifier()
        sip.transferto(made, None)
        _notifier = made
    return _notifier


#: axross's sound sources with a volume, mute and output of their own in
#: the Audio Mixer: the Media Player, the Agent's voice, the media preview.
SOURCES = ("media", "voice", "preview", "games")
SOURCE_LABELS = {"media": "Media Player", "voice": "Agent voice", "preview": "Media preview",
                 "games": "Arcade"}


def output_gain() -> float:
    """The master volume as 0.0-1.0 (0 while the master is muted)."""
    saved = settings()
    return 0.0 if saved.output_muted else saved.output_volume / 100.0


def source_gain(source: str) -> float:
    """What *source* plays at, 0.0-1.0: the master volume times the
    source's own (0 when either is muted)."""
    if source not in SOURCES:
        raise ValueError(f"no audio source {source!r}")
    saved = settings()
    if getattr(saved, f"{source}_muted"):
        return 0.0
    return output_gain() * getattr(saved, f"{source}_volume") / 100.0


def source_output_id(source: str) -> str:
    """The device id *source* plays on: its own, else the output's ("" -
    the system's default)."""
    if source not in SOURCES:
        raise ValueError(f"no audio source {source!r}")
    saved = settings()
    return getattr(saved, f"{source}_output") or saved.output_device


def source_device(source: str):
    """The QAudioDevice of :func:`source_output_id` (None: the default)."""
    return output_device(source_output_id(source))


def eq_gains() -> list[float] | None:
    """The equalizer's gains when it is on and not flat, else None (play
    the sound as it is)."""
    from core.audio_eq import is_flat

    saved = settings()
    if not saved.eq_enabled or is_flat(saved.eq_gains):
        return None
    return list(saved.eq_gains)


def update(path=None, **changes) -> AudioSettings:
    """Change some settings: saved like the Audio page saves (OSError on a
    disk error, ValueError for a bad value - then nothing is saved) and
    published to everything that plays."""
    saved = AudioSettings.load(path)
    for name, value in changes.items():
        saved.set(name, value)
    saved.save(path)
    publish(saved)
    return saved


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


def qt_audio_outputs() -> list[tuple[str, str]]:
    """Qt's audio outputs as ``(id, description)`` - only after
    core.multimedia_probe answered ok (its rule for every device list)."""
    from PyQt6.QtMultimedia import QMediaDevices

    return [(device_id(d), d.description()) for d in QMediaDevices.audioOutputs()]


__all__ = ["SOURCES", "SOURCE_LABELS", "device_id", "eq_gains", "find_device", "forget",
           "input_device", "input_gain", "notifier", "output_device", "output_gain", "publish",
           "qt_audio_outputs", "settings", "source_device", "source_gain", "source_output_id",
           "update"]
