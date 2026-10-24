"""Sound for axross: which audio backend Qt uses, which devices, how loud.

``~/.config/axross/audio.json`` (0600)::

    {
      "version": 1,
      "backend": "auto",          # auto, pulseaudio, pipewire
      "output_device": "",        # a device id; "" is the system's default
      "input_device": "",
      "output_volume": 100,       # percent, 0-100
      "input_volume": 100
    }

The backend reaches Qt as ``QT_AUDIO_BACKEND`` (core.multimedia_env) before
any multimedia object exists; "auto" lets core.multimedia_probe find one
that answers. A device id is the same under both backends (PipeWire's
node.name is the name PulseAudio clients see), so a chosen device survives
a change of backend. Read by the Media Player, the media preview and the
Agent dock's voice.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path

BACKENDS = ("auto", "pulseaudio", "pipewire")
VOLUME_RANGE = (0, 100)


def _volume_ok(value) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            and VOLUME_RANGE[0] <= value <= VOLUME_RANGE[1])


#: name -> validator. The order is the settings page's.
FIELDS = {
    "backend": lambda v: v in BACKENDS,
    "output_device": lambda v: isinstance(v, str),
    "output_volume": _volume_ok,
    "input_device": lambda v: isinstance(v, str),
    "input_volume": _volume_ok,
}


def settings_file() -> Path:
    return Path.home() / ".config" / "axross" / "audio.json"


@dataclass
class AudioSettings:
    backend: str = "auto"
    output_device: str = ""
    output_volume: int = 100
    input_device: str = ""
    input_volume: int = 100

    def get(self, name: str):
        if name not in FIELDS:
            raise KeyError(name)
        return getattr(self, name)

    def set(self, name: str, value) -> None:
        if name not in FIELDS:
            raise KeyError(name)
        if not FIELDS[name](value):
            raise ValueError(f"invalid value for the audio setting {name}: {value!r}")
        setattr(self, name, value)

    @classmethod
    def from_dict(cls, data) -> AudioSettings:
        out = cls()
        if isinstance(data, dict):
            for f in fields(cls):
                if f.name in data:
                    try:
                        out.set(f.name, data[f.name])
                    except ValueError:
                        pass  # an invalid value keeps its default
        return out

    def to_dict(self) -> dict:
        return {"version": 1, **asdict(self)}

    @classmethod
    def load(cls, path: Path | None = None) -> AudioSettings:
        try:
            raw = json.loads(Path(path or settings_file()).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        return cls.from_dict(raw)

    def save(self, path: Path | None = None) -> None:
        path = Path(path or settings_file())
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)


def apply_saved_backend(environ: dict | None = None) -> str | None:
    """At the start, before any multimedia object: the saved backend for
    Qt (core.multimedia_env.apply_audio_backend); the value set or None.
    A broken settings file is "auto"."""
    from core.multimedia_env import apply_audio_backend

    try:
        backend = AudioSettings.load().backend
    except Exception:  # noqa: BLE001 - the start must not fail on it
        return None
    return apply_audio_backend(backend, environ)


__all__ = ["BACKENDS", "FIELDS", "VOLUME_RANGE", "AudioSettings", "apply_saved_backend",
           "settings_file"]
