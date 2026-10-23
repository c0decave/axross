"""Talking with the Agent dock: the voice settings, one JSON file.

``~/.config/axross/agent/voice.json`` (0600, beside the agent settings)::

    {
      "version": 1,
      "output_enabled": false,          # read the agent's answers aloud
      "language": "auto",               # auto (follow the answer), de, en
      "gender": "male",                 # male, female
      "input_mode": "push_to_talk",     # push_to_talk, toggle, conversation
      "hotkey": "F9",                   # held (push-to-talk) or pressed (toggle)
      "after_recognition": "insert",    # insert into the task field, or send
      "silence_seconds": 1.2            # this much quiet ends toggle/conversation input
    }

Every value is reachable through :meth:`VoiceSettings.get` and
:meth:`VoiceSettings.set`, which refuse what :data:`FIELDS` does not allow.
Which server recognises speech is part of the LLM profile
(core.llm_profiles: ``stt_engine``, ``stt_endpoint``, ``stt_model``).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from core import voice_text as VT

INPUT_MODES = ("push_to_talk", "toggle", "conversation")
LANGUAGES = ("auto", "de", "en")
GENDERS = ("male", "female")
AFTER_RECOGNITION = ("insert", "send")
SILENCE_RANGE = (0.5, 5.0)

#: A hold key with a modifier, or one that types nothing on its own.
_MODIFIERS = r"(?:(?:Ctrl|Alt|Shift|Meta)\+)"
_ALONE = r"(?:F(?:[1-9]|[12][0-9]|3[0-5])|Pause|ScrollLock|Insert|Menu)"
_TYPED = r"(?:[A-Z0-9]|Space|Home|End|PgUp|PgDown)"
_HOTKEY = re.compile(rf"{_MODIFIERS}*{_ALONE}|{_MODIFIERS}+{_TYPED}")


def _hotkey_ok(value) -> bool:
    return isinstance(value, str) and bool(_HOTKEY.fullmatch(value))


def _seconds_ok(value) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and SILENCE_RANGE[0] <= value <= SILENCE_RANGE[1])


#: name -> validator. The order is the settings page's.
FIELDS = {
    "output_enabled": lambda v: isinstance(v, bool),
    "language": lambda v: v in LANGUAGES,
    "gender": lambda v: v in GENDERS,
    "input_mode": lambda v: v in INPUT_MODES,
    "hotkey": _hotkey_ok,
    "after_recognition": lambda v: v in AFTER_RECOGNITION,
    "silence_seconds": _seconds_ok,
}


def settings_file() -> Path:
    from core.agent_settings import agent_dir

    return agent_dir() / "voice.json"


@dataclass
class VoiceSettings:
    output_enabled: bool = False
    language: str = "auto"
    gender: str = "male"
    input_mode: str = "push_to_talk"
    hotkey: str = "F9"
    after_recognition: str = "insert"
    silence_seconds: float = 1.2

    def get(self, name: str):
        if name not in FIELDS:
            raise KeyError(name)
        return getattr(self, name)

    def set(self, name: str, value) -> None:
        if name not in FIELDS:
            raise KeyError(name)
        if not FIELDS[name](value):
            raise ValueError(f"invalid value for the voice setting {name}: {value!r}")
        setattr(self, name, float(value) if name == "silence_seconds" else value)

    @classmethod
    def from_dict(cls, data) -> VoiceSettings:
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
    def load(cls, path: Path | None = None) -> VoiceSettings:
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


_VOICES = {
    ("de", "male"): "piper-de-thorsten",
    ("de", "female"): "piper-de-kerstin",
    ("en", "male"): "piper-en-ryan",
    ("en", "female"): "piper-en-lessac",
}


def voice_for(language: str, gender: str) -> str:
    """The voice model id of *language* (de, en) and *gender*."""
    lang = language if language in VT.LANGS else "en"
    return _VOICES[(lang, gender if gender in GENDERS else "male")]


def spoken_language(setting: str, text: str, fallback: str = "en") -> str:
    """The language *text* is spoken in: the setting, or the text's own."""
    if setting in VT.LANGS:
        return setting
    return VT.detect_language(text, fallback=fallback)


def phrase_language(setting: str, ui_language: str | None = None) -> str:
    """The language of what the voice says by itself (greeting, refusals):
    the setting, or the interface language when it is German."""
    if setting in VT.LANGS:
        return setting
    if ui_language is None:
        from core.i18n import active

        ui_language = active().language
    return "de" if ui_language == "de" else "en"
