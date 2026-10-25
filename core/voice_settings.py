"""Talking with the Agent dock: the voice settings, one JSON file.

``~/.config/axross/agent/voice.json`` (0600, beside the agent settings)::

    {
      "version": 1,
      "output_enabled": false,          # read the agent's answers aloud
      "language": "auto",               # auto (follow the answer), de, en
      "voice_de": "piper-de-thorsten",  # the voice of German speech (core.voice_models)
      "voice_en": "piper-en-ryan",      # the voice of English speech
      "tuning": {                       # how a voice speaks; a voice at TUNING's
        "piper-de-thorsten": {          # defaults is not stored
          "speed": 1.0, "pitch": 0.0, "expressiveness": 1.0, "rhythm": 1.0,
          "volume": 1.0, "pause": 0.3
        }
      },
      "input_mode": "push_to_talk",     # push_to_talk, toggle, conversation
      "hotkey": "F9",                   # held (push-to-talk) or pressed (toggle)
      "after_recognition": "insert",    # insert into the task field, or send
      "silence_seconds": 1.2            # this much quiet ends toggle/conversation input
    }

Every value is reachable through :meth:`VoiceSettings.get` and
:meth:`VoiceSettings.set`, which refuse what :data:`FIELDS` does not allow.
Up to 0.13.133 one ``"gender"`` (male, female) chose the voice of every
language; a file that has it and no ``voice_de`` / ``voice_en`` gets that
gender's voices.

:data:`TUNING` holds the range of each value of how a voice speaks; the
voice worker (core.voice_worker, op ``speak``) checks a request against the
same ranges.

Which server recognises speech is part of the LLM profile
(core.llm_profiles: ``stt_engine``, ``stt_endpoint``, ``stt_model``).
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from core import voice_models as VM
from core import voice_text as VT

INPUT_MODES = ("push_to_talk", "toggle", "conversation")
LANGUAGES = ("auto", "de", "en")
GENDERS = ("male", "female")
AFTER_RECOGNITION = ("insert", "send")
SILENCE_RANGE = (0.5, 5.0)
#: language -> the pinned voices (core.voice_models) that speak it.
VOICES: dict[str, tuple[str, ...]] = {
    lang: tuple(m.id for m in VM.MODELS if m.kind == "voice" and m.language == lang)
    for lang in VT.LANGS
}


@dataclass(frozen=True)
class Tuning:
    """The range of one value of how a voice speaks; *step* is a slider's."""

    low: float
    high: float
    default: float
    step: float


#: How a voice speaks - name -> range. Speed divides Piper's length_scale;
#: pitch is in semitones (core.voice_audio.pitch_shift); expressiveness and
#: rhythm scale Piper's noise_scale and noise_w_scale (the variation of the
#: tone and of the phoneme lengths); volume is a share of the Audio output
#: volume; pause is the silence between two sentences, in seconds.
TUNING: dict[str, Tuning] = {
    "speed": Tuning(0.5, 2.0, 1.0, 0.05),
    "pitch": Tuning(-6.0, 6.0, 0.0, 0.5),
    "expressiveness": Tuning(0.0, 2.0, 1.0, 0.05),
    "rhythm": Tuning(0.0, 2.0, 1.0, 0.05),
    "volume": Tuning(0.1, 1.0, 1.0, 0.05),
    "pause": Tuning(0.0, 2.0, 0.3, 0.05),
}


def default_tuning() -> dict[str, float]:
    return {name: t.default for name, t in TUNING.items()}


def tuning_value_ok(name: str, value) -> bool:
    """*value* is a number inside TUNING[*name*]'s range."""
    t = TUNING.get(name)
    return (t is not None and isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and t.low <= value <= t.high)


def _voice_id(value) -> str | None:
    """The language of the pinned voice *value*, None for anything else."""
    return next((lang for lang, ids in VOICES.items() if value in ids), None)


def _tuning_entry(value) -> dict[str, float]:
    """A complete tuning from a partial one; ValueError for a bad value."""
    if not isinstance(value, dict):
        raise ValueError(f"a voice's tuning is no object: {value!r}")
    out = default_tuning()
    for name, number in value.items():
        if not tuning_value_ok(name, number):
            raise ValueError(f"invalid value for {name}: {number!r}")
        out[name] = float(number)
    return out


def _normal_tuning(value, *, strict: bool) -> dict[str, dict[str, float]]:
    """voice id -> complete tuning, without the voices at their defaults.
    *strict*: ValueError for anything invalid; else what is invalid is left
    out (a voice keeps its valid values)."""
    if not isinstance(value, dict):
        if strict:
            raise ValueError(f"the tuning is no object: {value!r}")
        return {}
    out = {}
    for voice, entry in value.items():
        if _voice_id(voice) is None:
            if strict:
                raise ValueError(f"no such voice: {voice!r}")
            continue
        if not strict:
            entry = ({k: v for k, v in entry.items() if tuning_value_ok(k, v)}
                     if isinstance(entry, dict) else {})
        full = _tuning_entry(entry)
        if full != default_tuning():
            out[voice] = full
    return out


def _tuning_ok(value) -> bool:
    try:
        _normal_tuning(value, strict=True)
    except ValueError:
        return False
    return True

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
    "voice_de": lambda v: _voice_id(v) == "de",
    "voice_en": lambda v: _voice_id(v) == "en",
    "tuning": _tuning_ok,
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
    voice_de: str = "piper-de-thorsten"
    voice_en: str = "piper-en-ryan"
    tuning: dict = field(default_factory=dict)
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
        if name == "silence_seconds":
            value = float(value)
        elif name == "tuning":
            value = _normal_tuning(value, strict=True)
        setattr(self, name, value)

    def voice(self, language: str) -> str:
        """The voice model id that speaks *language* (English for any other)."""
        return self.voice_de if language == "de" else self.voice_en

    def tuning_for(self, voice_id: str) -> dict[str, float]:
        """How *voice_id* speaks: every TUNING value (a copy)."""
        return dict(self.tuning.get(voice_id) or default_tuning())

    @classmethod
    def from_dict(cls, data) -> VoiceSettings:
        out = cls()
        if isinstance(data, dict):
            if data.get("gender") in GENDERS:  # a file of 0.13.133 or older
                out.voice_de = voice_for("de", data["gender"])
                out.voice_en = voice_for("en", data["gender"])
            for f in fields(cls):
                if f.name == "tuning" and f.name in data:
                    out.tuning = _normal_tuning(data["tuning"], strict=False)
                elif f.name in data:
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
    """The voice model id of *language* (de, en) and *gender* - how a file
    of 0.13.133 or older chose its voices."""
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
