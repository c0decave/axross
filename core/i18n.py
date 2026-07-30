"""Choosing the interface language.

The requested behaviour was "decide from /etc/localtime or manually". On
the machine that asked for it, those two signals disagree:

    /etc/localtime -> Europe/Berlin      would say German
    LC_ALL, LANG   -> en_US.UTF-8        would say English

The owner sits in Berlin and deliberately runs an English locale. A
timezone says where the machine IS, not what its owner READS —
``Europe/Zurich`` is German, French or Italian; ``Europe/Brussels`` is
Dutch or French. The locale environment is a choice somebody made; the
timezone is a fact about geography. So the locale wins, and the timezone
is consulted only when the locale is silent (``C``, ``POSIX``, unset).

Order: explicit setting → ``LC_ALL`` / ``LC_MESSAGES`` / ``LANG`` →
timezone → English.

Two rules about *not* guessing:

* An unsupported language is rejected rather than approximated. Handing
  a Czech user the Polish catalogue produces words that look almost
  right, which is worse than English.
* A multilingual timezone yields nothing. Picking German for Zurich is
  wrong for half the country, and English is the honest answer.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_LANGUAGE = "en"

#: Language code -> display name, in the order a picker should show them.
#: Norwegian is Bokmål (``nb``); ``no`` and ``nn`` normalise onto it
#: rather than shipping three catalogues for one language, two of which
#: would inevitably rot.
SUPPORTED: dict[str, str] = {
    "en": "English",
    "de": "Deutsch",
    "fr": "Français",
    "es": "Español",
    "pl": "Polski",
    "sv": "Svenska",
    "nb": "Norsk (bokmål)",
}

#: Aliases that mean a supported language under another spelling.
_ALIASES = {"no": "nb", "nn": "nb", "nb": "nb"}

#: Locale values that carry no language information.
_NEUTRAL = {"c", "posix", ""}

#: Timezone -> language, ONLY where the zone is unambiguous. Zones for
#: multilingual countries are deliberately absent; see the module
#: docstring.
_TIMEZONE_LANGUAGE = {
    "Europe/Berlin": "de",
    "Europe/Vienna": "de",
    "Europe/Warsaw": "pl",
    "Europe/Paris": "fr",
    "Europe/Madrid": "es",
    "Atlantic/Canary": "es",
    "Europe/Stockholm": "sv",
    "Europe/Oslo": "nb",
    "Europe/London": "en",
    "Europe/Dublin": "en",
    "America/New_York": "en",
    "America/Chicago": "en",
    "America/Denver": "en",
    "America/Los_Angeles": "en",
    "Australia/Sydney": "en",
    "Pacific/Auckland": "en",
    "America/Mexico_City": "es",
    "America/Bogota": "es",
    "America/Argentina/Buenos_Aires": "es",
    "America/Santiago": "es",
}


def normalise_language(value: str | None) -> str | None:
    """Reduce a locale string to a supported language code, or ``None``.

    ``None`` means "no usable signal here" so the caller can move on to
    the next one, rather than settling on English prematurely.
    """
    if not value:
        return None
    text = value.strip().lower()
    if text in _NEUTRAL:
        return None
    # de_DE.UTF-8 / fr-CA / pl_PL -> the leading language subtag
    lang = text.split(".", 1)[0].replace("-", "_").split("_", 1)[0]
    if lang in _NEUTRAL:
        return None
    lang = _ALIASES.get(lang, lang)
    return lang if lang in SUPPORTED else None


def language_from_locale(env: dict | None = None) -> str | None:
    """The language the locale environment asks for, if any.

    ``LC_ALL`` outranks ``LC_MESSAGES`` outranks ``LANG``, which is the
    precedence POSIX defines — a user who set LC_ALL meant it.
    """
    source = os.environ if env is None else env
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        lang = normalise_language(source.get(var))
        if lang is not None:
            return lang
    return None


def language_from_timezone(timezone: str | None) -> str | None:
    """The language a timezone implies, only where it is unambiguous."""
    if not timezone:
        return None
    return _TIMEZONE_LANGUAGE.get(timezone.strip())


def timezone_from_localtime(path: str | Path = "/etc/localtime") -> str | None:
    """Read the zone name out of ``/etc/localtime``.

    Degrades to ``None`` on every failure. This runs during startup, and
    a machine without the file — a container, a stripped image — must
    still get a window.
    """
    try:
        target = Path(path).resolve()
    except OSError as exc:
        log.debug("i18n: cannot resolve %s: %s", path, exc)
        return None
    if not target.exists():
        return None
    parts = target.parts
    if "zoneinfo" not in parts:
        return None
    index = parts.index("zoneinfo")
    zone = "/".join(parts[index + 1 :])
    return zone or None


def detect_language(
    *,
    configured: str | None = None,
    env: dict | None = None,
    timezone: str | None = "",
) -> str:
    """The language to use, following the documented precedence.

    ``timezone`` defaults to the sentinel ``""`` meaning "read
    /etc/localtime"; pass ``None`` to skip the timezone step entirely,
    which is what the tests do to isolate the earlier signals.
    """
    explicit = normalise_language(configured)
    if explicit is not None:
        return explicit

    from_locale = language_from_locale(env)
    if from_locale is not None:
        return from_locale

    zone = timezone_from_localtime() if timezone == "" else timezone
    from_zone = language_from_timezone(zone)
    if from_zone is not None:
        return from_zone

    return DEFAULT_LANGUAGE


#: Where the language preference lives — the same file the window
#: already uses for persistent visual settings, rather than a second
#: settings store to keep in sync.
SETTINGS_FILE = Path.home() / ".config" / "axross" / "session.json"


def stored_language(path: str | Path | None = None) -> str | None:
    """The language the user picked, or ``None``.

    Every failure returns ``None`` so detection falls through to the
    locale: this runs before the window exists, and an unreadable
    settings file must cost the user their preference, not their
    application.
    """
    target = Path(path or SETTINGS_FILE)
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    window = data.get("window") if isinstance(data, dict) else None
    if not isinstance(window, dict):
        return None
    return normalise_language(window.get("language"))


def store_language(language: str, path: str | Path | None = None) -> None:
    """Persist the picked language, merging into the existing settings."""
    target = Path(path or SETTINGS_FILE)
    data: dict = {}
    try:
        loaded = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            data = loaded
    except (OSError, ValueError):
        pass
    window = data.get("window")
    if not isinstance(window, dict):
        window = {}
    window["language"] = language
    data["window"] = window
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(target)


#: Where the shipped catalogues live, relative to the project root.
CATALOGUE_DIR = Path(__file__).resolve().parent.parent / "resources" / "i18n"


class Translator:
    """A language plus its catalogue.

    Plain JSON rather than Qt's ``.ts``/``.qm``: ``lrelease``, which
    compiles the binary format ``QTranslator`` reads, is not in the build
    toolchain (only ``pylupdate6`` is). Adding it would bake another tool
    into the builder image, and bundled build-image components fighting
    the host already cost this project two separate bugs. A JSON
    catalogue ships as ordinary resource data the PyInstaller spec
    already collects.

    Every failure path returns the SOURCE text: a missing catalogue, a
    corrupt one, a non-string value or an empty translation all render
    English. A half-translated interface is usable; a blank one is not.
    """

    def __init__(self, language: str, catalogue_dir: str | Path | None = None) -> None:
        self.language = language
        self._catalogue_dir = Path(catalogue_dir or CATALOGUE_DIR)
        self._entries: dict[str, str] = {}
        if language != DEFAULT_LANGUAGE:
            self._entries = self._load()

    def _load(self) -> dict[str, str]:
        path = self._catalogue_dir / f"{self.language}.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            log.debug("i18n: no catalogue for %s at %s", self.language, path)
            return {}
        except (OSError, ValueError) as exc:
            log.warning("i18n: ignoring unusable catalogue %s: %s", path, exc)
            return {}
        if not isinstance(raw, dict):
            log.warning("i18n: catalogue %s is not an object; ignoring", path)
            return {}
        # Drop anything that cannot be rendered. An empty string is how
        # translation tools mark an untranslated entry, and rendering one
        # produces an invisible label.
        return {
            key: value
            for key, value in raw.items()
            if isinstance(key, str) and isinstance(value, str) and value.strip()
        }

    def tr(self, text: str) -> str:
        """Translate ``text``, or return it unchanged."""
        return self._entries.get(text, text)

    def __len__(self) -> int:
        return len(self._entries)


#: Process-wide translator. Replaced once at startup by ``install``.
_ACTIVE = Translator(DEFAULT_LANGUAGE)


def install(language: str, catalogue_dir: str | Path | None = None) -> Translator:
    """Make ``language`` the active one and return its translator."""
    global _ACTIVE
    _ACTIVE = Translator(language, catalogue_dir)
    log.info("i18n: language %s (%d translated strings)", language, len(_ACTIVE))
    return _ACTIVE


def active() -> Translator:
    return _ACTIVE


def tr(text: str) -> str:
    """Translate through the active translator.

    Deliberately a module function rather than a Qt ``self.tr`` call:
    the catalogue is plain data, so this works in dialogs, in core code
    and in tests without a QApplication.
    """
    return _ACTIVE.tr(text)


__all__ = [
    "CATALOGUE_DIR",
    "DEFAULT_LANGUAGE",
    "SUPPORTED",
    "detect_language",
    "language_from_locale",
    "language_from_timezone",
    "Translator",
    "active",
    "install",
    "SETTINGS_FILE",
    "normalise_language",
    "store_language",
    "stored_language",
    "timezone_from_localtime",
    "tr",
]
