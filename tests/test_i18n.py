#!/usr/bin/env python3
"""Choosing the interface language.

The requested behaviour was "decide from /etc/localtime or manually".
Measured on the reporting machine, those two signals disagree:

    /etc/localtime -> Europe/Berlin      would say German
    LC_ALL, LANG   -> en_US.UTF-8        would say English

The user sits in Berlin and deliberately runs an English locale. A
timezone says where the machine IS, not what its owner READS —
Europe/Zurich is German, French or Italian; Europe/Brussels is Dutch or
French. The locale environment is a choice the user made; the timezone
is a fact about geography.

So the order is: an explicit setting in axross, then LC_ALL /
LC_MESSAGES / LANG, then the timezone as a last hint, then English.
Every step is tested, because the whole point is that they are consulted
in that order and not another.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.i18n import (  # noqa: E402
    DEFAULT_LANGUAGE,
    SUPPORTED,
    detect_language,
    language_from_locale,
    language_from_timezone,
    normalise_language,
)

# --------------------------------------------------------------------------
# The supported set
# --------------------------------------------------------------------------


def test_happy_every_requested_language_is_supported():
    assert set(SUPPORTED) >= {"de", "en", "pl", "fr", "es", "sv", "nb"}


def test_happy_english_is_the_fallback():
    assert DEFAULT_LANGUAGE == "en"
    assert DEFAULT_LANGUAGE in SUPPORTED


# --------------------------------------------------------------------------
# normalise_language
# --------------------------------------------------------------------------


def test_happy_a_full_locale_reduces_to_its_language():
    assert normalise_language("de_DE.UTF-8") == "de"
    assert normalise_language("pl_PL") == "pl"
    assert normalise_language("fr-CA") == "fr"


def test_edge_norwegian_variants_all_land_on_one_catalogue():
    """no, nb and nn are all Norwegian; shipping three catalogues for
    one language would guarantee two of them rot."""
    for value in ("no", "no_NO", "nb", "nb_NO.UTF-8", "nn_NO"):
        assert normalise_language(value) == "nb", value


def test_sad_an_unsupported_language_is_rejected_not_approximated():
    """Falling back to a "close" language is worse than English: a
    Czech user handed Polish sees words that look almost right."""
    assert normalise_language("cs_CZ.UTF-8") is None
    assert normalise_language("ja_JP") is None


def test_edge_the_posix_locales_are_not_a_language():
    for value in ("C", "POSIX", "C.UTF-8", ""):
        assert normalise_language(value) is None, value


def test_edge_case_and_whitespace_do_not_matter():
    assert normalise_language("  DE_de.utf8  ") == "de"


# --------------------------------------------------------------------------
# language_from_locale
# --------------------------------------------------------------------------


def test_happy_lc_all_wins_over_lang():
    env = {"LC_ALL": "de_DE.UTF-8", "LANG": "fr_FR.UTF-8"}
    assert language_from_locale(env) == "de"


def test_happy_lc_messages_wins_over_lang():
    env = {"LC_MESSAGES": "sv_SE.UTF-8", "LANG": "fr_FR.UTF-8"}
    assert language_from_locale(env) == "sv"


def test_happy_lang_is_used_when_it_is_all_there_is():
    assert language_from_locale({"LANG": "es_ES.UTF-8"}) == "es"


def test_edge_an_unsupported_locale_falls_through_rather_than_matching():
    """It must return None so the NEXT signal gets a turn, instead of
    silently settling on English here."""
    assert language_from_locale({"LANG": "ja_JP.UTF-8"}) is None


def test_edge_a_c_locale_is_no_signal_at_all():
    assert language_from_locale({"LC_ALL": "C", "LANG": "C.UTF-8"}) is None


def test_edge_empty_environment():
    assert language_from_locale({}) is None


# --------------------------------------------------------------------------
# language_from_timezone
# --------------------------------------------------------------------------


def test_happy_an_unambiguous_zone_maps_to_its_language():
    assert language_from_timezone("Europe/Berlin") == "de"
    assert language_from_timezone("Europe/Warsaw") == "pl"
    assert language_from_timezone("Europe/Stockholm") == "sv"
    assert language_from_timezone("Europe/Oslo") == "nb"
    assert language_from_timezone("Europe/Madrid") == "es"
    assert language_from_timezone("Europe/Paris") == "fr"


def test_sad_a_multilingual_zone_yields_nothing():
    """Zurich is German, French or Italian; Brussels is Dutch or French.
    Guessing one insults the other half of the country, and English is
    the honest answer."""
    for zone in ("Europe/Zurich", "Europe/Brussels", "Europe/Luxembourg"):
        assert language_from_timezone(zone) is None, zone


def test_edge_an_unknown_zone_yields_nothing():
    assert language_from_timezone("Antarctica/Troll") is None
    assert language_from_timezone("") is None


def test_edge_a_zone_for_a_language_we_do_not_ship_yields_nothing():
    assert language_from_timezone("Asia/Tokyo") is None


# --------------------------------------------------------------------------
# detect_language — the precedence, which is the whole point
# --------------------------------------------------------------------------


def test_happy_an_explicit_setting_beats_everything():
    lang = detect_language(
        configured="pl",
        env={"LC_ALL": "de_DE.UTF-8"},
        timezone="Europe/Stockholm",
    )
    assert lang == "pl"


def test_happy_the_locale_beats_the_timezone():
    """The reporting machine exactly: Berlin, English locale."""
    lang = detect_language(
        configured=None,
        env={"LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"},
        timezone="Europe/Berlin",
    )
    assert lang == "en", "a deliberate locale must outrank geography"


def test_happy_the_timezone_is_used_when_the_locale_says_nothing():
    lang = detect_language(
        configured=None, env={"LANG": "C.UTF-8"}, timezone="Europe/Warsaw"
    )
    assert lang == "pl"


def test_sad_everything_silent_gives_english():
    assert detect_language(configured=None, env={}, timezone=None) == "en"


def test_sad_an_invalid_configured_value_does_not_win():
    """A stale or hand-edited setting must not pin the UI to a
    catalogue that does not exist."""
    lang = detect_language(
        configured="klingon", env={"LANG": "fr_FR.UTF-8"}, timezone=None
    )
    assert lang == "fr"


def test_edge_a_configured_locale_string_is_normalised_too():
    assert detect_language(configured="de_AT.UTF-8", env={}, timezone=None) == "de"


def test_edge_reading_the_real_timezone_does_not_raise(tmp_path):
    """On a machine without /etc/localtime the detector must degrade,
    not crash the application at startup."""
    from core.i18n import timezone_from_localtime

    assert timezone_from_localtime(tmp_path / "nope") is None


def test_edge_timezone_is_read_from_the_symlink_target(tmp_path):
    zoneinfo = tmp_path / "usr/share/zoneinfo/Europe/Berlin"
    zoneinfo.parent.mkdir(parents=True)
    zoneinfo.write_bytes(b"TZif")
    link = tmp_path / "localtime"
    link.symlink_to(zoneinfo)

    from core.i18n import timezone_from_localtime

    assert timezone_from_localtime(link) == "Europe/Berlin"


# --------------------------------------------------------------------------
# The catalogue
#
# Plain JSON rather than Qt's .ts/.qm: `lrelease`, which compiles the
# binary format QTranslator needs, is absent from the build toolchain
# (checked — only pylupdate6 is there). Adding it would mean another
# tool baked into the builder image, and this session already spent two
# bugs on bundled build-image components fighting the host. JSON
# catalogues ship as ordinary resource data the spec already bundles.
# --------------------------------------------------------------------------


def _catalogue(tmp_path, lang: str, mapping: dict) -> Path:
    import json

    d = tmp_path / "i18n"
    d.mkdir(exist_ok=True)
    (d / f"{lang}.json").write_text(json.dumps(mapping), encoding="utf-8")
    return d


def test_happy_a_known_string_is_translated(tmp_path):
    from core.i18n import Translator

    t = Translator("de", _catalogue(tmp_path, "de", {"Refresh": "Aktualisieren"}))
    assert t.tr("Refresh") == "Aktualisieren"


def test_happy_an_untranslated_string_falls_back_to_the_source_text(tmp_path):
    """A missing entry must show English, not a placeholder or a blank —
    a half-translated UI stays usable, an empty one does not."""
    from core.i18n import Translator

    t = Translator("de", _catalogue(tmp_path, "de", {"Refresh": "Aktualisieren"}))
    assert t.tr("Some New Button") == "Some New Button"


def test_happy_english_needs_no_catalogue(tmp_path):
    from core.i18n import Translator

    t = Translator("en", tmp_path / "i18n")
    assert t.tr("Refresh") == "Refresh"


def test_sad_a_missing_catalogue_degrades_to_source_text(tmp_path):
    """Shipping a language whose file failed to install must not blank
    the interface."""
    from core.i18n import Translator

    t = Translator("pl", tmp_path / "does-not-exist")
    assert t.tr("Refresh") == "Refresh"
    assert t.language == "pl"


def test_sad_a_corrupt_catalogue_degrades_to_source_text(tmp_path):
    from core.i18n import Translator

    d = tmp_path / "i18n"
    d.mkdir()
    (d / "de.json").write_text("{ not json", encoding="utf-8")
    t = Translator("de", d)
    assert t.tr("Refresh") == "Refresh"


def test_edge_a_non_string_value_is_ignored_rather_than_rendered(tmp_path):
    """A hand-edited catalogue must not put a list or a number into a
    button label."""
    from core.i18n import Translator

    t = Translator("de", _catalogue(tmp_path, "de", {"A": ["oops"], "B": "Bee"}))
    assert t.tr("A") == "A"
    assert t.tr("B") == "Bee"


def test_edge_an_empty_translation_is_treated_as_missing(tmp_path):
    """Translation tools leave untranslated entries as empty strings;
    rendering one would produce an invisible button."""
    from core.i18n import Translator

    t = Translator("de", _catalogue(tmp_path, "de", {"Refresh": ""}))
    assert t.tr("Refresh") == "Refresh"


def test_edge_the_shipped_german_catalogue_parses_and_has_no_empty_values():
    """Guards the file that actually ships."""
    import json

    path = Path(__file__).resolve().parent.parent / "resources/i18n/de.json"
    if not path.exists():
        import pytest

        pytest.skip("no German catalogue in this checkout")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict) and data
    empty = [k for k, v in data.items() if not (isinstance(v, str) and v.strip())]
    assert empty == [], f"untranslated entries would render blank: {empty[:5]}"


def test_edge_every_supported_language_has_a_catalogue_or_is_english():
    """A language offered in the picker with no catalogue at all shows a
    fully English UI — acceptable as a stub, but it must be a deliberate
    empty file rather than an oversight."""
    base = Path(__file__).resolve().parent.parent / "resources/i18n"
    if not base.exists():
        import pytest

        pytest.skip("no catalogue directory in this checkout")
    for lang in SUPPORTED:
        if lang == DEFAULT_LANGUAGE:
            continue
        assert (base / f"{lang}.json").exists(), f"no catalogue file for {lang}"


# --------------------------------------------------------------------------
# The stored preference
# --------------------------------------------------------------------------


def test_happy_a_stored_language_round_trips(tmp_path):
    from core.i18n import store_language, stored_language

    path = tmp_path / "session.json"
    store_language("de", path)
    assert stored_language(path) == "de"


def test_happy_storing_a_language_keeps_the_rest_of_the_settings(tmp_path):
    """It shares session.json with the window's visual settings; a
    language change must not wipe them."""
    import json

    path = tmp_path / "session.json"
    path.write_text(json.dumps({"window": {"monochrome_icons": True}, "panes": [1]}))
    from core.i18n import store_language

    store_language("sv", path)
    data = json.loads(path.read_text())
    assert data["window"]["monochrome_icons"] is True
    assert data["panes"] == [1]
    assert data["window"]["language"] == "sv"


def test_sad_a_missing_settings_file_yields_no_preference(tmp_path):
    from core.i18n import stored_language

    assert stored_language(tmp_path / "nope.json") is None


def test_sad_a_corrupt_settings_file_yields_no_preference(tmp_path):
    """This runs before the window exists — an unreadable file must cost
    the preference, not the application."""
    from core.i18n import stored_language

    path = tmp_path / "session.json"
    path.write_text("{{{ not json")
    assert stored_language(path) is None


def test_edge_a_stored_value_for_an_unsupported_language_is_ignored(tmp_path):
    import json

    from core.i18n import stored_language

    path = tmp_path / "session.json"
    path.write_text(json.dumps({"window": {"language": "klingon"}}))
    assert stored_language(path) is None
