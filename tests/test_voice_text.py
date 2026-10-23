"""What the Agent dock says, and how: core.voice_text.

German speech keeps English IT terms English: a sentence is split into
German fragments and English terms (a curated lexicon, a heuristic, and
terms an answer marks in {braces}); the worker phonemizes each part in
its own language. These tests hold the split on realistic agent answers,
the cleanup of what is spoken (no code, no URLs, no long paths), the
phoneme mapping onto the German voice, and the phrase normaliser of a
hidden reply.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import voice_text as VT  # noqa: E402


@pytest.fixture(scope="module")
def lex():
    return VT.load_lexicon()


def english(segments) -> list[str]:
    return [text for kind, text in segments if kind == "en"]


def german(segments) -> str:
    return " ".join(text for kind, text in segments if kind == "de")


# -- the lexicon -----------------------------------------------------------------------


def test_happy_the_shipped_lexicon_has_the_common_it_terms(lex):
    for term in ("server", "backup", "cache", "timeout", "commit", "pull request", "read only",
                 "python", "ssh", "json", "upload", "download", "shell", "tool"):
        assert lex.has(term), term


def test_sad_a_missing_lexicon_file_gives_an_empty_lexicon(tmp_path):
    lexicon = VT.load_lexicon(tmp_path / "missing.txt")
    assert not lexicon.has("server")


def test_edge_comments_blank_lines_and_case_in_the_lexicon_file(tmp_path):
    path = tmp_path / "terms.txt"
    path.write_text("# comment\n\n  Pull Request  \nKUBERNETES\n", encoding="utf-8")
    lexicon = VT.load_lexicon(path)
    assert lexicon.has("pull request") and lexicon.has("kubernetes")
    assert not lexicon.has("# comment")


def test_edge_extra_terms_extend_the_lexicon(tmp_path):
    lexicon = VT.load_lexicon(tmp_path / "missing.txt", extra=["Flux Capacitor"])
    assert lexicon.has("flux capacitor")


# -- splitting German sentences ----------------------------------------------------------


def test_happy_english_terms_in_a_german_agent_answer(lex):
    seg = VT.segment("Ich habe den Server neu gestartet und das Backup geprüft.", lex)
    assert english(seg) == ["Server", "Backup"]
    assert "neu gestartet" in german(seg) and "geprüft" in german(seg)


def test_happy_a_multiword_term_stays_one_english_part(lex):
    seg = VT.segment("Der Pull Request ist offen.", lex)
    assert english(seg) == ["Pull Request"]


def test_happy_braces_mark_a_term_and_are_not_spoken(lex):
    seg = VT.segment("Das nennt man {Flux Capacitor} im Labor.", lex)
    assert english(seg) == ["Flux Capacitor"]
    assert "{" not in german(seg) and "Labor" in german(seg)


def test_happy_hyphenated_english_terms_are_spoken_with_spaces(lex):
    seg = VT.segment("Die Dateien sind read-only.", lex)
    assert english(seg) == ["read only"]


def test_happy_a_compound_with_a_hyphen_splits_into_english_and_german(lex):
    seg = VT.segment("Der Tool-Aufruf wurde abgelehnt.", lex)
    assert english(seg) == ["Tool"]
    assert "Aufruf" in german(seg)


def test_happy_a_lexicon_phrase_inside_a_hyphen_compound(lex):
    seg = VT.segment("Die Aufrufe liefen im Read-only-Modus.", lex)
    assert english(seg) == ["Read only"]
    assert "Modus" in german(seg)


def test_happy_a_german_participle_of_an_english_verb(lex):
    seg = VT.segment("Kein Commit wurde gepusht oder gemergt.", lex)
    assert english(seg) == ["Commit", "gepusht", "gemergt"]


def test_happy_an_english_error_phrase_in_german_speech(lex):
    seg = VT.segment("Der Upload ist fehlgeschlagen: Permission denied.", lex)
    assert english(seg) == ["Upload", "Permission denied"]


def test_happy_compound_words_without_a_hyphen(lex):
    seg = VT.segment("Die Serverliste und der Datenbankserver sind da.", lex)
    assert english(seg) == ["Server", "server"]
    assert "liste" in german(seg) and "Datenbank" in german(seg)


def test_happy_german_plural_endings_on_english_terms(lex):
    seg = VT.segment("In beiden Containern laufen die Commits durch.", lex)
    assert english(seg) == ["Containern", "Commits"]


def test_happy_code_identifiers_are_english(lex):
    seg = VT.segment("Ich rufe list_dir und readFile auf.", lex)
    assert english(seg) == ["list dir", "read File"]


def test_happy_file_names_are_english_with_dot(lex):
    seg = VT.segment("Öffne die Datei config.json bitte.", lex)
    assert english(seg) == ["config dot json"]


def test_happy_heuristic_finds_terms_the_lexicon_lacks(lex):
    seg = VT.segment("Das Sharding und der Gateway brauchen einen Hook.", lex)
    assert english(seg) == ["Sharding", "Gateway", "Hook"]


def test_sad_ordinary_german_stays_german(lex):
    sentence = ("Die Bearbeitung der Reaktion ist gering, der Frühling beginnt und das "
                "Theater zeigt einen linearen Ozean im Haushalt.")
    seg = VT.segment(sentence, lex)
    assert english(seg) == []


def test_sad_umlauts_never_make_a_word_english(lex):
    seg = VT.segment("Prüfung, Größe, Übung, Straße.", lex)
    assert english(seg) == []


def test_sad_short_german_words_are_no_compound_terms(lex):
    # "Mailand" starts with "mail", "Bugwelle" with "bug": too short a prefix.
    seg = VT.segment("Wir fahren nach Mailand und sehen die Bugwelle.", lex)
    assert english(seg) == []


def test_edge_numbers_and_versions_stay_german(lex):
    seg = VT.segment("Version 0.12.175 hat 3 Fehler.", lex)
    assert english(seg) == []
    assert "0.12.175" in german(seg)


def test_edge_python_version(lex):
    seg = VT.segment("Mit Python 3.14 geht das.", lex)
    assert english(seg) == ["Python"]
    assert "3.14" in german(seg)


def test_edge_adjacent_terms_merge_into_one_part(lex):
    seg = VT.segment("Der SSH Server läuft.", lex)
    assert english(seg) == ["SSH Server"]


def test_edge_empty_and_punctuation_only(lex):
    assert VT.segment("", lex) == []
    assert english(VT.segment("…!?", lex)) == []


def test_edge_an_unclosed_brace_is_plain_text(lex):
    seg = VT.segment("Das {geht so nicht.", lex)
    assert english(seg) == []


# -- what is spoken ------------------------------------------------------------------------


def test_happy_code_blocks_are_not_read_but_announced():
    text = "Hier ist das Skript:\n```python\nprint('x')\n```\nFertig."
    spoken = VT.speakable_text(text, "de")
    assert "print" not in spoken
    assert "Code" in spoken and "Fertig." in spoken


def test_happy_code_blocks_in_english():
    spoken = VT.speakable_text("Run this:\n```\nls -la\n```", "en")
    assert "ls" not in spoken and "code" in spoken.lower()


def test_happy_urls_and_long_paths_are_not_read():
    text = "Siehe https://example.com/a/b?c=1 und ~/projekte/axross/core/agent.py dazu."
    spoken = VT.speakable_text(text, "de")
    assert "example" not in spoken and "agent.py" not in spoken
    assert "Link" in spoken and "Pfad" in spoken


def test_happy_markdown_markers_are_not_read():
    spoken = VT.speakable_text("## Ergebnis\n- **zwei** Dateien\n- _eine_ Warnung\n> Zitat", "de")
    for marker in ("#", "**", "_eine_", ">", "- "):
        assert marker not in spoken
    assert "zwei" in spoken and "eine" in spoken


def test_happy_a_markdown_link_reads_its_text():
    spoken = VT.speakable_text("Lies [die Anleitung](https://example.com/x).", "de")
    assert "die Anleitung" in spoken and "example" not in spoken


def test_happy_inline_code_identifier_is_kept_as_a_term():
    spoken = VT.speakable_text("Die Funktion `list_dir` liest.", "de")
    assert "{list_dir}" in spoken


def test_sad_inline_code_with_spaces_is_dropped():
    spoken = VT.speakable_text("Starte `rm -rf /tmp/x` nicht.", "de")
    assert "rm" not in spoken


def test_edge_very_long_answers_are_cut_with_a_note():
    spoken = VT.speakable_text("Satz eins ist da. " * 400, "de")
    assert len(spoken) < VT.MAX_SPOKEN_CHARS + 200
    assert spoken.rstrip().endswith(VT.PHRASES["de"]["rest_shown"])


def test_edge_empty_answer_says_nothing():
    assert VT.speakable_text("", "de") == ""
    assert VT.speakable_text("```\nonly code\n```", "en") == VT.PHRASES["en"]["code_shown"]


# -- braces in what is shown -----------------------------------------------------------------


def test_happy_braces_are_stripped_from_the_shown_text():
    assert VT.strip_term_braces("Das ist {read-only} jetzt.") == "Das ist read-only jetzt."


def test_sad_json_and_code_braces_are_kept():
    text = 'Antwort: {"a": 1} und ```\nif x { y }\n``` und `{z}`'
    assert VT.strip_term_braces(text) == text


def test_edge_nested_or_empty_braces_are_kept():
    assert VT.strip_term_braces("{} und {{x}}") == "{} und {{x}}"


# -- language of an answer -------------------------------------------------------------------


def test_happy_detects_german_and_english():
    assert VT.detect_language("Ich habe die Datei gelesen und nichts gefunden.") == "de"
    assert VT.detect_language("I have read the file and found nothing.") == "en"


def test_edge_german_with_many_english_terms_is_german():
    assert VT.detect_language("Der Server hat den Cache und das Backup im Container.") == "de"


def test_edge_no_signal_falls_back():
    assert VT.detect_language("42", fallback="en") == "en"
    assert VT.detect_language("", fallback="de") == "de"


# -- sentences ---------------------------------------------------------------------------------


def test_happy_split_sentences():
    assert VT.split_sentences("Eins. Zwei! Drei? Vier") == ["Eins.", "Zwei!", "Drei?", "Vier"]


def test_edge_versions_do_not_split_sentences():
    assert VT.split_sentences("Version 0.12.175 ist da. Gut.") == ["Version 0.12.175 ist da.",
                                                                  "Gut."]


# -- phonemes ------------------------------------------------------------------------------------


def test_happy_english_phonemes_map_onto_the_german_voice():
    assert VT.map_english_phonemes("ɹɪˈpɒzɪtəɹi") == "ɾɪˈpɔzɪtəɾi"
    assert VT.map_english_phonemes("θɪŋk ðə wɜːld") == "sɪŋk də vøːld"
    assert VT.map_english_phonemes("kəʊd") == "koːd"


def test_edge_mapping_order_is_the_reference_order():
    # "əʊ" must map before a lone "ə" could ever be touched (it never is).
    assert VT.ENGLISH_TO_GERMAN_PHONEMES[0] == ("əʊ", "oː")
    assert ("w", "v") in VT.ENGLISH_TO_GERMAN_PHONEMES


def test_happy_american_diphthongs_and_r_colouring_map_too():
    assert VT.map_english_phonemes("sˈɝvɚ") == "sˈøːɐvɐ"
    assert VT.map_english_phonemes("təmˈeɪtoʊ") == "təmˈeːtoː"


def test_sad_german_phonemes_pass_unchanged():
    assert VT.map_english_phonemes("ɡəˈʃtaɾtət") == "ɡəˈʃtaɾtət"


# -- phrases ---------------------------------------------------------------------------------------


def test_happy_refusal_phrases_say_why_in_each_language():
    assert "read-only" in VT.refusal_phrase("read_only", "de")
    assert "Permission" in VT.refusal_phrase("permission", "de")
    assert "permission" in VT.refusal_phrase("permission", "en").lower()
    assert "allow" in VT.refusal_phrase("declined", "en")


def test_sad_unknown_reason_or_language_still_says_it_cannot():
    assert VT.refusal_phrase("weird", "en") == VT.PHRASES["en"]["refused"]
    assert VT.refusal_phrase("read_only", "xx") == VT.refusal_phrase("read_only", "en")


def test_happy_greeting_wishes_a_nice_day():
    assert "schönen Tag" in VT.greeting_phrase("de")
    assert "nice day" in VT.greeting_phrase("en")


# -- the hidden reply's phrase ------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "open the pod bay doors",
    "Open the pod bay doors, HAL.",
    "Open the podbay doors HAL.",
    "open  the   pod bay doors",
    "OPEN THE POD-BAY DOORS!",
    "Hal, open the pod bay doors, please.",
    "Please open the pod bay doors, Hal",
    "open the pod doors",
    "Open the pod doors, HAL!",
    "open the pod bay doors please hal",
    "  open,the pod bay doors ",
])
def test_happy_the_phrase_and_its_close_spellings(text):
    assert VT.is_pod_bay_request(text)


@pytest.mark.parametrize("text", [
    "",
    "open the doors",
    "open the pod",
    "the pod bay doors are open",
    "Can you open the pod bay doors?",
    "open the pod bay doors and list the files",
    "close the pod bay doors",
    "Kubernetes pods: open the bay doors config",
    "Please list the pods behind the doors",
    "open the pod bay door",
    "hal hal hal",
])
def test_sad_sentences_that_merely_mention_pods_or_doors(text):
    assert not VT.is_pod_bay_request(text)


def test_edge_non_string_is_no_request():
    assert not VT.is_pod_bay_request(None)  # type: ignore[arg-type]
