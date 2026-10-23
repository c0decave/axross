"""What the Agent dock speaks, and in which language each part is spoken.

Pure text work, no audio and no third-party package: the voice worker
(core.voice_worker) phonemizes and synthesizes what this module hands it.

* :func:`speakable_text` - the part of an agent answer worth hearing: no
  code blocks (a short note that code is shown instead), no URLs or long
  paths, no Markdown markers, at most :data:`MAX_SPOKEN_CHARS`.
* :func:`segment` - a German sentence split into German fragments and
  English terms. An English IT term in German speech is spoken in English
  (with English phonemes mapped onto the German voice, see
  :data:`ENGLISH_TO_GERMAN_PHONEMES`), never read as a German word. A term
  is English when the answer marks it in {braces}, when the curated
  lexicon (resources/voice/english_terms.txt) holds it, when it is a code
  identifier (snake_case, camelCase, file.ext), or when its spelling is
  English only (:func:`_looks_english`).
* :func:`detect_language` - German or English, for "follow the answer".
* :func:`is_pod_bay_request` - the normaliser of one fixed phrase.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

LANGS = ("de", "en")
LEXICON_FILE = Path(__file__).resolve().parent.parent / "resources" / "voice" / "english_terms.txt"
#: The longest answer read out loud; the rest is left to the screen.
MAX_SPOKEN_CHARS = 1200

#: English phonemes a German voice never heard, as a German speaker says
#: them - in this order (a Whisper A/B check found this variant understood
#: best). "əʊ" goes first: it is one sound.
ENGLISH_TO_GERMAN_PHONEMES: tuple[tuple[str, str], ...] = (
    ("əʊ", "oː"), ("ɜː", "øː"), ("ɹ", "ɾ"), ("æ", "ɛ"), ("ɒ", "ɔ"), ("ʌ", "a"), ("w", "v"),
    ("θ", "s"), ("ð", "d"),
)

#: What the voice says itself, per language. Terms in braces are English.
PHRASES: dict[str, dict[str, str]] = {
    "de": {
        "code_shown": "Der Code wird im Fenster angezeigt.",
        "link": "ein Link",
        "path": "ein Pfad",
        "rest_shown": "Den Rest zeigt das Fenster.",
        "refused": "Das geht leider nicht.",
        "read_only": "Das geht leider nicht: {Files read-only} ist eingeschaltet.",
        "declined": "Das geht leider nicht: Du hast den Aufruf nicht erlaubt.",
        "permission": "Das geht leider nicht: Die {Permission} fehlt.",
        "greeting": "Hallo! Ich wünsche dir einen schönen Tag.",
    },
    "en": {
        "code_shown": "The code is shown on screen.",
        "link": "a link",
        "path": "a path",
        "rest_shown": "The rest is shown on screen.",
        "refused": "That is not possible.",
        "read_only": "That is not possible: Files read-only is on.",
        "declined": "That is not possible: you did not allow this call.",
        "permission": "That is not possible: permission denied.",
        "greeting": "Hello! I wish you a nice day.",
    },
}
REFUSAL_REASONS = ("read_only", "declined", "permission")


def phrase(key: str, lang: str) -> str:
    return PHRASES.get(lang, PHRASES["en"]).get(key, PHRASES["en"].get(key, ""))


def refusal_phrase(reason: str, lang: str) -> str:
    """Short, in *lang*: that it cannot be done, and why when known."""
    return phrase(reason if reason in REFUSAL_REASONS else "refused", lang)


def greeting_phrase(lang: str) -> str:
    return phrase("greeting", lang)


# -- the lexicon ---------------------------------------------------------------------------

#: German plural and case endings an English term takes in German text.
_STEM_ENDINGS = ("es", "en", "s", "n")
#: German words that a lexicon term plus an ending would swallow.
_GERMAN_WORDS = frozenset({
    "links", "logen", "loge", "branche", "branchen", "moden", "locken", "hosen", "rate",
    "raten", "kind", "will", "hell", "fast", "gift", "art", "also", "bad",
})


def _norm_term(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("-", " ").replace("_", " ")).strip().lower()


@dataclass(frozen=True)
class Lexicon:
    words: frozenset = field(default_factory=frozenset)
    phrases: frozenset = field(default_factory=frozenset)
    #: The most words a phrase has.
    longest: int = 1

    def has(self, term: str) -> bool:
        norm = _norm_term(term)
        return norm in self.words or norm in self.phrases

    def has_word(self, word: str) -> bool:
        """*word*, or *word* without a German ending, is a lexicon term."""
        low = word.lower()
        if low in _GERMAN_WORDS:
            return False
        if low in self.words:
            return True
        return any(low.endswith(end) and len(low) - len(end) >= 2 and low[: -len(end)] in self.words
                   for end in _STEM_ENDINGS)

    def has_phrase(self, words: list[str]) -> bool:
        if len(words) < 2:
            return False
        norm = _norm_term(" ".join(words))
        if norm in self.phrases:
            return True
        head, last = norm.rsplit(" ", 1)
        return any(last.endswith(end) and f"{head} {last[: -len(end)]}" in self.phrases
                   for end in _STEM_ENDINGS)


def load_lexicon(path: Path | str | None = None, extra=()) -> Lexicon:
    """The terms of *path* (default: the shipped list) plus *extra*. A
    missing or unreadable file gives the extra terms only."""
    lines: list[str] = []
    try:
        lines = Path(path or LEXICON_FILE).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        lines = []
    words, phrases = set(), set()
    for line in [*lines, *extra]:
        term = _norm_term(str(line))
        if not term or term.startswith("#"):
            continue
        (phrases if " " in term else words).add(term)
    longest = max((p.count(" ") + 1 for p in phrases), default=1)
    return Lexicon(frozenset(words), frozenset(phrases), longest)


# -- is a word English? -------------------------------------------------------------------------

_UMLAUTS = set("äöüÄÖÜß")
_VOWELS = set("aeiouyäöü")
#: German words with an English-looking ending.
_GERMAN_ING = frozenset({"gering", "hering", "ehering", "messing", "wirsing", "fasching"})
#: Consonant pairs a German word may start with (the rest of a compound).
_GERMAN_ONSETS = frozenset({
    "bl", "br", "ch", "dr", "fl", "fr", "gl", "gn", "gr", "kl", "kn", "kr", "pf", "ph", "pl",
    "pr", "sc", "sk", "sl", "sm", "sn", "sp", "st", "sw", "th", "tr", "ts", "zw", "wr",
})
_COMPOUND_PART = 5  # letters of the English part of a compound, at least
_COMPOUND_REST = 4  # letters of the German rest, at least


def _looks_english(low: str) -> bool:
    """Spellings German words do not have (*low* is lower case)."""
    if len(low) < 4:
        return False
    if low.startswith(("sh", "wr")) or (low.endswith("sh") and not low.endswith("sch")):
        return True
    if (re.search(r"ings?$", low) and len(low) >= 5 and not re.search(r"lings?$", low)
            and low.rstrip("s") not in _GERMAN_ING and not re.search(r"[^aeiouy]rings?$", low)):
        return True
    if low.endswith(("ow", "ows", "th", "ths")) or re.search(r"(?:[^aeiou]|[eao])ys?$", low):
        return True
    if low.endswith("ed") and len(low) >= 6 and not low.endswith(("ied", "eed")):
        return True
    return bool(re.search(r"oad|oar|(?<!k)oo[klp]|ou[ndt]", low))


def _plausible_german_start(rest: str) -> bool:
    low = rest.lower()
    if len(low) < _COMPOUND_REST:
        return False
    if low[0] in _VOWELS:
        return True
    if len(low) > 1 and low[1] in _VOWELS:
        return True
    return low[:2] in _GERMAN_ONSETS


def _split_camel(word: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", word)


def _classify_word(word: str, lexicon: Lexicon) -> list[tuple[str, str]]:
    """(kind, text) parts of one word: "en" or "de", "sep" between them."""
    if any(ch in _UMLAUTS for ch in word):
        return [("de", word)]
    if "-" in word:
        # The longest lexicon phrase over the parts ("Read-only-Modus"),
        # else each part on its own ("Tool-Aufruf"); spoken with spaces.
        parts = [p for p in word.split("-") if p]
        out: list[tuple[str, str]] = []
        i = 0
        while i < len(parts):
            if out:
                out.append(("sep", " "))
            span = next((j for j in range(len(parts), i + 1, -1)
                         if lexicon.has_phrase(parts[i:j])), 0)
            if span:
                out.append(("en", " ".join(parts[i:span])))
                i = span
                continue
            out.extend(_classify_word(parts[i], lexicon))
            i += 1
        return out
    if "_" in word.strip("_") and re.search(r"[A-Za-z]", word):
        return [("en", word.replace("_", " ").strip())]
    low = word.lower()
    if low in _GERMAN_WORDS:
        return [("de", word)]
    if lexicon.has_word(word):
        return [("en", word)]
    participle = re.fullmatch(r"ge([a-z]{3,})e?t", low)
    if participle and {participle.group(1), participle.group(1) + "e"} & lexicon.words:
        # "gepusht", "gemergt"
        return [("en", word)]
    if re.search(r"[a-z][A-Z]", word):
        return [("en", _split_camel(word))]
    if word.isupper() or any(ch.isdigit() for ch in word):
        return [("de", word)]
    if _looks_english(low):
        return [("en", word)]
    for cut in range(len(word) - _COMPOUND_REST, _COMPOUND_PART - 1, -1):
        if low[:cut] in lexicon.words and _plausible_german_start(word[cut:]) \
                and low[cut - 1] != low[cut]:
            return [("en", word[:cut]), ("de", word[cut:])]
    for cut in range(_COMPOUND_REST, len(word) - _COMPOUND_PART + 1):
        if low[cut:] in lexicon.words and len(low) - cut >= _COMPOUND_PART:
            return [("de", word[:cut]), ("en", word[cut:])]
    return [("de", word)]


_TOKEN = re.compile(
    r"(?P<brace>\{[^{}\n]{1,60}\})"
    r"|(?P<dotted>[A-Za-z_][\w-]+(?:\.[A-Za-z][\w-]+)+)"
    r"|(?P<number>\d+(?:[.,:]\d+)*(?!\w))"
    r"|(?P<word>\w(?:[\w'’]|-(?=\w))*)"
    r"|(?P<other>\s+|[^\w\s])",
)


def _term_text(text: str) -> str:
    """An English term as it is spoken: hyphens and underscores as spaces,
    the dot of a file name as "dot"."""
    text = re.sub(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z])", " dot ", text)
    return re.sub(r"\s+", " ", text.replace("-", " ").replace("_", " ")).strip()


def segment(sentence: str, lexicon: Lexicon) -> list[tuple[str, str]]:
    """*sentence* as ("de" | "en", text) parts in order; adjacent English
    terms with only spaces between them are one part."""
    tokens = [(m.lastgroup, m.group()) for m in _TOKEN.finditer(sentence or "")]
    items: list[tuple[str, str]] = []
    i = 0
    while i < len(tokens):
        kind, text = tokens[i]
        if kind == "word":
            # The longest lexicon phrase starting here (words split by single spaces).
            matched = 0
            words = [text]
            j = i
            while len(words) < lexicon.longest and j + 2 < len(tokens) \
                    and tokens[j + 1] == ("other", " ") and tokens[j + 2][0] == "word":
                words.append(tokens[j + 2][1])
                j += 2
                if lexicon.has_phrase(words):
                    matched = j
            if matched:
                phrase_words = [tokens[k][1] for k in range(i, matched + 1, 2)]
                items.append(("en", " ".join(phrase_words)))
                i = matched + 1
                continue
            items.extend(_classify_word(text, lexicon))
        elif kind == "brace":
            inner = text[1:-1].strip()
            items.append(("en", _term_text(inner)) if inner else ("sep", " "))
        elif kind == "dotted":
            items.append(("en", _term_text(text)))
        elif kind == "number":
            items.append(("de", text))
        else:
            items.append(("sep", "" if text in "{}" else text))
        i += 1
    return _merge(items)


def _merge(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    parts: list[list[str]] = []
    sep = ""
    for kind, text in items:
        if kind == "sep":
            sep += text
            continue
        last = parts[-1] if parts else None
        if kind == "en" and last is not None and last[0] == "en" and not sep.strip():
            last[1] += " " + text
        elif kind == "de" and last is not None and last[0] == "de":
            last[1] += sep + text
        else:
            if sep.strip():  # punctuation between two parts belongs to the German side
                if kind == "de":
                    text = sep + text
                elif last is not None and last[0] == "de":
                    last[1] += sep
                else:
                    parts.append(["de", sep])
            parts.append([kind, text])
        sep = ""
    if sep.strip():
        if parts and parts[-1][0] == "de":
            parts[-1][1] += sep
        else:
            parts.append(["de", sep])
    result = []
    for kind, text in parts:
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            result.append((kind, text))
    return result


#: Applied after the reference mapping: the diphthongs and r-coloured
#: vowels of espeak-ng's American English (core.voice_worker phonemizes
#: English terms with "en-us"), as German has them. Measured in a
#: disposable container (thorsten-high, Whisper small, 5 sentences x 4 runs,
#: 44 terms): en-gb-x-rp with the reference mapping 27/44 recognised,
#: en-us with this addition 31/44, every part read as German 22/44.
EXTRA_ENGLISH_TO_GERMAN_PHONEMES: tuple[tuple[str, str], ...] = (
    ("eɪ", "eː"), ("oʊ", "oː"), ("ɔɪ", "ɔʏ"), ("ɚ", "ɐ"), ("ɝ", "øːɐ"), ("ᵻ", "ɪ"),
    ("ɪə", "iːɐ"), ("eə", "ɛːɐ"), ("ʊə", "uːɐ"),
)


def map_english_phonemes(phonemes: str) -> str:
    for english, german in ENGLISH_TO_GERMAN_PHONEMES + EXTRA_ENGLISH_TO_GERMAN_PHONEMES:
        phonemes = phonemes.replace(english, german)
    return phonemes


# -- what is spoken -------------------------------------------------------------------------------

_FENCE = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)
_INLINE = re.compile(r"`([^`\n]*)`")
_MD_LINK = re.compile(r"\[([^\]\n]+)\]\((?:[^)\s]+)\)")
_URL = re.compile(r"\b(?:https?|ftp|sftp|smb|ssh|file)://\S+|\bwww\.\S+", re.IGNORECASE)
_PATH = re.compile(r"(?<![\w.:/])(?:~|\.{1,2})?/(?:[\w.@+-]+/)+[\w.@+-]*")
_IDENTIFIER = re.compile(r"[A-Za-z_][\w.+#-]{0,39}")


def speakable_text(answer: str, lang: str) -> str:
    """The part of *answer* the voice reads, in *lang*'s phrases."""
    if not answer or not answer.strip():
        return ""
    text = _FENCE.sub(lambda _m: f"\n{phrase('code_shown', lang)}\n", answer)
    text = _MD_LINK.sub(lambda m: m.group(1), text)
    text = _URL.sub(phrase("link", lang), text)
    text = _INLINE.sub(lambda m: f"{{{m.group(1)}}}" if _IDENTIFIER.fullmatch(m.group(1)) else "",
                       text)
    text = _PATH.sub(phrase("path", lang), text)
    lines = []
    for line in text.splitlines():
        line = re.sub(r"^\s{0,3}(?:#{1,6}\s+|>\s?|[-*+]\s+|\d{1,3}[.)]\s+)", "", line)
        line = re.sub(r"\*\*|__|~~", "", line)
        line = re.sub(r"(?<!\w)[*_]([^*_\n]+)[*_](?!\w)", r"\1", line)
        line = line.replace("|", " ")
        line = re.sub(r"\s+", " ", line).strip()
        if not line or re.fullmatch(r"[-=:\s]+", line):
            continue
        if line[-1] not in ".!?:;,":
            line += "."
        lines.append(line)
    spoken = " ".join(lines).strip()
    if len(spoken) > MAX_SPOKEN_CHARS:
        cut = spoken.rfind(" ", 0, MAX_SPOKEN_CHARS)
        for sentence_end in (". ", "! ", "? "):
            end = spoken.rfind(sentence_end, 0, MAX_SPOKEN_CHARS)
            if end > MAX_SPOKEN_CHARS // 2:
                cut = max(cut if cut < end else end + 1, end + 1)
        spoken = spoken[: cut if cut > 0 else MAX_SPOKEN_CHARS].rstrip() + " " + \
            phrase("rest_shown", lang)
    return spoken


_SHOWN_BRACE = re.compile(r"(?<![{\w$%])\{([A-Za-z][\w .+#/'’-]{0,48})\}(?![}\w])")


def strip_term_braces(text: str) -> str:
    """*text* as shown: "{term}" becomes "term" outside code; JSON, code
    and template braces stay."""
    if not text or "{" not in text:
        return text
    out = []
    pos = 0
    for m in re.finditer(r"```.*?(?:```|\Z)|`[^`\n]*`", text, re.DOTALL):
        out.append(_SHOWN_BRACE.sub(r"\1", text[pos:m.start()]))
        out.append(m.group())
        pos = m.end()
    out.append(_SHOWN_BRACE.sub(r"\1", text[pos:]))
    return "".join(out)


def split_sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.!?…])\s+", (text or "").strip()) if s.strip()]


# -- language of an answer -------------------------------------------------------------------------

_DE_WORDS = frozenset(
    "der die das und ist nicht ich ein eine einen mit für auf den dem zu es sich von auch wird "
    "sind werden kann du sie wir bitte oder aber wenn dass im habe hat ist noch schon keine "
    "nur hier jetzt dann was wie diese dieser gibt gefunden datei ordner".split()
)
_EN_WORDS = frozenset(
    "the and is are not you a an with for on to it of this that can will be i please or but if "
    "in have has was were there here now then what how these found file folder no only".split()
)


def detect_language(text: str, fallback: str = "en") -> str:
    """"de" or "en" by function words (and umlauts); *fallback* without
    any signal."""
    words = re.findall(r"[^\W\d_]+", (text or "").lower())
    de = sum(1 for w in words if w in _DE_WORDS) + 2 * sum(1 for ch in text or "" if ch in _UMLAUTS)
    en = sum(1 for w in words if w in _EN_WORDS)
    if de == en:
        return fallback if fallback in LANGS else "en"
    return "de" if de > en else "en"


# -- one fixed phrase ---------------------------------------------------------------------

_POD_BAY = frozenset({"openthepodbaydoors", "openthepoddoors"})
_POD_BAY_EXTRA = frozenset({"hal", "please"})


def is_pod_bay_request(text) -> bool:
    if not isinstance(text, str):
        return False
    norm = unicodedata.normalize("NFKC", text).lower()
    words = re.sub(r"[^a-z0-9]+", " ", norm).split()
    while words and words[0] in _POD_BAY_EXTRA:
        words.pop(0)
    while words and words[-1] in _POD_BAY_EXTRA:
        words.pop()
    return "".join(words) in _POD_BAY
