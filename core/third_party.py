"""Third-party software that axross uses and ships - one data file, three views.

``resources/credits/third_party.json`` is the single source of truth: every
Python package, native library, bundled program, downloaded model, host
program and container image axross relies on, with what axross uses it for,
its licence (an SPDX expression), its upstream link and how it reaches the
user (``ships``). From it come

* Help > Third-Party Software… (``ui/third_party_dialog.py``),
* the "Third-party software and thanks" section at the end of README.md,
  README_de.md and README_es.md,
* the tables of THIRD_PARTY_LICENSES.md.

``python -m core.third_party --write`` regenerates the README sections and the
tables (between their ``<!-- third-party:NAME -->`` markers);
``--check`` fails when one of them drifted from the data. The release gate
(tests/test_third_party_bundle.py) holds the data against what a built
one-file binary really contains, with :func:`classify_bundle`.

Values of ``ships``:

``axross-full`` / ``axross-slim``  inside that Linux one-file binary
``pip``         installed by ``pip install axross``
``pip-extra``   installed with an extra (``extras`` names which)
``host``        a program on the user's system that axross calls
``download``    downloaded by axross when the user asks for it
``container``   in or behind a container image (Dockerfiles, MCP hub)
``source``      part of the axross source (re-drawn or a public list)
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from urllib.parse import urlsplit

SCHEMA = 1
DATA_FILE = Path(__file__).resolve().parent.parent / "resources" / "credits" / "third_party.json"
#: Largest data file read (the real one is ~90 KB).
MAX_DATA_BYTES = 4 * 1024 * 1024

KINDS = ("python", "library", "program", "data", "container", "project")
SHIPS = ("axross-full", "axross-slim", "pip", "pip-extra", "host", "download", "container",
         "source")
BUNDLES = ("axross-full", "axross-slim")
REQUIRED = ("id", "name", "kind", "purpose", "license", "url", "ships")
OPTIONAL_TEXT = ("via", "version", "binary", "group", "note")
OPTIONAL_LISTS = ("pypi", "extras")
MATCH_KEYS = ("modules", "libraries", "paths")
MAX_PURPOSE = 200

README_FILES = ("README.md", "README_de.md", "README_es.md")
README_LANGUAGES = {"README.md": "en", "README_de.md": "de", "README_es.md": "es"}
LICENSES_FILE = "THIRD_PARTY_LICENSES.md"

#: Top-level names of axross itself inside a bundle.
FIRST_PARTY = frozenset({"axross", "core", "ui", "models", "security", "resources", "examples",
                         "main", "licenses"})
#: Standard-library modules that newer Pythons dropped, so the running
#: interpreter's ``sys.stdlib_module_names`` misses them in an older bundle.
REMOVED_STDLIB = frozenset({
    "aifc", "asynchat", "asyncore", "audioop", "cgi", "cgitb", "chunk", "crypt", "distutils",
    "imghdr", "imp", "lib2to3", "mailcap", "msilib", "nis", "nntplib", "ossaudiodev", "pipes",
    "smtpd", "sndhdr", "spwd", "sunau", "telnetlib", "uu", "xdrlib", "_compression",
    "_pydatetime", "_pydecimal", "_pyio", "_pylong", "_bootsubprocess",
})


class DataError(ValueError):
    """The data file is missing, unreadable or does not follow the schema."""


@dataclass(frozen=True)
class Entry:
    id: str
    name: str
    kind: str
    purpose: str
    license: str
    url: str
    ships: tuple[str, ...]
    pypi: tuple[str, ...] = ()
    extras: tuple[str, ...] = ()
    via: str = ""
    version: str = ""
    binary: str = ""
    group: str = ""
    note: str = ""
    modules: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    @property
    def in_bundle(self) -> bool:
        return any(b in self.ships for b in BUNDLES)

    @property
    def has_match(self) -> bool:
        return bool(self.modules or self.libraries or self.paths)


# --------------------------------------------------------------------------
# Loading and validation
# --------------------------------------------------------------------------

_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_LICENSE_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*)")
_OPERATORS = ("AND", "OR", "WITH")


def normalise_name(name: str) -> str:
    """A distribution name the PEP 503 way: ``adb_shell`` == ``ADB-Shell``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def valid_license(expr: str) -> bool:
    """True when *expr* reads as an SPDX licence expression: identifiers
    joined by AND / OR, an identifier WITH an exception, parentheses."""
    if not isinstance(expr, str) or not expr.strip() or "\n" in expr:
        return False
    tokens, pos = [], 0
    while pos < len(expr):
        if expr[pos:].strip() == "":
            break
        m = _LICENSE_TOKEN.match(expr, pos)
        if not m:
            return False
        tokens.append(m.group(1))
        pos = m.end()

    def term(i: int) -> int:
        if i >= len(tokens):
            return -1
        if tokens[i] == "(":
            i = expression(i + 1)
            if i < 0 or i >= len(tokens) or tokens[i] != ")":
                return -1
            return i + 1
        if tokens[i] in _OPERATORS or tokens[i] == ")":
            return -1
        i += 1
        if i < len(tokens) and tokens[i] == "WITH":
            if i + 1 >= len(tokens) or tokens[i + 1] in (*_OPERATORS, "(", ")"):
                return -1
            i += 2
        return i

    def expression(i: int) -> int:
        i = term(i)
        while 0 <= i < len(tokens) and tokens[i] in ("AND", "OR"):
            i = term(i + 1)
        return i

    return expression(0) == len(tokens)


def valid_url(url: str) -> bool:
    """A plain https link to a host: no other scheme, no credentials, no
    whitespace or control characters."""
    if not isinstance(url, str) or not url.startswith("https://"):
        return False
    if any(c.isspace() or ord(c) < 32 for c in url):
        return False
    parts = urlsplit(url)
    return parts.scheme == "https" and bool(parts.hostname) and "@" not in parts.netloc


def _text(raw: Mapping, key: str, where: str, *, required: bool) -> str:
    value = raw.get(key, "")
    if value == "" and not required:
        return ""
    if not isinstance(value, str) or not value.strip():
        raise DataError(f"{where}: field {key!r} must be a non-empty string")
    if "\n" in value or "\r" in value:
        raise DataError(f"{where}: field {key!r} must be one line")
    return value


def _strings(value, where: str, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise DataError(f"{where}: field {key!r} must be a list of non-empty strings")
    return tuple(value)


def _entry(raw, index: int) -> Entry:
    if not isinstance(raw, dict):
        raise DataError(f"entry {index}: must be an object")
    where = f"entry {raw.get('id', index)!r}"
    for key in REQUIRED:
        if key not in raw:
            raise DataError(f"{where}: field {key!r} is missing")
    unknown = set(raw) - set(REQUIRED) - set(OPTIONAL_TEXT) - set(OPTIONAL_LISTS) - {"match"}
    if unknown:
        raise DataError(f"{where}: unknown field(s) {sorted(unknown)}")
    entry_id = _text(raw, "id", where, required=True)
    if not _ID.match(entry_id):
        raise DataError(f"{where}: field 'id' must be lower-case letters, digits and '-'")
    kind = _text(raw, "kind", where, required=True)
    if kind not in KINDS:
        raise DataError(f"{where}: field 'kind' must be one of {', '.join(KINDS)}")
    purpose = _text(raw, "purpose", where, required=True)
    if len(purpose) > MAX_PURPOSE:
        raise DataError(f"{where}: field 'purpose' is longer than {MAX_PURPOSE} characters")
    licence = raw["license"]
    if not valid_license(licence):
        raise DataError(f"{where}: field 'license' is no SPDX expression: {licence!r}")
    url = raw["url"]
    if not valid_url(url):
        raise DataError(f"{where}: field 'url' must be a plain https link: {url!r}")
    ships = _strings(raw["ships"], where, "ships")
    if not ships or len(set(ships)) != len(ships) or not set(ships) <= set(SHIPS):
        raise DataError(f"{where}: field 'ships' must name some of {', '.join(SHIPS)}, once each")
    lists = {key: _strings(raw[key], where, key) if key in raw else () for key in OPTIONAL_LISTS}
    if lists["extras"] and "pip-extra" not in ships:
        raise DataError(f"{where}: field 'extras' needs 'pip-extra' in 'ships'")
    match = raw.get("match", {})
    if not isinstance(match, dict) or not set(match) <= set(MATCH_KEYS):
        raise DataError(f"{where}: field 'match' takes only {', '.join(MATCH_KEYS)}")
    matches = {key: _strings(match[key], where, f"match.{key}") if key in match else ()
               for key in MATCH_KEYS}
    texts = {key: _text(raw, key, where, required=False) for key in OPTIONAL_TEXT}
    return Entry(id=entry_id, name=_text(raw, "name", where, required=True), kind=kind,
                 purpose=purpose, license=licence, url=url, ships=ships, **lists, **texts,
                 **matches)


def parse(doc) -> list[Entry]:
    """The entries of a decoded data file; :class:`DataError` names the
    first entry and field that does not follow the schema."""
    if not isinstance(doc, dict):
        raise DataError("the data file must hold an object")
    if doc.get("schema") != SCHEMA:
        raise DataError(f"unsupported schema {doc.get('schema')!r} (expected {SCHEMA})")
    raw_entries = doc.get("entries")
    if not isinstance(raw_entries, list):
        raise DataError("'entries' must be a list")
    entries, seen = [], set()
    for index, raw in enumerate(raw_entries):
        entry = _entry(raw, index)
        if entry.id in seen:
            raise DataError(f"duplicate id {entry.id!r}")
        seen.add(entry.id)
        entries.append(entry)
    return entries


def load(path: Path | str | None = None) -> list[Entry]:
    """The validated entries of the data file (the shipped one by default)."""
    path = Path(path) if path is not None else DATA_FILE
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_DATA_BYTES + 1)
    except OSError as exc:
        raise DataError(f"{path}: {exc.strerror or exc}") from exc
    if len(data) > MAX_DATA_BYTES:
        raise DataError(f"{path}: larger than {MAX_DATA_BYTES} bytes")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DataError(f"{path}: not valid JSON: {exc}") from exc
    return parse(doc)


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------

_SHIP_LABELS = {
    "en": {"host": "on your system", "download": "downloaded on request",
           "container": "container image", "source": "axross source",
           "pip-extra": "pip (with an extra)"},
    "de": {"host": "auf dem eigenen System", "download": "Download auf Anfrage",
           "container": "Container-Image", "source": "axross-Quellcode",
           "pip-extra": "pip (mit einem Extra)"},
    "es": {"host": "en tu sistema", "download": "descarga bajo demanda",
           "container": "imagen de contenedor", "source": "código de axross",
           "pip-extra": "pip (con un extra)"},
}


def ships_label(entry: Entry, language: str = "en") -> str:
    """How *entry* reaches the user, for people: ``axross-full, pip [voice]``."""
    labels = _SHIP_LABELS.get(language, _SHIP_LABELS["en"])
    parts = []
    for value in SHIPS:
        if value not in entry.ships:
            continue
        if value == "pip-extra":
            parts.append(f"pip [{', '.join(entry.extras)}]" if entry.extras
                         else labels["pip-extra"])
        else:
            parts.append(labels.get(value, value))
    return ", ".join(parts)


def search_text(entry: Entry) -> str:
    """What the filter looks at, case-folded."""
    return " ".join((entry.name, entry.purpose, entry.license, ships_label(entry), entry.via,
                     entry.version, entry.note, entry.kind, " ".join(entry.ships))).casefold()


def filter_entries(entries: Sequence[Entry], text: str) -> list[Entry]:
    """The entries whose name, purpose, licence, shipping, ``via`` or note
    contain *text* (case-insensitive); all of them for a blank *text*."""
    needle = (text or "").strip().casefold()
    if not needle:
        return list(entries)
    return [e for e in entries if needle in search_text(e)]


def missing_packages(entries: Iterable[Entry], wanted: Iterable[str]) -> list[str]:
    """The distribution names in *wanted* that no entry lists in ``pypi``."""
    have = {normalise_name(p) for e in entries for p in e.pypi}
    return sorted({normalise_name(w) for w in wanted} - have)


def by_name(entries: Iterable[Entry]) -> list[Entry]:
    return sorted(entries, key=lambda e: (e.name.casefold(), e.id))


# --------------------------------------------------------------------------
# Markdown views
# --------------------------------------------------------------------------


def block_begin(name: str) -> str:
    return f"<!-- third-party:{name} -->"


def block_end(name: str) -> str:
    return f"<!-- /third-party:{name} -->"


_GENERATED = ("<!-- Generated from resources/credits/third_party.json by "
              "`python -m core.third_party --write`; edit the data file, not this block. -->")


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _link(entry: Entry) -> str:
    name = _cell(entry.name).replace("[", "\\[").replace("]", "\\]")
    return f"[{name}]({entry.url})"


def _table(header: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


_README_TEXT = {
    "en": {
        "heading": "## Third-party software and thanks",
        "thanks": ("axross stands on the work of many people. Thank you to everyone who builds "
                   "and maintains the projects below - axross would not exist without them."),
        "source": ("The list is generated from "
                   "[`resources/credits/third_party.json`](resources/credits/third_party.json), "
                   "the same data the app shows in **Help > Third-Party Software…**. Licence "
                   "texts and notes for redistributors are in "
                   "[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)."),
        "direct": ("Project", "Used for", "License", "Comes with"),
        "more": "{n} more libraries that come with the projects above",
        "indirect": ("Project", "Used by", "License", "Comes with"),
    },
    "de": {
        "heading": "## Third-Party-Software und Dank",
        "thanks": ("axross baut auf der Arbeit vieler Menschen auf. Danke an alle, die die "
                   "Projekte unten bauen und pflegen - ohne sie gäbe es axross nicht."),
        "source": ("Die Liste wird aus "
                   "[`resources/credits/third_party.json`](resources/credits/third_party.json) "
                   "erzeugt, denselben Daten, die die App unter **Help > Third-Party "
                   "Software…** zeigt. Lizenztexte und Hinweise für Weiterverteiler stehen in "
                   "[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)."),
        "direct": ("Projekt", "Wofür", "Lizenz", "Kommt mit"),
        "more": "{n} weitere Libraries, die mit den Projekten oben kommen",
        "indirect": ("Projekt", "Benutzt von", "Lizenz", "Kommt mit"),
    },
    "es": {
        "heading": "## Software de terceros y agradecimientos",
        "thanks": ("axross se apoya en el trabajo de muchas personas. Gracias a todos los que "
                   "crean y mantienen los proyectos de abajo: sin ellos axross no existiría."),
        "source": ("La lista se genera a partir de "
                   "[`resources/credits/third_party.json`](resources/credits/third_party.json), "
                   "los mismos datos que la aplicación muestra en **Help > Third-Party "
                   "Software…**. Los textos de las licencias y las notas para quien redistribuye "
                   "están en [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)."),
        "direct": ("Proyecto", "Para qué", "Licencia", "Viene con"),
        "more": "{n} bibliotecas más que llegan con los proyectos de arriba",
        "indirect": ("Proyecto", "Usado por", "Licencia", "Viene con"),
    },
}


def render_readme(entries: Sequence[Entry], language: str = "en") -> str:
    """The README section (without its markers): thanks, the projects axross
    uses directly, and - folded - what comes with them."""
    text = _README_TEXT[language]
    direct = [e for e in by_name(entries) if not e.via]
    indirect = [e for e in by_name(entries) if e.via]
    parts = [_GENERATED, "", text["heading"], "", text["thanks"], "", text["source"], "",
             _table(text["direct"], ((_link(e), _cell(e.purpose), _cell(e.license),
                                      _cell(ships_label(e, language))) for e in direct))]
    if indirect:
        parts += ["", "<details>", f"<summary>{text['more'].format(n=len(indirect))}</summary>",
                  "",
                  _table(text["indirect"], ((_link(e), _cell(e.via), _cell(e.license),
                                             _cell(ships_label(e, language)))
                                            for e in indirect)),
                  "", "</details>"]
    return "\n".join(parts)


def _first(entry: Entry) -> str:
    return _cell(f"{entry.name} {entry.version}" if entry.version else entry.name)


def _in_bundles(entry: Entry) -> str:
    return ", ".join(b.split("-", 1)[1] for b in BUNDLES if b in entry.ships)


def render_licenses(entries: Sequence[Entry]) -> dict[str, str]:
    """The tables of THIRD_PARTY_LICENSES.md, by block name."""
    ordered = by_name(entries)
    extras_rows = sorted(((x, e) for e in ordered for x in e.extras),
                         key=lambda pair: (pair[0], pair[1].name.casefold()))
    blocks = {
        "runtime": _table(("Package", "SPDX license", "Upstream"), (
            (_cell(e.name), _cell(e.license), e.url) for e in ordered
            if e.kind == "python" and "pip" in e.ships and not e.via)),
        "extras": _table(("Extra", "Package", "SPDX license", "Upstream"), (
            (f"`[{x}]`", _cell(e.name), _cell(e.license), e.url) for x, e in extras_rows)),
        "programs": _table(("Tool", "Binary", "SPDX license", "Purpose"), (
            (_first(e), f"`{e.binary}`" if e.binary else "", _cell(e.license), _cell(e.purpose))
            for e in ordered if e.kind == "program" and e.in_bundle)),
        "voice": _table(("Component", "SPDX license", "Note"), (
            (_first(e), _cell(e.license),
             _cell(e.purpose + (f"; {e.note}" if e.note else "")))
            for e in ordered if e.group == "voice")),
        "downloads": _table(("Data", "SPDX license", "Note"), (
            (_first(e), _cell(e.license), _cell(e.purpose + (f"; {e.note}" if e.note else "")))
            for e in ordered if "download" in e.ships)),
        "python-binaries": _table(("Package", "SPDX license", "Used for", "In"), (
            (_link(e), _cell(e.license), _cell(e.purpose), _in_bundles(e))
            for e in ordered if e.kind == "python" and e.in_bundle)),
        "native-binaries": _table(("Component", "SPDX license", "Used for", "In"), (
            (_link(e) + (f" {_cell(e.version)}" if e.version else ""), _cell(e.license),
             _cell(e.purpose + (f"; {e.note}" if e.note else "")), _in_bundles(e))
            for e in ordered if e.kind not in ("python", "program") and e.in_bundle)),
        "host": _table(("Tool", "SPDX license", "Purpose"), (
            (_link(e), _cell(e.license), _cell(e.purpose + (f" ({e.note})" if e.note else "")))
            for e in ordered if "host" in e.ships)),
        "containers": _table(("Project", "SPDX license", "Purpose", "Note"), (
            (_link(e), _cell(e.license), _cell(e.purpose), _cell(e.note))
            for e in ordered if "container" in e.ships)),
    }
    return blocks


def replace_block(text: str, name: str, body: str) -> str | None:
    """*text* with the content between the markers of block *name* replaced
    by *body*; None when the markers are missing or out of order."""
    begin, end = block_begin(name), block_end(name)
    start = text.find(begin)
    stop = text.find(end, start + len(begin)) if start >= 0 else -1
    if start < 0 or stop < 0 or text.count(begin) != 1 or text.count(end) != 1:
        return None
    return text[:start + len(begin)] + "\n" + body + "\n" + text[stop:]


def _rendered(root: Path, entries: Sequence[Entry]) -> dict[str, tuple[str, str | None]]:
    """file -> (current text, wanted text or None when its markers are missing)."""
    out: dict[str, tuple[str, str | None]] = {}
    for name in README_FILES:
        current = (root / name).read_text(encoding="utf-8")
        out[name] = (current, replace_block(current, "readme",
                                            render_readme(entries, README_LANGUAGES[name])))
    current = (root / LICENSES_FILE).read_text(encoding="utf-8")
    wanted: str | None = current
    for block, body in render_licenses(entries).items():
        wanted = replace_block(wanted, block, body) if wanted is not None else None
    out[LICENSES_FILE] = (current, wanted)
    return out


def check(root: Path | str, entries: Sequence[Entry] | None = None) -> list[str]:
    """The generated files under *root* that differ from the data (or lack
    their markers); empty when everything is current."""
    entries = load() if entries is None else entries
    return [name for name, (current, wanted) in _rendered(Path(root), entries).items()
            if wanted is None or wanted != current]


def write(root: Path | str, entries: Sequence[Entry] | None = None) -> list[str]:
    """Regenerates the README sections and licence tables under *root*;
    returns the files it changed. A file without its markers is a
    :class:`DataError` (nothing is written then)."""
    entries = load() if entries is None else entries
    rendered = _rendered(Path(root), entries)
    broken = [name for name, (_, wanted) in rendered.items() if wanted is None]
    if broken:
        raise DataError(f"missing third-party markers in: {', '.join(broken)}")
    changed = []
    for name, (current, wanted) in rendered.items():
        if wanted != current:
            (Path(root) / name).write_text(wanted, encoding="utf-8")
            changed.append(name)
    return changed


# --------------------------------------------------------------------------
# What a built bundle contains
# --------------------------------------------------------------------------

_SO = re.compile(r"^(?P<stem>.+?)\.so(\.[0-9][0-9.]*)?$")
_WHEEL_HASH = re.compile(r"(-[0-9a-f]{8})+$")


def normalise_library(name: str) -> str:
    """The family name of a shared library: no folder, no ``.so.N`` version,
    no auditwheel hash (``pillow.libs/libjpeg-6dc8d115.so.62`` -> ``libjpeg``)."""
    base = name.rsplit("/", 1)[-1]
    m = _SO.match(base)
    stem = m.group("stem") if m else base
    return _WHEEL_HASH.sub("", stem)


def stdlib_modules() -> frozenset[str]:
    return frozenset(sys.stdlib_module_names) | REMOVED_STDLIB


def _is_library(name: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    return base.startswith("lib") and ".so" in base and ".cpython-" not in base \
        and ".abi3." not in base


def _skipped_module(top: str, stdlib: frozenset[str]) -> bool:
    return (top in stdlib or top in FIRST_PARTY or top.startswith(("pyimod", "pyiboot", "_pyi_"))
            or top.startswith("_sysconfigdata_"))


@dataclass
class BundleReport:
    #: TOC names / ``module X`` / dist-info folders no entry claims.
    unclaimed: list[str] = field(default_factory=list)
    #: entry id -> what it claimed in this bundle.
    claimed: dict[str, list[str]] = field(default_factory=dict)
    #: entries that list this bundle in ``ships`` but match nothing in it.
    stale: list[str] = field(default_factory=list)
    #: entries that match something in this bundle it does not list in ``ships``.
    unlisted: list[str] = field(default_factory=list)


def classify_bundle(entries: Sequence[Entry], flavor: str, toc: Iterable[tuple[str, str]],
                    modules: Iterable[str], stdlib: frozenset[str],
                    pypi_names: Mapping[str, str] | None = None) -> BundleReport:
    """Who owns each part of a one-file bundle.

    *toc* is the CArchive table of contents as (typecode, name): binaries
    (``b``) and data (``x``) are looked at, bootstrap code, the PYZ and
    symlinks (``n``, whose targets are listed anyway) are not. *modules* are
    the PYZ module names. A part is claimed by an entry's ``paths`` (glob on
    the full name) first, then - for a shared library - by its
    ``libraries`` (glob on :func:`normalise_library`), else by its
    ``modules`` (the top-level name of an extension module, a data folder or
    a PYZ module). ``*.dist-info`` folders are claimed through ``pypi``.
    """
    report = BundleReport()
    dist_owner: dict[str, str] = {}
    for entry in entries:
        for pypi in entry.pypi:
            dist_owner.setdefault(normalise_name(pypi), entry.id)
    dist_owner.update(pypi_names or {})
    module_owners: dict[str, list[str]] = {}
    for entry in entries:
        for module in entry.modules:
            module_owners.setdefault(module, []).append(entry.id)
    unclaimed: set[str] = set()

    def claim(entry_id: str, what: str) -> None:
        report.claimed.setdefault(entry_id, []).append(what)

    def claim_module(top: str, what: str) -> bool:
        owners = module_owners.get(top, [])
        for owner in owners:
            claim(owner, what)
        return bool(owners)

    for kind, name in toc:
        if kind not in ("b", "x"):
            continue
        by_path = [e for e in entries if any(fnmatch.fnmatchcase(name, p) for p in e.paths)]
        if by_path:
            for e in by_path:
                claim(e.id, name)
            continue
        first = name.split("/", 1)[0]
        if kind == "b" and _is_library(name):
            family = normalise_library(name)
            owners = [e for e in entries
                      if any(fnmatch.fnmatchcase(family, p) for p in e.libraries)]
            for e in owners:
                claim(e.id, name)
            if not owners:
                unclaimed.add(name)
            continue
        if first.startswith("python3.") or name == "base_library.zip":
            continue
        dist = re.match(r"^(.+)-[^-]+\.dist-info$", first)
        if dist:
            owner = dist_owner.get(normalise_name(dist.group(1)))
            if owner:
                claim(owner, first)
            else:
                unclaimed.add(first)
            continue
        top = first.split(".", 1)[0] if "/" not in name else first
        if _skipped_module(top, stdlib):
            continue
        if not claim_module(top, name):
            unclaimed.add(name if kind == "b" else top)
    for module in modules:
        top = module.split(".", 1)[0]
        if _skipped_module(top, stdlib):
            continue
        if not claim_module(top, f"module {module}"):
            unclaimed.add(f"module {top}")
    report.unclaimed = sorted(unclaimed)
    for entry in entries:
        found = entry.id in report.claimed
        if flavor in entry.ships and entry.has_match and not found:
            report.stale.append(entry.id)
        if found and flavor not in entry.ships:
            report.unlisted.append(entry.id)
    return report


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m core.third_party",
        description="Check or regenerate the third-party sections of the READMEs and of "
                    "THIRD_PARTY_LICENSES.md from resources/credits/third_party.json.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 when a file drifted")
    mode.add_argument("--write", action="store_true", help="regenerate the files")
    parser.add_argument("--root", default=str(DATA_FILE.parent.parent.parent),
                        help="the source tree (default: this checkout)")
    args = parser.parse_args(argv)
    try:
        entries = load()
        if args.check:
            stale = check(args.root, entries)
            for name in stale:
                print(f"out of date: {name} (run python -m core.third_party --write)")
            return 1 if stale else 0
        for name in write(args.root, entries):
            print(f"written: {name}")
        return 0
    except (DataError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
