"""Help > Handbook: which file, which section, where a link goes.

The handbook is the user guide, ``docs/USAGE.md`` - or its translation for
the interface language, ``USAGE_de.md`` / ``USAGE_es.md`` (core.i18n); a
language without one gets the English guide.

**Where the files are.** One copy, docs/, in every artefact:

* a source checkout and the sdist (MANIFEST.in) read ``docs/`` itself;
* a wheel installs the same files as ``resources/handbook/``: pyproject.toml
  maps the package ``resources.handbook`` onto the directory ``docs``
  (``[tool.setuptools.package-dir]``) and takes only :data:`HANDBOOK_FILES`
  from it (package-data, exclude-package-data);
* the PyInstaller bundle (build/axross.spec) collects :data:`HANDBOOK_FILES`
  from docs/ into ``resources/handbook/`` too.

Nothing is copied by hand, so nothing can drift; tests/test_handbook.py
holds the three lists to :data:`HANDBOOK_FILES`. ``resources/handbook``
is looked at first: in an installed tree a ``docs/`` beside the packages
belongs to whichever other package put it there.

**Sections.** F1 opens the handbook at the section of the area that has
the focus: a *topic* (:data:`SECTIONS`) names the English heading. The
translations keep the English outline - the same ``##`` / ``###``
headings in the same order (tests/test_usage_translations_in_step.py) -
so the section of a translated guide is the heading at the same place.
An unknown topic, or a heading that is gone, opens the contents.

Plain Python, no Qt (ui.handbook is the window).
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.guide_text import headings, plain_heading, read_guide

#: Interface language -> its guide; English is the fallback of every other.
HANDBOOK_FILES: dict[str, str] = {
    "en": "USAGE.md",
    "de": "USAGE_de.md",
    "es": "USAGE_es.md",
}
ENGLISH = "en"
#: Where a wheel and the bundle carry the files, relative to the project root.
PACKAGED_DIR = os.path.join("resources", "handbook")
#: Where a checkout and the sdist have them.
SOURCE_DIR = "docs"
#: ``source`` of a handbook that is not installed (no file found).
BUILT_IN_SOURCE = "built-in"
#: The GitHub repository whose docs a link to another document opens.
REPOSITORY = "https://github.com/c0decave/axross"

#: Help topic -> the English heading of docs/USAGE.md it opens. The keys are
#: what widgets carry (ui.handbook.HELP_TOPIC_PROPERTY); "settings.<page>"
#: is a page of Edit > Settings… (a page without a row opens "Settings").
SECTIONS: dict[str, str] = {
    "panes": "Multi-pane layout",
    "path-bar": "Path bar",
    "bookmarks": "Path bar",
    "workspaces": "Workspaces — several layouts, on several screens",
    "docks": "Docks: the right column and automatic tabs",
    "transfers": "Transfers",
    "terminal": "Transfers, terminal, log dock",
    "log": "Transfers, terminal, log dock",
    "connections": "Connections",
    "find-files": "Find Files",
    "analysis": "Find Files and sift",
    "scripting": "Scripting & embedded REPL",
    "agent": "Agent dock — a local LLM works with axross",
    "mail": "Mail docks and mail projects",
    # The tool windows of their own (each takes F1 itself, ui.handbook.install_help_key).
    "index": "The offline index",
    "duplicates": "Duplicate Finder",
    "disk-usage": "Disk Usage",
    "scheduler": "Scheduled Jobs",
    "diagnostics": "Diagnostics and Recovery Scan",
    "system-info": "System Information",
    "arcade": "Arcade",
    "agent-stats": "Agent dock — a local LLM works with axross",
    "handbook": "Handbook and tours",
    "settings": "Settings",
    "settings.network": "Connections",
    "settings.llm": "Agent dock — a local LLM works with axross",
    "settings.analysis": "Find Files and sift",
    "settings.agent": "Agent dock — a local LLM works with axross",
    "settings.voice": "Talking with the agent",
    "settings.search": "The offline index",
    "settings.updates": "Updates",
    "settings.logging": "Logging",
}

BUILT_IN_HANDBOOK = """\
# Using axross

The handbook's files are not part of this installation. Read it online:
{url}

* **F1** opens the handbook at the section for the area you are in.
* **Help > Tours…** walks through the window: the panes, connections,
  copying safely, finding and organizing, automation and extensions.
* **Help > Keyboard Shortcuts** (Ctrl+F1) lists every key.
"""


@dataclass(frozen=True)
class Handbook:
    """A loaded handbook: its Markdown, the file it came from (or
    :data:`BUILT_IN_SOURCE`) and the language of that file."""

    text: str
    source: str
    language: str


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def handbook_dirs(root: str | None = None) -> list[str]:
    """The directories that may hold the handbook, in the order they are
    asked: the packaged copy of a wheel or bundle, then docs/."""
    base = root or project_root()
    return [os.path.join(base, PACKAGED_DIR), os.path.join(base, SOURCE_DIR)]


def _language_of(language: str | None) -> str:
    if language is None:
        from core.i18n import active

        language = active().language
    return language or ENGLISH


def load(language: str | None = None, *, root: str | None = None) -> Handbook:
    """The handbook for *language* (default: the interface language): its
    own file, else the English one, else the built-in note."""
    language = _language_of(language)
    wanted = [language] if language in HANDBOOK_FILES and language != ENGLISH else []
    wanted.append(ENGLISH)
    for lang in wanted:
        for folder in handbook_dirs(root):
            path = os.path.join(folder, HANDBOOK_FILES[lang])
            text = read_guide(path)
            if text is not None:
                return Handbook(text, path, lang)
    return Handbook(BUILT_IN_HANDBOOK.format(url=web_url("docs/USAGE.md")), BUILT_IN_SOURCE,
                    ENGLISH)


def sibling(handbook: Handbook, language: str) -> Handbook | None:
    """The handbook of *language* next to *handbook* (the same folder), or
    None when it has none."""
    name = HANDBOOK_FILES.get(language)
    if name is None or handbook.source == BUILT_IN_SOURCE:
        return None
    path = os.path.join(os.path.dirname(handbook.source), name)
    text = read_guide(path)
    return Handbook(text, path, language) if text is not None else None


# -- sections ------------------------------------------------------------------------------


def outline(markdown: str) -> list[str]:
    """The ``##`` and ``###`` headings of *markdown* in order, as rendered."""
    return [plain_heading(text) for level, text in headings(markdown) if level in (2, 3)]


def topic_heading(topic: str | None) -> str | None:
    """The English heading of *topic*: a settings page without a row of its
    own is "Settings"; an unknown topic is None (the contents)."""
    if not topic:
        return None
    if topic in SECTIONS:
        return SECTIONS[topic]
    if topic.startswith("settings."):
        return SECTIONS["settings"]
    return None


def section_in(english_heading: str, markdown: str, english_markdown: str | None) -> str | None:
    """The heading of *markdown* that stands where *english_heading* stands
    in the English guide: itself in the English guide, the heading at the
    same place of the outline in a translation. None when it is not there."""
    wanted = plain_heading(english_heading)
    own = outline(markdown)
    english = outline(english_markdown) if english_markdown is not None else []
    # The place first: a translation may keep an English heading word for
    # word ("Transfers") somewhere else of its outline.
    if wanted in english and len(english) == len(own):
        return own[english.index(wanted)]
    return wanted if wanted in own else None


def english_text(handbook: Handbook, *, root: str | None = None) -> str | None:
    """The English guide that belongs to *handbook* (for the outline)."""
    if handbook.language == ENGLISH:
        return handbook.text
    english = sibling(handbook, ENGLISH)
    if english is None:
        english = load(ENGLISH, root=root)
        if english.source == BUILT_IN_SOURCE:
            return None
    return english.text


def section_for(topic: str | None, handbook: Handbook, *, root: str | None = None) -> str | None:
    """The heading of *handbook* that *topic* opens, or None (the contents)."""
    heading = topic_heading(topic)
    if heading is None:
        return None
    return section_in(heading, handbook.text, english_text(handbook, root=root))


# -- links ---------------------------------------------------------------------------------


def web_url(repo_path: str, fragment: str = "") -> str:
    """*repo_path* (``docs/MCP.md``) of this version's tag on GitHub."""
    try:
        from axross._version import __version__ as version
    except ImportError:  # pragma: no cover - the package is always there
        version = ""
    ref = f"v{version}" if version else "main"
    url = f"{REPOSITORY}/blob/{ref}/{repo_path}"
    return f"{url}#{fragment}" if fragment else url


def classify_link(href: str) -> tuple[str, str, str]:
    """What a link of the handbook does, as ``(kind, value, fragment)``:

    * ``("section", "", slug)`` - a heading of this guide (``#slug``);
    * ``("language", code, slug)`` - the guide of another language
      (``USAGE_de.md``), at ``#slug`` when given;
    * ``("web", url, "")`` - an http(s) page, or another document of the
      repository on GitHub (``MCP.md``, ``../INSTALL.md``), opened in the
      browser;
    * ``("none", reason, "")`` - nothing happens (``file:``, ``mailto:``,
      ``javascript:``, a path out of the repository).
    """
    try:
        parts = urlsplit(href)
    except ValueError:
        return ("none", "not a URL", "")
    scheme = parts.scheme.lower()
    fragment = parts.fragment
    if scheme in ("http", "https"):
        if not parts.netloc:
            return ("none", "a web link without a host", "")
        return ("web", href, "")
    if scheme or parts.netloc:
        return ("none", f"{scheme or 'host'} links do not open from the handbook", "")
    path = parts.path
    if not path:
        return ("section", "", fragment) if fragment else ("none", "an empty link", "")
    if path.startswith("/"):
        return ("none", "an absolute path", "")
    name = posixpath.basename(path)
    folder = posixpath.dirname(posixpath.normpath(path))
    if folder in ("", ".") and name in HANDBOOK_FILES.values():
        code = next(code for code, file in HANDBOOK_FILES.items() if file == name)
        return ("language", code, fragment)
    target = posixpath.normpath(posixpath.join(SOURCE_DIR, path))
    if target == ".." or target.startswith("../"):
        return ("none", "a path out of the repository", "")
    return ("web", web_url(target, fragment), "")


__all__ = [
    "BUILT_IN_HANDBOOK",
    "BUILT_IN_SOURCE",
    "ENGLISH",
    "HANDBOOK_FILES",
    "Handbook",
    "PACKAGED_DIR",
    "REPOSITORY",
    "SECTIONS",
    "SOURCE_DIR",
    "classify_link",
    "english_text",
    "handbook_dirs",
    "load",
    "outline",
    "project_root",
    "section_for",
    "section_in",
    "sibling",
    "topic_heading",
    "web_url",
]
