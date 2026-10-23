"""Help > Scripting Guide gets a structure: contents, links to sub-topics and
to the API (punch-list item 45).

Operator: *„scripting guide bitte mit links zu unterthemen und apis versehen
und nicht nur einen großen fließtext, soll sauber strukturiert und
verständlich sein"*.

- A contents tree beside each tab (guide: its sections; API reference: the
  topics with their functions); a click scrolls to the heading.
- The guide files start with a Contents list of links (they work on GitHub
  too); in the app a "#section" link scrolls the guide.
- `axross.name` mentions in the guide's prose link to that function in the
  API tab; the guide's API section gets a line of links to the reference
  topics.
- Links to the other language files switch the guide's language.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QUrl  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from ui import scripting_guide as SG  # noqa: E402

APP = QApplication.instance() or QApplication([])
GUIDES = ("SCRIPTING.md", "SCRIPTING_de.md", "SCRIPTING_es.md")


# -- parsing -------------------------------------------------------------------


def test_happy_slugs_follow_github():
    assert SG.github_slug("The `axross.*` API") == "the-axross-api"
    assert SG.github_slug("Open / connect") == "open--connect"
    assert SG.github_slug("Safety + diagnostics") == "safety--diagnostics"
    assert SG.github_slug("Datei-Metadata") == "datei-metadata"
    assert SG.github_slug("Véase también") == "véase-también"


def test_edge_headings_inside_code_fences_are_not_headings():
    md = "# Title\n\n```python\n# Verbinden\nx = 1\n```\n\n## Real\n\n### Sub\n"
    assert SG.headings(md) == [(1, "Title"), (2, "Real"), (3, "Sub")]


def test_happy_reference_topics_list_their_functions():
    from core import scripting

    topics = SG.reference_topics(scripting.docs())
    assert "open" in topics["Open / connect"] and "open_url" in topics["Open / connect"]
    assert "copy" in topics["File I/O"]
    assert all(names for names in topics.values())


def test_happy_inline_api_mentions_become_links_but_not_in_code():
    md = ("Call `axross.docs()` or `axross.help(name)`; `axross.nope()` is not real.\n\n"
          "```python\naxross.docs()  # `axross.docs()` stays code here\n```\n")
    out = SG.link_guide(md, {"Topic": ["docs", "help"]})
    assert "[`axross.docs()`](api:docs)" in out and "[`axross.help(name)`](api:help)" in out
    assert "`axross.nope()`" in out and "api:nope" not in out
    assert "axross.docs()  # `axross.docs()` stays code here" in out


def test_happy_the_api_section_gets_links_to_the_reference_topics():
    md = "# T\n\n## The `axross.*` API\n\nText.\n\n## Next\n"
    out = SG.link_guide(md, {"Open / connect": ["open"], "File I/O": ["copy"]})
    section = out.split("## The `axross.*` API", 1)[1].split("## Next", 1)[0]
    assert "(apitopic:Open%20/%20connect)" in section and "(apitopic:File%20I/O)" in section


def test_happy_a_subsection_named_like_a_topic_links_its_functions():
    md = "## The `axross.*` API\n\n### File I/O\n\n```python\naxross.copy(a, b, c, d)\n```\n\n### Other\n"
    out = SG.link_guide(md, {"File I/O": ["copy", "move"]})
    after = out.split("### File I/O", 1)[1].split("```", 1)[0]
    assert "[`copy`](api:copy) · [`move`](api:move)" in after
    assert "api:" not in out.split("### Other", 1)[1]


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_starts_with_contents_that_resolve(name):
    md = (ROOT / "docs" / name).read_text(encoding="utf-8")
    slugs = {SG.github_slug(text) for _level, text in SG.headings(md)}
    links = re.findall(r"\]\(#([^)]+)\)", md)
    sections = [text for level, text in SG.headings(md) if level == 2]
    assert len(links) >= len(sections) - 1, "a contents list linking the sections"
    missing = [link for link in links if link not in slugs]
    assert missing == []


# -- the dialog ----------------------------------------------------------------


@pytest.fixture()
def dialog():
    dlg = SG.ScriptingGuideDialog(language="en")
    dlg.show()
    APP.processEvents()
    yield dlg
    dlg.close()
    dlg.deleteLater()
    APP.processEvents()


def _top_items(tree):
    return [tree.topLevelItem(i).text(0) for i in range(tree.topLevelItemCount())]


def _cursor_heading(view):
    return view.textCursor().block().text()


def test_happy_the_contents_tree_lists_the_guide_sections(dialog):
    top = _top_items(dialog.contents)
    assert "The ways to run code against axross" in top
    assert "The Scripts dock" in top
    api = next(i for i in range(dialog.contents.topLevelItemCount())
               if dialog.contents.topLevelItem(i).text(0).startswith("The axross"))
    assert dialog.contents.topLevelItem(api).childCount() >= 5  # its ### topics


def test_happy_a_click_in_the_tree_scrolls_to_the_heading(dialog):
    item = next(dialog.contents.topLevelItem(i) for i in range(dialog.contents.topLevelItemCount())
                if dialog.contents.topLevelItem(i).text(0) == "REPL slash-commands")
    dialog.contents.itemActivated.emit(item, 0)
    APP.processEvents()
    assert _cursor_heading(dialog.guide) == "REPL slash-commands"
    assert dialog.guide.verticalScrollBar().value() > 0


def test_happy_the_api_tab_tree_has_topics_and_functions(dialog):
    dialog.tabs.setCurrentIndex(1)
    APP.processEvents()
    top = _top_items(dialog.contents)
    assert "Open / connect" in top and "File I/O" in top
    open_topic = dialog.contents.topLevelItem(top.index("Open / connect"))
    children = [open_topic.child(i).text(0) for i in range(open_topic.childCount())]
    assert "open_url" in children
    dialog.contents.itemActivated.emit(open_topic.child(children.index("open_url")), 0)
    APP.processEvents()
    assert _cursor_heading(dialog.api).startswith("axross.open_url(")


def test_happy_an_api_link_in_the_guide_opens_the_function(dialog):
    dialog.on_link(QUrl("api:copy"))
    APP.processEvents()
    assert dialog.tabs.currentIndex() == 1
    assert _cursor_heading(dialog.api).startswith("axross.copy(")


def test_happy_a_topic_link_opens_the_reference_topic(dialog):
    dialog.on_link(QUrl("apitopic:File%20I/O"))
    assert dialog.tabs.currentIndex() == 1
    assert _cursor_heading(dialog.api) == "File I/O"


def test_happy_a_contents_link_scrolls_the_guide(dialog):
    dialog.on_link(QUrl("#the-scripts-dock"))
    APP.processEvents()
    assert dialog.tabs.currentIndex() == 0
    assert _cursor_heading(dialog.guide) == "The Scripts dock"


def test_happy_the_guide_text_carries_api_links(dialog):
    html = dialog.guide.toHtml()
    assert 'href="api:docs"' in html


def test_happy_a_language_link_switches_the_guide(dialog):
    dialog.on_link(QUrl("SCRIPTING_de.md"))
    APP.processEvents()
    assert "Das Scripts-Dock" in _top_items(dialog.contents)
    assert dialog.source.endswith("SCRIPTING_de.md")


def test_sad_an_unknown_target_says_so_and_moves_nothing(dialog):
    before = dialog.guide.textCursor().position()
    dialog.on_link(QUrl("api:no_such_function"))
    assert "not found" in dialog.search_hint.text().lower()
    dialog.on_link(QUrl("#no-such-section"))
    assert dialog.guide.textCursor().position() == before


def test_edge_external_links_go_to_the_browser(dialog):
    with mock.patch("PyQt6.QtGui.QDesktopServices.openUrl") as opened:
        dialog.on_link(QUrl("https://github.com/c0decave/axross"))
    opened.assert_called_once()


def test_edge_the_built_in_guide_also_gets_a_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(SG, "_project_root", lambda: str(tmp_path))
    dlg = SG.ScriptingGuideDialog(language="en")
    try:
        assert dlg.source == SG.BUILT_IN_SOURCE
        assert dlg.contents.topLevelItemCount() >= 1
    finally:
        dlg.close()
        dlg.deleteLater()


def test_e2e_help_menu_guide_contents_and_api_link(tmp_path):
    """Help > Scripting Guide from the real window: the contents tree, a
    click on a section, an API link into the reference."""
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        action = next(a for m in win.menuBar().actions() if m.menu()
                      for a in m.menu().actions() if a.text().replace("&", "") == "Scripting Guide")
        action.trigger()
        APP.processEvents()
        dlg = win._scripting_guide
        assert dlg.isVisible() and dlg.contents.topLevelItemCount() >= 8
        item = next(dlg.contents.topLevelItem(i) for i in range(dlg.contents.topLevelItemCount())
                    if dlg.contents.topLevelItem(i).text(0) == "The MCP tool surface")
        dlg.contents.itemClicked.emit(item, 0)
        assert _cursor_heading(dlg.guide) == "The MCP tool surface"
        dlg.on_link(QUrl("api:docs"))
        assert dlg.tabs.currentIndex() == 1 and _cursor_heading(dlg.api).startswith("axross.docs(")
        dlg.close()
    finally:
        win.close()
        win.deleteLater()
