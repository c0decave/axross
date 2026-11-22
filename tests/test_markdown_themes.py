"""axross-markdown 0.17.0: twelve themes for the Markdown reader, in the window and in the terminal
(core.markdown_themes, ui.markdown_theme_ui, ui.markdown_html, ui.markdown_view, core.markdown_term,
core.markdown_cli).

Every theme defines every colour and reaches WCAG AA for its text and links (the High Contrast ones AAA);
the names are generic. In the window: View > Theme (kept; "Automatic" follows the window - axross's theme
in axross), every open page made anew in the new colours and shown in one change (no flash, the old page
until the new one is there), rapid switching rate-limited, and a big page's switch keeps the window
answering (a heartbeat on the GUI thread). In the terminal: --theme NAME, --list-themes, truecolor / 256 /
16 colours, NO_COLOR, and the default from the environment or the settings.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import markdown_themes as MT  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

_HEX = re.compile(r"#[0-9a-f]{6}")


# -- the themes -------------------------------------------------------------------------------------------

def test_happy_at_least_ten_themes_each_with_every_colour():
    assert len(MT.THEMES) >= 10
    assert MT.CHOICES[0] == "auto" and set(MT.CHOICES[1:]) == set(MT.THEMES)
    for theme in MT.THEMES.values():
        assert set(theme.page) >= set(MT.PAGE_KEYS), theme.id
        assert set(theme.code) == set(MT.CODE_KEYS), theme.id
        assert set(theme.term) >= set(MT.TERM_KEYS), theme.id
        for colour in (*theme.page.values(), *theme.code.values(), *theme.term.values()):
            assert _HEX.fullmatch(colour), (theme.id, colour)
        # (the page's ground, text, headings, links, code, syntax, quotes, tables, alerts, math, selection)
        for key in ("page_bg", "text", "h1", "link", "code_bg", "pre_bg", "quote_bg", "th_bg", "zebra", "note",
                    "caution", "math", "selection_bg", "selection_fg"):
            assert key in theme.page
    assert sum(theme.dark for theme in MT.THEMES.values()) >= 4
    assert sum(not theme.dark for theme in MT.THEMES.values()) >= 4


def test_happy_every_theme_reaches_wcag_aa_for_its_text_and_links():
    """The contrast of body text and links on the page (and in the terminal, on its ground) - AA's 4.5:1,
    the High Contrast themes AAA's 7:1; every other role its own floor (MT.PAGE_PAIRS)."""
    for theme in MT.THEMES.values():
        page = theme.page
        least = 7.0 if theme.aaa else 4.5
        assert MT.contrast(page["text"], page["page_bg"]) >= least, theme.id
        assert MT.contrast(page["link"], page["page_bg"]) >= least, theme.id
        assert MT.contrast(theme.term["text"], theme.term["page_bg"]) >= least, theme.id
        assert MT.contrast(theme.term["link"], theme.term["page_bg"]) >= least, theme.id
        low = [(fg, bg, round(ratio, 2), floor) for fg, bg, ratio, floor in MT.contrast_report(theme)
               if ratio < floor]
        assert not low, (theme.id, low)
    assert [theme.id for theme in MT.THEMES.values() if theme.aaa] == ["high-contrast-light", "high-contrast-dark"]


def test_happy_contrast_is_wcag_s():
    assert MT.contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert MT.contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)
    assert MT.contrast("#ffffff", "#ffffff") == pytest.approx(1.0)


def test_sad_theme_names_are_generic_not_products():
    brands = ("github", "solarized", "nord", "dracula", "gruvbox", "one dark", "onedark", "atom", "monokai",
              "material", "vscode", "sublime")
    for theme in MT.THEMES.values():
        for name in (theme.id, theme.label.lower()):
            assert not any(brand in name.replace("-", " ") for brand in brands), name


def test_happy_light_and_dark_are_the_colours_the_reader_always_had():
    from core import markdown_term as T
    from ui import markdown_html as H

    assert H.LIGHT is MT.LIGHT_PAGE and H.DARK is MT.DARK_PAGE
    assert H.GITHUB_LIGHT is MT.LIGHT_CODE and H.GITHUB_DARK is MT.DARK_CODE
    assert T.DARK is MT.DARK_TERM and T.LIGHT is MT.LIGHT_TERM
    assert H.colours(False) is H.LIGHT and H.colours(True) is H.DARK
    assert H.colours(MT.THEMES["sepia"]) is MT.THEMES["sepia"].page
    assert bool(MT.THEMES["slate"]) and not MT.THEMES["paper"]  # (a theme where "dark" stood)


def test_happy_the_page_its_code_and_its_export_take_the_theme():
    pytest.importorskip("markdown_it")
    from core import markdown_doc as MD
    from ui import markdown_html as H

    theme = MT.THEMES["retro"]
    sheet = H.style_sheet(theme)
    for key in ("text", "link", "h1", "code_bg", "pre_bg", "quote_bg", "th_bg", "math"):
        assert theme.page[key] in sheet, key
    doc = MD.parse("# T\n\n```python\ndef f():\n    return 1\n```\n\n> [!WARNING]\n> careful\n")
    page = "".join(H.to_html_parts(doc, theme, 0)).lower()  # (Pygments writes its colours in capitals)
    assert theme.code["keyword"] in page and theme.page["warning"] in page
    assert MT.DARK_CODE["keyword"] not in page and MT.LIGHT_CODE["keyword"] not in page
    exported = H.export_html(MD.parse("# T\n"), dark=theme)
    assert f"background: {theme.page['page_bg']}" in exported
    assert H.export_html(MD.parse("# T\n")).count("background: #ffffff") == 1  # (as before: light)


# -- the terminal -----------------------------------------------------------------------------------------

def _sgr_colours(text: str, kind: str) -> list[tuple[int, int, int]]:
    return [tuple(map(int, m)) for m in re.findall(rf"{kind};2;(\d+);(\d+);(\d+)", text)]


def _mdcat(capsys, *args) -> str:
    from core import markdown_cli as C

    assert C.main(["--no-pager", *args]) == 0
    return capsys.readouterr().out


@pytest.fixture
def page(tmp_path):
    pytest.importorskip("markdown_it")
    path = tmp_path / "page.md"
    path.write_text("# Title\n\nSome *text* and a [link](https://example.org).\n\n```python\nx = 1\n```\n\n"
                    "| a | b |\n|---|---|\n| 1 | 2 |\n", encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _no_theme_said(monkeypatch, tmp_path):
    monkeypatch.delenv(MT.ENV_TERM, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("AXROSS_MARKDOWN_SETTINGS", raising=False)


def test_happy_theme_paints_its_ground_and_colours_in_truecolor(capsys, page):
    theme = MT.THEMES["solar-light"]
    out = _mdcat(capsys, "--color", "truecolor", "--width", "60", "--theme", "solar-light", str(page))
    ground = MT.rgb(theme.term["page_bg"])
    assert ground in _sgr_colours(out, "48")
    assert MT.rgb(theme.term["text"]) in _sgr_colours(out, "38")
    assert MT.rgb(theme.term["link"]) in _sgr_colours(out, "38")
    from core.markdown_doc import cell_width

    plain = re.compile(r"\x1b\[[0-9;]*m|\x1b\]8;;[^\x1b]*\x1b\\")
    for line in out.rstrip("\n").split("\n"):  # (every line on the ground, to the width)
        assert line.startswith("\x1b[48;2;"), line[:30]
        assert cell_width(plain.sub("", line)) >= 60
        assert line.endswith("\x1b[0m")


def test_happy_auto_is_the_terminal_s_own_ground_as_before(capsys, page):
    out = _mdcat(capsys, "--color", "truecolor", str(page))
    assert "\x1b[48;2;253;246;227m" not in out and not out.startswith("\x1b[48")
    assert MT.rgb(MT.DARK_TERM["h1"]) in _sgr_colours(out, "38")  # (COLORFGBG unset: dark)


def test_happy_256_colours_keep_the_contrast_and_16_colours_paint_no_rgb(capsys, page):
    out = _mdcat(capsys, "--color", "256", "--theme", "night-violet", str(page))
    assert re.search(r"\x1b\[48;5;\d+m", out) and "38;2;" not in out and "48;2;" not in out
    out16 = _mdcat(capsys, "--color", "16", "--theme", "night-violet", str(page))
    assert "38;2;" not in out16 and "38;5;" not in out16 and "48;" not in out16 and "\x1b[" in out16
    for theme in MT.THEMES.values():  # (the 256 colours chosen keep AA on the 256-colour ground)
        ground = MT.xterm256_rgb(MT.nearest256(theme.term["page_bg"]))
        for role in ("text", "link"):
            chosen = MT.xterm256_rgb(MT.readable256(theme.term[role], theme.term["page_bg"]))
            assert MT.contrast(chosen, ground) >= 4.45, (theme.id, role)


def test_sad_no_color_means_no_colour_whatever_the_theme(capsys, page, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    out = _mdcat(capsys, "--theme", "arctic", str(page))
    assert "\x1b[" not in out and "Title" in out


def test_happy_the_default_theme_from_the_environment_or_the_settings(capsys, page, monkeypatch, tmp_path):
    from core import markdown_settings

    markdown_settings.write_setting(MT.SETTING_TERM, "paper")
    out = _mdcat(capsys, "--color", "truecolor", str(page))
    assert MT.rgb(MT.THEMES["paper"].term["page_bg"]) in _sgr_colours(out, "48")
    monkeypatch.setenv(MT.ENV_TERM, "slate")
    out = _mdcat(capsys, "--color", "truecolor", str(page))
    assert MT.rgb(MT.THEMES["slate"].term["page_bg"]) in _sgr_colours(out, "48")
    out = _mdcat(capsys, "--color", "truecolor", "--theme", "auto", str(page))  # (the option first)
    assert not _sgr_colours(out, "48") or MT.rgb(MT.THEMES["slate"].term["page_bg"]) not in _sgr_colours(out, "48")
    monkeypatch.setenv(MT.ENV_TERM, "no-such-theme")  # (a name of none: the settings')
    assert MT.terminal_default() == "paper"
    out = _mdcat(capsys, "--color", "truecolor", "--theme", "paper", "--background", "off", str(page))
    assert not _sgr_colours(out, "48") or MT.rgb(MT.THEMES["paper"].term["page_bg"]) not in _sgr_colours(out, "48")
    assert MT.rgb(MT.THEMES["paper"].term["text"]) not in _sgr_colours(out, "48")


def test_happy_list_themes_names_each_with_its_contrast(capsys):
    from core import markdown_cli as C

    assert C.main(["--list-themes", "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("auto")
    for theme in MT.THEMES.values():
        line = next(line for line in out.splitlines() if line.startswith(theme.id + " "))
        ratio = float(re.search(r"text\s+([\d.]+):1", line).group(1))
        links = float(re.search(r"links\s+([\d.]+):1", line).group(1))
        assert ratio == pytest.approx(MT.contrast(theme.term["text"], theme.term["page_bg"]), abs=0.01)
        assert links == pytest.approx(MT.contrast(theme.term["link"], theme.term["page_bg"]), abs=0.01)
        assert ("AAA" in line) == (min(ratio, links) >= 7) and ("AA" in line)
        assert "AAA" in line or not theme.aaa
    with pytest.raises(SystemExit):
        C._parser().parse_args(["--theme", "no-such-theme"])


def test_happy_a_reset_inside_a_line_sets_the_ground_and_the_text_colour_again():
    from core import markdown_term as T

    out = T.on_ground("a\x1b[1mb\x1b[0mc\x1b[38;2;1;2;3md\x1b[39me\x1b[49mf\n", "#102030", 10, "truecolor", "#eeeeee")
    ground, text = "\x1b[48;2;16;32;48m", "\x1b[38;2;238;238;238m"
    assert out.startswith(ground + text) and out.endswith("    \x1b[0m\n")
    assert f"\x1b[0m{ground}{text}c" in out and f"\x1b[39m{text}e" in out and f"\x1b[49m{ground}f" in out
    assert "\x1b[38;2;1;2;3m" + ground not in out  # (an extended colour's 2 is no reset)
    picture = "\x1b_Gf=100;AAAA\x1b\\"
    assert T.on_ground(picture + "\n", "#102030", 10, "truecolor") == picture + "\n"
    assert T.on_ground("x", "", 10, "truecolor") == "x" and T.on_ground("x", "#000000", 10, "none") == "x"


def test_happy_code_in_the_terminal_takes_the_theme_s_syntax_colours():
    pytest.importorskip("pygments")
    from core import markdown_term as T

    theme = MT.THEMES["arctic"]
    out = T.render("```python\ndef f():\n    return 1\n```\n",
                   T.Options(width=40, depth="truecolor", theme="arctic", background=True))
    assert MT.rgb(theme.code["keyword"]) in _sgr_colours(out, "38")


# -- the window -------------------------------------------------------------------------------------------

@pytest.fixture
def qt(monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    pytest.importorskip("markdown_it")
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    from PyQt6.QtGui import QColor, QPalette

    from ui import markdown_theme_ui as TU

    # (the window's own colours as a fresh start has them - light: a test before this one may have left
    # axross's dark theme on the application, and "Automatic" follows it, as it should)
    palette, sheet = QPalette(app.palette()), app.styleSheet()
    light = QPalette()
    for role, colour in ((QPalette.ColorRole.Window, "#efefef"), (QPalette.ColorRole.Base, "#ffffff"),
                         (QPalette.ColorRole.Text, "#000000"), (QPalette.ColorRole.WindowText, "#000000")):
        light.setColor(role, QColor(colour))
    app.setStyleSheet("")
    app.setPalette(light)
    hub = TU.hub()
    hub._timer.stop()
    hub._pending, hub._applied, hub._theme, hub.clock = None, float("-inf"), "auto", time.monotonic
    TU.store_theme("auto")  # (nothing another test kept)
    yield app
    hub._timer.stop()
    hub._pending, hub._theme, hub.clock = None, "auto", time.monotonic
    hub._applied = float("-inf")
    TU.store_theme("auto")
    for widget in app.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    app.setPalette(palette)
    app.setStyleSheet(sheet)


@pytest.fixture
def qt_plain():
    """An application in light colours, the theme hub as the tests before left it - for the pair below,
    which checks that the conftests (axross's, the export's) leave nothing of one test's choice."""
    pytest.importorskip("PyQt6.QtWidgets")
    pytest.importorskip("markdown_it")
    from PyQt6.QtGui import QColor, QPalette
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    palette, sheet = QPalette(app.palette()), app.styleSheet()
    light = QPalette()
    for role, colour in ((QPalette.ColorRole.Window, "#efefef"), (QPalette.ColorRole.Base, "#ffffff"),
                         (QPalette.ColorRole.Text, "#000000"), (QPalette.ColorRole.WindowText, "#000000")):
        light.setColor(role, QColor(colour))
    app.setStyleSheet("")
    app.setPalette(light)
    yield app
    for widget in app.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    app.setPalette(palette)
    app.setStyleSheet(sheet)


def _pump(seconds: float = 0.05) -> None:
    from PyQt6.QtWidgets import QApplication

    end = time.monotonic() + seconds
    while time.monotonic() < end:
        QApplication.processEvents()
        time.sleep(0.003)


def _until(condition, seconds: float = 30.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        _pump(0.02)
    return bool(condition())


def _viewer(tmp_path, text: str, full: bool = True):
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    path = tmp_path / "page.md"
    path.write_text(text, encoding="utf-8")
    viewer = MarkdownViewerDialog(LocalFS(), str(path))
    viewer.view.full = viewer.view.full and full
    viewer.resize(1000, 750)
    viewer.show()
    if not full:
        viewer.view.render(text)
    assert _until(lambda: viewer.view._readable and viewer.view.markdown, 120)
    _until(lambda: not viewer.view._scheduled, 120)
    _pump(0.1)
    return viewer


def _ground(view) -> str:
    from PyQt6.QtGui import QPalette

    return view.browser.palette().color(QPalette.ColorRole.Base).name()


def _switched(view, theme_id: str, seconds: float = 120) -> bool:
    return _until(lambda: view.theme is MT.THEMES.get(theme_id, view.theme) and view._readable
                  and not view._scheduled and not view.timer.isActive(), seconds)


PARSERS = pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])


def test_happy_view_theme_lists_every_theme_and_automatic_first(qt, tmp_path):
    viewer = _viewer(tmp_path, "# A\n")
    menu = viewer.theme_menu
    assert viewer.view_button.menu().actions()[0].menu() is menu
    actions = menu.actions()
    assert [action.data() for action in actions] == list(MT.CHOICES)
    from ui import markdown_theme_ui as TU

    assert actions[0].text() == TU.auto_label() and actions[0].isChecked()
    assert TU.auto_label() == ("Automatic (as the window)" if TU.standalone() else "Automatic (as axross)")
    assert [action.text() for action in actions[1:]] == [theme.label for theme in MT.THEMES.values()]


@PARSERS
def test_happy_a_theme_chosen_paints_every_open_page_and_is_kept(qt, tmp_path, full):
    from ui import markdown_theme_ui as TU

    first = _viewer(tmp_path, "# A\n\nText [link](b.md).\n\n```python\nx = 1\n```\n", full)
    (tmp_path / "two").mkdir()
    second = _viewer(tmp_path / "two", "# B\n\n> quote\n", full)
    theme = MT.THEMES["sepia"]
    next(a for a in first.theme_menu.actions() if a.data() == "sepia").trigger()
    for viewer in (first, second):
        assert _switched(viewer.view, "sepia")
        assert _ground(viewer.view) == theme.page["page_bg"] and viewer.view.dark is False
    if full:
        assert f"color: {theme.page['text']}" in first.view.browser.document().defaultStyleSheet()
    else:
        assert first.view.highlighter.theme is theme
        assert first.view.highlighter.colours()["keyword"].foreground().color().name() == theme.code["keyword"]
    assert TU.stored_theme() == "sepia"
    TU.hub().choose("auto")
    assert _switched(first.view, "light") and first.view.theme is MT.THEMES["light"]
    assert first.view._ground is None  # (the window's palette again)


def test_happy_the_choice_is_kept_in_axross_or_in_axross_markdown(qt, monkeypatch, tmp_path):
    from core import markdown_settings
    from ui import markdown_theme_ui as TU

    monkeypatch.setattr(TU, "standalone", lambda: True)
    TU.store_theme("arctic")
    assert markdown_settings.read_setting(MT.SETTING_PAGE) == "arctic" and TU.stored_theme() == "arctic"
    monkeypatch.setattr(TU, "standalone", lambda: False)
    try:
        from core import open_limits
    except ImportError:
        pytest.skip("axross's settings: in axross")
    TU.store_theme("slate")
    assert open_limits.read_setting(TU.AXROSS_SETTING) == "slate" and TU.stored_theme() == "slate"
    open_limits.write_setting(TU.AXROSS_SETTING, ["nonsense"])  # (hand-edited: the window's)
    assert TU.stored_theme() == "auto"


def test_happy_automatic_follows_the_window_and_a_chosen_theme_stays(qt, tmp_path):
    from PyQt6.QtGui import QColor, QPalette

    from ui import markdown_theme_ui as TU

    viewer = _viewer(tmp_path, "# A\n\ntext\n")
    view = viewer.view
    assert view.theme is MT.THEMES["light"]
    dark = QPalette(view.palette())
    dark.setColor(QPalette.ColorRole.Base, QColor("#101010"))
    dark.setColor(QPalette.ColorRole.Text, QColor("#eeeeee"))
    view.setPalette(dark)  # (axross's theme turned dark)
    assert _switched(view, "dark") and view.theme is MT.THEMES["dark"]
    TU.hub().choose("paper")
    assert _switched(view, "paper")
    light = QPalette(view.palette())
    light.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
    view.setPalette(light)
    _pump(0.5)
    assert view.theme is MT.THEMES["paper"] and _ground(view) == MT.THEMES["paper"].page["page_bg"]


def test_sad_rapid_switching_is_rate_limited_to_one_change_a_moment(qt, tmp_path):
    from ui import markdown_theme_ui as TU

    hub = TU.hub()
    seen = []
    now = [1000.0]  # (the hub's clock held: a slow machine's pumping is no switch's interval)
    hub.clock = lambda: now[0]
    hub.changed.connect(seen.append)
    try:
        for theme_id in ("dark", "sepia", "arctic", "retro", "slate", "paper", "night-violet"):
            hub.choose(theme_id)  # (no event handled between: a slow runner's turns are no switch's interval)
            now[0] += 0.02
        assert seen == ["dark"]  # (the first at once; the rest within MIN_INTERVAL_MS: held)
        assert hub._timer.isActive()  # noqa: SLF001
        now[0] += TU.MIN_INTERVAL_MS / 1000
        assert TB.until_within(_until, lambda: len(seen) == 2, 5)
        assert seen[-1] == "night-violet"  # (the latest of them, once)
        _pump(0.2)
        assert seen == ["dark", "night-violet"] and hub.theme_id() == "night-violet"
        assert TU.stored_theme() == "night-violet"
    finally:
        hub.changed.disconnect(seen.append)
        import time as _time

        hub.clock = _time.monotonic


@PARSERS
def test_sad_a_switch_never_flashes_the_page_shows_one_change(qt, tmp_path, full):
    """From the choice until the new page is shown, the old page stays in its own colours (ground and
    text); then both change in the same turn - never a turn of one theme's ground under the other's text,
    never a blank page between."""
    from PyQt6.QtCore import QTimer

    from ui import markdown_theme_ui as TU

    text = "".join(f"## Part {n}\n\nWords *and* `code` and [a link](#part-{n}).\n\n" for n in range(3000))
    viewer = _viewer(tmp_path, text, full)
    view = viewer.view
    old, new = MT.THEMES["light"], MT.THEMES["night-violet"]
    before = view.ground_changes
    seen = []

    def look():
        sheet = view.browser.document().defaultStyleSheet()
        seen.append((_ground(view), new.page["text"] in sheet if full else view.highlighter.theme is new,
                     view.browser.document().characterCount() > 10))

    sampler = QTimer()
    sampler.setInterval(1)
    sampler.timeout.connect(look)
    sampler.start()
    TU.hub().choose("night-violet")
    assert _switched(view, "night-violet")
    _pump(0.1)
    sampler.stop()
    assert view.ground_changes == before + 1
    assert all(shown for _ground_now, _text, shown in seen)  # (never blank)
    grounds = [ground for ground, _text, _shown in seen]
    assert grounds[0] == "#ffffff" and grounds[-1] == new.page["page_bg"]
    assert {ground for ground in grounds} <= {old.page["page_bg"], new.page["page_bg"]}
    for ground, new_text, _shown in seen:  # (the ground and the page's colours change together)
        assert (ground == new.page["page_bg"]) == new_text, seen
    flips = sum(1 for a, b in zip(grounds, grounds[1:]) if a != b)
    assert flips == 1


@PARSERS
def test_sad_switching_the_theme_of_a_big_page_keeps_the_window_answering(qt, tmp_path, full):
    """A theme chosen on a page of 6,000 sections (markdown-it) or 20,000 lines of code (Qt's own parser):
    the page made anew on a worker, laid out a part a turn - the heartbeat's longest gap within budget."""
    from tests import markdown_heartbeat as HB
    from ui import markdown_theme_ui as TU

    if full:
        text = "".join(f"## H{i}\n\nPara *{i}* with `code` and [link](#h{i}).\n\n- item\n- item\n\n> quote\n\n"
                       for i in range(6000))
    else:
        text = "```python\n" + "".join(f"def f{n}(a):\n    return a + {n}\n" for n in range(10000)) + "```\n"
    viewer = _viewer(tmp_path, text, full)
    beat = HB.Heartbeat()
    TU.hub().choose("slate")
    assert _switched(viewer.view, "slate", 240)
    _pump(0.1)
    _turn, gap = beat.stop()
    assert _ground(viewer.view) == MT.THEMES["slate"].page["page_bg"]
    HB.assert_responsive(gap, ("theme switch", full))


def test_sad_1_a_theme_chosen_and_kept_here(qt_plain):
    """(with the next test) a choice made and kept by one test - as View > Theme keeps it ..."""
    from ui import markdown_theme_ui as TU

    TU.hub()._applied = float("-inf")
    TU.hub().choose("retro")
    assert TU.hub().theme_id() == "retro" and TU.stored_theme() == "retro"


def test_sad_2_is_no_later_test_s_default(qt_plain, tmp_path):
    """... is not where the next test begins - a later test's layout and turns are measured in the page's
    own colours: "auto", none kept, the page Light."""
    from ui import markdown_theme_ui as TU

    assert TU.hub().theme_id() == "auto" and TU.stored_theme() == "auto"
    viewer = _viewer(tmp_path, "# A\n\ntext\n")
    assert viewer.view.theme is MT.THEMES["light"] and viewer.view._ground is None


def test_happy_the_program_s_view_menu_has_the_page_theme_then_the_window_theme(qt):
    from ui.markdown_app import MarkdownApp

    viewer = MarkdownApp().open_paths([""])[0]
    menus = [action.menu() for action in viewer.view_button.menu().actions() if action.menu() is not None]
    assert [menu.objectName() for menu in menus] == ["markdown_page_theme", "window_theme"]
    assert menus[0].actions()[0].text() in ("Automatic (as the window)", "Automatic (as axross)")


def test_happy_every_string_of_the_themes_and_updates_is_in_german():
    names = [theme.label for theme in MT.THEMES.values()] + [
        "Theme", "Window Theme", "Automatic (as axross)", "Automatic (as the window)", "The theme of the page",
        "The theme of the page and of the window", "&Help", "Updates of axross-markdown, and About", "Check for Updates…",
        "Updates", "Off", "Tell me about new versions", "Install new versions automatically", "Install",
        "axross-markdown updates", "axross-markdown {new} is available (this is {current}).",
        "To update it: {command}", "axross-markdown {current} is up to date.",
        "axross-markdown {new} is installed and checked – it starts the next time.",
        "The update was not installed: {why}"]
    path = ROOT / "resources" / "i18n" / "de.json"
    if not path.is_file():  # (the export: beside the code)
        path = next(ROOT.glob("src/*/_ax/resources/i18n/de.json"))
    german = json.loads(path.read_text(encoding="utf-8"))
    missing = [name for name in names if not german.get(name)]
    assert not missing, missing
    for name in names:  # (du-form: no "Sie", "Ihr")
        assert not re.search(r"\b(Sie|Ihnen|Ihr|Ihre)\b", german[name]), german[name]
