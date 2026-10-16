"""Help > Scripting Guide, and the Scripting section of the F1 list.

The guide renders docs/SCRIPTING*.md in the interface language. A wheel
and the frozen bundle ship no docs/ (MANIFEST.in puts it in the sdist
only), so there the guide is built from the text in code plus
core.scripting.docs() — and must still show content.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from ui import scripting_guide as SG  # noqa: E402

APP = QApplication.instance() or QApplication([])


# ---------------------------------------------------------------------------
# Which text the guide shows
# ---------------------------------------------------------------------------


def test_happy_the_english_guide_is_docs_scripting_md() -> None:
    text, source = SG.guide_markdown("en")
    assert source == str(ROOT / "docs" / "SCRIPTING.md")
    assert text == (ROOT / "docs" / "SCRIPTING.md").read_text(encoding="utf-8")


def test_happy_the_interface_language_picks_its_variant() -> None:
    for lang in ("de", "es"):
        text, source = SG.guide_markdown(lang)
        assert source == str(ROOT / "docs" / f"SCRIPTING_{lang}.md")


def test_edge_a_language_without_a_variant_falls_back_to_english() -> None:
    _text, source = SG.guide_markdown("fr")
    assert source == str(ROOT / "docs" / "SCRIPTING.md")


def test_sad_without_docs_the_built_in_guide_is_used(tmp_path) -> None:
    text, source = SG.guide_markdown("de", root=str(tmp_path))
    assert source == SG.BUILT_IN_SOURCE
    assert "Scripts" in text and "Run in Console" in text
    assert ".run <name>" in text  # the slash-command reference
    assert "du.py" in text  # the bundled examples, from core.scripting.docs("scripts")


def test_sad_an_oversized_docs_file_is_not_loaded(tmp_path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "SCRIPTING.md").write_text("x" * (SG.MAX_GUIDE_BYTES + 1))
    _text, source = SG.guide_markdown("en", root=str(tmp_path))
    assert source == SG.BUILT_IN_SOURCE


def test_edge_the_guide_shows_content_in_an_installed_layout(tmp_path) -> None:
    """Copy what the wheel ships (pyproject's packages + main.py, no docs/)
    and open the guide from there in a fresh interpreter."""
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    top_levels = {p.split(".")[0] for p in pyproject["tool"]["setuptools"]["packages"]}
    site = tmp_path / "site-packages"
    for top in sorted(top_levels):
        shutil.copytree(
            ROOT / top, site / top, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
    shutil.copy2(ROOT / "main.py", site / "main.py")
    assert not (site / "docs").exists()
    code = textwrap.dedent(
        """
        import sys
        from PyQt6.QtWidgets import QApplication
        app = QApplication([])
        import ui.scripting_guide as SG
        assert SG.__file__.startswith(sys.argv[1]), SG.__file__
        dlg = SG.ScriptingGuideDialog()
        guide = dlg.guide.toPlainText()
        api = dlg.api.toPlainText()
        print("SOURCE", dlg.source)
        print("GUIDE", len(guide), "Run in Console" in guide)
        print("API", len(api), "axross.open" in api)
        """
    )
    env = dict(os.environ, PYTHONPATH=str(site), QT_QPA_PLATFORM="offscreen")
    proc = subprocess.run(
        [sys.executable, "-c", code, str(site)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    out = proc.stdout
    assert f"SOURCE {SG.BUILT_IN_SOURCE}" in out
    assert "GUIDE" in out and " True" in out.split("GUIDE", 1)[1].splitlines()[0]
    assert " True" in out.split("API", 1)[1].splitlines()[0]


# ---------------------------------------------------------------------------
# The dialog
# ---------------------------------------------------------------------------


@pytest.fixture()
def dialog():
    dlg = SG.ScriptingGuideDialog()
    dlg.show()
    APP.processEvents()
    yield dlg
    dlg.close()
    dlg.deleteLater()
    APP.processEvents()


def test_happy_the_dialog_has_the_guide_and_the_api_reference(dialog) -> None:
    assert dialog.tabs.count() == 2
    assert "Scripting" in dialog.guide.toPlainText()
    assert "axross.open" in dialog.api.toPlainText()


def test_happy_find_moves_to_the_next_match_and_wraps(dialog) -> None:
    dialog.tabs.setCurrentIndex(1)
    dialog.search.setText("axross.copy")
    assert dialog.find_next() is True
    first = dialog.api.textCursor().position()
    hits = 1
    while dialog.find_next() and dialog.api.textCursor().position() != first:
        hits += 1
        assert hits < 50
    assert dialog.api.textCursor().position() == first  # wrapped to the first hit


def test_sad_find_without_a_match_says_so(dialog) -> None:
    dialog.search.setText("no-such-text-anywhere-xyz")
    assert dialog.find_next() is False
    assert dialog.search_hint.text()


# ---------------------------------------------------------------------------
# F1: the Scripting section
# ---------------------------------------------------------------------------


def test_happy_f1_lists_the_scripts_panel_keys_and_the_slash_commands() -> None:
    from ui.shortcuts_dialog import SHORTCUTS

    scripting_rows = {k: d for s, keys, d in SHORTCUTS if s == "Scripting" for k in keys}
    assert "Ctrl+S" in scripting_rows and "Ctrl+Return" in scripting_rows
    assert ".run <name>" in scripting_rows


def test_edge_every_repl_slash_command_is_in_the_f1_list() -> None:
    """Derived, not typed twice: the REPL's own .help text is the source."""
    import re

    from ui.repl_widget import ReplWidget
    from ui.shortcuts_dialog import SHORTCUTS

    commands = set(re.findall(r"^\s+(\.\w+)", ReplWidget._SLASH_HELP, re.M))
    assert {".help", ".run", ".save"} <= commands
    listed = {k.split()[0] for s, keys, _d in SHORTCUTS if s == "Scripting" for k in keys}
    assert commands - listed == set()
