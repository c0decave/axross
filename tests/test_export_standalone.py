"""scripts/export_standalone.py: the Media Player and System Information as
projects of their own - only the modules they run on, every import
rewritten, nothing left that reaches into the rest of axross, and the
exported program starts.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("export_standalone", ROOT / "scripts" / "export_standalone.py")
EXP = importlib.util.module_from_spec(_spec)
sys.modules["export_standalone"] = EXP
_spec.loader.exec_module(EXP)


@pytest.fixture(scope="module", params=sorted(EXP.APPS))
def exported(request, tmp_path_factory):
    out = tmp_path_factory.mktemp(request.param) / "project"
    EXP.export(request.param, out)
    return request.param, out


def test_happy_the_project_has_its_command_and_only_what_the_tool_needs(exported):
    name, out = exported
    app = EXP.APPS[name]
    ax = out / "src" / app.package / "_ax"
    assert (out / "pyproject.toml").read_text().count(f'{app.dist} = "{app.package}.__main__:main"') == 1
    assert (ax / "resources" / "i18n" / "de.json").is_file()
    files = {p.relative_to(ax).as_posix() for p in ax.rglob("*.py")}
    assert app.start in files
    for heavy in ("ui/main_window.py", "ui/file_pane.py", "core/bluetooth.py", "core/scripting.py"):
        assert heavy not in files, heavy
    assert len(files) < 45


def test_happy_no_exported_module_imports_axross_directly(exported):
    name, out = exported
    app = EXP.APPS[name]
    for path in (out / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [module or ""]
            for n in names:
                assert n.split(".")[0] not in EXP.PACKAGES, f"{path}: {n}"
    probe = out / "src" / app.package / "_ax" / "core" / "multimedia_probe.py"
    if name == "media-player":
        # The probe starts itself as a child: by its new module name.
        assert f'"-m", "{app.package}._ax.core.multimedia_probe"' in probe.read_text()
    else:
        # No sound: nothing of Qt Multimedia comes along (nor gets bundled).
        assert not probe.exists()


def test_happy_the_exported_program_starts_and_ends_cleanly(exported, tmp_path):
    pytest.importorskip("PyQt6.QtWidgets")
    name, out = exported
    app = EXP.APPS[name]
    env = dict(os.environ, HOME=str(tmp_path), QT_QPA_PLATFORM="offscreen", AXROSS_SMOKE_MS="1500",
               PYTHONPATH=str(out / "src"))
    # -I keeps the axross checkout off the path: the export must stand alone.
    result = subprocess.run([sys.executable, "-I", "-c",
                             f"import sys; sys.path.insert(0, {str(out / 'src')!r}); "
                             f"from {app.package}.__main__ import main; sys.exit(main())"],
                            env=env, cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "Unhandled exception" not in result.stderr


def test_sad_an_unguarded_import_of_a_module_left_behind_stops_the_export():
    text = "def f():\n    from axross_media_player._ax.ui.main_window import MainWindow\n"
    problems = EXP.check_exported("ui/x.py", text, "axross_media_player", {"ui/x.py"})
    assert problems and "not guarded" in problems[0]
    guarded = ("def f():\n    try:\n        from axross_media_player._ax.ui.main_window import M\n"
               "    except ImportError:\n        M = None\n")
    assert EXP.check_exported("ui/x.py", guarded, "axross_media_player", {"ui/x.py"}) == []


def test_sad_an_import_left_unrewritten_stops_the_export():
    problems = EXP.check_exported("ui/x.py", "from core import i18n\n", "p", {"ui/x.py"})
    assert problems and "not rewritten" in problems[0]


def test_edge_imports_are_rewritten_and_a_plain_import_is_refused():
    text = "from core.i18n import tr\n    import ui.themes as T\nfrom ui import title_bar\nimport json\n"
    out = EXP.rewrite_imports(text, "pkg")
    assert "from pkg._ax.core.i18n import tr" in out and "import pkg._ax.ui.themes as T" in out
    assert "from pkg._ax.ui import title_bar" in out and "import json" in out
    with pytest.raises(SystemExit):
        EXP.rewrite_imports("import core.i18n\n", "pkg")


def test_sad_an_unknown_tool_or_a_full_folder_is_refused(tmp_path):
    with pytest.raises(SystemExit):
        EXP.export("nope", tmp_path / "a")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "x").write_text("")
    with pytest.raises(SystemExit):
        EXP.export("system-info", tmp_path / "b")
