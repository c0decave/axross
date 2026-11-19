"""scripts/export_standalone.py: the Media Player and System Information as
projects of their own - only the modules they run on, every import
rewritten, nothing left that reaches into the rest of axross, and the
exported program starts. The headless MCP server (``mcp`` -> axross-headless-mcp)
keeps its module names, carries nothing of ui/ and no module that imports
PyQt6 when it is imported, and answers over stdio and HTTP.
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
    if name == "mcp":
        # The server's groups need the scripting API and the agent; never the GUI.
        assert not [f for f in files if f.startswith("ui/")]
        assert "main.py" not in files
        # Named in strings only (the backend registry): they came along.
        assert {"core/ssh_client.py", "core/s3_client.py", "core/agent_worker.py"} <= files
        assert len([f for f in files if not f.startswith("resources/")]) < 260
        return
    # axross-amp carries the Bluetooth connector on purpose; nothing else of
    # axross's file manager, scripting or voice comes along with any tool.
    heavy = ["ui/main_window.py", "ui/file_pane.py", "core/scripting.py", "ui/voice.py",
             "core/analysis_worker.py", "core/agent.py"]
    if name != "amp":
        heavy.append("core/bluetooth.py")
    for module in heavy:
        assert module not in files, module
    assert len(files) < {"amp": 75, "markdown": 60}.get(name, 45), len(files)


def test_happy_no_exported_module_imports_axross_directly(exported):
    name, out = exported
    app = EXP.APPS[name]
    if app.layout == "path":
        pytest.skip("the MCP server keeps its module names (layout 'path')")
    for path in (out / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [module or ""]
            for n in names:
                assert n.split(".")[0] not in EXP.PACKAGES, f"{path}: {n}"
    probe = out / "src" / app.package / "_ax" / "core" / "multimedia_probe.py"
    if name in ("media-player", "amp"):
        # The probe starts itself as a child: by its new module name.
        assert f'"-m", "{app.package}._ax.core.multimedia_probe"' in probe.read_text()
    else:
        # No sound: nothing of Qt Multimedia comes along (nor gets bundled).
        assert not probe.exists()


def test_happy_the_exported_program_starts_and_ends_cleanly(exported, tmp_path):
    name, out = exported
    app = EXP.APPS[name]
    if app.kind == "mcp":
        # Its own smoke tests: stdio and HTTP with every group, a read_file,
        # the manifest - and PyQt6 never imported.
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                                 str(out / "tests")], cwd=out, capture_output=True, text=True,
                                timeout=600)
        assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
        return
    pytest.importorskip("PyQt6.QtWidgets")
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


# --- the headless MCP server (axross-headless-mcp) ------------------------------------------


def test_happy_the_mcp_package_has_no_qt_and_names_its_registry_entry(tmp_path):
    out = EXP.export("mcp", tmp_path / "mcp")
    pyproject = (out / "pyproject.toml").read_text()
    assert "PyQt6" not in pyproject and "gui-scripts" not in pyproject
    assert '"jsonschema>=4.21"' in pyproject and '"cryptography>=50.0.0"' in pyproject
    # The official MCP registry checks the PyPI description for this line.
    assert (out / "README.md").read_text().startswith(
        "<!-- mcp-name: io.github.c0decave/axross-headless-mcp -->\n")
    main = (out / "src" / "axross_headless_mcp" / "__main__.py").read_text()
    assert "from core.mcp_cli import main as run" in main
    ax = out / "src" / "axross_headless_mcp" / "_ax"
    for path in ax.rglob("*.py"):
        if "resources" in path.relative_to(ax).parts:
            continue  # example scripts and GUI extensions: data, never imported here
        assert EXP.import_time_imports(path.read_text(encoding="utf-8"), ("PyQt6",)) == [], path
    # The real axross package (lazy scripting API), not the tools' stub.
    assert "def __getattr__" in (ax / "axross" / "__init__.py").read_text()
    # The directory listings' files (Glama, Cline, the logo) come with every export,
    # so a re-export never drops them.
    import json
    import struct

    assert json.loads((out / "glama.json").read_text())["maintainers"] == ["c0decave"]
    guide = (out / "llms-install.md").read_text()
    assert "uvx axross-headless-mcp" in guide and "--mcp-root" in guide
    logo = (out / "docs" / "assets" / "logo.png").read_bytes()
    assert logo[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack(">II", logo[16:24]) == (400, 400)
    server = json.loads((EXP.ROOT / "server.json").read_text())
    assert server["name"] == "io.github.c0decave/axross-headless-mcp"
    assert server["repository"]["url"] == "https://github.com/c0decave/axross-headless-mcp"


def test_happy_the_mcp_extras_mirror_axross():
    extras = dict(EXP.project_extras(EXP.APPS["mcp"]))
    known = EXP.axross_extras()
    assert extras["smb"] == tuple(known["smb"]) and extras["images"] == ("Pillow>=13.0.0",)
    # "all" leaves out what axross's own "all" leaves out.
    assert "impacket>=0.11" not in extras["all"] and "Pillow>=13.0.0" in extras["all"]
    assert set(extras["all"]) - {"Pillow>=13.0.0"} <= set(known["all"])


def test_sad_a_qt_import_at_import_time_stops_the_export():
    text = "from PyQt6.QtCore import QObject\n\nclass W(QObject):\n    pass\n"
    problems = EXP.check_exported("core/x.py", text, "p", {"core/x.py"}, rewritten=False,
                                  forbid=("PyQt6",))
    assert problems and "imports PyQt6.QtCore when it is imported" in problems[0]


def test_edge_guarded_lazy_and_type_checking_qt_imports_are_allowed():
    text = ("from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n    from PyQt6.QtCore import QObject\n"
            "try:\n    from PyQt6 import sip\nexcept ImportError:\n    sip = None\n"
            "def f():\n    from PyQt6.QtGui import QImage\n    return QImage\n")
    assert EXP.import_time_imports(text, ("PyQt6",)) == []
    assert EXP.check_exported("core/x.py", text, "p", {"core/x.py"}, rewritten=False,
                              forbid=("PyQt6",)) == []


def test_happy_markdown_ships_its_reviewed_lock_and_runs_the_gate_on_it(tmp_path):
    """axross locks axross-markdown's dependencies (one of the supply-chain
    gate's locks); the export carries that lock, installs from it by hash in
    its CI and runs axross's gate on it there."""
    import tomllib

    out = EXP.export("markdown", tmp_path / "md")
    lock = (out / "requirements.lock.txt").read_text()
    assert lock == EXP.lock_path("markdown").read_text()
    pins = {line.split("==")[0] for line in lock.splitlines() if "==" in line and not line.startswith("#")}
    assert {"pyqt6", "markdown-it-py", "mdit-py-plugins", "pygments", "pillow", "linkify-it-py"} <= pins
    config = tomllib.loads((out / "supply-chain-gate.toml").read_text())
    assert config["locks"] == ["requirements.lock.txt"]
    assert config["baseline_dir"] == ".axross/security/supply_chain_baseline"
    workflow = (out / ".github" / "workflows" / "tests.yml").read_text()
    assert "--require-hashes -r requirements.lock.txt" in workflow and "--no-deps ." in workflow
    assert "supply_chain_gate.py --config supply-chain-gate.toml check" in workflow
    assert "--scan-python" in workflow and "verify-env" in workflow
    assert "requirements.lock.txt" in (out / "README.md").read_text()


def test_sad_a_lock_made_for_other_requirements_stops_the_export(tmp_path, monkeypatch):
    stale = tmp_path / "requirements-standalone-markdown.txt"
    stale.write_text("# input sha256 " + "0" * 64 + " - stale\n")
    monkeypatch.setattr(EXP, "lock_path", lambda name: stale)
    with pytest.raises(EXP.ExportError, match="lock_standalone_deps.sh markdown"):
        EXP.export("markdown", tmp_path / "md")


def test_happy_tools_without_a_lock_export_as_before(tmp_path):
    out = EXP.export("system-info", tmp_path / "si")
    assert not (out / "requirements.lock.txt").exists()
    assert "supply-chain" not in (out / ".github" / "workflows" / "tests.yml").read_text()
