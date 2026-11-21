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
    # (markdown: 64 - its SVGs are drawn through core.svg_gate and core.svg_worker's child; 72 - the
    # editor's highlighting child, core.lex_worker, runs on core.image_worker's pool of children)
    assert len(files) < {"amp": 75, "markdown": 72}.get(name, 45), len(files)


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


@pytest.mark.parametrize("name", ["markdown", "mcp"])
def test_happy_the_readme_is_a_short_front_page_and_the_full_text_is_beside_it(tmp_path, name):
    """The README (GitHub's front page and PyPI's description): the ten
    punchlines, the contents with the extended README first, screenshots that
    the export carries - by absolute URLs, which PyPI needs - and no wall of
    text; the full text is docs/README-extended.md."""
    import re

    app = EXP.APPS[name]
    out = EXP.export(name, tmp_path / name)
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert len(app.pitch) == 10 and all(line in readme for line in app.pitch)
    assert readme.index(app.pitch[-1]) < readme.index("## Contents")
    if len(app.shots) > 1:  # (the first is the hero, over the punchlines; the others under the contents)
        assert readme.index("## Contents") < readme.index("## Screenshots")
    contents = readme.split("## Contents", 1)[1].split("\n## ", 1)[0]
    first = contents.strip().splitlines()[0]
    assert f"{app.repo}/blob/main/{EXP.EXTENDED}" in first
    raw = f"https://raw.githubusercontent.com/{app.repo.removeprefix('https://github.com/')}/main/"
    images = re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", readme)
    assert images and all(url.startswith(raw) for url in images)
    for url in images:
        assert (out / url.removeprefix(raw)).is_file(), url
    assert len(readme.splitlines()) <= 100
    extended = (out / EXP.EXTENDED).read_text(encoding="utf-8")
    assert app.readme in extended and "](../README.md)" in extended


def test_happy_the_readme_is_title_tagline_hero_punchlines_contents_then_the_other_screenshots(tmp_path):
    """The user's README rule: the title, a one-line tagline, the hero
    screenshot, the ten punchlines, the contents, then the other screenshots;
    the details in docs/README-extended.md, which the contents link - its
    sections too (keys, export, themes, the terminal, security, limits,
    install)."""
    app = EXP.APPS["markdown"]
    out = EXP.export("markdown", tmp_path / "md")
    readme = (out / "README.md").read_text(encoding="utf-8")
    lines = [line for line in readme.splitlines() if line.strip()]
    assert lines[0] == f"# {app.dist}" and lines[1] == f"*{app.tagline}*"
    assert lines[2].startswith("![") and app.shots[0][0] in lines[2]
    assert lines[3:13] == list(app.pitch) and lines[13] == "## Contents"
    assert readme.index("## Contents") < readme.index("## Screenshots") < readme.index(app.shots[1][0])
    extended = (out / EXP.EXTENDED).read_text(encoding="utf-8")
    contents = readme.split("## Contents", 1)[1].split("\n## ", 1)[0]
    for section in ("The window: keys", "Export and print", "Themes", "In the terminal: axross-mdcat",
                    "The security model", "Limits", "Install options"):
        assert f"## {section}\n" in extended and f"[{section}]({app.repo}/blob/main/{EXP.EXTENDED}#" in contents
    assert "Ctrl+F" in extended and "--watch" in extended and "settings.json" in extended


def test_happy_markdown_ships_the_readers_own_tests_their_imports_as_the_codes(tmp_path):
    import re

    app = EXP.APPS["markdown"]
    out = EXP.export("markdown", tmp_path / "md")
    tests = out / "tests"
    assert len(app.tests) >= 20 and all((tests / name).is_file() for name in app.tests)
    assert (tests / "conftest.py").is_file() and (tests / "golden" / "markdown" / "golden.json").is_file()
    for name in app.tests:
        text = (tests / name).read_text(encoding="utf-8")
        assert not re.search(r"^[ \t]*(?:from|import)[ \t]+(?:core|ui)\b", text, re.M), name
    assert "from axross_markdown._ax.core import markdown_doc" in (tests / "test_markdown_reader_bugs19.py").read_text()


def test_sad_the_exported_tests_name_no_axross_module_in_their_strings(tmp_path):
    """Review 19: seven shipped tests ran axross's modules in a child or patched them by name
    ("import core.markdown_cli as C", "from ui.markdown_app import main", "import ui",
    monkeypatch.setattr("core.x.f")) - the export has none of them: they failed in a fresh venv."""
    import io
    import re
    import tokenize

    out = EXP.export("markdown", tmp_path / "md")
    pattern = re.compile(r"(?:^[\"']|\\n|[;\s\"'(])(?:from (?:core|ui)[. ]|(?<!_ax )import (?:core|ui)\b)|^[\"'](?:core|ui)\.\w")
    for name in EXP.APPS["markdown"].tests:
        text = (out / "tests" / name).read_text(encoding="utf-8")
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.STRING and not token.string.startswith(('"""', "'''")):
                assert not pattern.search(token.string), (name, token.start, token.string[:120])
    assert EXP.rewrite_string_imports('c = "import core.qt_exit\\nprint(core.qt_exit.x)"', "P") == \
        'c = "import P._ax.core.qt_exit; from P._ax import core\\nprint(core.qt_exit.x)"'
    assert EXP.rewrite_string_imports('f("import ui", "core.a.b", "from ui import v")', "P") == \
        'f("from P._ax import ui", "P._ax.core.a.b", "from P._ax.ui import v")'
    assert EXP.rewrite_string_imports('"""from core we import ui things"""', "P") == \
        '"""from core we import ui things"""'


def test_sad_the_release_svg_check_runs_against_the_exported_package(tmp_path):
    """packaging/svg_check.py imported core.svg_worker - there is no such module in the export."""
    import subprocess

    out = EXP.export("markdown", tmp_path / "md")
    check = out / "packaging" / "svg_check.py"
    assert "axross_markdown._ax.core.svg_worker" in check.read_text(encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update(PYTHONPATH=str(out / "src"), QT_QPA_PLATFORM="offscreen")
    result = subprocess.run([sys.executable, str(check)], cwd=tmp_path, env=env, capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0 and "svg drawn" in result.stdout, result.stderr[-2000:]


def test_happy_the_readme_screenshots_are_made_by_a_script_and_show_the_programs_window(tmp_path):
    """Review 19: the README's screenshots were older than the Open… and View buttons, and nothing
    made them. scripts/markdown_screenshots.py makes them offscreen, in the program's own windows."""
    pytest.importorskip("PyQt6.QtWidgets")
    import subprocess

    script = EXP.ROOT / "scripts" / "markdown_screenshots.py"
    result = subprocess.run([sys.executable, str(script), str(tmp_path)], capture_output=True, text=True,
                            timeout=300, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 0, result.stderr[-2000:]
    from PyQt6.QtGui import QImage

    shots = EXP.ROOT / "scripts" / "standalone_repo" / "axross-markdown" / "docs" / "screenshots"
    for name in ("viewer-light.png", "viewer-dark.png", "viewer-math.png"):
        made, shipped = QImage(str(tmp_path / name)), QImage(str(shots / name))
        assert not made.isNull() and made.size() == shipped.size(), name
    light = QImage(str(tmp_path / "viewer-light.png"))
    dark = QImage(str(tmp_path / "viewer-dark.png"))
    assert light.pixelColor(600, 400).lightness() > 200 and dark.pixelColor(600, 300).lightness() < 80


def test_sad_the_windows_program_opens_no_console_window_and_mdcat_is_one_of_its_own():
    """Review 19: console=True opened a console window beside the viewer on Windows. The window program
    is windowed there, the terminal view a console program of its own (axross-mdcat.exe)."""
    packaging = EXP.ROOT / "scripts" / "standalone_repo" / "axross-markdown" / "packaging"
    spec = (packaging / "axross-markdown.spec").read_text(encoding="utf-8")
    assert "console=not WINDOWS" in spec and 'name="axross-mdcat"' in spec and "entry_mdcat.py" in spec
    assert "from axross_markdown._ax.core.markdown_cli import main" in (packaging / "entry_mdcat.py").read_text()
    workflow = (EXP.ROOT / "scripts" / "standalone_repo" / "axross-markdown" / ".github" / "workflows"
                / "release.yml").read_text(encoding="utf-8")
    assert 'cp build/dist/axross-mdcat.exe "release/axross-mdcat-' in workflow
    assert "axross-mdcat.exe wrote no heading" in workflow


def test_sad_the_windowed_program_writes_to_the_console_it_was_started_from(monkeypatch):
    import types

    path = EXP.ROOT / "scripts" / "standalone_repo" / "axross-markdown" / "packaging" / "entry.py"
    entry = types.ModuleType("ax_md_entry")  # (read, not imported: no __pycache__ in the repo's files)
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), entry.__dict__)

    class Kernel:
        def __init__(self, handle=0, console=True):
            self.handle, self.console, self.attached = handle, console, False

        def GetStdHandle(self, which):  # noqa: N802 - Windows' name
            return self.handle

        def AttachConsole(self, pid):  # noqa: N802
            self.attached = pid == -1 and self.console
            return self.attached

    opened = []
    monkeypatch.setattr(entry, "open", lambda name, *a, **kw: opened.append(name) or object(), raising=False)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(sys, "stdin", None)
    assert not entry.attach_console(["x", "README.md"], "win32", Kernel())  # (the window: no console)
    assert not entry.attach_console(["x", "--term", "a.md"], "linux", Kernel())
    kernel = Kernel()
    assert entry.attach_console(["x", "--term", "a.md"], "win32", kernel) and kernel.attached
    assert opened == ["CONOUT$", "CONOUT$"]
    monkeypatch.setattr(sys, "stdout", None)
    kernel = Kernel()
    assert not entry.attach_console(["x", "--svg-worker", "1"], "win32", kernel) and not kernel.attached
    monkeypatch.setattr(entry, "_handed_on", lambda k, which, mode: f"handed {which}")
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stdin", None)
    assert entry.attach_console(["x", "--svg-worker", "1"], "win32", Kernel())
    assert sys.stdout == "handed -11" and sys.stdin == "handed -10"


def test_sad_the_release_smoke_test_checks_every_child_and_coloured_code(tmp_path):
    """Review 20 (M4): the release checked only --svg-worker. It checks --lex-worker (a YAML and a
    Python block, their colours) and --image-worker (a PNG) inside the binary, and that the terminal
    view - axross-mdcat.exe on Windows - colours a YAML block through its own lexing child."""
    import subprocess

    workflow = (EXP.ROOT / "scripts" / "standalone_repo" / "axross-markdown" / ".github" / "workflows"
                / "release.yml").read_text(encoding="utf-8")
    smoke = workflow.split("- name: Smoke tests", 1)[1].split("\n    - name:", 1)[0]
    assert 'AXROSS_BUNDLE_SMOKE=1 "$bin" --script packaging/children_check.py' in smoke
    assert '"release/axross-mdcat-${{ matrix.suffix }}" --no-pager --color truecolor yaml.md' in smoke
    assert '"$bin" --term --no-pager --color truecolor yaml.md' in smoke and "YAML not coloured" in smoke
    out = EXP.export("markdown", tmp_path / "md")
    check = out / "packaging" / "children_check.py"
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update(PYTHONPATH=str(out / "src"), QT_QPA_PLATFORM="offscreen")
    result = subprocess.run([sys.executable, str(check)], cwd=tmp_path, env=env, capture_output=True, text=True,
                            timeout=180)
    assert result.returncode == 0 and "children checked" in result.stdout, result.stderr[-2000:]


def test_sad_the_extended_readme_says_one_thing_and_lists_what_it_holds(tmp_path):
    """Review 20 (L4): the extended README said both that the theme is kept in axross-markdown's own
    settings and that its settings are axross's; it repeated the README's Install, Tests and Licence,
    none of them in its contents; its Limits left out the guards; "a remote image is a box naming its
    address" - the window shows its alt text."""
    import re

    out = EXP.export("markdown", tmp_path / "md")
    extended = (out / EXP.EXTENDED).read_text(encoding="utf-8")
    assert "so both share the language, the theme" not in extended
    assert "~/.config/axross-markdown/settings.json" in extended.split("## Where it comes from", 1)[1]
    for repeated in ("## Install and run", "## Tests", "## Licence"):
        assert repeated not in extended, repeated
    headings = re.findall(r"^## (.+)$", extended, re.M)
    contents = extended.split("## The window: keys", 1)[0]
    for heading in headings:
        assert f"]({EXP._anchor(heading)})" in contents, heading
    limits = extended.split("## Limits", 1)[1].split("\n## ", 1)[0]
    assert "100,000" in limits and "2,000 characters" in limits
    assert "a remote image is a box with its alt text" in extended


def test_sad_a_readme_without_ten_one_line_punchlines_stops_the_export():
    import dataclasses

    app = dataclasses.replace(EXP.APPS["markdown"], pitch=EXP.APPS["markdown"].pitch[:9])
    with pytest.raises(EXP.ExportError, match="ten one-line punchlines"):
        EXP.short_readme(app)


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
    # (the build backend from the lock as well: nothing unpinned fetched for the build)
    assert "--no-build-isolation --no-deps ." in workflow and "setuptools" in pins
    # (a failure's pytest summary as annotations, readable through the API - v0.16.7's ci / test)
    assert "-rfE tests 2>&1 | tee \"$RUNNER_TEMP/tests.log\"" in workflow and "set -o pipefail" in workflow
    assert "if: failure()\n        run: python packaging/ci_log_tail.py \"$RUNNER_TEMP/tests.log\" tests 150" \
        in workflow and (out / "packaging" / "ci_log_tail.py").is_file()
    assert "supply_chain_gate.py --config supply-chain-gate.toml check" in workflow
    assert "--scan-python" in workflow and "verify-env" in workflow
    assert "requirements.lock.txt" in (out / "README.md").read_text()


def test_sad_the_markdown_release_builds_its_sdist_and_wheel_with_hashed_tools_only(tmp_path):
    """0.16.8's release ran "pip install build twine" and an isolated "python -m build": build, twine and the
    backend (setuptools>=77) came from PyPI unpinned and unhashed, past the lock and the gate. Now build and
    twine come from packaging/requirements-build.txt (every pin hashed, written by lock_standalone_deps.sh),
    and the build is --no-isolation: setuptools from requirements.lock.txt."""
    import re

    text = (STANDALONE_REPO / "axross-markdown" / ".github" / "workflows" / "release.yml").read_text()
    step = next(step for step in _workflow("axross-markdown")["jobs"]["python"]["steps"]
                if step.get("name") == "sdist and wheel")["run"]
    assert "pip install --require-hashes -r packaging/requirements-build.txt" in step
    assert "python -m build --no-isolation --outdir release/" in step
    assert "pip install build" not in text and not re.search(r"python -m build(?! --no-isolation)", text)
    lock = (STANDALONE_REPO / "axross-markdown" / "packaging" / "requirements-build.txt").read_text()
    pins = re.findall(r"^([a-z0-9-]+)==\S+((?:\s*;[^\\\n]*)?) \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)",
                      lock, re.MULTILINE)
    names = {name for name, _marker, _hashes in pins}
    assert {"build", "twine", "pyproject-hooks", "packaging"} <= names
    assert len(pins) == len(re.findall(r"^[a-z0-9-]+==", lock, re.MULTILINE))  # (every pin with its hashes)
    build = re.search(r"^build==\S+", lock, re.MULTILINE).group(0)
    assert re.search(rf"^{re.escape(build)} ", (EXP.ROOT / "build" / "requirements-dist-tools.txt").read_text(),
                     re.MULTILINE)  # (axross's reviewed build)
    script = (EXP.ROOT / "scripts" / "lock_standalone_deps.sh").read_text()
    assert "packaging/requirements-build.txt" in script and "--generate-hashes" in script
    out = EXP.export("markdown", tmp_path / "md")
    assert (out / "packaging" / "requirements-build.txt").read_text() == lock
    workflow = (out / ".github" / "workflows" / "tests.yml").read_text()
    assert "pip install --require-hashes -r packaging/requirements-build.txt && python -m build --no-isolation" \
        in workflow and "pip install build" not in workflow


def test_sad_the_markdown_release_and_ci_install_pytest_hashed_and_build_before_it(tmp_path):
    """0.16.9's release ran "pip install pytest" (no version, no hash) in the job and interpreter that then
    built the sdist and wheel with --no-isolation - pytest, pluggy and iniconfig unverified from PyPI in the
    build environment (review 23's N10); the exported tests.yml likewise. pytest and its dependencies come
    from packaging/requirements-test.txt now (every pin hashed, written by lock_standalone_deps.sh), and the
    release builds the sdist and wheel before any test tool is installed."""
    import re

    text = (STANDALONE_REPO / "axross-markdown" / ".github" / "workflows" / "release.yml").read_text()
    assert not re.search(r"pip install (?:[^\n]* )?pytest\b", text), "pytest unpinned in release.yml"
    steps = _workflow("axross-markdown")["jobs"]["python"]["steps"]
    names = [step.get("name") for step in steps]
    build, tests = names.index("sdist and wheel"), names.index("Tests against the locked dependencies")
    assert build < tests  # (built first: nothing of the tests' tools in its environment)
    assert "pip install --require-hashes -r packaging/requirements-test.txt" in steps[tests]["run"]
    assert "pip install --require-hashes -r requirements.lock.txt" in steps[build]["run"]
    lock = (STANDALONE_REPO / "axross-markdown" / "packaging" / "requirements-test.txt").read_text()
    pins = re.findall(r"^([a-z0-9-]+)==\S+((?:\s*;[^\\\n]*)?) \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)",
                      lock, re.MULTILINE)
    assert {"pytest", "pluggy", "iniconfig", "packaging"} <= {name for name, _m, _h in pins}
    assert len(pins) == len(re.findall(r"^[a-z0-9-]+==", lock, re.MULTILINE))  # (every pin with its hashes)
    runtime = (EXP.ROOT / "build" / "requirements-standalone-markdown.txt").read_text()
    for name, version in re.findall(r"^([a-z0-9-]+)==(\S+)", lock, re.MULTILINE):  # (the program's own kept)
        found = re.search(rf"^{re.escape(name)}==(\S+)", runtime, re.MULTILINE)
        assert found is None or found.group(1) == version, (name, version)
    script = (EXP.ROOT / "scripts" / "lock_standalone_deps.sh").read_text()
    assert "packaging/requirements-test.txt" in script or "requirements-test.txt" in script
    out = EXP.export("markdown", tmp_path / "md")
    assert (out / "packaging" / "requirements-test.txt").read_text() == lock
    workflow = (out / ".github" / "workflows" / "tests.yml").read_text()
    assert "pip install --require-hashes -r packaging/requirements-test.txt" in workflow
    assert not re.search(r"pip install (?:[^\n]* )?pytest\b", workflow), "pytest unpinned in tests.yml"
    assert (out / "tests" / "markdown_heartbeat.py").is_file()  # (the stress tests' heartbeat goes with them)


def test_sad_the_markdown_program_does_not_count_backends_at_every_start(tmp_path):
    """"Backend registry initialized: 40 backends" on stderr at every start of a Markdown viewer: said at
    DEBUG in the export (axross's own log keeps it)."""
    out = EXP.export("markdown", tmp_path / "md")
    registry = (out / "src" / "axross_markdown" / "_ax" / "core" / "backend_registry.py").read_text()
    assert 'log.debug("Backend registry initialized: %d backends"' in registry
    assert 'log.info("Backend registry initialized' not in registry
    assert 'log.info("Backend registry initialized: %d backends"' in \
        (EXP.ROOT / "core" / "backend_registry.py").read_text()


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


# -- the spin-off repositories' GitHub releases (scripts/standalone_repo/) ------------------

STANDALONE_REPO = EXP.ROOT / "scripts" / "standalone_repo"
_SHA_PIN = __import__("re").compile(r"uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d")


def _workflow(name: str) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((STANDALONE_REPO / name / ".github" / "workflows" / "release.yml")
                          .read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["axross-markdown", "axross-headless-mcp"])
def test_happy_the_release_workflow_pins_every_action_and_writes_only_in_its_release_job(name):
    text = (STANDALONE_REPO / name / ".github" / "workflows" / "release.yml").read_text()
    uses = [line.strip() for line in text.splitlines() if "uses:" in line and "uses: ./.github/" not in line]
    assert uses and all(_SHA_PIN.search(line) for line in uses), uses
    workflow = _workflow(name)
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow[True]["push"]["tags"] == ["v*.*.*"]  # YAML's "on" reads as True
    writers = [job for job, spec in workflow["jobs"].items() if spec.get("permissions")]
    assert writers == ["release"]
    assert workflow["jobs"]["release"]["permissions"] == {"contents": "write"}
    assert "gh release create" in text and "SHA256SUMS" in text and "${{ github.token }}" in text


def test_sad_the_markdown_release_builds_nothing_before_the_gate_and_the_tests(tmp_path):
    """The release built and published without waiting for the supply-chain gate, which ran in tests.yml
    only; and the gate took axross's default branch - at v0.16.6 an older release with an older baseline,
    so the gate failed. The release calls tests.yml (workflow_call) and every job needs it; in tests.yml
    the tests need the gate, and the gate's axross is pinned to a commit (v0.15.180's)."""
    import re

    yaml = pytest.importorskip("yaml")
    jobs = _workflow("axross-markdown")["jobs"]
    assert jobs["ci"] == {"uses": "./.github/workflows/tests.yml"}

    def needs(job: str) -> set:
        direct = jobs[job].get("needs", [])
        direct = [direct] if isinstance(direct, str) else direct
        return set(direct).union(*(needs(other) for other in direct))

    for job in jobs:
        if job != "ci":
            assert "ci" in needs(job), job
    out = EXP.export("markdown", tmp_path / "md")
    tests = yaml.safe_load((out / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    assert "workflow_call" in tests[True]
    assert tests["jobs"]["test"]["needs"] == "supply-chain"
    gate = [step for step in tests["jobs"]["supply-chain"]["steps"]
            if step.get("with", {}).get("repository") == "c0decave/axross"]
    assert len(gate) == 1 and gate[0]["with"]["ref"] == EXP.GATE_AXROSS_COMMIT
    assert re.fullmatch(r"[0-9a-f]{40}", EXP.GATE_AXROSS_COMMIT)
    assert EXP.GATE_AXROSS_COMMIT.startswith("37373f7f")  # (axross v0.15.180)


@pytest.mark.parametrize("name, app", [("axross-markdown", "markdown"),
                                       ("axross-headless-mcp", "mcp")])
def test_happy_the_changelog_has_the_exported_version(name, app):
    version = EXP.APPS[app].version or EXP._version()
    text = (STANDALONE_REPO / name / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"\n## {version} - " in text


def test_happy_both_release_notes_scripts_are_one():
    a = (STANDALONE_REPO / "axross-markdown" / "packaging" / "release_notes.py").read_bytes()
    b = (STANDALONE_REPO / "axross-headless-mcp" / "packaging" / "release_notes.py").read_bytes()
    assert a == b


def test_happy_the_markdown_binaries_follow_axross_s_build():
    """The same Qt plugin drops, the same hashed PyInstaller, the same pinned
    appimagetool and runtime as axross's own binaries."""
    import re

    def constants(path: Path) -> dict:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        return {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in ("DROPPED", "DROPPED_FOLDERS")}

    packaging = STANDALONE_REPO / "axross-markdown" / "packaging"
    scope = constants(packaging / "axross-markdown.spec")
    bundle_options = constants(EXP.ROOT / "scripts" / "bundle_options.py")
    assert scope == bundle_options and set(scope) == {"DROPPED", "DROPPED_FOLDERS"}
    assert (packaging / "fetch_appimagetool.sh").read_bytes() == \
        (EXP.ROOT / "scripts" / "fetch_appimagetool.sh").read_bytes()
    pins = (packaging / "requirements-pyinstaller.txt").read_text(encoding="utf-8")
    locks = ((EXP.ROOT / "build" / "requirements-bundle.txt").read_text(encoding="utf-8")
             + (EXP.ROOT / "build" / "requirements-bootstrap.txt").read_text(encoding="utf-8"))
    for pin in re.findall(r"^([a-z0-9-]+==[^ ;]+)", pins, re.MULTILINE):
        assert re.search(rf"^{re.escape(pin)}\b", locks, re.MULTILINE), pin
    for digest in re.findall(r"sha256:([0-9a-f]{64})", pins):
        assert digest in locks
    workflow = _workflow("axross-markdown")
    oses = [entry["os"] for entry in workflow["jobs"]["binaries"]["strategy"]["matrix"]["include"]]
    assert oses == ["ubuntu-22.04", "macos-latest", "windows-latest"]
    text = (STANDALONE_REPO / "axross-markdown" / ".github" / "workflows" / "release.yml").read_text()
    for needle in ("--version", "--html smoke.md", "--term --no-pager", "AXROSS_SMOKE_MS",
                   "packaging/build_appimage.sh", "packaging/build_macos_dmg.sh",
                   "--require-hashes -r requirements.lock.txt -r packaging/requirements-pyinstaller.txt"):
        assert needle in text, needle


def test_happy_the_repo_files_hold_no_invisible_characters():
    """The push check flags invisible Unicode (format characters, odd spaces)."""
    import unicodedata

    for path in STANDALONE_REPO.rglob("*"):
        if not path.is_file() or path.suffix in (".png",):
            continue
        text = path.read_text(encoding="utf-8")
        odd = {c for c in text if c not in "\n\t" and (unicodedata.category(c) in ("Cf", "Zl", "Zp")
               or (unicodedata.category(c) == "Zs" and c != " ") or unicodedata.category(c) == "Cc")}
        assert not odd, (path, sorted(map(hex, map(ord, odd))))


@pytest.mark.parametrize("app, files", [
    ("markdown", ("CHANGELOG.md", ".github/workflows/release.yml", ".github/workflows/tests.yml",
                  "packaging/axross-markdown.spec", "packaging/build_appimage.sh",
                  "packaging/build_macos_dmg.sh", "packaging/release_notes.py",
                  "packaging/icons/axross-logo-512.png")),
    ("mcp", ("CHANGELOG.md", ".github/workflows/release.yml", ".github/workflows/tests.yml",
             "packaging/release_notes.py", "glama.json")),
])
def test_happy_an_export_carries_its_release_files(tmp_path, app, files):
    out = EXP.export(app, tmp_path / app)
    for name in files:
        assert (out / name).is_file(), name


@pytest.mark.parametrize("name", ["axross-markdown", "axross-headless-mcp"])
def test_happy_every_job_shows_the_end_of_its_log_on_failure(name):
    """The log storage may be out of reach (a sandboxed maintainer): every
    job tees its heavy steps and turns the last lines into annotations."""
    workflow = _workflow(name)
    for job, spec in workflow["jobs"].items():
        if "uses" in spec:  # (a reusable workflow called - tests.yml: its jobs are its own)
            continue
        tails = [s for s in spec["steps"] if "ci_log_tail.py" in s.get("run", "")]
        assert len(tails) == 1 and tails[0]["if"] == "failure()", job
        assert any('tee -a "$RUNNER_TEMP/job.log"' in s.get("run", "") for s in spec["steps"]), job
    text = (STANDALONE_REPO / name / ".github" / "workflows" / "release.yml").read_text()
    # pytest's own dependencies: never installed with --no-deps (v0.16.0's first run)
    assert not __import__("re").search(r"--no-deps[^\n]*pytest", text)


def test_happy_ci_log_tail_escapes_and_splits(tmp_path):
    a = (STANDALONE_REPO / "axross-markdown" / "packaging" / "ci_log_tail.py").read_bytes()
    assert a == (STANDALONE_REPO / "axross-headless-mcp" / "packaging" / "ci_log_tail.py").read_bytes()
    log = tmp_path / "job.log"
    log.write_text("".join(f"line {i}: 100% done, ok\r\n" for i in range(70)))
    out = subprocess.run([sys.executable, "-I", str(STANDALONE_REPO / "axross-markdown" / "packaging"
                                                     / "ci_log_tail.py"), str(log), "a: b, c"],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    assert len(out) == 3 and all(line.startswith("::error title=a%3A b%2C c (") for line in out)
    assert "line 10:" in out[0] and "line 69:" in out[2] and "line 9:" not in "".join(out)
    assert "100%25 done" in out[0] and "\r" not in "".join(out) and "%0A" in out[0]
    more = subprocess.run([sys.executable, "-I", str(STANDALONE_REPO / "axross-markdown" / "packaging"
                                                      / "ci_log_tail.py"), str(log), "t", "45"],
                          capture_output=True, text=True, check=True).stdout.splitlines()
    assert len(more) == 3 and "line 25:" in more[0] and "line 24:" not in "".join(more)
    missing = subprocess.run([sys.executable, "-I", str(STANDALONE_REPO / "axross-markdown" /
                                                        "packaging" / "ci_log_tail.py"),
                              str(tmp_path / "none")], capture_output=True, text=True)
    assert missing.returncode == 0 and missing.stdout.startswith("::error title=")


def test_happy_the_appimage_script_works_with_relative_paths():
    """v0.16.0's first run: the image was read back from another folder
    through a relative path (exit 127)."""
    text = (STANDALONE_REPO / "axross-markdown" / "packaging" / "build_appimage.sh").read_text()
    assert 'OUT="$(cd "$(dirname -- "$OUT")" && pwd)/$(basename -- "$OUT")"' in text
    assert 'ELF="$(cd "$(dirname -- "$ELF")" && pwd)/$(basename -- "$ELF")"' in text
    assert text.index('OUT="$(cd') < text.index('(cd "$WORK/check" && "$OUT" --appimage-extract')
