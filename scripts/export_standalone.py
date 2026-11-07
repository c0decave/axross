#!/usr/bin/env python3
"""Write an axross tool as a program of its own: ``export_standalone.py APP OUT_DIR``.

APP is ``media-player`` (the Media Player: local files, folders, M3U
playlists and http / https streams) or ``system-info`` (System Information).
Both stay part of axross; this writes the same code as an installable
project with its own command:

    OUT_DIR/
      pyproject.toml          axross-media-player / axross-system-info, its command
      README.md, LICENSE
      src/PACKAGE/__main__.py the command (python -m PACKAGE)
      src/PACKAGE/_ax/        the axross modules the tool runs on - core/,
                              ui/, resources/ - with every import rewritten
                              to PACKAGE._ax.*, and the interface languages
      tests/test_smoke.py     starts the program and checks it ends cleanly

Which modules go along is worked out here, not listed by hand: everything
the tool's start module imports at module level, followed through every
module, plus the modules it imports later (inside functions) that it needs
(LAZY). Every other late import must be guarded - inside a ``try`` that
catches ImportError - or the export stops: a program of its own must not
fail when a menu reaches a part of axross it does not carry.

The settings stay axross's: ~/.config/axross (the player's list and
position, the language, the theme, the window sizes), so the program and
axross's panel share them.
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
#: axross's top-level packages a copied module may import.
PACKAGES = ("core", "ui", "resources", "axross")
#: Packages whose __init__ is written here instead of copied (axross's own
#: imports the scripting API on first use - not part of a tool).
STUB_INITS = {"axross/__init__.py": '"""The version of the axross code this tool comes from."""\n'}


@dataclass(frozen=True)
class App:
    dist: str
    package: str
    start: str                    # the start module (ui/..._app.py)
    title: str
    summary: str
    requires: tuple[str, ...]
    #: modules imported inside functions that the tool needs
    lazy: tuple[str, ...]
    #: (file, old, new): rewrites beyond the imports, each must apply
    rewrites: tuple[tuple[str, str, str], ...] = ()
    readme: str = ""
    smoke_args: tuple[str, ...] = field(default=())


def _probe_rewrites(package: str) -> tuple[tuple[str, str, str], ...]:
    # The multimedia probe starts itself as a child: by its new module name.
    return (("core/multimedia_probe.py", '"-m", "core.multimedia_probe"',
             f'"-m", "{package}._ax.core.multimedia_probe"'),)


APPS = {
    "media-player": App(
        dist="axross-media-player",
        package="axross_media_player",
        start="ui/media_player_app.py",
        title="axross Media Player",
        summary="axross's Media Player on its own: playlists, a 10-band equalizer, "
                "visualizations, internet radio",
        requires=("PyQt6>=6.6,<6.12", "numpy>=2.0"),
        lazy=("resources/extensions/media_player.py", "core/secure_storage.py",
              "core/multimedia_probe.py", "core/thread_relay.py", "core/tls_env.py",
              "ui/close_corner.py", "ui/icon_provider.py",
              "ui/window_dock_bar.py", "ui/screen_fit.py", "ui/state_files.py",
              "ui/window_prefs.py", "ui/qt_translations.py", "core/qt_exit.py",
              "core/posix_compat.py", "core/audio_eq.py", "core/subprocess_env.py",
              "core/json_store.py", "core/path_policy.py"),
        rewrites=_probe_rewrites("axross_media_player"),
        readme="""\
Play local files, folders and M3U playlists, and internet radio by its http / https
URL. A 10-band equalizer with presets, animated visualizations (in a window of their
own or full screen), shuffle and repeat; the list, the track and its position come
back at the next start.

```sh
axross-media-player                      # the last list
axross-media-player ~/Music/album/       # add a folder and play it
axross-media-player https://example.org/radio.mp3
```

Keys: Space play / pause, Left / Right seek, Up / Down volume, M mute.
Files on axross's remote connections (SFTP, SMB, S3 ...) are a feature of axross itself.
""",
    ),
    "system-info": App(
        dist="axross-system-info",
        package="axross_system_info",
        start="ui/system_info_app.py",
        title="axross System Information",
        summary="axross's System Information on its own: everything about this computer's "
                "hardware, live gauges, text and JSON export",
        requires=("PyQt6>=6.6,<6.12",),
        lazy=("ui/system_info_window.py", "core/thread_relay.py", "ui/close_corner.py",
              "ui/icon_provider.py", "ui/window_dock_bar.py", "ui/screen_fit.py",
              "ui/state_files.py", "ui/window_prefs.py", "ui/qt_translations.py",
              "core/qt_exit.py", "core/posix_compat.py", "axross/_version.py",
              "core/subprocess_env.py", "core/multimedia_env.py", "core/tls_env.py",
              "core/json_store.py"),
        readme="""\
CPU, memory, disks, graphics and displays, network, sound, USB, PCI, battery, sensors,
firmware, the OS and virtualisation - as a dashboard with live gauges and a page per
area. Reads /proc and /sys without root and starts no program. Search across all
pages, copy a page or everything, save a text or JSON report; serial numbers, MAC and
IP addresses and UUIDs stay hidden until *Show identifiers* is ticked.

```sh
axross-system-info                       # the window
axross-system-info --json report.json    # write the report (identifiers hidden) and quit
```
""",
        smoke_args=(),
    ),
}

_IMPORT_LINE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<kw>from|import)[ \t]+(?P<top>" + "|".join(PACKAGES) + r")(?P<rest>[.\s])",
    re.MULTILINE)


class ExportError(SystemExit):
    pass


def _module_file(name: str) -> str | None:
    for candidate in (ROOT / (name.replace(".", "/") + ".py"),
                      ROOT / name.replace(".", "/") / "__init__.py"):
        if candidate.is_file():
            return candidate.relative_to(ROOT).as_posix()
    return None


def _imports(tree: ast.Module):
    """(node, module names, guarded, top level) for every axross import."""
    guarded_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            catches = any(_catches_import_error(h) for h in node.handlers)
            if catches:
                for inner in node.body:
                    for sub in ast.walk(inner):
                        guarded_ids.add(id(sub))
    top_ids: set[int] = set()

    def visit(body):
        for n in body:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                top_ids.add(id(n))
            elif isinstance(n, (ast.If, ast.Try)):
                visit(n.body)
                visit(getattr(n, "orelse", []))
                visit(getattr(n, "finalbody", []))
                for h in getattr(n, "handlers", []):
                    visit(h.body)
    visit(tree.body)
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        names = [n for n in names if n.split(".")[0] in PACKAGES]
        if names:
            yield node, names, id(node) in guarded_ids, id(node) in top_ids


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    names = [handler.type] if not isinstance(handler.type, ast.Tuple) else handler.type.elts
    return any(getattr(n, "id", getattr(n, "attr", "")) in
               ("ImportError", "ModuleNotFoundError", "Exception", "BaseException") for n in names)


def closure(app: App) -> list[str]:
    """The files the tool runs on: its start module, everything imported at
    module level from there, the LAZY modules and their imports, and the
    __init__ of every package on the way."""
    wanted = set(app.lazy)
    seen: set[str] = set()
    todo = [app.start, *app.lazy]
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        if not (ROOT / rel).is_file():
            raise ExportError(f"export: {rel} does not exist - update LAZY")
        seen.add(rel)
        parts = Path(rel).parts
        for i in range(1, len(parts)):
            init = Path(*parts[:i], "__init__.py").as_posix()
            if (ROOT / init).is_file() or init in STUB_INITS:
                todo.append(init)
        if rel in STUB_INITS:
            continue
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        for _node, names, _guarded, top in _imports(tree):
            for name in names:
                found = _module_file(name)
                if found and (top or found in wanted):
                    todo.append(found)
    return sorted(seen)


def rewrite_imports(text: str, package: str) -> str:
    """``from core.x import y`` -> ``from PACKAGE._ax.core.x import y`` (and
    ``import ui.x as z``); a plain ``import core.x`` would bind another name
    and is refused."""
    def sub(m: re.Match) -> str:
        if m.group("kw") == "import":
            line_end = text.find("\n", m.end())
            line = text[m.start():line_end if line_end != -1 else len(text)]
            if " as " not in line:
                raise ExportError(f"export: refusing to rewrite {line.strip()!r} (no 'as')")
        return f"{m.group('indent')}{m.group('kw')} {package}._ax.{m.group('top')}{m.group('rest')}"

    return _IMPORT_LINE.sub(sub, text)


def check_exported(rel: str, text: str, package: str, files: set[str]) -> list[str]:
    """What is wrong with an exported module: an axross import left as it
    was, or an unguarded import of a module that did not come along."""
    problems = []
    tree = ast.parse(text)
    prefix = f"{package}._ax."
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            if name.split(".")[0] in PACKAGES:
                problems.append(f"{rel}:{node.lineno}: import of {name} not rewritten")
    for node, names, guarded, _top in _imports(ast.parse(_unprefix(text, prefix))):
        module_names = [names[0]] if isinstance(node, ast.ImportFrom) else names
        for name in module_names:
            found = _module_file(name)
            if found is None:
                # "from core import x" where x is a module: names[1:] cover it
                continue
            if found not in files and not guarded:
                problems.append(f"{rel}:{node.lineno}: {name} is not exported and its import "
                                "is not guarded (try/except ImportError)")
        if isinstance(node, ast.ImportFrom):
            for name in names[1:]:
                found = _module_file(name)
                if found is not None and found not in files and not guarded:
                    problems.append(f"{rel}:{node.lineno}: {name} is not exported and its "
                                    "import is not guarded (try/except ImportError)")
    return problems


def _unprefix(text: str, prefix: str) -> str:
    return text.replace(prefix, "")


def _pyproject(app: App, version: str) -> str:
    deps = ",\n    ".join(f'"{d}"' for d in app.requires)
    return f'''[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[project]
name = "{app.dist}"
version = "{version}"
description = "{app.summary}"
readme = "README.md"
license = {{text = "Apache-2.0"}}
requires-python = ">=3.11"
dependencies = [
    {deps},
]

[project.scripts]
{app.dist} = "{app.package}.__main__:main"

[project.gui-scripts]
{app.dist}-gui = "{app.package}.__main__:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
"*" = ["*.json"]
'''


def _smoke_test(app: App) -> str:
    return f'''"""{app.title} starts, shows its window and ends cleanly."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_happy_the_program_starts_and_ends_cleanly(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), QT_QPA_PLATFORM="offscreen",
               AXROSS_SMOKE_MS="1500",
               PYTHONPATH=os.pathsep.join([str(ROOT / "src"), os.environ.get("PYTHONPATH", "")]))
    result = subprocess.run([sys.executable, "-m", "{app.package}"], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "Unhandled exception" not in result.stderr
'''


def export(name: str, out: Path) -> Path:
    if name not in APPS:
        raise ExportError(f"export: unknown tool {name!r} (one of {', '.join(APPS)})")
    app = APPS[name]
    if out.exists() and any(out.iterdir()):
        raise ExportError(f"export: {out} is not empty")
    files = closure(app)
    pkg = out / "src" / app.package
    ax = pkg / "_ax"
    texts: dict[str, str] = {}
    for rel in files:
        text = STUB_INITS.get(rel)
        if text is None:
            text = rewrite_imports((ROOT / rel).read_text(encoding="utf-8"), app.package)
        texts[rel] = text
    for rel, old, new in app.rewrites:
        if old not in texts.get(rel, ""):
            raise ExportError(f"export: {rel} no longer contains {old!r} - update the rewrites")
        texts[rel] = texts[rel].replace(old, new)
    problems = [p for rel, text in texts.items()
                for p in check_exported(rel, text, app.package, set(files))]
    if problems:
        raise ExportError("export: " + "\n  ".join(["the tool would break:", *problems]))
    for rel, text in texts.items():
        target = ax / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (ax / "__init__.py").write_text('"""The axross modules this tool runs on."""\n', encoding="utf-8")
    i18n = ax / "resources" / "i18n"
    i18n.mkdir(parents=True, exist_ok=True)
    for catalogue in sorted((ROOT / "resources" / "i18n").glob("*.json")):
        shutil.copyfile(catalogue, i18n / catalogue.name)
    start_module = app.start[:-3].replace("/", ".")
    (pkg / "__init__.py").write_text(f'"""{app.title} (see README.md)."""\n', encoding="utf-8")
    (pkg / "__main__.py").write_text(
        f'"""{app.title}: ``python -m {app.package}`` / ``{app.dist}``."""\n\n'
        "import sys\n\n"
        f"from {app.package}._ax.{start_module} import main\n\n"
        'if __name__ == "__main__":\n    sys.exit(main())\n', encoding="utf-8")
    version = _version()
    (out / "pyproject.toml").write_text(_pyproject(app, version), encoding="utf-8")
    (out / "README.md").write_text(
        f"# {app.dist}\n\n{app.summary}.\n\n{app.readme}\n"
        "It is the same code as in [axross](https://github.com/c0decave/axross), written out by\n"
        f"axross's `scripts/export_standalone.py {name}`; its settings are axross's\n"
        "(`~/.config/axross`), so both share the language, the theme and the tool's state.\n\n"
        "## Install and run\n\n```sh\npip install .\n"
        f"{app.dist}\n```\n\n## Tests\n\n```sh\npython -m pytest tests\n```\n\n"
        "## Licence\n\nApache-2.0, as axross.\n", encoding="utf-8")
    shutil.copyfile(ROOT / "LICENSE", out / "LICENSE")
    (out / "tests").mkdir()
    (out / "tests" / "test_smoke.py").write_text(_smoke_test(app), encoding="utf-8")
    return out


def _version() -> str:
    text = (ROOT / "axross" / "_version.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    if not match:
        raise ExportError("export: no version in axross/_version.py")
    return match.group(1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("app", choices=sorted(APPS))
    ap.add_argument("out", type=Path, help="an empty or new folder")
    args = ap.parse_args(argv)
    out = export(args.app, args.out)
    app = APPS[args.app]
    print(f"{app.dist} written to {out}: cd {out} && python -m pytest tests && pip install .")
    return 0


if __name__ == "__main__":
    sys.exit(main())
