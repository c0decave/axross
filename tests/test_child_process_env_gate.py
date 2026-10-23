"""Tree gate: no child process inherits a frozen build's loader path.

A PyInstaller one-file build points LD_LIBRARY_PATH at its extraction
folder; a host program started with the inherited environment resolves its
libraries against the bundled ones (dist/axross-full 0.13.22: ``bash -c
true`` rc 127 "symbol lookup error", ``ffprobe`` "GLIBCXX_3.4.32 not
found"). core.subprocess_env existed, yet twelve modules, both
ProxyCommand sites, QDesktopServices.openUrl and webbrowser started children
without it - each found only by running the shipped binary.

This test reads every module under core/, ui/, models/, resources/ and
main.py and fails for:

* a ``subprocess`` / ``asyncio`` child start without ``env=``;
* a module that starts children without importing ``core.subprocess_env``
  (the env it passes is then not one of its documented kinds) - unless it
  is in ALLOWED with the reason;
* a QProcess whose module never sets a process environment;
* a start that cannot take an environment at all: os.system, os.popen,
  os.exec*/spawn* without ``e``, pty.spawn, subprocess.getoutput,
  QProcess.startDetached/execute, paramiko.ProxyCommand (use
  core.ssh_client.CleanEnvProxyCommand), QDesktopServices.openUrl and
  webbrowser.open* (use core.desktop_open) - the last two are allowed only
  in core/desktop_open.py.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNED_DIRS = ("core", "ui", "models", "resources")

#: Modules that start children without core.subprocess_env, and why that is
#: safe. Every entry is checked to still start a child (no stale entries).
ALLOWED = {
    "core/elevated_io.py":
        "builds the helper's environment from scratch (PATH, LANG, LC_ALL only)",
    "core/mcp_client.py":
        "passes only named variables (PATH, HOME, LANG ...) plus the server's own configured env",
    "ui/scripts_dock.py":
        "its QProcess gets the environment of core.script_runner.child_env (clean_child_env)",
    "ui/features_dialog.py":
        "runs pip only from a Python install; core.features.can_pip_install refuses a frozen build",
}

_SUBPROCESS_STARTS = {"run", "Popen", "call", "check_call", "check_output"}
_SUBPROCESS_NO_ENV = {"getoutput", "getstatusoutput"}
_DESKTOP_MODULE = "core/desktop_open.py"


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _imports_subprocess_env(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "core.subprocess_env":
                return True
            if node.module == "core" and any(a.name == "subprocess_env" for a in node.names):
                return True
        elif isinstance(node, ast.Import):
            if any(a.name == "core.subprocess_env" for a in node.names):
                return True
    return False


def violations(source: str, rel: str) -> list[str]:
    """What is wrong with the child starts of one module."""
    tree = ast.parse(source)
    sub_modules = {"subprocess"}
    sub_names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess" and alias.asname:
                    sub_modules.add(alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            for alias in node.names:
                sub_names[alias.asname or alias.name] = alias.name

    found: list[str] = []
    starts = 0
    qprocess = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        head, _, attr = name.rpartition(".")
        keywords = {k.arg for k in node.keywords}
        where = f"{rel}:{node.lineno}"
        if (head in sub_modules and attr in _SUBPROCESS_STARTS) or (
                not head and sub_names.get(attr) in _SUBPROCESS_STARTS):
            starts += 1
            if "env" not in keywords:
                found.append(f"{where}: {name}() without env= inherits the loader path")
        elif (head in sub_modules and attr in _SUBPROCESS_NO_ENV) or (
                not head and sub_names.get(attr) in _SUBPROCESS_NO_ENV):
            found.append(f"{where}: {name}() cannot take an environment")
        elif head == "asyncio" and attr.startswith("create_subprocess"):
            starts += 1
            if "env" not in keywords:
                found.append(f"{where}: {name}() without env= inherits the loader path")
        elif head == "os" and (attr.startswith("exec") or attr.startswith("spawn")
                               or attr.startswith("posix_spawn")):
            if attr.startswith("posix_spawn") or attr.endswith("e"):
                starts += 1
            else:
                found.append(f"{where}: {name}() cannot take an environment")
        elif name in ("os.system", "os.popen", "pty.spawn"):
            found.append(f"{where}: {name}() cannot take an environment")
        elif name in ("QProcess", "QtCore.QProcess", "PyQt6.QtCore.QProcess"):
            starts += 1
            qprocess = True
        elif name.endswith("QProcess.startDetached") or name.endswith("QProcess.execute"):
            found.append(f"{where}: {name}() cannot take an environment")
        elif name.endswith("ProxyCommand") and head.endswith("paramiko"):
            found.append(f"{where}: paramiko.ProxyCommand inherits the environment - "
                         "use core.ssh_client.CleanEnvProxyCommand")
        elif rel != _DESKTOP_MODULE and (
                name.endswith("QDesktopServices.openUrl")
                or (head == "webbrowser" and attr in ("open", "open_new", "open_new_tab", "get"))):
            found.append(f"{where}: {name}() starts a host program with the inherited "
                         "environment - use core.desktop_open")

    if starts and rel not in ALLOWED and not _imports_subprocess_env(tree):
        found.append(f"{rel}: starts child processes without core.subprocess_env")
    if qprocess and rel not in ALLOWED and "setProcessEnvironment" not in source:
        found.append(f"{rel}: a QProcess without setProcessEnvironment inherits the loader path")
    if rel in ALLOWED and not starts:
        found.append(f"{rel}: listed in ALLOWED but starts no child process any more")
    return found


def _modules() -> list[Path]:
    files = [ROOT / "main.py"]
    for folder in SCANNED_DIRS:
        files += sorted((ROOT / folder).rglob("*.py"))
    return files


def test_no_module_starts_a_child_with_the_inherited_loader_path():
    files = _modules()
    found: list[str] = []
    parsed = 0
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        found += violations(path.read_text(encoding="utf-8"), rel)
        parsed += 1
    print(f"child-env gate: parsed {parsed}/{len(files)} modules")
    assert parsed == len(files) and parsed > 300  # the tree, not an empty glob
    assert not found, "\n".join(found)


def test_every_allowed_module_exists():
    assert all((ROOT / rel).is_file() for rel in ALLOWED)


# -- the gate itself: each rule fires on a module that breaks it ----------------------------


def _check(source: str, rel: str = "core/x.py") -> list[str]:
    return violations(source, rel)


def test_sad_the_gate_flags_a_run_without_env():
    assert _check("import subprocess\nsubprocess.run(['ls'])\n")


def test_sad_the_gate_flags_an_alias_and_a_from_import():
    assert _check("import subprocess as sp\nsp.Popen(['ls'])\n")
    assert _check("from subprocess import check_output as co\nco(['ls'])\n")


def test_sad_the_gate_flags_an_env_that_does_not_come_from_subprocess_env():
    found = _check("import os, subprocess\nsubprocess.run(['ls'], env=dict(os.environ))\n")
    assert found == ["core/x.py: starts child processes without core.subprocess_env"]


def test_sad_the_gate_flags_starts_that_cannot_take_an_environment():
    for source in ("import os\nos.system('ls')\n", "import os\nos.popen('ls')\n",
                   "import os\nos.execvp('ls', ['ls'])\n", "import pty\npty.spawn('sh')\n",
                   "import subprocess\nsubprocess.getoutput('ls')\n",
                   "from PyQt6.QtCore import QProcess\nQProcess.startDetached('ls')\n",
                   "import paramiko\nparamiko.ProxyCommand('nc h 22')\n"):
        assert _check(source), source


def test_sad_the_gate_flags_a_qprocess_without_an_environment():
    found = _check("from core.subprocess_env import clean_child_env\n"
                   "from PyQt6.QtCore import QProcess\np = QProcess()\n")
    assert found == ["core/x.py: a QProcess without setProcessEnvironment inherits the loader path"]


def test_sad_the_gate_flags_desktop_and_browser_opens_outside_desktop_open():
    assert _check("from PyQt6.QtGui import QDesktopServices\nQDesktopServices.openUrl(u)\n")
    assert _check("import webbrowser\nwebbrowser.open('https://x')\n")
    assert not _check("import webbrowser\nwebbrowser.open('https://x')\n", _DESKTOP_MODULE)


def test_happy_the_gate_accepts_a_clean_start():
    assert not _check("import subprocess\nfrom core.subprocess_env import clean_child_env\n"
                      "subprocess.run(['ls'], env=clean_child_env())\n")
    assert not _check("import os\nfrom core import subprocess_env\n"
                      "os.execve('/bin/sh', ['sh'], subprocess_env.clean_child_env())\n")


def test_edge_a_stale_allow_list_entry_is_reported():
    assert _check("x = 1\n", "core/elevated_io.py") == [
        "core/elevated_io.py: listed in ALLOWED but starts no child process any more"]

