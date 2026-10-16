"""No first-party module names something that is not defined.

The public CI lints with ``flake8 --select=E9,F63,F7,F82``; 0.10.66
failed there on F821 ``undefined name 'ExecResult'``: four exec()
signatures returned the string annotation ``"ExecResult"`` without
importing it (pyflakes checks string annotations too). This test runs
the same class of check over the same files locally with pyflakes, so it
fails before a push.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pyflakes_api = pytest.importorskip("pyflakes.api")
from pyflakes import messages  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
#: What the CI's ``flake8 .`` leaves out: build output, and F821 in
#: resources/scripts (those scripts run with axross.* injected). Hidden
#: directories (virtualenvs, .git) are not part of a checkout's code.
SKIPPED = ("build", "dist", "resources/scripts")


def _first_party_files() -> list[Path]:
    out = []
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if any(part.startswith(".") or part == "__pycache__" for part in rel.parts):
            continue
        if any(rel.as_posix().startswith(prefix + "/") for prefix in SKIPPED):
            continue
        out.append(path)
    return out


UNDEFINED = (messages.UndefinedName, messages.UndefinedExport, messages.UndefinedLocal)


class _Collect:
    def __init__(self):
        self.found = []

    def unexpectedError(self, filename, msg):  # noqa: N802 - pyflakes reporter API
        self.found.append(f"{filename}: {msg}")

    def syntaxError(self, filename, msg, lineno, offset, text):  # noqa: N802
        self.found.append(f"{filename}:{lineno}: syntax error: {msg}")

    def flake(self, message):
        if isinstance(message, UNDEFINED):
            self.found.append(str(message))


def _check(source: str, name: str = "probe.py") -> list[str]:
    reporter = _Collect()
    pyflakes_api.check(source, name, reporter)
    return reporter.found


def test_happy_first_party_code_has_no_undefined_names():
    reporter = _Collect()
    files = _first_party_files()
    assert len(files) > 300 and any(p.name == "main.py" for p in files)
    for path in files:
        pyflakes_api.checkPath(str(path), reporter)
    assert reporter.found == []


def test_sad_an_unimported_string_annotation_is_caught():
    # The exact shape that broke 0.10.66.
    assert _check('def f() -> "ExecResult":\n    return None\n')


def test_edge_a_type_checking_import_satisfies_it():
    source = (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from models.exec_result import ExecResult\n"
        'def f() -> "ExecResult":\n'
        "    return None\n"
    )
    assert _check(source) == []
