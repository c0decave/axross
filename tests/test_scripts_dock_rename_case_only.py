"""Scripts dock: renaming a script only in case ("Backup" -> "backup")
keeps the script.

Reproduced 2026-11-19 (independent review): on a case-insensitive file
system (macOS' APFS, Windows' NTFS) "Backup.py" and "backup.py" are one
file. The free-name check compared case-sensitively, so the rename went
ahead: save_script("backup") rewrote Backup.py, then delete_script("Backup")
unlinked that same file - the script was gone. Now names are compared
casefolded, a case-only rename goes through a temp name, and a source that
is the same file as the target is never deleted.

No case-insensitive mount is possible in the test run: the file system is
emulated - every path in the script folder is looked up case-insensitively
(case-preserving), as APFS and NTFS do.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import scripting  # noqa: E402
from ui import scripts_dock as SD  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def script_folder(tmp_path, monkeypatch):
    folder = tmp_path / "scripts"
    folder.mkdir()
    monkeypatch.setattr(scripting, "script_dir", lambda: str(folder))
    return folder


@pytest.fixture()
def aliases():
    """Extra names the emulated file system resolves to another entry
    ({"b.py": "a.py"}): two names, one file, beyond case."""
    return {}


@pytest.fixture()
def case_insensitive(script_folder, aliases, monkeypatch):
    """Paths in the script folder name an entry that differs only in case."""
    sdir = str(script_folder)

    def fold(p):
        if isinstance(p, int):
            return p
        p = os.fspath(p)
        if isinstance(p, str) and os.path.dirname(p) == sdir:
            base = os.path.basename(p)
            base = aliases.get(base.casefold(), base)
            for entry in os.listdir(sdir):
                if entry.casefold() == base.casefold():
                    return os.path.join(sdir, entry)
        return p

    real = {n: getattr(os, n) for n in ("open", "lstat", "stat", "unlink", "chmod")}
    real_replace, real_rename = os.replace, os.rename

    def move(func):
        def moved(src, dst, *a, **k):
            src, folded = fold(src), fold(dst)
            if os.path.basename(src).casefold() != os.path.basename(folded).casefold():
                dst = folded  # onto an existing entry of another case: that entry
            # Same entry in another case: a case-preserving file system
            # takes the new spelling.
            return func(src, dst, *a, **k)
        return moved

    for name, func in real.items():
        monkeypatch.setattr(os, name, lambda p, *a, _f=func, **k: _f(fold(p), *a, **k))
    monkeypatch.setattr(os, "replace", move(real_replace))
    monkeypatch.setattr(os, "rename", move(real_rename))
    return script_folder


class Prompts:
    def __init__(self) -> None:
        self.names: list[str | None] = []
        self.warnings: list[str] = []

    def install(self, dock) -> None:
        dock._ask_name = lambda *a, **k: self.names.pop(0) if self.names else None
        dock._confirm = lambda _title, _text: True
        dock._warn = lambda _title, text: self.warnings.append(text)


@pytest.fixture()
def dock():
    d = SD.ScriptsDock(scheduled_jobs=lambda: {})
    d.prompts = Prompts()
    d.prompts.install(d)
    yield d
    d.shutdown()
    d.close()
    d.deleteLater()
    APP.processEvents()


def _files(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


def test_happy_a_case_only_rename_keeps_the_script(case_insensitive, dock):
    scripting.save_script("Backup", "print('my backup job')\n")
    dock.refresh()
    dock.open_script("Backup")
    dock.prompts.names = ["backup"]
    dock.rename()
    assert _files(case_insensitive) == ["backup.py"]
    assert scripting.load_script("backup") == "print('my backup job')\n"
    assert dock.current() == ("user", "backup")
    assert dock.prompts.warnings == []


def test_happy_a_case_only_rename_on_a_case_sensitive_system(script_folder, dock):
    scripting.save_script("Backup", "x = 1\n")
    dock.refresh()
    dock.open_script("Backup")
    dock.prompts.names = ["backup"]
    dock.rename()
    assert _files(script_folder) == ["backup.py"]
    assert scripting.load_script("backup") == "x = 1\n"


def test_sad_a_name_differing_only_in_case_from_another_script_is_taken(script_folder, dock):
    """"Report" is taken when "report" exists: on APFS / NTFS it is that file."""
    scripting.save_script("report", "r = 1\n")
    scripting.save_script("other", "o = 1\n")
    dock.refresh()
    dock.open_script("other")
    dock.prompts.names = ["Report", None]
    dock.rename()
    assert _files(script_folder) == ["other.py", "report.py"]
    assert any("already exists" in w for w in dock.prompts.warnings)


def test_edge_the_same_file_under_another_name_is_never_deleted(case_insensitive, aliases):
    """The rename's last step deletes the source only when it is not the
    file just written (os.path.samefile): here the file system resolves
    "beta.py" to "alpha.py" - writing beta wrote alpha."""
    scripting.save_script("alpha", "keep = 1\n")
    aliases["beta.py"] = "alpha.py"
    SD._rename_script_file("alpha", "beta")
    assert _files(case_insensitive) == ["alpha.py"]
    assert scripting.load_script("beta") == "keep = 1\n"


def test_edge_a_case_only_rename_through_the_temp_name(case_insensitive):
    scripting.save_script("Backup", "keep = 1\n")
    SD._rename_script_file("Backup", "BACKUP")
    assert _files(case_insensitive) == ["BACKUP.py"]
    assert scripting.load_script("BACKUP") == "keep = 1\n"


def test_edge_an_ordinary_rename_still_moves_the_file(script_folder, dock):
    a, b = f"a_{uuid.uuid4().hex[:6]}", f"b_{uuid.uuid4().hex[:6]}"
    scripting.save_script(a, "a = 1\n")
    dock.refresh()
    dock.open_script(a)
    dock.prompts.names = [b]
    dock.rename()
    assert _files(script_folder) == [f"{b}.py"]
