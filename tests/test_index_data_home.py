"""The offline index and the duplicate index follow ``$XDG_DATA_HOME``.

Operator item 26: "wo und in welcher datei wird das indexing eigentlich
gespeichert?" - the answer had a flaw: ``core.metadata_index`` (and its twin
``core.cas``) always used ``~/.local/share/axross`` and ignored
``$XDG_DATA_HOME``, while the voice models (``core.voice_models.data_dir``),
the state files (``$XDG_STATE_HOME``) and the thumbnails (``$XDG_CACHE_HOME``)
follow the XDG variables.

Now both files live in ``$XDG_DATA_HOME/axross`` when that variable is an
absolute path - unless an index already sits at the old place and none at
the new one: then the old file stays in use, so nothing indexed before is
orphaned. ``$AXROSS_METADATA_DB`` / ``$AXROSS_CAS_DB`` still win.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from core.secure_storage import data_file_path  # noqa: E402


def _legacy(home: Path, name: str) -> Path:
    return home / ".local" / "share" / "axross" / name


# --- the resolver --------------------------------------------------------------


def test_happy_xdg_data_home_is_used(tmp_path):
    env = {"XDG_DATA_HOME": str(tmp_path / "data")}
    expected = tmp_path / "data" / "axross" / "metadata.sqlite"
    assert data_file_path("metadata.sqlite", "AXROSS_METADATA_DB", environ=env,
                          home=tmp_path / "home") == expected


def test_happy_without_xdg_the_home_folder_default_stays(tmp_path):
    home = tmp_path / "home"
    assert data_file_path("cas.sqlite", "AXROSS_CAS_DB", environ={}, home=home) == _legacy(
        home, "cas.sqlite")


def test_happy_the_override_variable_wins(tmp_path):
    env = {"XDG_DATA_HOME": str(tmp_path / "data"), "AXROSS_METADATA_DB": str(tmp_path / "x.db")}
    assert data_file_path("metadata.sqlite", "AXROSS_METADATA_DB", environ=env,
                          home=tmp_path) == tmp_path / "x.db"


def test_sad_a_relative_or_empty_xdg_data_home_is_ignored(tmp_path):
    """The XDG spec: a relative path in these variables is invalid."""
    home = tmp_path / "home"
    for value in ("relative/data", "", "   "):
        assert data_file_path("metadata.sqlite", "AXROSS_METADATA_DB",
                              environ={"XDG_DATA_HOME": value},
                              home=home) == _legacy(home, "metadata.sqlite"), value


def test_sad_an_empty_override_variable_does_not_count(tmp_path):
    env = {"AXROSS_METADATA_DB": "", "XDG_DATA_HOME": str(tmp_path / "d")}
    assert data_file_path("metadata.sqlite", "AXROSS_METADATA_DB", environ=env,
                          home=tmp_path) == tmp_path / "d" / "axross" / "metadata.sqlite"


def test_edge_an_existing_old_index_is_not_orphaned(tmp_path):
    home = tmp_path / "home"
    old = _legacy(home, "metadata.sqlite")
    old.parent.mkdir(parents=True)
    old.write_bytes(b"")
    env = {"XDG_DATA_HOME": str(tmp_path / "data")}
    assert data_file_path("metadata.sqlite", "AXROSS_METADATA_DB", environ=env, home=home) == old


def test_edge_a_new_index_wins_once_both_exist(tmp_path):
    home = tmp_path / "home"
    old = _legacy(home, "metadata.sqlite")
    new = tmp_path / "data" / "axross" / "metadata.sqlite"
    for path in (old, new):
        path.parent.mkdir(parents=True)
        path.write_bytes(b"")
    env = {"XDG_DATA_HOME": str(tmp_path / "data")}
    assert data_file_path("metadata.sqlite", "AXROSS_METADATA_DB", environ=env, home=home) == new


def test_edge_xdg_data_home_naming_the_default_folder_is_the_same_file(tmp_path):
    home = tmp_path / "home"
    env = {"XDG_DATA_HOME": str(home / ".local" / "share")}
    assert data_file_path("cas.sqlite", "AXROSS_CAS_DB", environ=env, home=home) == _legacy(
        home, "cas.sqlite")


# --- the modules, as a fresh process sees them ----------------------------------------


def _python(code: str, env: dict) -> str:
    clean = {k: v for k, v in os.environ.items()
             if k not in ("XDG_DATA_HOME", "AXROSS_METADATA_DB", "AXROSS_CAS_DB")}
    clean.update(env)
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=clean, check=True,
                         capture_output=True, text=True, timeout=120)
    return out.stdout.strip()


_INDEX_AND_SEARCH = (
    "import sys; sys.path.insert(0, '.');"
    "from core import metadata_index as M, cas as C; from core.local_fs import LocalFS;"
    "M.index_dir(LocalFS(), sys.argv[1] if len(sys.argv) > 1 else {folder!r}, backend_id='local');"
    "print(M.default_db_path()); print(C.default_db_path());"
    "print(sorted(e.name for e in M.search('note')))"
)


def test_happy_e2e_a_fresh_process_indexes_into_xdg_data_home(tmp_path):
    home, data = tmp_path / "home", tmp_path / "data"
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "note.txt").write_text("x")
    lines = _python(_INDEX_AND_SEARCH.format(folder=str(folder)),
                    {"HOME": str(home), "XDG_DATA_HOME": str(data)}).splitlines()
    assert lines[0] == str(data / "axross" / "metadata.sqlite")
    assert lines[1] == str(data / "axross" / "cas.sqlite")
    assert lines[2] == "['note.txt']"
    assert (data / "axross" / "metadata.sqlite").is_file()
    assert not _legacy(home, "metadata.sqlite").exists()


def test_edge_e2e_an_index_made_before_keeps_its_entries(tmp_path):
    """An index filled by an older version at ~/.local/share stays the one in
    use after XDG_DATA_HOME is set: its entries are still found."""
    home, data = tmp_path / "home", tmp_path / "data"
    old_folder = tmp_path / "old"
    old_folder.mkdir()
    (old_folder / "old-note.txt").write_text("x")
    _python(_INDEX_AND_SEARCH.format(folder=str(old_folder)), {"HOME": str(home)})
    assert _legacy(home, "metadata.sqlite").is_file()
    lines = _python(_INDEX_AND_SEARCH.format(folder=str(old_folder)),
                    {"HOME": str(home), "XDG_DATA_HOME": str(data)}).splitlines()
    assert lines[0] == str(_legacy(home, "metadata.sqlite"))
    assert lines[2] == "['old-note.txt']"
    assert not (data / "axross" / "metadata.sqlite").exists()


@pytest.mark.parametrize("module,var", [("metadata_index", "AXROSS_METADATA_DB"),
                                        ("cas", "AXROSS_CAS_DB")])
def test_sad_e2e_the_override_still_wins_in_a_fresh_process(tmp_path, module, var):
    target = tmp_path / "chosen.sqlite"
    out = _python(f"import sys; sys.path.insert(0, '.'); from core import {module} as M;"
                  "print(M.default_db_path())",
                  {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "d"), var: str(target)})
    assert out == str(target)
