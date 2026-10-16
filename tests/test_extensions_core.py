"""Finding extensions and remembering which ones are on.

An extension is Python code that runs inside axross, so nothing of it may
run before the user switched it on: finding one reads its manifest with
``ast`` and never imports it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import extensions as EX  # noqa: E402

GOOD = '''
EXTENSION = {
    "name": "Hello",
    "version": "1.2.0",
    "description": "Says hello.",
    "author": "someone",
}


def activate(api):
    api.add_menu_action("Say Hello", lambda: None)
'''

SIDE_EFFECT = '''
import pathlib
pathlib.Path(__file__).with_name("RAN").write_text("imported")
EXTENSION = {"name": "Noisy", "version": "0.1", "description": "x"}


def activate(api):
    pass
'''


@pytest.fixture
def user_dir(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    d = EX.extensions_dir()
    d.mkdir(parents=True)
    return d


def _write(d: Path, name: str, text: str) -> Path:
    path = d / f"{name}.py"
    path.write_text(text)
    return path


# --- happy -----------------------------------------------------------------


def test_happy_the_user_folder_is_below_the_axross_config(user_dir) -> None:
    assert user_dir == Path(os.environ["HOME"]) / ".config" / "axross" / "extensions"


def test_happy_discover_reads_the_manifest(user_dir) -> None:
    _write(user_dir, "hello", GOOD)
    found = {e.ext_id: e for e in EX.discover(include_bundled=False)}
    info = found["user:hello"]
    assert (info.name, info.version, info.description, info.author) == (
        "Hello",
        "1.2.0",
        "Says hello.",
        "someone",
    )
    assert info.source == "user" and info.error == ""


def test_happy_a_package_folder_is_an_extension_too(user_dir) -> None:
    pkg = user_dir / "treemap"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(GOOD.replace("Hello", "Treemap"))
    found = {e.ext_id: e for e in EX.discover(include_bundled=False)}
    assert found["user:treemap"].name == "Treemap"
    assert found["user:treemap"].path == str(pkg / "__init__.py")


def test_happy_enabled_state_round_trips(user_dir) -> None:
    assert EX.enabled_ids() == set()
    EX.set_enabled("user:hello", True)
    EX.set_enabled("bundled:checksum_manifest", True)
    assert EX.enabled_ids() == {"user:hello", "bundled:checksum_manifest"}
    EX.set_enabled("user:hello", False)
    assert EX.enabled_ids() == {"bundled:checksum_manifest"}
    stored = EX.settings_file()
    assert oct(stored.stat().st_mode & 0o777) == "0o600"


def test_happy_the_bundled_examples_are_found_and_off(user_dir) -> None:
    bundled = [e for e in EX.discover() if e.source == "bundled"]
    assert len(bundled) >= 5
    assert all(e.error == "" for e in bundled), [(e.ext_id, e.error) for e in bundled]
    assert not EX.enabled_ids()


# --- sad -------------------------------------------------------------------


def test_sad_discovery_never_runs_extension_code(user_dir) -> None:
    _write(user_dir, "noisy", SIDE_EFFECT)
    found = {e.ext_id: e for e in EX.discover(include_bundled=False)}
    assert found["user:noisy"].name == "Noisy"
    assert not (user_dir / "RAN").exists()


@pytest.mark.parametrize(
    "text, reason",
    [
        ("def activate(api): pass\n", "no EXTENSION manifest"),
        ('EXTENSION = {"name": "X"}\n', "no activate()"),
        ('EXTENSION = dict(name="X")\n\ndef activate(api): pass\n', "plain literal"),
        ('EXTENSION = {"version": "1"}\n\ndef activate(api): pass\n', "name"),
        ("def broken(:\n", "syntax"),
    ],
)
def test_sad_a_bad_extension_is_listed_with_its_error(user_dir, text, reason) -> None:
    _write(user_dir, "bad", text)
    info = {e.ext_id: e for e in EX.discover(include_bundled=False)}["user:bad"]
    assert reason in info.error


def test_sad_a_corrupt_settings_file_is_kept_aside(user_dir) -> None:
    EX.settings_file().write_text("{not json")
    assert EX.enabled_ids() == set()
    EX.set_enabled("user:hello", True)
    kept = list(EX.settings_file().parent.glob("extensions.json.unreadable-*"))
    assert len(kept) == 1 and kept[0].read_text() == "{not json"
    assert EX.enabled_ids() == {"user:hello"}


def test_sad_paranoid_mode_allows_no_extension(user_dir, monkeypatch) -> None:
    from core import security_mode

    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    assert not EX.extensions_allowed()
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.NORMAL)
    assert EX.extensions_allowed()


# --- edge ------------------------------------------------------------------


def test_edge_no_user_folder_yet(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "fresh"))
    assert [e for e in EX.discover() if e.source == "user"] == []


def test_edge_hidden_files_caches_and_symlinks_are_skipped(user_dir, tmp_path) -> None:
    _write(user_dir, "_private", GOOD)
    _write(user_dir, ".hidden", GOOD)
    (user_dir / "__pycache__").mkdir()
    outside = tmp_path / "elsewhere.py"
    outside.write_text(GOOD)
    (user_dir / "linked.py").symlink_to(outside)
    ids = {e.ext_id for e in EX.discover(include_bundled=False)}
    assert ids == set()


def test_edge_a_huge_file_is_refused_unread(user_dir) -> None:
    path = _write(user_dir, "huge", GOOD + "#" * (EX.MAX_SOURCE_BYTES + 10))
    info = {e.ext_id: e for e in EX.discover(include_bundled=False)}["user:huge"]
    assert "too large" in info.error
    assert path.stat().st_size > EX.MAX_SOURCE_BYTES


def test_edge_unknown_ids_in_the_settings_are_kept(user_dir) -> None:
    EX.settings_file().write_text(json.dumps({"enabled": ["user:gone", 7, "user:hello"]}))
    assert EX.enabled_ids() == {"user:gone", "user:hello"}
