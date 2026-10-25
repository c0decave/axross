"""The third-party credits: one data file (resources/credits/third_party.json)
and the views made from it - the README sections, the tables of
THIRD_PARTY_LICENSES.md and Help > Third-Party Software….

A view that drifts from the data fails here, and so does a package that
pyproject.toml installs but the data file does not name.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import tomllib

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import third_party as T  # noqa: E402

PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
DOCKERFILE = (ROOT / "Dockerfile.build").read_text(encoding="utf-8")


def _raw() -> dict:
    return json.loads(T.DATA_FILE.read_text(encoding="utf-8"))


def _entry(**over) -> dict:
    base = {"id": "demo", "name": "Demo", "kind": "python", "purpose": "Testing",
            "license": "MIT", "url": "https://example.org/demo", "ships": ["pip"]}
    base.update(over)
    return base


def _doc(*entries: dict) -> dict:
    return {"schema": T.SCHEMA, "entries": list(entries)}


def _requirement_names(specs) -> list[str]:
    return [T.normalise_name(re.split(r"[ ;<>=!~\[(]", s.strip(), maxsplit=1)[0]) for s in specs]


# --- happy -----------------------------------------------------------------


def test_happy_the_shipped_data_file_loads():
    entries = T.load()
    assert len(entries) > 150
    assert len({e.id for e in entries}) == len(entries)
    names = {e.name for e in entries}
    assert {"PyQt6", "paramiko", "Qt 6", "ripgrep", "fd", "Python", "OpenSSL"} <= names


def test_happy_every_pyproject_dependency_and_extra_has_an_entry():
    wanted = set(_requirement_names(PYPROJECT["project"]["dependencies"]))
    for extra, specs in PYPROJECT["project"]["optional-dependencies"].items():
        wanted |= set(_requirement_names(specs))
    assert T.missing_packages(T.load(), wanted) == []


def test_happy_the_extras_of_an_entry_are_the_ones_pyproject_lists():
    extras: dict[str, set[str]] = {}
    for extra, specs in PYPROJECT["project"]["optional-dependencies"].items():
        if extra == "all":
            continue
        for name in _requirement_names(specs):
            extras.setdefault(name, set()).add(extra)
    for entry in T.load():
        for pypi in entry.pypi:
            key = T.normalise_name(pypi)
            if key in extras and not entry.via:
                assert set(entry.extras) == extras[key], entry.id


def test_happy_core_dependencies_come_with_pip_and_extras_with_pip_extra():
    by_pypi = {T.normalise_name(p): e for e in T.load() for p in e.pypi}
    for name in _requirement_names(PYPROJECT["project"]["dependencies"]):
        assert "pip" in by_pypi[name].ships, name
    for extra, specs in PYPROJECT["project"]["optional-dependencies"].items():
        for name in _requirement_names(specs):
            entry = by_pypi[name]
            assert "pip" in entry.ships or "pip-extra" in entry.ships, name


def test_happy_the_readmes_and_the_licence_file_match_the_data():
    assert T.check(ROOT) == []


def test_happy_the_readme_section_is_the_last_thing_in_each_readme():
    for name in T.README_FILES:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert text.rstrip().endswith(T.block_end("readme")), name


def test_happy_pinned_versions_are_the_ones_the_builder_installs():
    by_id = {e.id: e for e in T.load()}
    for key, entry_id in (("RG", "ripgrep"), ("FD", "fd")):
        pin = re.search(rf"^ARG {key}_VERSION=(\S+)$", DOCKERFILE, re.MULTILINE).group(1)
        assert by_id[entry_id].version == pin
    for entry_id in ("piper-tts", "onnxruntime", "faster-whisper", "ctranslate2"):
        name = by_id[entry_id].pypi[0]
        assert f'"{name}=={by_id[entry_id].version}"' in DOCKERFILE, entry_id


def test_happy_filter_looks_at_name_purpose_licence_and_shipping():
    entries = T.load()
    assert [e.id for e in T.filter_entries(entries, "RIPGREP")] == ["ripgrep"]
    assert "ripgrep" in {e.id for e in T.filter_entries(entries, "content search")}
    assert "piper-tts" in {e.id for e in T.filter_entries(entries, "gpl-3.0-or-later")}
    slim = T.filter_entries(entries, "axross-slim")
    assert slim and all("axross-slim" in e.ships for e in slim)


def test_happy_ships_label_names_the_extras():
    entry = T.parse(_doc(_entry(ships=["axross-full", "pip-extra"], extras=["voice"])))[0]
    assert T.ships_label(entry) == "axross-full, pip [voice]"
    entry = T.parse(_doc(_entry(ships=["host"])))[0]
    assert T.ships_label(entry) == "on your system"


def test_happy_the_cli_check_passes_on_the_tree():
    result = subprocess.run([sys.executable, "-m", "core.third_party", "--check"], cwd=ROOT,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


def test_happy_write_regenerates_a_drifted_copy(tmp_path):
    for name in (*T.README_FILES, T.LICENSES_FILE):
        (tmp_path / name).write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8").replace("| Qt 6 |", "| Qt 5 |"),
                      encoding="utf-8")
    entries = T.load()
    assert T.check(tmp_path, entries) == ["README.md"]
    assert T.write(tmp_path, entries) == ["README.md"]
    assert T.check(tmp_path, entries) == []


# --- sad -------------------------------------------------------------------


@pytest.mark.parametrize("field", ["id", "name", "kind", "purpose", "license", "url", "ships"])
def test_sad_a_missing_field_names_the_entry_and_the_field(field):
    entry = _entry()
    del entry[field]
    with pytest.raises(T.DataError, match=field):
        T.parse(_doc(entry))


@pytest.mark.parametrize("expr", ["", "MIT and", "(MIT", "MIT)", "MIT/BSD", "OR MIT",
                                  "MIT AND AND BSD-3-Clause", "GPL v3"])
def test_sad_a_licence_that_is_no_spdx_expression_is_refused(expr):
    with pytest.raises(T.DataError, match="license"):
        T.parse(_doc(_entry(license=expr)))


@pytest.mark.parametrize("url", ["http://example.org", "javascript:alert(1)", "https://",
                                 "https://exa mple.org", "file:///etc/passwd", "ftp://x.org",
                                 "https://example.org/\n"])
def test_sad_only_plain_https_links_are_accepted(url):
    with pytest.raises(T.DataError, match="url"):
        T.parse(_doc(_entry(url=url)))


def test_sad_unknown_ships_value_duplicate_id_and_bad_id_are_refused():
    with pytest.raises(T.DataError, match="ships"):
        T.parse(_doc(_entry(ships=["pip", "pypi"])))
    with pytest.raises(T.DataError, match="ships"):
        T.parse(_doc(_entry(ships=[])))
    with pytest.raises(T.DataError, match="duplicate"):
        T.parse(_doc(_entry(), _entry(name="Other")))
    with pytest.raises(T.DataError, match="id"):
        T.parse(_doc(_entry(id="Bad Id")))


def test_sad_extras_without_pip_extra_and_unknown_kind_are_refused():
    with pytest.raises(T.DataError, match="extras"):
        T.parse(_doc(_entry(extras=["voice"])))
    with pytest.raises(T.DataError, match="kind"):
        T.parse(_doc(_entry(kind="plugin")))


def test_sad_a_wrong_schema_or_shape_is_refused():
    with pytest.raises(T.DataError, match="schema"):
        T.parse({"schema": 99, "entries": []})
    with pytest.raises(T.DataError, match="entries"):
        T.parse({"schema": T.SCHEMA, "entries": {}})
    with pytest.raises(T.DataError):
        T.parse([])
    with pytest.raises(T.DataError, match="match"):
        T.parse(_doc(_entry(match={"modules": "PyQt6"})))
    with pytest.raises(T.DataError, match="match"):
        T.parse(_doc(_entry(match={"files": ["x"]})))


def test_sad_a_missing_or_corrupt_data_file_raises_data_error(tmp_path):
    with pytest.raises(T.DataError):
        T.load(tmp_path / "absent.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(T.DataError):
        T.load(bad)


def test_sad_a_pyproject_package_without_an_entry_is_reported():
    entries = T.parse(_doc(_entry(pypi=["Demo_Pkg"])))
    assert T.missing_packages(entries, {"demo-pkg", "other"}) == ["other"]


def test_sad_a_readme_without_the_markers_is_reported_not_passed(tmp_path):
    for name in (*T.README_FILES, T.LICENSES_FILE):
        (tmp_path / name).write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "README_de.md").write_text("# axross\n\nno markers here\n", encoding="utf-8")
    problems = T.check(tmp_path)
    assert problems == ["README_de.md"]
    with pytest.raises(T.DataError, match="README_de.md"):
        T.write(tmp_path)


def test_sad_the_cli_check_fails_on_drift(tmp_path):
    for name in (*T.README_FILES, T.LICENSES_FILE):
        text = (ROOT / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(text.replace("| paramiko |", "| paramikko |"),
                                     encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "core.third_party", "--check",
                             "--root", str(tmp_path)], cwd=ROOT, capture_output=True, text=True,
                            timeout=60)
    assert result.returncode == 1
    assert "THIRD_PARTY_LICENSES.md" in result.stdout + result.stderr


# --- edge ------------------------------------------------------------------


def test_edge_an_empty_or_blank_filter_keeps_everything():
    entries = T.load()
    assert T.filter_entries(entries, "") == entries
    assert T.filter_entries(entries, "   ") == entries
    assert T.filter_entries(entries, "no-such-thing-at-all") == []


def test_edge_names_are_compared_the_pep_503_way():
    assert T.normalise_name("adb_shell") == T.normalise_name("ADB-Shell") == "adb-shell"
    assert T.normalise_name("backports.zstd") == "backports-zstd"


def test_edge_a_pipe_in_a_cell_is_escaped_and_a_newline_refused():
    entry = T.parse(_doc(_entry(purpose="A | B")))[0]
    assert "A \\| B" in T.render_readme([entry], "en")
    with pytest.raises(T.DataError, match="purpose"):
        T.parse(_doc(_entry(purpose="two\nlines")))


def test_edge_with_and_parentheses_are_valid_licence_syntax():
    for expr in ("GPL-3.0-or-later WITH GCC-exception-3.1", "(MIT OR Apache-2.0) AND Unicode-3.0",
                 "LicenseRef-PublicDomain", "MIT"):
        assert T.parse(_doc(_entry(license=expr)))[0].license == expr


def test_edge_every_via_names_entries_of_the_data_file():
    entries = T.load()
    names = {e.name for e in entries}
    unknown = {e.id: e.via for e in entries
               if e.via and not set(e.via.split(", ")) <= names}
    assert unknown == {}


def test_edge_write_is_idempotent(tmp_path):
    for name in (*T.README_FILES, T.LICENSES_FILE):
        (tmp_path / name).write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
    assert T.write(tmp_path) == []
    before = {n: (tmp_path / n).read_bytes() for n in (*T.README_FILES, T.LICENSES_FILE)}
    assert T.write(tmp_path) == []
    assert before == {n: (tmp_path / n).read_bytes() for n in before}


def test_edge_the_data_file_is_packaged_for_pip_and_the_bundle():
    tool = PYPROJECT["tool"]["setuptools"]
    assert "resources.credits" in tool["packages"]
    assert tool["package-data"]["resources.credits"] == ["*.json"]
    assert (ROOT / "resources" / "credits" / "__init__.py").is_file()
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include resources/credits *.json" in manifest
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    loop = re.search(r"for sub in \(([^)]*)\):", spec).group(1)
    assert '"credits"' in loop


def test_edge_parse_does_not_mutate_its_input():
    doc = _doc(_entry(match={"modules": ["demo"]}))
    snapshot = copy.deepcopy(doc)
    T.parse(doc)
    assert doc == snapshot
