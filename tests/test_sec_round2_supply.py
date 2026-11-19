"""Second security review, the supply-chain gate: the release CI's macOS and
Windows bundles go through the gate like the Linux ones (markers per
platform, the locks they install, reduced locks, verify-env), and the
index check knows -i, -f, uv's --index / --default-index and the pip and
uv config files."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security import supply_chain_gate as G  # noqa: E402
from security.dep_floor_audit import LockedPin, parse_lock  # noqa: E402


# --- markers per platform -------------------------------------------------------------------------

@pytest.mark.parametrize("marker,platform,want", [
    ("", "windows-amd64", True),
    ("sys_platform == 'linux'", "linux-x86_64", True),
    ("sys_platform == 'linux'", "macos-arm64", False),
    ("sys_platform == 'win32'", "windows-amd64", True),
    ("sys_platform == 'win32'", "linux-x86_64", False),
    ("sys_platform == 'darwin'", "macos-arm64", True),
    ("os_name == 'nt'", "windows-amd64", True),
    ("os_name == 'nt'", "macos-arm64", False),
    ("sys_platform == 'linux' or sys_platform == 'win32'", "windows-amd64", True),
    ("sys_platform == 'linux' or sys_platform == 'win32'", "macos-arm64", False),
    ("(platform_machine == 'AMD64' and sys_platform == 'linux') or "
     "(platform_machine == 'x86_64' and sys_platform == 'linux')", "linux-x86_64", True),
    ("(platform_machine == 'AMD64' and sys_platform == 'linux') or "
     "(platform_machine == 'x86_64' and sys_platform == 'linux')", "windows-amd64", False),
    ("python_full_version < '3.14'", "macos-arm64", True),
    ("python_full_version >= '3.14'", "macos-arm64", False),
    ("platform_python_implementation == 'PyPy'", "linux-x86_64", False),
    ("implementation_name != 'PyPy' and platform_python_implementation == 'PyPy'", "linux-x86_64", False),
    ("sys_platform != 'android' and sys_platform != 'emscripten'", "macos-arm64", True),
    ("'linux' in sys_platform", "linux-x86_64", True),
    ("sys_platform not in 'win32 cygwin'", "windows-amd64", False),
])
def test_happy_a_marker_is_read_for_each_platform(marker, platform, want):
    assert G.marker_applies(marker, platform) is want


@pytest.mark.parametrize("marker", ["extra == 'x'", "some_new_variable == '1'", "sys_platform ==",
                                    "((sys_platform == 'linux'", "sys_platform === 'linux' garbage"])
def test_edge_a_marker_the_gate_cannot_read_counts_as_applying(marker):
    # conservative: what the gate does not understand is checked, never skipped
    assert G.marker_applies(marker, "macos-arm64") is True


def test_happy_a_pin_for_another_platform_is_not_checked_and_left_out_of_the_reduced_lock(tmp_path):
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    lock = tmp_path / "build" / "requirements-bundle.txt"
    lock.parent.mkdir()
    lock.write_text(f"foo==1.0 ; sys_platform == 'linux' \\\n    --hash=sha256:{a}\n"
                    f"bar==2.0 ; sys_platform == 'win32' \\\n    --hash=sha256:{b}\n"
                    f"baz==3.0 \\\n    --hash=sha256:{c}\n", encoding="utf-8")
    seen = []

    def checker(rel, pin, platforms):
        seen.append((pin.name, tuple(platforms)))
        res = G.PinResult(pin=pin, lock=rel)
        res.used_hashes = list(pin.hashes)
        return res

    locks = ("build/requirements-bundle.txt",)
    results, _ = G.run_check(["windows-amd64"], root=tmp_path, locks=locks, top=[], osv=lambda p: [[] for _ in p],
                             checker=checker)
    assert seen == [("bar", ("windows-amd64",)), ("baz", ("windows-amd64",))]
    out = tmp_path / "rl"
    G.write_reduced_locks(results, out, root=tmp_path, locks=locks, platforms=["windows-amd64"])
    names = [p.name for p in parse_lock((out / "requirements-bundle.txt").read_text())]
    assert names == ["bar", "baz"]


def test_happy_a_pin_in_two_locks_is_checked_where_its_marker_applies(tmp_path):
    a = "a" * 64
    (tmp_path / "one.txt").write_text(f"pyc==1.0 ; platform_python_implementation == 'PyPy' \\\n"
                                      f"    --hash=sha256:{a}\n", encoding="utf-8")
    (tmp_path / "two.txt").write_text(f"pyc==1.0 ; implementation_name != 'PyPy' \\\n"
                                      f"    --hash=sha256:{a}\n", encoding="utf-8")
    seen = []

    def checker(rel, pin, platforms):
        seen.append(rel)
        return G.PinResult(pin=pin, lock=rel)

    G.run_check(["linux-x86_64"], root=tmp_path, locks=("one.txt", "two.txt"), top=[],
                osv=lambda p: [[] for _ in p], checker=checker)
    assert seen == ["two.txt"]


def test_sad_check_takes_only_locks_the_gate_knows():
    rc = G.main(["check", "--lock", "/tmp/elsewhere.txt"])
    assert rc == 2


def test_happy_check_with_lock_checks_only_those_locks(monkeypatch, tmp_path):
    got = {}

    def fake_run_check(platforms, *, locks=None, scan_python=None, **kw):
        got["locks"], got["platforms"] = locks, platforms
        return [], []

    monkeypatch.setattr(G, "run_check", fake_run_check)
    monkeypatch.setattr(G, "write_reduced_locks", lambda results, out, locks=None, platforms=None:
                        got.update(rl_locks=locks, rl_platforms=platforms) or [])
    rc = G.main(["check", "--platform", "macos-arm64", "--lock", "build/requirements-bootstrap.txt",
                 "--lock", "build/requirements-bundle.txt", "--reduced-locks", str(tmp_path / "rl")])
    assert rc == 0
    assert got["locks"] == ("build/requirements-bootstrap.txt", "build/requirements-bundle.txt")
    assert got["rl_locks"] == got["locks"] and got["rl_platforms"] == ["macos-arm64"]


# --- the release CI's bundle job --------------------------------------------------------------------

def _bundle_job() -> str:
    text = (ROOT / ".github" / "workflows" / "cross-platform.yml").read_text(encoding="utf-8")
    start = text.index("\n  bundle:\n")
    end = text.index("\n  linux:\n", start)
    return text[start:end]


def test_happy_the_ci_bundle_job_goes_through_the_gate_before_installing():
    job = _bundle_job()
    gate = job.index("security/supply_chain_gate.py check")
    first_install = job.index("python -m pip install")
    assert gate < first_install
    assert "--platform ${{ matrix.gate_platform }}" in job
    assert "gate_platform: macos-arm64" in job and "gate_platform: windows-amd64" in job
    assert "--lock build/requirements-bootstrap.txt --lock build/requirements-bundle.txt" in job
    assert "--reduced-locks" in job
    # every pip install reads the reduced locks, never the raw ones
    for line in job.splitlines():
        if "python -m pip install" in line:
            assert "-r build/requirements-" not in line, line
            assert '-r "$RUNNER_TEMP/reviewed-locks/' in line, line
    verify = job.index("supply_chain_gate.py verify-env")
    assert verify > job.rindex("python -m pip install") and verify < job.index("python -m PyInstaller")


# --- the index check -----------------------------------------------------------------------------------

def _script(tmp_path: Path, text: str) -> list[str]:
    (tmp_path / "scripts").mkdir(exist_ok=True)
    (tmp_path / "scripts" / "build_dist.sh").write_text(text, encoding="utf-8")
    return [p for p in G.index_problems(tmp_path) if not p.startswith("environment:")]


@pytest.mark.parametrize("line", [
    "pip install -i https://evil.example/simple x",
    "python -m pip install -ihttps://evil.example/simple x",
    "pip install -qi https://evil.example/simple x",
    "pip install -f https://evil.example/wheels x",
    "pip install --find-links=/tmp/wheels x",
    "uv pip install --index https://evil.example/simple x",
    "uv pip install --index=evil=https://evil.example/simple x",
    "uv pip compile --default-index https://evil.example/simple a.in",
    "uv pip compile --index-strategy unsafe-best-match a.in",
    "rm -rf x && uv pip install -f ./wheels y",
    "uv pip install --extra-index-url=https://evil.example/simple y",
])
def test_sad_every_way_to_name_another_index_on_a_pip_or_uv_line_is_found(tmp_path, line):
    assert _script(tmp_path, line + "\n"), line


@pytest.mark.parametrize("line", [
    "grep -i pattern file", "sed -i 's/a/b/' file", "rm -rf build", "pip install -r req.txt",
    "pip install --index-url https://pypi.org/simple x", "uv pip install --index-strategy first-index x",
    "uv pip install --default-index https://pypi.org/simple/ x",
])
def test_happy_ordinary_lines_are_no_index(tmp_path, line):
    assert _script(tmp_path, line + "\n") == [], line


def test_sad_an_index_in_a_requirements_input_is_found(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "requirements-bundle.in").write_text("-i https://evil.example/simple\nfoo>=1\n")
    assert [p for p in G.index_problems(tmp_path) if "requirements-bundle.in" in p]
    (tmp_path / "build" / "requirements-bundle.in").write_text("--find-links ./w\nfoo>=1\n")
    assert [p for p in G.index_problems(tmp_path) if "requirements-bundle.in" in p]


@pytest.mark.parametrize("rel,text", [
    ("pip.conf", "[global]\nindex-url = https://evil.example/simple\n"),
    ("pip.ini", "[install]\nextra-index-url=https://evil.example/simple\n"),
    ("pip.conf", "[global]\nfind-links = /tmp/w\n"),
    ("uv.toml", "[[index]]\nurl = 'https://evil.example/simple'\n"),
    ("uv.toml", "index-url = 'https://evil.example/simple'\n"),
    ("pyproject.toml", "[project]\nname='x'\n[[tool.uv.index]]\nname='e'\nurl='https://evil.example/simple'\n"),
    ("pyproject.toml", "[tool.uv]\nextra-index-url = ['https://evil.example/simple']\n"),
    ("pyproject.toml", "[tool.uv.pip]\nfind-links = ['./w']\n"),
])
def test_sad_a_pip_or_uv_config_file_of_the_project_naming_an_index_is_found(tmp_path, rel, text):
    (tmp_path / rel).write_text(text, encoding="utf-8")
    assert [p for p in G.index_problems(tmp_path) if rel in p], rel


def test_happy_a_project_config_that_names_pypi_only_passes(tmp_path):
    (tmp_path / "pip.conf").write_text("[global]\nindex-url = https://pypi.org/simple\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\ndescription = 'an index of things'\n")
    assert [p for p in G.index_problems(tmp_path) if not p.startswith("environment:")] == []


def test_sad_a_user_pip_or_uv_config_naming_an_index_is_found(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".config" / "pip").mkdir(parents=True)
    (home / ".config" / "pip" / "pip.conf").write_text("[global]\nextra-index-url = https://evil.example/s\n")
    (home / ".config" / "uv").mkdir(parents=True)
    (home / ".config" / "uv" / "uv.toml").write_text("[[index]]\nurl = 'https://evil.example/s'\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    found = G.index_problems(tmp_path / "proj")
    assert any("pip.conf" in p and p.startswith("environment:") for p in found)
    assert any("uv.toml" in p and p.startswith("environment:") for p in found)


@pytest.mark.parametrize("var", ["UV_DEFAULT_INDEX", "UV_FIND_LINKS", "UV_INDEX_STRATEGY", "PIP_INDEX"])
def test_sad_more_index_variables_are_found(tmp_path, monkeypatch, var):
    monkeypatch.setenv(var, "https://evil.example/simple" if var != "UV_INDEX_STRATEGY" else "unsafe-best-match")
    assert any(var in p for p in G.index_problems(tmp_path))


def test_happy_the_ci_workflows_are_index_checked():
    assert ".github/workflows/cross-platform.yml" in G.INDEX_CONFIG
    assert "pyproject.toml" in G.INDEX_CONFIG


@pytest.mark.parametrize("line", [
    "PIP_INDEX_URL=https://evil.example/simple pip install x",
    "export UV_DEFAULT_INDEX=https://evil.example/simple",
    "      PIP_EXTRA_INDEX_URL: https://evil.example/simple",
    "export PIP_CONFIG_FILE=/tmp/my.conf",
])
def test_sad_an_index_variable_set_in_a_build_file_is_found(tmp_path, line):
    assert _script(tmp_path, line + "\n"), line


def test_happy_the_build_s_own_pip_variables_are_no_index(tmp_path):
    assert _script(tmp_path, "export PIP_DISABLE_PIP_VERSION_CHECK=1\nPIP_INDEX_URL=https://pypi.org/simple pip x\n") == []


# --- reviewing the macOS and Windows wheels of reviewed pins ---------------------------------------

def test_happy_a_review_of_another_platform_s_wheel_is_added_to_the_reviewed_entry():
    old = {"name": "foo", "version": "1.0", "archives": {"foo-1.0-cp312-manylinux_2_28_x86_64.whl":
                                                          {"sha256": "a" * 64, "manifest": "m1"}},
           "accepted_findings": ["k1"], "reviewed": {"by": "r", "date": "2026-11-01", "note": "linux wheel read"},
           "provenance": {"foo-1.0-cp312-manylinux_2_28_x86_64.whl": {"repository": "o/foo"}},
           "scans": {"keys": ["k1"], "capa": {"x": {}}, "yara": ["y1"]}, "young_release": "CVE fix"}
    new = {"name": "foo", "version": "1.0", "archives": {"foo-1.0-cp312-win_amd64.whl":
                                                          {"sha256": "b" * 64, "manifest": "m2"},
                                                          "foo-1.0-cp312-manylinux_2_28_x86_64.whl":
                                                          {"sha256": "a" * 64, "manifest": "m1"}},
           "accepted_findings": ["k2"], "reviewed": {"by": "s", "date": "2026-11-20", "note": "windows wheel read"},
           "provenance": {"foo-1.0-cp312-win_amd64.whl": {"repository": "o/foo"}},
           "scans": {"keys": ["k2"], "capa": {"z": {}}, "yara": []}}
    merged = G.merge_entries(old, new)
    assert set(merged["archives"]) == {"foo-1.0-cp312-manylinux_2_28_x86_64.whl", "foo-1.0-cp312-win_amd64.whl"}
    assert merged["accepted_findings"] == ["k1", "k2"] and merged["scans"]["keys"] == ["k1", "k2"]
    assert set(merged["scans"]["capa"]) == {"x", "z"} and merged["young_release"] == "CVE fix"
    assert merged["reviewed"]["note"] == "windows wheel read"
    assert merged["reviewed"]["earlier"][0]["note"] == "linux wheel read"
    assert len(merged["provenance"]) == 2


def test_sad_a_new_review_never_replaces_a_reviewed_archive_with_another_file():
    old = {"name": "foo", "version": "1.0", "archives": {"foo.whl": {"sha256": "a" * 64, "manifest": "m"}}}
    new = {"name": "foo", "version": "1.0", "archives": {"foo.whl": {"sha256": "b" * 64, "manifest": "m"}}}
    with pytest.raises(G.GateError):
        G.merge_entries(old, new)


def test_happy_survey_incomplete_takes_a_reviewed_pin_only_when_an_archive_was_not_reviewed(tmp_path, monkeypatch):
    lock = tmp_path / "l.txt"
    lock.write_text("foo==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\nbar==2.0 \\\n    --hash=sha256:" + "b" * 64
                    + "\nwin==3.0 ; sys_platform == 'win32' \\\n    --hash=sha256:" + "c" * 64 + "\n")
    monkeypatch.setattr(G, "ROOT", tmp_path)
    monkeypatch.setattr(G, "LOCKS", ("l.txt",))
    monkeypatch.setattr(G, "load_baseline", lambda n, v: {"archives": {}})
    checked = []

    def check_pin(rel, pin, platforms):
        checked.append((pin.name, tuple(platforms)))
        r = G.PinResult(pin=pin, lock=rel)
        if pin.name == "foo":
            r.problems.append(G.Problem("foo", "foo-1.0-cp312-macosx_11_0_arm64.whl was not part of the review",
                                        "baseline"))
        return r

    surveyed = []
    monkeypatch.setattr(G, "check_pin", check_pin)
    monkeypatch.setattr(G, "run_scanners", lambda results, *a, **k: surveyed.extend(r.pin.name for r in results))
    monkeypatch.setattr(G, "baseline_entry", lambda r, *a, **k: {"name": r.pin.name})
    G.survey(tmp_path / "out", ["macos-arm64"], "py", locks=("l.txt",), incomplete=True)
    assert checked == [("foo", ("macos-arm64",)), ("bar", ("macos-arm64",))]
    assert surveyed == ["foo"]
