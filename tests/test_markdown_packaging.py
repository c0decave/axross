"""axross-markdown's release packaging (scripts/standalone_repo/axross-markdown/packaging) - the twenty-seventh
review's P1 to P6: the Linux one-file program carried 94 of the build machine's libraries (libcups.so.2, libgtk-3,
gnutls among them; 48 loaded by nothing that stays in it) without a licence text or a source pointer; the sdist
held none of what THIRD_PARTY_LICENSES.txt said it holds, and was not reproducible; CI tested the source tree,
never the wheel; the release published tests.yml's supply-chain report as assets.

Each test here failed before.
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "scripts" / "standalone_repo" / "axross-markdown" / "packaging"
WORKFLOW = ROOT / "scripts" / "standalone_repo" / "axross-markdown" / ".github" / "workflows" / "release.yml"
sys.path.insert(0, str(PACKAGING))
sys.dont_write_bytecode, _WROTE = True, sys.dont_write_bytecode  # (no __pycache__ in the exported repo's files)

import reproducible_sdist as RS  # noqa: E402
import system_libraries as SL  # noqa: E402

sys.dont_write_bytecode = _WROTE

LINUX = sys.platform.startswith("linux")


def _qt() -> Path:
    pytest.importorskip("PyQt6")
    import PyQt6

    folder = Path(PyQt6.__file__).parent / "Qt6"
    if not (folder / "lib" / "libQt6Gui.so.6").is_file():
        pytest.skip("no Linux Qt of PyQt6's wheel")
    return folder


def _system(name: str) -> str:
    for folder in ("/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib"):
        path = os.path.join(folder, name)
        if os.path.exists(path):
            return path
    pytest.skip(f"no {name} on this system")


@pytest.mark.skipif(not LINUX, reason="ELF")
def test_happy_the_elf_reader_reads_what_a_qt_library_needs():
    qt = _qt()
    gui = SL.needed(qt / "lib" / "libQt6Gui.so.6")
    assert "libQt6Core.so.6" in gui and "libc.so.6" in gui
    assert "libcups.so.2" in SL.needed(qt / "plugins" / "printsupport" / "libcupsprintersupport.so")
    assert SL.needed(__file__) == []


@pytest.mark.skipif(not LINUX, reason="ELF")
def test_sad_a_system_library_only_a_dropped_plugin_needs_is_left_out():
    """The CUPS print plugin and the GTK theme are dropped by the spec, but PyInstaller had put in the system
    libraries they need: libcups.so.2, libgtk-3. Only the closure of what stays is kept now."""
    qt = _qt()
    cups, gtk, z = _system("libcups.so.2"), _system("libgtk-3.so.0"), _system("libz.so.1")
    fontconfig = _system("libfontconfig.so.1")
    toc = [("libQt6Gui.so.6", str(qt / "lib" / "libQt6Gui.so.6"), "BINARY"),
           ("libQt6Core.so.6", str(qt / "lib" / "libQt6Core.so.6"), "BINARY"),
           ("libcups.so.2", cups, "BINARY"), ("libgtk-3.so.0", gtk, "BINARY"),
           ("libz.so.1", z, "BINARY"), ("libfontconfig.so.1", fontconfig, "BINARY")]
    assert all(SL.is_system(source) for _name, source, _kind in toc[2:])
    assert not SL.is_system(toc[0][1])
    kept, gone = SL.pruned(toc)
    names = {name for name, _source, _kind in kept}
    assert {"libQt6Gui.so.6", "libQt6Core.so.6", "libz.so.1", "libfontconfig.so.1"} <= names
    assert {name for name, _source, _kind in gone} == {"libcups.so.2", "libgtk-3.so.0"}


@pytest.mark.skipif(not LINUX or shutil.which("dpkg") is None, reason="a Debian or Ubuntu system")
def test_sad_every_bundled_system_library_comes_with_its_licence_and_source(tmp_path):
    """No licence text or source pointer for any of them: now each package's copyright file and an index of
    the library, its package, version and source package."""
    toc = [("libz.so.1", _system("libz.so.1"), "BINARY"), ("libfontconfig.so.1", _system("libfontconfig.so.1"),
                                                            "BINARY")]
    datas = SL.notices(toc, tmp_path / "system")
    names = {name for name, _source, _kind in datas}
    assert "licenses/system/INDEX.txt" in names and "licenses/system/zlib1g.copyright" in names
    index = (tmp_path / "system" / "INDEX.txt").read_text(encoding="utf-8")
    assert "libz.so.1" in index and "package zlib1g" in index and "source  zlib " in index
    assert "licences: licenses/system/zlib1g.copyright" in index
    assert ("snapshot.debian.org/package/zlib/" in index) or ("launchpad.net/ubuntu/+source/zlib/" in index)
    assert "Copyright" in (tmp_path / "system" / "zlib1g.copyright").read_text(encoding="utf-8", errors="replace")


@pytest.mark.skipif(not LINUX or shutil.which("dpkg") is None, reason="a Debian or Ubuntu system")
def test_sad_a_library_without_its_package_stops_the_build(tmp_path):
    stray = tmp_path / "lib" / "libstray.so.1"
    stray.parent.mkdir()
    stray.write_bytes(b"\x7fELF")
    original = SL.is_system
    try:
        SL.is_system = lambda source: True
        with pytest.raises(SystemExit) as stopped:
            SL.notices([("libstray.so.1", str(stray), "BINARY")], tmp_path / "out")
    finally:
        SL.is_system = original
    assert "without its licence" in str(stopped.value)


def test_sad_the_spec_prunes_the_system_libraries_and_stops_with_libcups_in():
    spec = (PACKAGING / "axross-markdown.spec").read_text(encoding="utf-8")
    assert "system_libraries.pruned(a.binaries)" in spec and "system_libraries.notices(" in spec
    assert 'startswith("libcups.so")' in spec
    check = (PACKAGING / "licences_check.py").read_text(encoding="utf-8")
    assert "INDEX.txt" in check and "libcups.so" in check


def _sdist(folder: Path, mtime: float, order) -> bytes:
    out = io.BytesIO()
    with gzip.GzipFile(filename="x.tar", mode="wb", fileobj=out, mtime=mtime) as packed, \
            tarfile.open(fileobj=packed, mode="w") as target:
        for name in order:
            data = (folder / name).read_bytes() if (folder / name).is_file() else None
            info = tarfile.TarInfo(f"axross_markdown-1.0/{name}")
            info.mtime, info.uid, info.uname = mtime, 1000, "builder"
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o775
                target.addfile(info)
            else:
                info.size, info.mode = len(data), 0o664
                target.addfile(info, io.BytesIO(data))
    return out.getvalue()


def test_sad_the_sdist_is_the_same_bytes_for_the_same_commit(tmp_path):
    """Two builds of one commit gave two sdists (the build's times, its order, the gzip header's time)."""
    (tmp_path / "packaging").mkdir()
    (tmp_path / "PKG-INFO").write_text("Name: axross-markdown\n")
    (tmp_path / "packaging" / "a.py").write_text("print(1)\n")
    first = _sdist(tmp_path, time.time() - 1000, ["packaging", "packaging/a.py", "PKG-INFO"])
    second = _sdist(tmp_path, time.time(), ["PKG-INFO", "packaging", "packaging/a.py"])
    assert first != second
    one, two = RS.rewritten(first, 1700000000), RS.rewritten(second, 1700000000)
    assert one == two
    with tarfile.open(fileobj=io.BytesIO(one), mode="r:gz") as packed:
        assert packed.getnames() == sorted(packed.getnames())
        assert {member.mtime for member in packed.getmembers()} == {1700000000}
        assert packed.extractfile("axross_markdown-1.0/packaging/a.py").read() == b"print(1)\n"


def test_sad_an_sdist_without_the_build_s_scripts_and_locks_is_refused(tmp_path):
    (tmp_path / "PKG-INFO").write_text("x\n")
    lacking = RS.missing(_sdist(tmp_path, 0, ["PKG-INFO"]))
    assert ".github/workflows/release.yml" in lacking and "requirements.lock.txt" in lacking
    path = tmp_path / "x.tar.gz"
    path.write_bytes(_sdist(tmp_path, 0, ["PKG-INFO"]))
    out = subprocess.run([sys.executable, str(PACKAGING / "reproducible_sdist.py"), "--check", str(path)],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 1 and "lacks" in out.stdout


def test_sad_the_export_s_sdist_holds_the_build_and_the_tests(tmp_path):
    """No MANIFEST.in: the published sdist (151 entries) held no workflow, no packaging/, no lock."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import export_standalone as ES

    for line in ("graft .github", "graft packaging", "graft tests", "include requirements.lock.txt"):
        assert line in ES.MANIFEST
    exported = (ROOT / "scripts" / "export_standalone.py").read_text(encoding="utf-8")
    assert '(out / "MANIFEST.in").write_text(MANIFEST' in exported
    licences = (ROOT / "scripts" / "standalone_licences.py").read_text(encoding="utf-8")
    assert "on PyPI and on the " not in licences and "reproducible_sdist.py --check" in licences


def test_sad_the_release_tests_the_wheel_it_built_and_publishes_its_own_assets_only():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "pip install --no-deps release/*.whl" in workflow
    assert 'AXROSS_MARKDOWN_TEST_INSTALLED: "1"' in workflow
    assert "pip install --no-build-isolation --no-deps .\n          python -m pip install --require-hashes -r " \
           "packaging/requirements-test.txt" not in workflow
    assert 'pattern: "{python,binaries-*}"' in workflow and "merge-multiple: true" in workflow
    assert "reproducible_sdist.py release/*.tar.gz" in workflow and "SOURCE_DATE_EPOCH" in workflow
    assert "SYSTEM-LIBRARIES-${{ matrix.suffix }}.txt" in workflow
    sys.path.insert(0, str(ROOT / "scripts"))
    import export_standalone as ES

    assert "AXROSS_MARKDOWN_TEST_INSTALLED" in ES.TESTS_CONFTEST


def test_sad_the_release_notes_count_no_text_as_a_binary(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    import release_notes as RN

    (tmp_path / "SHA256SUMS").write_text("".join(f"{'0' * 64}  {name}\n" for name in (
        "axross_markdown-1.0.tar.gz", "THIRD_PARTY_LICENSES.txt", "SYSTEM-LIBRARIES-linux-x86_64.txt",
        "SUPPLY-CHAIN.json", "SUPPLY-CHAIN.md")))
    monkeypatch.setattr(RN, "section", lambda text, version: "notes")
    assert RN.main(["release_notes.py", "1.0", str(tmp_path)]) == 0
    assert "not notarized" not in capsys.readouterr().out  # (no binary among them)
