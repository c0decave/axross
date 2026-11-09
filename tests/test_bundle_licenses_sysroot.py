"""scripts/bundle_licenses.py in a sysroot build (scripts/build_dist.sh).

The release binaries are built against the packages scripts/sysroot_fetch.py
unpacks into a folder: no rpm or dpkg database there, and the build
machine's ``rpm -qf`` knows none of the files. Each bundled system library
must still name its package and version in licenses/system/LIBRARIES.txt
and bring that package's licence texts - from the sysroot's FILES.json,
which records which package wrote each file. Real folders and symlinks
here, laid out as build_dist.sh does (a libs/ folder of absolute links into
the root, the root's own links relative).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_licenses as BL  # noqa: E402


def _sysroot(tmp_path: Path, system: str, files: dict[str, str | tuple[str, str]],
             packages: dict[str, tuple[str, str]]) -> Path:
    """A sysroot: *files* maps a path under root/ to its package, or to
    (package, symlink target); *packages* maps name -> (version, source)."""
    root = tmp_path / "sysroot" / "root"
    root.mkdir(parents=True)
    owners = {}
    for rel, what in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(what, tuple):
            what, link = what
            os.symlink(link, path)
        else:
            path.write_text(f"{rel}\n", encoding="utf-8")
        owners[rel] = what
    manifest = {"system": system, "files": owners,
                "packages": {n: {"version": v, "source": s} for n, (v, s) in packages.items()}}
    (root.parent / "FILES.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def _libs(root: Path, *names: str, folder: str = "usr/lib64") -> list[tuple[str, str, str]]:
    """build_dist.sh's libs/ folder: absolute links into the root; the
    PyInstaller TOC entries for them."""
    libs = root.parent / "libs"
    libs.mkdir(exist_ok=True)
    out = []
    for name in names:
        link = libs / name
        if not link.is_symlink():
            os.symlink(root / folder / name, link)
        out.append((name, str(link), "BINARY"))
    return out


ALMA = {
    "usr/lib64/libkrb5.so.3.3": "krb5-libs",
    "usr/lib64/libkrb5.so.3": ("krb5-libs", "libkrb5.so.3.3"),
    "usr/share/licenses/krb5-libs/LICENSE": "krb5-libs",
    "usr/share/doc/krb5-libs/README": "krb5-libs",
    "usr/lib64/libX11.so.6.4.0": "libX11",
    "usr/lib64/libX11.so.6": ("libX11", "libX11.so.6.4.0"),
    "usr/share/licenses/libX11/COPYING": "libX11",
    "usr/lib64/libX11-xcb.so.1.0.0": "libX11-xcb",
    "usr/lib64/libX11-xcb.so.1": ("libX11-xcb", "libX11-xcb.so.1.0.0"),
}
ALMA_PACKAGES = {"krb5-libs": ("1.21.1-10.el9_8", "krb5"), "libX11": ("1.8.12-1.el9", "libX11"),
                 "libX11-xcb": ("1.8.12-1.el9", "libX11"), "zlib": ("1.2.11-41.el9", "zlib")}


def _no_rpm(*_args, **_kw):
    pytest.fail("rpm was asked in a sysroot build")


# --- happy -----------------------------------------------------------------


def test_happy_a_sysroot_library_names_its_package_version_and_licence(tmp_path, monkeypatch):
    monkeypatch.setattr(BL.subprocess, "run", _no_rpm)
    root = _sysroot(tmp_path, "almalinux9", ALMA, ALMA_PACKAGES)
    target = BL.TargetPackages.load(root)
    datas, manifest = BL.system_licence_datas(_libs(root, "libkrb5.so.3"), target=target)
    assert manifest == ["libkrb5.so.3\tkrb5-libs\t1.21.1-10.el9_8"]
    assert datas == [(str(root / "usr/share/licenses/krb5-libs/LICENSE"),
                      "licenses/system/krb5-libs")]


def test_happy_a_sub_package_without_licence_gets_its_same_source_siblings(tmp_path):
    root = _sysroot(tmp_path, "almalinux9", ALMA, ALMA_PACKAGES)
    datas, manifest = BL.system_licence_datas(_libs(root, "libX11-xcb.so.1"),
                                              target=BL.TargetPackages.load(root))
    assert manifest == ["libX11-xcb.so.1\tlibX11-xcb\t1.8.12-1.el9"]
    assert datas == [(str(root / "usr/share/licenses/libX11/COPYING"),
                      "licenses/system/libX11-xcb")]


def test_happy_a_debian_library_brings_its_copyright_file(tmp_path):
    root = _sysroot(tmp_path, "debian12", {
        "usr/lib/x86_64-linux-gnu/libkrb5.so.3.3": "libkrb5-3",
        "usr/lib/x86_64-linux-gnu/libkrb5.so.3": ("libkrb5-3", "libkrb5.so.3.3"),
        "usr/share/doc/libkrb5-3/copyright": "libkrb5-3",
        "usr/share/doc/libkrb5-3/changelog.Debian.gz": "libkrb5-3",
        # libatomic1's doc folder is a link to gcc-12-base's (one source, gcc-12)
        "usr/lib/x86_64-linux-gnu/libatomic.so.1.2.0": "libatomic1",
        "usr/lib/x86_64-linux-gnu/libatomic.so.1": ("libatomic1", "libatomic.so.1.2.0"),
        "usr/share/doc/gcc-12-base/copyright": "gcc-12-base",
        "usr/share/doc/libatomic1": ("libatomic1", "gcc-12-base"),
    }, {"libkrb5-3": ("1.20.1-2+deb12u5", "krb5"), "libatomic1": ("12.2.0-14+deb12u1", "gcc-12"),
        "gcc-12-base": ("12.2.0-14+deb12u1", "gcc-12")})
    target = BL.TargetPackages.load(root)
    assert target.format == "deb"
    datas, manifest = BL.system_licence_datas(
        _libs(root, "libkrb5.so.3", "libatomic.so.1", folder="usr/lib/x86_64-linux-gnu"),
        target=target)
    assert manifest == ["libatomic.so.1\tlibatomic1\t12.2.0-14+deb12u1",
                        "libkrb5.so.3\tlibkrb5-3\t1.20.1-2+deb12u5"]
    assert sorted(datas) == [
        (str(root / "usr/share/doc/gcc-12-base/copyright"), "licenses/system/libatomic1"),
        (str(root / "usr/share/doc/libkrb5-3/copyright"), "licenses/system/libkrb5-3")]


def test_happy_licence_datas_asks_rpm_in_the_container_and_files_json_in_a_sysroot(
        tmp_path, monkeypatch):
    """The container build (no AXROSS_TARGET_ROOT) is as it was: rpm answers,
    for libraries of /usr/lib64 and friends. A sysroot build asks FILES.json
    and records the package format in SYSTEM.txt."""
    licence = tmp_path / "rpmdb" / "LICENSE"
    licence.parent.mkdir()
    licence.write_text("MIT\n")
    asked = []

    def rpm(args, **_kw):
        asked.append(args[1:])
        out = {"-qf": "krb5-libs\n", "-q": "1.21.1-10.el9_8\n", "-qL": f"{licence}\n"}
        return type("R", (), {"returncode": 0, "stdout": out.get(args[1], "")})()
    monkeypatch.setattr(BL.subprocess, "run", rpm)
    monkeypatch.delenv("AXROSS_TARGET_ROOT", raising=False)
    analysis = type("A", (), {"pure": [], "datas": [], "binaries": [
        ("libkrb5.so.3", "/usr/lib64/libkrb5.so.3", "BINARY")]})()
    toc = BL.licence_datas(analysis, str(tmp_path / "work-container"))
    assert ("licenses/system/krb5-libs/LICENSE", str(licence), "DATA") in toc
    assert (tmp_path / "work-container/LIBRARIES.txt").read_text() == \
        "libkrb5.so.3\tkrb5-libs\t1.21.1-10.el9_8\n"
    assert not any(dest == "licenses/system/SYSTEM.txt" for dest, *_ in toc)
    assert asked[0][0] == "-qf"

    root = _sysroot(tmp_path, "almalinux9", ALMA, ALMA_PACKAGES)
    monkeypatch.setenv("AXROSS_TARGET_ROOT", str(root))
    monkeypatch.setattr(BL.subprocess, "run", _no_rpm)
    analysis.binaries = _libs(root, "libkrb5.so.3") + [
        ("libpython3.12.so.1.0", str(tmp_path / "python/lib/libpython3.12.so.1.0"), "BINARY")]
    toc = BL.licence_datas(analysis, str(tmp_path / "work-sysroot"))
    assert ("licenses/system/krb5-libs/LICENSE",
            str(root / "usr/share/licenses/krb5-libs/LICENSE"), "DATA") in toc
    # libpython is the build's own (python-build-standalone), not the target's
    assert (tmp_path / "work-sysroot/LIBRARIES.txt").read_text() == \
        "libkrb5.so.3\tkrb5-libs\t1.21.1-10.el9_8\n"
    assert (tmp_path / "work-sysroot/SYSTEM.txt").read_text() == "rpm\talmalinux9\n"


# --- sad -------------------------------------------------------------------


def test_sad_a_root_library_no_package_wrote_stays_a_dash(tmp_path):
    root = _sysroot(tmp_path, "almalinux9", ALMA, ALMA_PACKAGES)
    (root / "usr/lib64/libstray.so.1").write_text("made later\n")
    datas, manifest = BL.system_licence_datas(_libs(root, "libstray.so.1"),
                                              target=BL.TargetPackages.load(root))
    assert manifest == ["libstray.so.1\t-\t-"] and datas == []


def test_sad_a_sysroot_without_files_json_stops_the_build(tmp_path, monkeypatch):
    root = tmp_path / "old-sysroot" / "root"
    root.mkdir(parents=True)
    monkeypatch.setenv("AXROSS_TARGET_ROOT", str(root))
    with pytest.raises(SystemExit, match="FILES.json"):
        BL.TargetPackages.from_environment()
    monkeypatch.delenv("AXROSS_TARGET_ROOT")
    assert BL.TargetPackages.from_environment() is None


def test_sad_a_package_without_any_licence_text_brings_none(tmp_path):
    root = _sysroot(tmp_path, "almalinux9", {
        "usr/lib64/libz.so.1.2.11": "zlib",
        "usr/lib64/libz.so.1": ("zlib", "libz.so.1.2.11"),
        "usr/share/doc/zlib/README": "zlib"}, ALMA_PACKAGES)
    datas, manifest = BL.system_licence_datas(_libs(root, "libz.so.1"),
                                              target=BL.TargetPackages.load(root))
    assert manifest == ["libz.so.1\tzlib\t1.2.11-41.el9"] and datas == []


# --- edge ------------------------------------------------------------------


def test_edge_symlinks_resolve_as_in_a_chroot_of_the_root(tmp_path):
    root = _sysroot(tmp_path, "almalinux9", {
        "lib64": ("filesystem", "usr/lib64"),
        "usr/lib64/libgcc_s-11-20240719.so.1": "libgcc",
        # absolute: counts from the root, never from this machine's /usr/lib64
        "usr/lib64/libgcc_s.so.1": ("libgcc", "/usr/lib64/libgcc_s-11-20240719.so.1"),
        "usr/lib64/libup.so.1": ("evil", "../../../../etc/passwd"),
        "usr/lib64/libloop.so.1": ("evil", "libloop.so.1"),
    }, {"libgcc": ("11.5.0-5.el9", "gcc"), "filesystem": ("3.16-5.el9", "filesystem"),
        "evil": ("1-1", "evil")})
    target = BL.TargetPackages.load(root)
    final, links = target.relative(str(root / "lib64/libgcc_s.so.1"))
    assert final == "usr/lib64/libgcc_s-11-20240719.so.1"
    assert links == ["usr/lib64/libgcc_s.so.1"]
    assert target.package(_libs(root, "libgcc_s.so.1", folder="lib64")[0][1]) == "libgcc"
    assert target.relative(str(root / "usr/lib64/libup.so.1")) is None
    assert target.relative(str(root / "usr/lib64/libloop.so.1")) is None
    assert target.relative("/usr/lib64/libgcc_s.so.1") is None


def test_edge_a_link_a_package_owns_names_it_when_the_file_is_nobody_s(tmp_path):
    root = _sysroot(tmp_path, "almalinux9", {
        "usr/lib64/libalt.so.1": ("libalt", "libalt.so.1.0"),
        "usr/lib64/libalt.so.1.0": "",  # written later by a script, not by a package
    }, {"libalt": ("1-1", "libalt")})
    manifest = json.loads((root.parent / "FILES.json").read_text())
    del manifest["files"]["usr/lib64/libalt.so.1.0"]
    target = BL.TargetPackages(root, manifest)
    assert target.package(str(root / "usr/lib64/libalt.so.1")) == "libalt"


def test_edge_two_sibling_copyright_files_stay_apart(tmp_path):
    root = _sysroot(tmp_path, "debian12", {
        "usr/lib/x86_64-linux-gnu/libxcb-shm.so.0": "libxcb-shm0",
        "usr/share/doc/libxcb1/copyright": "libxcb1",
        "usr/share/doc/libxcb-render0/copyright": "libxcb-render0",
    }, {"libxcb-shm0": ("1.15-1", "libxcb"), "libxcb1": ("1.15-1", "libxcb"),
        "libxcb-render0": ("1.15-1", "libxcb")})
    datas, _ = BL.system_licence_datas(
        _libs(root, "libxcb-shm.so.0", folder="usr/lib/x86_64-linux-gnu"),
        target=BL.TargetPackages.load(root))
    assert datas == [
        (str(root / "usr/share/doc/libxcb-render0/copyright"), "licenses/system/libxcb-shm0"),
        (str(root / "usr/share/doc/libxcb1/copyright"),
         "licenses/system/libxcb-shm0/libxcb1")]


# --- the building interpreter's libpython ------------------------------------
# build_dist.sh builds with uv's CPython (python-build-standalone): its
# libpython is no package's, in no sysroot. The container build shipped the
# python3.12-libs rpm's licence; this one ships CPython's LICENSE.txt.


def _uv_python(tmp_path: Path, *, full: bool = False) -> tuple[BL.BuildPython, Path]:
    """uv's layout: cpython-3.12.8-linux-x86_64-gnu/ and the link
    cpython-3.12-linux-x86_64-gnu -> it (the venv's base prefix). *full*: a
    full python-build-standalone archive (python/install/ next to
    python/PYTHON.json and python/licenses/)."""
    base = tmp_path / ("python" if full else "uv")
    real = base / ("install" if full else "cpython-3.12.8-linux-x86_64-gnu")
    (real / "lib/python3.12").mkdir(parents=True)
    (real / "lib/libpython3.12.so.1.0").write_bytes(b"\x7fELF")
    (real / "lib/libpython3.so").write_bytes(b"\x7fELF")
    (real / "lib/python3.12/LICENSE.txt").write_text("PSF LICENSE AGREEMENT\n")
    prefix = real
    if full:
        (base / "PYTHON.json").write_text('{"licenses": ["Python-2.0"]}\n')
        (base / "licenses").mkdir()
        (base / "licenses/LICENSE.openssl-3.txt").write_text("Apache-2.0\n")
    else:
        prefix = base / "cpython-3.12-linux-x86_64-gnu"
        os.symlink(real.name, prefix)
    return BL.BuildPython(str(prefix), str(prefix / "lib/python3.12"), "3.12.8"), real


def test_happy_the_build_python_s_libpython_brings_cpython_s_licence(tmp_path):
    python, real = _uv_python(tmp_path)
    root = _sysroot(tmp_path, "almalinux9", ALMA, ALMA_PACKAGES)
    binaries = _libs(root, "libkrb5.so.3") + [
        ("libpython3.12.so.1.0", str(real / "lib/libpython3.12.so.1.0"), "BINARY"),
        ("libpython3.so", str(real / "lib/libpython3.so"), "BINARY")]
    datas, manifest = BL.system_licence_datas(binaries, target=BL.TargetPackages.load(root),
                                              python=python)
    assert manifest == ["libkrb5.so.3\tkrb5-libs\t1.21.1-10.el9_8",
                        "libpython3.12.so.1.0\tpython\t3.12.8", "libpython3.so\tpython\t3.12.8"]
    assert (str(Path(python.stdlib) / "LICENSE.txt"), "licenses/system/python") in datas
    assert len([d for d in datas if d[1].startswith("licenses/system/python")]) == 1


def test_happy_a_full_standalone_archive_brings_its_component_notices(tmp_path):
    python, real = _uv_python(tmp_path, full=True)
    datas, manifest = BL.system_licence_datas(
        [("libpython3.12.so.1.0", str(real / "lib/libpython3.12.so.1.0"), "BINARY")],
        query=lambda path: pytest.fail("not a system library"), python=python)
    base = tmp_path / "python"
    assert manifest == ["libpython3.12.so.1.0\tpython\t3.12.8"]
    assert datas == [(str(real / "lib/python3.12/LICENSE.txt"), "licenses/system/python"),
                     (str(base / "PYTHON.json"), "licenses/system/python"),
                     (str(base / "licenses/LICENSE.openssl-3.txt"),
                      "licenses/system/python/licenses")]


def test_sad_a_libpython_rpm_owns_stays_the_rpm_s(tmp_path):
    """The container build: /usr/lib64/libpython3.12.so.1.0 is python3.12-libs'."""
    python = BL.BuildPython("/usr", "/usr/lib64/python3.12", "3.12.15")
    datas, manifest = BL.system_licence_datas(
        [("libpython3.12.so.1.0", "/usr/lib64/libpython3.12.so.1.0", "BINARY")],
        query=lambda path: "python3.12-libs", licence_files=lambda pkg: ["/l/LICENSE.txt"],
        version=lambda pkg: "3.12.15-1.el9_8", python=python)
    assert manifest == ["libpython3.12.so.1.0\tpython3.12-libs\t3.12.15-1.el9_8"]
    assert datas == [("/l/LICENSE.txt", "licenses/system/python3.12-libs")]


def test_sad_another_python_s_libpython_is_not_the_build_s(tmp_path):
    python, _real = _uv_python(tmp_path)
    other = tmp_path / "elsewhere/libpython3.12.so.1.0"
    other.parent.mkdir()
    other.write_bytes(b"\x7fELF")
    datas, manifest = BL.system_licence_datas(
        [("libpython3.12.so.1.0", str(other), "BINARY")], python=python,
        query=lambda path: pytest.fail("not a system library"))
    assert datas == [] and manifest == []


def test_edge_an_unowned_libpython_under_the_build_prefix_in_a_container(tmp_path):
    """No package owns it (rpm says so): the building interpreter's own."""
    python, real = _uv_python(tmp_path)
    datas, manifest = BL.system_licence_datas(
        [("libpython3.12.so.1.0", str(real / "lib/libpython3.12.so.1.0"), "BINARY"),
         ("python3.12/lib-dynload/libpython-helper.so", str(real / "lib/libpython3.so"),
          "BINARY")],
        query=lambda path: None, licence_files=lambda pkg: [], python=python)
    assert manifest == ["libpython3.12.so.1.0\tpython\t3.12.8"]
    assert [folder for _, folder in datas] == ["licenses/system/python"]


def _notices(tmp_path: Path, version: str = "3.12.8") -> Path:
    """What scripts/python_licences.py writes (AXROSS_PYTHON_LICENSES)."""
    out = tmp_path / "python-licences"
    (out / "licenses").mkdir(parents=True)
    (out / "PYTHON.json").write_text(json.dumps({"python_version": version}))
    (out / "licenses/LICENSE.openssl-3.txt").write_text("Apache-2.0\n")
    (out / "licenses/LICENSE.sqlite.txt").write_text("public domain\n")
    return out


def test_happy_the_standalone_archive_s_licences_come_with_libpython(tmp_path, monkeypatch):
    uv, real = _uv_python(tmp_path)
    notices = _notices(tmp_path)
    monkeypatch.setenv("AXROSS_PYTHON_LICENSES", str(notices))
    python = BL.BuildPython.current()
    python.prefix, python.stdlib, python.version = uv.prefix, uv.stdlib, "3.12.8"
    datas, manifest = BL.system_licence_datas(
        [("libpython3.12.so.1.0", str(real / "lib/libpython3.12.so.1.0"), "BINARY")],
        query=lambda path: None, python=python)
    assert manifest == ["libpython3.12.so.1.0\tpython\t3.12.8"]
    assert datas == [
        (str(Path(uv.stdlib) / "LICENSE.txt"), "licenses/system/python"),
        (str(notices / "PYTHON.json"), "licenses/system/python"),
        (str(notices / "licenses/LICENSE.openssl-3.txt"), "licenses/system/python/licenses"),
        (str(notices / "licenses/LICENSE.sqlite.txt"), "licenses/system/python/licenses")]


def test_sad_licences_of_another_cpython_or_none_stop_the_build(tmp_path):
    uv, real = _uv_python(tmp_path)
    other = BL.BuildPython(uv.prefix, uv.stdlib, "3.12.8", str(_notices(tmp_path, "3.12.7")))
    with pytest.raises(SystemExit, match="3.12.7"):
        other.licence_files()
    empty = BL.BuildPython(uv.prefix, uv.stdlib, "3.12.8", str(tmp_path / "nothing"))
    with pytest.raises(SystemExit, match="PYTHON.json"):
        empty.licence_files()


# --- a library a wheel ships at the bundle's top level ------------------------


class _Path(PurePosixPath):
    base = Path("/nonexistent")

    def locate(self):
        return self.base / str(self)


class _Dist:
    def __init__(self, site: Path, name: str, version: str, files: list[str]):
        self.metadata = {"Name": name}
        self.version = version
        cls = type("P", (_Path,), {"base": site})
        self.files = [cls(f) for f in files]


def test_happy_a_wheel_s_top_level_library_names_the_wheel(tmp_path):
    site = tmp_path / "site-packages"
    (site / "libusb_package").mkdir(parents=True)
    (site / "libusb_package/libusb-1.0.so").write_bytes(b"\x7fELF")
    owner = BL.wheel_library_owner([_Dist(site, "libusb_package", "1.0.26.4",
                                          ["libusb_package/libusb-1.0.so",
                                           "libusb_package/__init__.py"])])
    datas, manifest = BL.system_licence_datas(
        [("libusb-1.0.so", str(site / "libusb_package/libusb-1.0.so"), "BINARY")],
        query=lambda path: pytest.fail("not a system library"), wheels=owner)
    assert manifest == ["libusb-1.0.so\twheel:libusb-package\t1.0.26.4"]
    # the wheel has only its own Apache-2.0 text: libusb's LGPL comes along
    assert datas == [
        (str(ROOT / "build/licenses/libusb/COPYING"),
         "licenses/python/libusb-package-1.0.26.4/libusb"),
        (str(ROOT / "build/licenses/libusb/AUTHORS"),
         "licenses/python/libusb-package-1.0.26.4/libusb")]
    assert "GNU LESSER GENERAL PUBLIC LICENSE" in (ROOT / "build/licenses/libusb/COPYING").read_text()


def test_happy_any_wheel_s_top_level_library_is_listed_as_its(tmp_path):
    site = tmp_path / "site"
    (site / "pkg.libs").mkdir(parents=True)
    (site / "pkg.libs/libthing.so.2").write_bytes(b"\x7fELF")
    os.symlink(site / "pkg.libs/libthing.so.2", tmp_path / "libthing.so.2")
    owner = BL.wheel_library_owner([_Dist(site, "Some.Wheel", "2.0", ["pkg.libs/libthing.so.2"])])
    datas, manifest = BL.system_licence_datas(
        [("libthing.so.2", str(tmp_path / "libthing.so.2"), "BINARY")],
        query=lambda path: None, wheels=owner)
    assert manifest == ["libthing.so.2\twheel:some-wheel\t2.0"] and datas == []


def test_sad_a_top_level_library_of_no_wheel_and_no_system_stays_out(tmp_path):
    stray = tmp_path / "stray/libstray.so.1"
    stray.parent.mkdir()
    stray.write_bytes(b"\x7fELF")
    datas, manifest = BL.system_licence_datas(
        [("libstray.so.1", str(stray), "BINARY")], query=lambda path: None,
        wheels=BL.wheel_library_owner([]))
    assert datas == [] and manifest == []


def test_edge_a_wheel_whose_extra_licence_is_missing_stops_the_build(tmp_path, monkeypatch):
    monkeypatch.setattr(BL, "PROJECT_ROOT", tmp_path)
    with pytest.raises(SystemExit, match="build/licenses/libusb/COPYING"):
        BL.wheel_library_notices("libusb-package", "1.0.26.4")
    assert BL.wheel_library_notices("other-wheel", "1") == []
