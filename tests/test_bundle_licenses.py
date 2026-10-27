"""scripts/bundle_licenses.py: the licence texts build/axross.spec puts into a
one-file bundle - every bundled Python distribution's own licence files
under licenses/python/, and for each system library the builder image
contributes, the licence files of its rpm package under licenses/system/
(with licenses/system/LIBRARIES.txt naming which package a library is from).
"""

from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_licenses as BL  # noqa: E402

SPEC = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")


class FakeFile(PurePosixPath):
    """A PackagePath stand-in: locate() resolves below the fake site dir."""

    site: Path = Path("/nonexistent")

    def locate(self):  # noqa: D401 - mirrors importlib.metadata.PackagePath
        return (self.site / str(self)).resolve()


class FakeDist:
    def __init__(self, site: Path, name: str, version: str, files: list[str]):
        self.metadata = {"Name": name, "Version": version}
        self.version = version
        cls = type("F", (FakeFile,), {"site": site})
        self.files = [cls(f) for f in files]


def _touch(site: Path, rel: str, text: str = "licence text\n") -> None:
    path = site / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- happy -----------------------------------------------------------------


def test_happy_licence_files_of_a_distribution_land_under_its_own_folder(tmp_path):
    files = ["Demo_Pkg-1.2.dist-info/licenses/LICENSE",
             "Demo_Pkg-1.2.dist-info/licenses/vendor/zlib/LICENSE",
             "Demo_Pkg-1.2.dist-info/sboms/auditwheel.cdx.json",
             "Demo_Pkg-1.2.dist-info/METADATA",
             "demo_pkg/ThirdPartyNotices.txt",
             "demo_pkg/__init__.py"]
    for f in files:
        _touch(tmp_path, f)
    datas = BL.python_licence_datas([FakeDist(tmp_path, "Demo_Pkg", "1.2", files)])
    got = sorted((Path(src).relative_to(tmp_path).as_posix(), dest) for src, dest in datas)
    assert got == [
        ("Demo_Pkg-1.2.dist-info/licenses/LICENSE", "licenses/python/demo-pkg-1.2"),
        ("Demo_Pkg-1.2.dist-info/licenses/vendor/zlib/LICENSE",
         "licenses/python/demo-pkg-1.2/vendor/zlib"),
        ("Demo_Pkg-1.2.dist-info/sboms/auditwheel.cdx.json",
         "licenses/python/demo-pkg-1.2/sboms"),
        ("demo_pkg/ThirdPartyNotices.txt", "licenses/python/demo-pkg-1.2/demo_pkg"),
    ]


def test_happy_system_libraries_bring_their_rpm_licence_files(tmp_path):
    _touch(tmp_path, "openssl-libs/LICENSE.txt")
    lic = str(tmp_path / "openssl-libs" / "LICENSE.txt")
    binaries = [("libssl.so.3", "/usr/lib64/libssl.so.3", "BINARY"),
                ("PIL/_imaging.so", "/site/PIL/_imaging.so", "BINARY")]
    datas, manifest = BL.system_licence_datas(
        binaries, query=lambda path: "openssl-libs", licence_files=lambda pkg: [lic],
        version=lambda pkg: "3.5.8-2.el9_8")
    assert datas == [(lic, "licenses/system/openssl-libs")]
    assert manifest == ["libssl.so.3\topenssl-libs\t3.5.8-2.el9_8"]


def test_happy_rpm_version_is_version_and_release():
    calls = []

    def run(args):
        calls.append(args)
        return "3.5.8-2.el9_8\n"
    assert BL.rpm_version("openssl-libs", run=run) == "3.5.8-2.el9_8"
    assert calls == [["-q", "--qf", "%{VERSION}-%{RELEASE}\n", "openssl-libs"]]


def _fake_rpm(tmp_path, listed: dict[str, list[str]], sources: dict[str, str],
              docs: dict[str, list[str]] | None = None):
    def run(args):
        if args[0] in ("-qL", "-qd"):
            table = listed if args[0] == "-qL" else (docs or {})
            return "".join(f"{tmp_path / f}\n" for f in table.get(args[1], [])) or \
                "(contains no files)\n"
        if args[0] == "-q":
            return sources.get(args[-1], "")
        if args[0] == "-qa":
            return "".join(f"{n} {s}\n" for n, s in sources.items())
        return None
    return run


def test_happy_rpm_licence_files_are_the_ones_rpm_marks(tmp_path):
    _touch(tmp_path, "usr/lib64/python3.12/LICENSE.txt")
    run = _fake_rpm(tmp_path, {"python3.12-libs": ["usr/lib64/python3.12/LICENSE.txt"]}, {})
    assert BL.rpm_licence_files("python3.12-libs", run=run) == \
        [str(tmp_path / "usr/lib64/python3.12/LICENSE.txt")]


def test_happy_a_sub_package_without_licence_gets_its_siblings(tmp_path):
    _touch(tmp_path, "licenses/libgcc/COPYING.RUNTIME")
    run = _fake_rpm(tmp_path, {"libgcc": ["licenses/libgcc/COPYING.RUNTIME"]},
                    {"libatomic": "gcc-11.src.rpm", "libgcc": "gcc-11.src.rpm",
                     "zlib": "zlib-1.src.rpm"})
    assert BL.rpm_licence_files("libatomic", run=run) == \
        [str(tmp_path / "licenses/libgcc/COPYING.RUNTIME")]


def test_happy_the_spec_collects_the_licences_after_the_filters():
    assert "from bundle_licenses import" in SPEC
    after_filter = SPEC.index("dropped_data(entry[0])")
    assert SPEC.index("licence_datas(", after_filter) > after_filter
    assert "licenses/system/LIBRARIES.txt" in SPEC or "LIBRARIES.txt" in SPEC


def test_happy_distributions_are_found_for_the_bundled_top_level_names():
    mapping = {"PIL": ["pillow"], "yaml": ["PyYAML"], "_yaml": ["PyYAML"]}
    found = BL.distribution_names({"PIL", "_yaml", "yaml", "core", "json"}, mapping)
    assert found == ["PyYAML", "pillow"]


# --- sad -------------------------------------------------------------------


def test_sad_a_distribution_without_files_or_missing_files_gives_nothing(tmp_path):
    empty = FakeDist(tmp_path, "empty", "1", [])
    empty.files = None
    ghost = FakeDist(tmp_path, "ghost", "1", ["ghost-1.dist-info/licenses/LICENSE"])
    assert BL.python_licence_datas([empty, ghost]) == []


def test_sad_an_unowned_library_or_a_failing_rpm_is_listed_without_texts():
    binaries = [("libfoo.so.1", "/usr/lib64/libfoo.so.1", "BINARY")]
    datas, manifest = BL.system_licence_datas(binaries, query=lambda path: None,
                                              licence_files=lambda pkg: [],
                                              version=lambda pkg: "1-1")
    assert datas == [] and manifest == ["libfoo.so.1\t-\t-"]


def test_sad_a_package_whose_version_rpm_cannot_tell_is_listed_with_a_dash():
    binaries = [("libfoo.so.1", "/usr/lib64/libfoo.so.1", "BINARY")]
    _, manifest = BL.system_licence_datas(binaries, query=lambda path: "foo",
                                          licence_files=lambda pkg: [],
                                          version=lambda pkg: None)
    assert manifest == ["libfoo.so.1\tfoo\t-"]
    assert BL.rpm_version("foo", run=lambda args: None) is None
    assert BL.rpm_version("foo", run=lambda args: "package foo is not installed\n") is None


def test_happy_a_licence_kept_as_documentation_is_found(tmp_path):
    _touch(tmp_path, "doc/libXau/COPYING")
    _touch(tmp_path, "doc/libXau/README")
    run = _fake_rpm(tmp_path, {}, {"libXau": "libXau-1.src.rpm"},
                    docs={"libXau": ["doc/libXau/COPYING", "doc/libXau/README"]})
    assert BL.rpm_licence_files("libXau", run=run) == [str(tmp_path / "doc/libXau/COPYING")]


def test_sad_no_licence_anywhere_in_the_source_rpm_gives_nothing(tmp_path):
    run = _fake_rpm(tmp_path, {}, {"libxcb": "libxcb-1.13.src.rpm"})
    assert BL.rpm_licence_files("libxcb", run=run) == []
    assert BL.rpm_licence_files("unknown", run=lambda args: None) == []


def test_sad_rpm_query_without_rpm_returns_none(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert BL.rpm_package("/usr/lib64/libssl.so.3") is None


# --- edge ------------------------------------------------------------------


def test_edge_python_sources_and_bytecode_named_like_licences_are_skipped(tmp_path):
    files = ["x-1.dist-info/licenses/AUTHORS.py", "x-1.dist-info/licenses/__pycache__/a.pyc",
             "x/license.py", "x/LICENSE-MIT", "x/COPYING.LESSER.txt"]
    for f in files:
        _touch(tmp_path, f)
    datas = BL.python_licence_datas([FakeDist(tmp_path, "x", "1", files)])
    assert sorted(Path(s).name for s, _ in datas) == ["COPYING.LESSER.txt", "LICENSE-MIT"]


def test_edge_a_package_path_outside_the_site_dir_is_kept_flat(tmp_path):
    site = tmp_path / "lib" / "site"
    _touch(tmp_path, "share/doc/impacket/LICENSE")
    files = ["../../share/doc/impacket/LICENSE"]
    datas = BL.python_licence_datas([FakeDist(site, "impacket", "0.13.1", files)])
    assert datas == [(str(tmp_path / "share/doc/impacket/LICENSE"),
                      "licenses/python/impacket-0.13.1")]


def test_edge_libraries_in_subfolders_are_not_system_libraries():
    binaries = [("pillow.libs/libjpeg-1234abcd.so.62", "/usr/lib64/libjpeg.so.62", "BINARY"),
                ("PyQt6/Qt6/lib/libQt6Core.so.6", "/site/PyQt6/Qt6/lib/libQt6Core.so.6", "BINARY")]
    datas, manifest = BL.system_licence_datas(binaries, query=lambda path: "x",
                                              licence_files=lambda pkg: ["/x/LICENSE"])
    assert datas == [] and manifest == []


def test_edge_one_package_for_many_libraries_is_collected_once():
    binaries = [("libkrb5.so.3", "/usr/lib64/libkrb5.so.3", "BINARY"),
                ("libk5crypto.so.3", "/usr/lib64/libk5crypto.so.3", "BINARY")]
    asked = []
    datas, manifest = BL.system_licence_datas(binaries, query=lambda path: "krb5-libs",
                                              licence_files=lambda pkg: ["/l/krb5/LICENSE"],
                                              version=lambda pkg: asked.append(pkg) or "1.21")
    assert datas == [("/l/krb5/LICENSE", "licenses/system/krb5-libs")]
    assert manifest == ["libk5crypto.so.3\tkrb5-libs\t1.21", "libkrb5.so.3\tkrb5-libs\t1.21"]
    assert asked == ["krb5-libs"]


def test_edge_two_licence_files_with_one_name_stay_apart():
    binaries = [("libsystemd.so.0", "/usr/lib64/libsystemd.so.0", "BINARY")]
    datas, _ = BL.system_licence_datas(
        binaries, query=lambda path: "systemd-libs",
        licence_files=lambda pkg: ["/l/systemd/LICENSE", "/l/udev/LICENSE"])
    assert datas == [("/l/systemd/LICENSE", "licenses/system/systemd-libs"),
                     ("/l/udev/LICENSE", "licenses/system/systemd-libs/udev")]
