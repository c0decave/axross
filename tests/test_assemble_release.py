"""scripts/assemble_release.py: the release assets, put together and checked
through core.self_update and core.packs (docs/PACKAGING.md, "Release flow").

The inputs are small fake files laid out the way scripts/build_dist.sh and
the bundle job of .github/workflows/cross-platform.yml write them; every key
is generated here, the real release key is never read.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent

import sys  # noqa: E402

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import assemble_release as AR  # noqa: E402
import sign_release  # noqa: E402

from core import self_update as SU  # noqa: E402
from tests.fake_github import FakeGitHub, FakeHttpsHandler, FakeRelease, newer_than  # noqa: E402
from tests.fake_github import public_key_b64  # noqa: E402

VERSION = "9.9.9"
CONTRACT = {  # docs/PACKAGING.md, "Asset names"
    "axross-full", "axross-slim", "axross-base",
    "axross-full-glibc2.36", "axross-slim-glibc2.36", "axross-base-glibc2.36",
    "axross-slim-macos-arm64", "axross-slim-windows-x64.exe",
}


# -- fake inputs ---------------------------------------------------------------------


def elf(tag: str) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"\x02\x00\x3e\x00" + tag.encode() * 40


def macho(tag: str) -> bytes:
    return b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + tag.encode() * 40


def pe(tag: str) -> bytes:
    return b"MZ\x90\x00" + tag.encode() * 40


def sums_of(folder: Path, names) -> None:
    (folder / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256((folder / n).read_bytes()).hexdigest()}  {n}\n" for n in names))


def make_dist(root: Path, version: str = VERSION, *, variants=SU.VARIANTS, python=True,
              packs=True, blobs=2, pypi=True) -> Path:
    """dist/<version>/ as scripts/build_dist.sh writes it."""
    dist = root / "dist" / version
    dist.mkdir(parents=True)
    for variant in variants:
        folder = dist / variant
        folder.mkdir()
        names = []
        for name in [f"axross-{f}" for f in SU.FLAVORS] + [f"axross-{t}" for t in AR.TOOLS]:
            (folder / name).write_bytes(elf(name + variant))
            names.append(name)
        (folder / f"BUILD-PACKAGES-{variant}.txt").write_text("glibc 2.x\n")
        sums_of(folder, names)
    if python:
        wheel, sdist = f"axross-{version}-py3-none-any.whl", f"axross-{version}.tar.gz"
        (dist / wheel).write_bytes(b"PK\x03\x04 wheel")
        (dist / sdist).write_bytes(b"\x1f\x8b sdist")
        sums_of(dist, [wheel, sdist])
        (dist / "BUILD-INFO.md").write_text("# build\n")
        standalone = dist / "standalone"
        standalone.mkdir()
        tool = f"axross_media_player-{version}-py3-none-any.whl"
        (standalone / tool).write_bytes(b"PK\x03\x04 tool")
        sums_of(standalone, [tool])
    if packs:
        make_packs(dist / "packs", version, blobs=blobs, pypi=pypi)
    return dist


def make_packs(folder: Path, version: str = VERSION, *, blobs=2, pypi=True) -> Path:
    folder.mkdir(parents=True)
    entries = {}
    for i in range(blobs):
        name = f"dep{i}-1.0-py3-none-any.whl"
        data = f"wheel {i}".encode() * 10
        (folder / name).write_bytes(data)
        entries[name] = {"distribution": f"dep{i}", "sha256": hashlib.sha256(data).hexdigest(),
                         "size": len(data),
                         "pypi": f"https://files.pythonhosted.org/packages/{name}" if pypi else ""}
    manifest = {"format": 1, "version": version, "platform": "linux-x86_64",
                "units": {"cloud": {"kind": "extra", "title": "Cloud", "needs": [],
                                    "blobs": sorted(entries)}},
                "blobs": entries}
    name = f"packs-{version}.json"
    (folder / name).write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    sums_of(folder, [name, *sorted(entries)])
    return folder


def make_ci(root: Path, *, zipped=False, flavors=("slim", "full")) -> Path:
    """The bundle job's artifacts, as gh run download (folders) or the web
    page (.zip) hands them out."""
    ci = root / "ci"
    ci.mkdir()
    for runner_os, arch, ext, make in (("macOS", "ARM64", "", macho), ("Windows", "X64", ".exe", pe)):
        for flavor in flavors:
            artifact = f"axross-{flavor}-{runner_os}-{arch}"
            binary = f"axross-{flavor}{ext}"
            data = make(artifact)
            check = f"{hashlib.sha256(data).hexdigest()}  {binary}\n"
            if zipped:
                with zipfile.ZipFile(ci / f"{artifact}.zip", "w") as zf:
                    zf.writestr(binary, data)
                    zf.writestr(binary + ".sha256", check)
            else:
                (ci / artifact).mkdir()
                (ci / artifact / binary).write_bytes(data)
                (ci / artifact / (binary + ".sha256")).write_text(check)
    return ci


def write_key(path: Path, key: Ed25519PrivateKey) -> Path:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    return path


@pytest.fixture
def field_key(tmp_path, monkeypatch):
    """A throwaway key, pinned and in the field (as the old key is today)."""
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(SU, "TRUSTED_KEYS", (public_key_b64(key),))
    monkeypatch.setattr(sign_release, "FIELD_KEYS", (public_key_b64(key),))
    return key, write_key(tmp_path / "release.pem", key)


def run(*args) -> int:
    return AR.main([str(a) for a in args])


def assets_of(out: Path) -> set[str]:
    return {p.name for p in (out / "assets").iterdir()}


# -- happy ---------------------------------------------------------------------------


def test_happy_everything_assembled_signed_and_checked(tmp_path, field_key, capsys):
    key, key_file = field_key
    dist, ci, out = make_dist(tmp_path), make_ci(tmp_path), tmp_path / "rel"
    assert run("--version", VERSION, "--dist", dist, "--ci", ci, "--out", out, "--key", key_file,
               "--require-all") == 0
    names = assets_of(out)
    assert CONTRACT <= names
    assert {"axross-full-macos-arm64", "axross-full-windows-x64.exe",  # download only
            "axross-media-player", "axross-system-info-glibc2.36",
            f"axross-{VERSION}-py3-none-any.whl", f"axross-{VERSION}.tar.gz",
            f"axross_media_player-{VERSION}-py3-none-any.whl",
            f"packs-{VERSION}.json", "dep0-1.0-py3-none-any.whl", "SHA256SUMS",
            "SHA256SUMS.sig"} <= names
    # the per-folder sums and the CI .sha256 are gone; nothing else came along
    assert not any(n.endswith(".sha256") or n.startswith("BUILD-") for n in names)
    data = (out / "assets" / "SHA256SUMS").read_bytes()
    assert data.startswith(f"# axross-release {VERSION}\n".encode())
    sums = SU.parse_sums(data.decode())
    assert set(sums) == names - {"SHA256SUMS", "SHA256SUMS.sig"}
    for name, digest in sums.items():
        assert hashlib.sha256((out / "assets" / name).read_bytes()).hexdigest() == digest
    SU.verify_signature(data, (out / "assets" / "SHA256SUMS.sig").read_bytes(),
                        keys=sign_release.FIELD_KEYS)
    for name in CONTRACT:
        assert (out / "assets" / name).stat().st_mode & 0o777 == 0o755
    assert (out / "assets" / f"packs-{VERSION}.json").stat().st_mode & 0o777 == 0o644
    report = capsys.readouterr().out
    assert "XX" not in report and "--  " not in report
    assert "axross-base glibc-2.36" in report and "no variant file: before 0.15.166" in report


def test_happy_the_upload_lists_put_the_updaters_assets_first(tmp_path, field_key):
    _key, key_file = field_key
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--ci", make_ci(tmp_path),
               "--out", out, "--key", key_file) == 0
    first = (out / "upload-1.txt").read_text().split()
    then = (out / "upload-2.txt").read_text().split()
    assert first[:2] == ["assets/SHA256SUMS", "assets/SHA256SUMS.sig"]
    assert f"assets/packs-{VERSION}.json" in first
    assert then == ["assets/dep0-1.0-py3-none-any.whl", "assets/dep1-1.0-py3-none-any.whl"]
    assert {Path(p).name for p in first + then} == assets_of(out)


def test_happy_e2e_an_installed_old_binary_updates_from_the_assembled_release(
        tmp_path, field_key, monkeypatch):
    """The assembled folder, served as the release, is what a binary of
    0.14.136 (no variant file, the field key only) takes."""
    from axross._version import __version__

    _key, key_file = field_key
    version = newer_than(__version__)
    dist = make_dist(tmp_path, version, packs=False)
    out = tmp_path / "rel"
    assert run("--version", version, "--dist", dist, "--out", out, "--key", key_file) == 0

    class Assembled(FakeRelease):
        def all_files(self):
            return dict(self.files)  # SHA256SUMS and its signature are among them

    release = Assembled(version, {p.name: p.read_bytes() for p in (out / "assets").iterdir()})
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    exe = tmp_path / "bin" / "axross-full"
    exe.parent.mkdir()
    exe.write_bytes(b"old")
    exe.chmod(0o755)
    inst = SU.detect_install(frozen=True, executable=str(exe), bundle_dir=None,
                             platform="linux", machine="x86_64")
    with FakeGitHub(release) as server:
        opener = SU.build_opener(handlers=[FakeHttpsHandler(server.port)])
        found = SU.check(opener=opener).release
        assert SU.update(found, inst, opener=opener).replaced
    assert exe.read_bytes() == (dist / "glibc-2.34" / "axross-full").read_bytes()


def test_happy_zipped_ci_artifacts_work_as_well(tmp_path, field_key):
    _key, key_file = field_key
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--ci",
               make_ci(tmp_path, zipped=True), "--out", out, "--key", key_file,
               "--require-all") == 0
    assert {"axross-slim-macos-arm64", "axross-slim-windows-x64.exe"} <= assets_of(out)


def test_happy_check_mode_rechecks_an_assembled_folder(tmp_path, field_key, capsys):
    _key, key_file = field_key
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--ci", make_ci(tmp_path),
               "--out", out, "--key", key_file) == 0
    assert run("--version", VERSION, "--check", out, "--require-all") == 0
    (out / "assets" / "axross-slim").write_bytes(elf("tampered"))
    capsys.readouterr()
    assert run("--version", VERSION, "--check", out) == 1
    assert "axross-slim: its SHA256SUMS line does not match" in capsys.readouterr().out


# -- partial inputs ------------------------------------------------------------------


def test_edge_only_linux_says_what_is_missing(tmp_path, capsys):
    out = tmp_path / "rel"
    dist = make_dist(tmp_path, variants=("glibc-2.34",), python=False, packs=False)
    assert run("--version", VERSION, "--dist", dist, "--out", out) == 0
    report = capsys.readouterr().out
    assert assets_of(out) == {"axross-full", "axross-slim", "axross-base", "axross-media-player",
                              "axross-system-info", "SHA256SUMS"}
    for missing in ("glibc-2.36/", "the macOS and Windows binaries", f"packs-{VERSION}.json",
                    f"axross-{VERSION}-py3-none-any.whl", "not signed",
                    "darwin arm64 axross-slim: no axross-slim-macos-arm64",
                    "axross-full glibc-2.36: no axross-full-glibc2.36"):
        assert missing in report, missing


def test_sad_require_all_refuses_partial_inputs_before_writing(tmp_path, capsys):
    out = tmp_path / "rel"
    dist = make_dist(tmp_path, packs=False)
    assert run("--version", VERSION, "--dist", dist, "--out", out, "--require-all") == 1
    err = capsys.readouterr().err
    assert "--require-all: missing" in err and "packs" in err and "macOS and Windows" in err
    assert not out.exists()


def test_edge_no_packs_is_fine_without_require_all(tmp_path, field_key):
    _key, key_file = field_key
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path, packs=False), "--ci",
               make_ci(tmp_path), "--out", out, "--key", key_file) == 0
    assert not any(n.startswith("packs-") for n in assets_of(out))
    assert (out / "upload-2.txt").read_text() == ""


# -- refusals ------------------------------------------------------------------------


def test_sad_a_broken_ci_download_is_refused(tmp_path):
    ci = make_ci(tmp_path)
    (ci / "axross-slim-Windows-X64" / "axross-slim.exe").write_bytes(pe("cut"))
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--ci", ci, "--out", out) == 1
    assert not (out / "assets").exists()


def test_sad_a_binary_that_differs_from_its_folders_sums_is_refused(tmp_path, capsys):
    dist = make_dist(tmp_path)
    (dist / "glibc-2.36" / "axross-base").write_bytes(elf("other"))
    assert run("--version", VERSION, "--dist", dist, "--out", tmp_path / "rel") == 1
    assert "glibc-2.36/axross-base differs from the checksum" in capsys.readouterr().err


def test_sad_a_swapped_artifact_is_refused(tmp_path, capsys):
    ci = make_ci(tmp_path)
    folder = ci / "axross-slim-macOS-ARM64"
    data = pe("windows")
    (folder / "axross-slim").write_bytes(data)
    (folder / "axross-slim.sha256").write_text(f"{hashlib.sha256(data).hexdigest()}  axross-slim\n")
    assert run("--version", VERSION, "--ci", ci, "--out", tmp_path / "rel") == 1
    assert "not an arm64 Mach-O executable" in capsys.readouterr().err


def test_sad_a_pack_wheel_other_than_the_manifest_is_refused(tmp_path, capsys):
    dist = make_dist(tmp_path)
    (dist / "packs" / "dep1-1.0-py3-none-any.whl").write_bytes(b"swapped")
    (dist / "packs" / "SHA256SUMS").unlink()
    assert run("--version", VERSION, "--dist", dist, "--out", tmp_path / "rel") == 1
    assert "dep1-1.0-py3-none-any.whl" in capsys.readouterr().err


def test_sad_a_manifest_of_another_version_is_refused(tmp_path, capsys):
    dist = make_dist(tmp_path, packs=False)
    make_packs(dist / "packs", "9.9.8")
    (dist / "packs" / f"packs-{VERSION}.json").write_text(
        (dist / "packs" / "packs-9.9.8.json").read_text())
    assert run("--version", VERSION, "--dist", dist, "--out", tmp_path / "rel") == 1
    assert "is for version 9.9.8" in capsys.readouterr().err


def test_sad_a_non_empty_out_folder_is_refused(tmp_path):
    out = tmp_path / "rel"
    out.mkdir()
    (out / "old-asset").write_text("x")
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--out", out) == 1
    assert {p.name for p in out.iterdir()} == {"old-asset"}


def test_sad_the_new_key_is_refused_and_with_the_override_flagged(tmp_path, monkeypatch, capsys):
    """The second key is pinned in this tree, but no binary in the field pins
    it: signing with it needs --allow-new-key, and the check then says the
    installed binaries refuse the release."""
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    monkeypatch.setattr(SU, "TRUSTED_KEYS", (public_key_b64(old), public_key_b64(new)))
    monkeypatch.setattr(sign_release, "FIELD_KEYS", (public_key_b64(old),))
    key_file = write_key(tmp_path / "new.pem", new)
    dist = make_dist(tmp_path)
    assert run("--version", VERSION, "--dist", dist, "--out", tmp_path / "a", "--key",
               key_file) == 1
    assert "FIELD_KEYS" in capsys.readouterr().err
    assert not (tmp_path / "a" / "assets").exists()
    assert run("--version", VERSION, "--dist", dist, "--out", tmp_path / "b", "--key", key_file,
               "--allow-new-key") == 0
    captured = capsys.readouterr()
    assert "WARNING" in captured.err and "0.14.136 and older refuse" in captured.out
    data = (tmp_path / "b" / "assets" / "SHA256SUMS").read_bytes()
    with pytest.raises(SU.SignatureError):
        SU.verify_signature(data, (tmp_path / "b" / "assets" / "SHA256SUMS.sig").read_bytes(),
                            keys=sign_release.FIELD_KEYS)


def test_sad_an_unpinned_key_is_refused(tmp_path, capsys):
    key_file = write_key(tmp_path / "k.pem", Ed25519PrivateKey.generate())
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--out", tmp_path / "rel",
               "--key", key_file) == 1
    assert "not pinned" in capsys.readouterr().err


def test_happy_a_dry_run_with_a_throwaway_key(tmp_path, capsys):
    key_file = write_key(tmp_path / "k.pem", Ed25519PrivateKey.generate())
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--ci", make_ci(tmp_path),
               "--out", out, "--key", key_file, "--allow-unpinned") == 0
    report = capsys.readouterr().out
    assert "the signing key alone" in report and "XX" not in report


def test_sad_pack_wheels_past_the_first_100_assets_need_a_pypi_address(tmp_path, capsys):
    """The updater reads the first 100 assets the API lists
    (core.self_update.parse_release); a wheel past them can only come from
    PyPI."""
    dist = make_dist(tmp_path, blobs=AR.API_ASSETS, pypi=False)
    assert run("--version", VERSION, "--dist", dist, "--out", tmp_path / "a") == 1
    assert "has no PyPI address" in capsys.readouterr().out
    assert not (tmp_path / "a" / "upload-1.txt").exists()  # nothing to upload from
    dist2 = make_dist(tmp_path / "2", blobs=AR.API_ASSETS)
    assert run("--version", VERSION, "--dist", dist2, "--out", tmp_path / "b") == 0
    assert "a base fetches it from PyPI" in capsys.readouterr().out


def test_edge_asset_names_are_the_updaters(tmp_path):
    """Every name assemble_release gives a binary the updater serves is
    asset_name's; the download-only ones follow the same pattern."""
    assert AR.ci_asset_name("slim", "macos-arm64") == SU.asset_name("darwin", "arm64", "slim")
    assert AR.ci_asset_name("slim", "windows-x64") == SU.asset_name("win32", "amd64", "slim")
    for variant in SU.VARIANTS:
        assert "axross-full" + AR.variant_suffix(variant) == SU.asset_name(
            "linux", "x86_64", "full", variant)


def test_edge_the_ci_artifact_names_match_the_workflow():
    workflow = (ROOT / ".github" / "workflows" / "cross-platform.yml").read_text()
    assert "name: axross-${{ matrix.flavor }}-${{ runner.os }}-${{ runner.arch }}" in workflow
    assert "os: [ macos-latest, windows-latest ]" in workflow
    assert "'.sha256'" in workflow


def test_happy_check_mode_reads_a_downloaded_draft(tmp_path, field_key):
    """As step 7 of the release flow: the assets as gh release download
    writes them (flat), with or without the upload lists next to them."""
    import shutil

    _key, key_file = field_key
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path, blobs=AR.API_ASSETS),
               "--ci", make_ci(tmp_path), "--out", out, "--key", key_file) == 0
    draft = tmp_path / "draft"
    shutil.copytree(out / "assets", draft)
    assert run("--version", VERSION, "--check", draft, "--require-all") == 0
    for name in ("upload-1.txt", "upload-2.txt"):
        shutil.copy(out / name, draft / name)
    assert run("--version", VERSION, "--check", draft, "--require-all") == 0
    (draft / "SHA256SUMS.sig").unlink()
    assert run("--version", VERSION, "--check", draft, "--require-all") == 1


def test_happy_the_release_flow_is_the_scripted_one():
    """docs/PACKAGING.md "Release flow": build_dist.sh, the tag's CI
    artifacts, assemble_release.py with the field key, a draft, TestPyPI
    before PyPI, and an installed 0.14.136 binary that updates."""
    text = (ROOT / "docs" / "PACKAGING.md").read_text(encoding="utf-8")
    flow = text[text.index("## Release flow"):text.index("## Self-update: what a release")]
    for needle in ("scripts/build_dist.sh", "gh run download", "scripts/assemble_release.py",
                   "--require-all", "FIELD_KEYS", "--draft", "upload-1.txt", "upload-2.txt",
                   "--repository testpypi", "twine upload", "0.14.136", "**CI**", "**builder**",
                   "**maintainer**"):
        assert needle in flow, needle
    assert "build_bundle.sh" not in flow and "three flavours" not in flow
    assert flow.index("--repository testpypi") < flow.index("--draft=false") \
        < flow.rindex("twine upload")
