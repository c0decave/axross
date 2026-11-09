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
        (dist / "NATIVE-COMPONENTS.md").write_text(
            "<!-- native-components -->\n## Native components in the Linux binaries\n\n"
            "- libfake 1.0\n")
        standalone = dist / "standalone"
        standalone.mkdir()
        tool = f"axross_media_player-{version}-py3-none-any.whl"
        (standalone / tool).write_bytes(b"PK\x03\x04 tool")
        sums_of(standalone, [tool])
    if packs:
        make_packs(dist / "packs", version, blobs=blobs, pypi=pypi)
    return dist


def wheel_bytes(package: str) -> bytes:
    """A small wheel (a zip, the same bytes every time)."""
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(zipfile.ZipInfo(f"{package}/__init__.py", (2020, 1, 1, 0, 0, 0)),
                    f"NAME = {package!r}\n")
    return buf.getvalue()


def make_packs(folder: Path, version: str = VERSION, *, blobs=2, pypi=True) -> Path:
    """packs/ as scripts/build_packs.py writes it. *pypi*: every wheel has a
    PyPI address (True), none (False), or ``pypi(i)`` says (the address
    itself when it returns a string)."""
    folder.mkdir(parents=True)
    entries = {}
    for i in range(blobs):
        name = f"dep{i}-1.0-py3-none-any.whl"
        data = wheel_bytes(f"dep{i}")
        (folder / name).write_bytes(data)
        hosted = pypi(i) if callable(pypi) else pypi
        address = hosted if isinstance(hosted, str) else \
            f"https://files.pythonhosted.org/packages/ab/cd/{name}" if hosted else ""
        entries[name] = {"distribution": f"dep{i}", "sha256": hashlib.sha256(data).hexdigest(),
                         "size": len(data), "pypi": address}
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


@pytest.fixture(autouse=True)
def changelog(tmp_path, monkeypatch):
    """The CHANGELOG.md the release notes start from (a released section)."""
    path = tmp_path / "CHANGELOG.md"
    path.write_text("# Changelog\n\n## 10.0.0 - 2027-01-01\n\n- Later.\n\n"
                    f"## {VERSION} - 2026-11-09\n\n### Fixed\n\n- **Updates.** A fix.\n\n"
                    "## 9.9.8 - 2026-11-01\n\n- Older.\n")
    monkeypatch.setattr(AR, "CHANGELOG", path, raising=False)
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
            f"packs-{VERSION}.json", "SHA256SUMS", "SHA256SUMS.sig"} <= names
    assert not any(n.startswith("dep") for n in names)  # on PyPI: a base fetches them there
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
    assert run("--version", VERSION, "--dist", make_dist(tmp_path, pypi=False),
               "--ci", make_ci(tmp_path), "--out", out, "--key", key_file) == 0
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
    """As step 9 of the release flow: the assets as gh release download
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


def test_happy_the_release_flow_has_the_final_reviews_steps():
    """The final release review: the full suite run locally (python-app.yml
    runs five files), a green cross-platform bundle run of a ci/ branch
    before the tag, the tour videos as a prerelease that never becomes
    Latest - before the app release -, notes.md written by the assembler,
    and the draft checked in GitHub's own order."""
    text = (ROOT / "docs" / "PACKAGING.md").read_text(encoding="utf-8")
    flow = text[text.index("## Release flow"):text.index("## Self-update: what a release")]
    for needle in ("pytest -q -p no:cacheprovider", 'HEAD:refs/heads/ci/$VERSION',
                   "--prerelease --latest=false", "releases/latest --jq .tag_name",
                   "--notes-file notes.md", "--api-json", "--release-id",
                   "--pack-wheels unhosted", "sorted by name, ignoring case"):
        assert needle in flow, needle
    assert "upload-1.txt first keeps" not in flow and "the test suite) must be green" not in flow
    assert flow.index("refs/heads/ci/") < flow.index('git tag -a "v$VERSION"')
    assert flow.index("--prerelease --latest=false") < flow.index("--draft --verify-tag") \
        < flow.index("--api-json")
    doc = (ROOT / "scripts" / "tour_videos.py").read_text(encoding="utf-8")
    assert "--prerelease --latest=false" in doc and "gh release create TAG" not in doc



# -- the order GitHub lists the assets in (final release review) ---------------------


def github_listing(folder: Path, version: str = VERSION, *, order=None, body: str = "") -> dict:
    """The release as GitHub's API answers for it: every asset, sorted by name
    ignoring case (measured on cli/cli and astral-sh/python-build-standalone),
    a draft's untagged download URLs."""
    files = sorted((p for p in folder.iterdir() if p.is_file() and p.name not in AR.NOT_ASSETS),
                   key=lambda p: p.name.lower())
    if order is not None:
        files = [folder / n for n in order]
    return {"id": 4242, "tag_name": f"v{version}", "draft": True, "body": body,
            "assets": [{"id": 9000 + i, "name": p.name, "size": p.stat().st_size,
                        "state": "uploaded",
                        "digest": "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest(),
                        "browser_download_url": f"https://github.com/c0decave/axross/releases/"
                                                f"download/untagged-1a2b/{p.name}"}
                       for i, p in enumerate(files)]}


def _position(listing: dict, name: str) -> int:
    return [a["name"] for a in listing["assets"]].index(name) + 1


def test_sad_too_many_assets_put_sha256sums_past_the_first_100_and_are_refused(tmp_path, capsys):
    """GitHub lists the assets by name, not in upload order: with 160 pack
    wheels attached SHA256SUMS sorts past the first 100, where the updater
    of 0.14.136 never looks - every installed binary would refuse the update
    ("has no SHA256SUMS"). The old check modelled the upload order and let
    it pass."""
    out = tmp_path / "rel"
    dist = make_dist(tmp_path, blobs=160, pypi=False)
    assert run("--version", VERSION, "--dist", dist, "--ci", make_ci(tmp_path), "--out", out) == 1
    report = capsys.readouterr().out
    assert "SHA256SUMS: asset" in report and "GitHub's order (by name, ignoring case)" in report
    assert "0.14.136 (every binary in use) reads only the first 100" in report
    assert not (out / "upload-1.txt").exists()  # nothing to upload from
    assert _position(github_listing(out / "assets"), "SHA256SUMS") > AR.API_ASSETS


def test_sad_attaching_every_wheel_is_refused_and_the_default_attaches_few(tmp_path, capsys):
    """The 0.15.177 case: about 160 pack wheels, all on PyPI but a few built
    from an sdist. --pack-wheels all makes 180 assets and is refused; the
    default attaches the few without a PyPI address and stays far below 100."""
    dist = make_dist(tmp_path, blobs=160, pypi=lambda i: i % 40 != 0)  # 4 without
    ci = make_ci(tmp_path)
    assert run("--version", VERSION, "--dist", dist, "--ci", ci, "--out", tmp_path / "all",
               "--pack-wheels", "all") == 1
    assert "SHA256SUMS: asset" in capsys.readouterr().out
    out = tmp_path / "few"
    assert run("--version", VERSION, "--dist", dist, "--ci", ci, "--out", out) == 0
    report = capsys.readouterr().out
    names = assets_of(out)
    assert {n for n in names if n.startswith("dep")} == {
        f"dep{i}-1.0-py3-none-any.whl" for i in (0, 40, 80, 120)}
    assert len(names) < AR.API_ASSETS
    assert "4 attached" in report and "156 fetched from PyPI" in report
    assert "156 more pack wheels not attached" in report
    sums = SU.parse_sums((out / "assets" / "SHA256SUMS").read_text())
    assert set(sums) == names - {"SHA256SUMS"}  # the PyPI wheels: in the signed manifest only


def test_happy_e2e_a_base_installs_attached_and_pypi_wheels(tmp_path, field_key):
    """core.packs installs a unit from the assembled release: the attached
    wheel from the release, the others from files.pythonhosted.org, each
    checked against the signed manifest."""
    from core import packs as P

    _key, key_file = field_key
    dist = make_dist(tmp_path, blobs=3, pypi=lambda i: i != 1)
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", dist, "--out", out, "--key", key_file) == 0
    assert "dep1-1.0-py3-none-any.whl" in assets_of(out) and "dep0-1.0-py3-none-any.whl" \
        not in assets_of(out)
    listing = github_listing(out / "assets")
    for entry in listing["assets"]:
        entry["browser_download_url"] = f"{SU.DOWNLOAD_PREFIX}v{VERSION}/{entry['name']}"
    listing["html_url"] = f"{SU.RELEASES_PREFIX}tag/v{VERSION}"
    release = SU.parse_release(listing)
    manifest = json.loads((dist / "packs" / f"packs-{VERSION}.json").read_text())
    pypi = {e["pypi"]: dist / "packs" / n for n, e in manifest["blobs"].items() if e["pypi"]}
    fetched = []

    def fetch(url, max_bytes, hosts=None):
        fetched.append((url.split("/")[2], url.rsplit("/", 1)[1]))
        path = pypi[url] if url in pypi else out / "assets" / url.rsplit("/", 1)[1]
        return path.read_bytes()[:max_bytes]
    done = P.install(release, ["cloud"], fetch=fetch, root=tmp_path / "packs")
    assert sorted(done) == sorted(manifest["blobs"])
    assert ("github.com", "dep1-1.0-py3-none-any.whl") in fetched
    assert ("files.pythonhosted.org", "dep0-1.0-py3-none-any.whl") in fetched
    assert ("files.pythonhosted.org", "dep2-1.0-py3-none-any.whl") in fetched


def test_edge_a_pypi_address_core_packs_would_not_use_means_attached(tmp_path):
    """Only an https address on files.pythonhosted.org that names the file
    itself counts; any other wheel is attached."""
    odd = {0: "http://files.pythonhosted.org/packages/dep0-1.0-py3-none-any.whl",
           1: "https://evil.example/packages/dep1-1.0-py3-none-any.whl",
           2: "https://files.pythonhosted.org/packages/other-1.0-py3-none-any.whl",
           3: True}
    dist = make_dist(tmp_path, blobs=4, pypi=lambda i: odd[i])
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", dist, "--out", out) == 0
    assert {n for n in assets_of(out) if n.startswith("dep")} == {
        "dep0-1.0-py3-none-any.whl", "dep1-1.0-py3-none-any.whl", "dep2-1.0-py3-none-any.whl"}


def test_sad_a_pypi_wheel_that_differs_from_the_manifest_is_refused(tmp_path, capsys):
    """Not attached, still checked: the manifest must name the very file
    the gate checked, or a base's download from PyPI fails."""
    dist = make_dist(tmp_path)
    (dist / "packs" / "dep1-1.0-py3-none-any.whl").write_bytes(wheel_bytes("other"))
    (dist / "packs" / "SHA256SUMS").unlink()
    assert run("--version", VERSION, "--dist", dist, "--out", tmp_path / "rel") == 1
    assert "packs/dep1-1.0-py3-none-any.whl differs from" in capsys.readouterr().err


def test_edge_every_updaters_asset_is_held_to_the_first_100():
    """The names the 0.14.136 updater and this tree's pick, for every
    platform, flavour and variant - and SHA256SUMS, its signature."""
    names = AR.updater_assets(VERSION)
    assert CONTRACT | {"SHA256SUMS", "SHA256SUMS.sig", f"packs-{VERSION}.json"} == names
    assert set(AR.FIELD_UPDATER_ASSETS) <= CONTRACT


def test_edge_the_orders_cover_both_case_foldings_and_the_upload():
    names = ["SHA256SUMS", "a_b", "aB", "ab", "axross-full"]
    orders = AR.listing_orders(names, upload=["ab"])
    assert orders["GitHub's order (by name, ignoring case)"] == [
        "a_b", "aB", "ab", "axross-full", "SHA256SUMS"]
    assert orders["by name, folded to upper case"] == [  # "_" sorts after "X" there
        "aB", "ab", "axross-full", "a_b", "SHA256SUMS"]
    assert orders["by name, byte order"][0] == "SHA256SUMS"
    assert orders["the upload order"][0] == "ab"


# -- --check against what GitHub holds -----------------------------------------------


def _assembled(tmp_path, field_key, **dist_kwargs) -> Path:
    _key, key_file = field_key
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path, **dist_kwargs),
               "--ci", make_ci(tmp_path), "--out", out, "--key", key_file) == 0
    return out


def test_happy_check_reads_the_order_from_githubs_answer(tmp_path, field_key, capsys):
    out = _assembled(tmp_path, field_key)
    api = tmp_path / "release.json"
    api.write_text(json.dumps(github_listing(out / "assets", body=(out / "notes.md").read_text())))
    capsys.readouterr()
    assert run("--version", VERSION, "--check", out / "assets", "--api-json", api,
               "--require-all") == 0
    report = capsys.readouterr().out
    assert "GitHub's answer" in report and "is modelled" not in report
    # the asset list, as gh api --paginate writes its pages (one after the other)
    entries = github_listing(out / "assets")["assets"]
    api.write_text(json.dumps(entries[:10]) + "\n" + json.dumps(entries[10:]))
    assert run("--version", VERSION, "--check", out / "assets", "--api-json", api) == 0


def test_sad_check_against_github_finds_what_was_not_uploaded_or_differs(tmp_path, field_key,
                                                                          capsys):
    out = _assembled(tmp_path, field_key)
    listing = github_listing(out / "assets")
    listing["assets"] = [a for a in listing["assets"] if a["name"] != "axross-slim-glibc2.36"]
    next(a for a in listing["assets"] if a["name"] == "axross-full")["size"] += 1
    next(a for a in listing["assets"] if a["name"] == "axross-base")["digest"] = "sha256:" + "0" * 64
    listing["assets"].append(dict(listing["assets"][0], name="axross-old-leftover", id=1))
    api = tmp_path / "release.json"
    api.write_text(json.dumps(listing))
    capsys.readouterr()
    assert run("--version", VERSION, "--check", out / "assets", "--api-json", api) == 1
    report = capsys.readouterr().out
    for needle in ("axross-slim-glibc2.36: in the folder, not among GitHub's assets",
                   "axross-full: GitHub states", "axross-base: GitHub's digest",
                   "axross-old-leftover: an asset on GitHub"):
        assert needle in report, needle


def test_sad_check_uses_githubs_order_not_the_upload_lists(tmp_path, field_key, capsys):
    """The upload lists put SHA256SUMS first; what counts is where GitHub
    lists it. The old --check read the local upload lists only."""
    _key, key_file = field_key
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path, blobs=160, pypi=False),
               "--ci", make_ci(tmp_path), "--out", out, "--key", key_file) == 1
    names = sorted((p.name for p in (out / "assets").iterdir()), key=str.lower)
    for listed in ("upload-1.txt", "upload-2.txt"):  # as the old flow had them
        first = [n for n in names if not n.startswith("dep")]
        (out / listed).write_text("".join(f"assets/{n}\n" for n in (
            first if listed == "upload-1.txt" else [n for n in names if n.startswith("dep")])))
    api = tmp_path / "release.json"
    api.write_text(json.dumps(github_listing(out / "assets")))
    capsys.readouterr()
    assert run("--version", VERSION, "--check", out, "--api-json", api) == 1
    report = capsys.readouterr().out
    assert "SHA256SUMS: asset" in report and "in GitHub's answer" in report


def test_happy_release_id_reads_the_json_with_gh_on_github_com(tmp_path, field_key, monkeypatch,
                                                               capsys):
    out = _assembled(tmp_path, field_key)
    api = tmp_path / "release.json"
    api.write_text(json.dumps(github_listing(out / "assets")))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.txt"
    gh = bin_dir / "gh"
    gh.write_text(f'#!/bin/sh\necho "$GH_HOST $*" >> {calls}\ncat {api}\n')
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.setenv("GH_HOST", "ghe.example.invalid")
    assert run("--version", VERSION, "--check", out, "--release-id", "4242") == 0
    assert calls.read_text().split() == ["github.com", "api", "repos/c0decave/axross/releases/4242"]
    capsys.readouterr()
    assert run("--version", VERSION, "--check", out, "--release-id", "../x") == 1
    assert "the release's number" in capsys.readouterr().err


def test_sad_an_api_answer_over_1_mib_is_refused(tmp_path, field_key):
    out = _assembled(tmp_path, field_key)
    report = AR.check_release(out / "assets", VERSION, keys=None, notes="x" * SU.MAX_API_BYTES)
    assert any("the updater takes at most 1048576" in p for p in report.problems)
    assert not any("1048576" in p for p in AR.check_release(out / "assets", VERSION,
                                                            keys=None).problems)


# -- notes.md ------------------------------------------------------------------------


def test_happy_notes_md_is_written_from_the_changelog(tmp_path, field_key):
    """Step 7 creates the release with --notes-file notes.md: the assembler
    writes it (nothing did before)."""
    key, _key_file = field_key
    out = _assembled(tmp_path, field_key)
    notes = (out / "notes.md").read_text()
    assert notes.startswith("### Fixed\n\n- **Updates.** A fix.\n")
    assert "Later." not in notes and "Older." not in notes
    assert "<!-- native-components -->" in notes and "libfake 1.0" in notes
    assert "## Assets" in notes and "`axross-slim-windows-x64.exe`" in notes
    assert "2 more come from PyPI" in notes
    assert "## How to verify" in notes and public_key_b64(key) in notes
    sums = SU.parse_sums((out / "assets" / "SHA256SUMS").read_text())
    assert f"{sums['axross-full']}  axross-full" in notes
    assert "notes.md" not in assets_of(out)


def test_happy_the_verify_commands_of_the_notes_work(tmp_path, field_key):
    import re
    import shutil
    import subprocess

    if not shutil.which("openssl") or not shutil.which("sha256sum"):
        pytest.skip("needs openssl and sha256sum")
    out = _assembled(tmp_path, field_key)
    script = re.search(r"```bash\n(.*?)```", (out / "notes.md").read_text(), re.S).group(1)
    ok = subprocess.run(["bash", "-e", "-c", script], cwd=out / "assets", capture_output=True,
                        text=True)
    assert ok.returncode == 0, ok.stderr
    with open(out / "assets" / "SHA256SUMS", "a") as fh:
        fh.write("# changed\n")
    bad = subprocess.run(["bash", "-e", "-c", script], cwd=out / "assets", capture_output=True)
    assert bad.returncode != 0


def test_sad_require_all_refuses_a_changelog_still_unreleased(tmp_path, changelog, capsys):
    changelog.write_text(f"# Changelog\n\n## Unreleased ({VERSION})\n\n- A fix.\n")
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--dist", make_dist(tmp_path), "--ci", make_ci(tmp_path),
               "--out", out, "--require-all") == 1
    assert f"'## Unreleased ({VERSION})' - turn it into '## {VERSION} - <date>'" in \
        capsys.readouterr().err
    changelog.write_text("# Changelog\n\n## 9.9.8 - 2026-11-01\n\n- Older.\n")
    assert run("--version", VERSION, "--dist", make_dist(tmp_path / "2"), "--ci",
               make_ci(tmp_path / "2"), "--out", out, "--require-all") == 1
    assert f"no section '## {VERSION} - <date>'" in capsys.readouterr().err


def test_edge_changelog_section_stops_at_the_next_version():
    text = "# C\n\n## 1.2.30 - x\n\n- no\n\n## 1.2.3 - y\n\nyes\n\n## 1.2.2\n\nno\n"
    assert AR.changelog_section(text, "1.2.3") == ("## 1.2.3 - y", "yes")
    assert AR.changelog_section(text, "1.2.4") is None


# -- the Linux dist from CI (cross-platform.yml, job linux) ----------------------------


def make_ci_with_linux(root: Path, *, zipped=False, with_bundles=True) -> Path:
    """Every artifact of a cross-platform run as gh run download (a folder
    each) or the web page (a .zip each) hands them out: the bundle job's and
    the linux job's axross-linux-dist - build_dist.sh's dist/<version>/,
    without file modes (an artifact keeps none)."""
    import shutil

    ci = make_ci(root, zipped=zipped) if with_bundles else root / "ci"
    ci.mkdir(exist_ok=True)
    built = make_dist(root / "linux-runner")
    for path in built.rglob("*"):
        if path.is_file():
            path.chmod(0o644)
    if zipped:
        with zipfile.ZipFile(ci / f"{AR.CI_LINUX}.zip", "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(built.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(built).as_posix())
    else:
        shutil.copytree(built, ci / AR.CI_LINUX)
    return ci


@pytest.mark.parametrize("zipped", [False, True], ids=["gh-run-download", "web-zip"])
def test_happy_the_ci_artifacts_alone_make_the_whole_release(tmp_path, field_key, zipped):
    """No builder: --ci with the linux job's artifact takes --dist's place,
    every Linux asset, the packs, wheel, sdist and NATIVE-COMPONENTS.md
    included (--require-all)."""
    _key, key_file = field_key
    ci, out = make_ci_with_linux(tmp_path, zipped=zipped), tmp_path / "rel"
    assert run("--version", VERSION, "--ci", ci, "--out", out, "--key", key_file,
               "--require-all") == 0
    names = assets_of(out)
    assert CONTRACT <= names
    assert {"axross-media-player-glibc2.36", f"axross-{VERSION}.tar.gz",
            f"axross_media_player-{VERSION}-py3-none-any.whl", f"packs-{VERSION}.json",
            "SHA256SUMS.sig"} <= names
    for name in ("axross-full", "axross-base-glibc2.36", "axross-system-info"):
        assert (out / "assets" / name).stat().st_mode & 0o777 == 0o755
    assert "libfake 1.0" in (out / "notes.md").read_text()
    # the .zip was unpacked next to the downloads for the run only
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".")) == []
    assert run("--version", VERSION, "--check", out / "assets", "--require-all") == 0


def test_edge_dist_wins_over_the_ci_linux_artifact(tmp_path, field_key, capsys):
    _key, key_file = field_key
    ci, out = make_ci_with_linux(tmp_path), tmp_path / "rel"
    local = make_dist(tmp_path / "builder")
    (local / "glibc-2.34" / "axross-full").write_bytes(elf("from the builder"))
    sums_of(local / "glibc-2.34", [f"axross-{n}" for n in (*SU.FLAVORS, *AR.TOOLS)])
    assert run("--version", VERSION, "--dist", local, "--ci", ci, "--out", out, "--key", key_file,
               "--require-all") == 0
    assert (out / "assets" / "axross-full").read_bytes() == elf("from the builder")
    assert f"ci/{AR.CI_LINUX}: not used, --dist names the Linux dist" in capsys.readouterr().out


def test_edge_without_the_linux_artifact_the_missing_dist_names_both_ways(tmp_path, capsys):
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--ci", make_ci(tmp_path), "--out", out) == 0
    assert f"or the linux job's {AR.CI_LINUX} in --ci" in capsys.readouterr().out


def _evil_zip(ci: Path, member: str, *, link=False) -> None:
    with zipfile.ZipFile(ci / f"{AR.CI_LINUX}.zip", "w") as zf:
        zf.writestr("glibc-2.34/axross-full", elf("ok"))
        info = zipfile.ZipInfo(member)
        if link:
            info.external_attr = (0o120777 << 16)
        zf.writestr(info, "/etc/passwd" if link else "x")


@pytest.mark.parametrize("member, link", [
    ("../escaped", False), ("/abs/escaped", False), ("glibc-2.34/../../escaped", False),
    ("glibc-2.34\\..\\escaped", False), ("glibc-2.36/axross-full", True)],
    ids=["dotdot", "absolute", "nested-dotdot", "backslash", "symlink"])
def test_sad_an_unsafe_linux_zip_is_refused_and_nothing_left(tmp_path, capsys, member, link):
    ci = make_ci(tmp_path)
    _evil_zip(ci, member, link=link)
    out = tmp_path / "rel"
    assert run("--version", VERSION, "--ci", ci, "--out", out) == 1
    assert f"{AR.CI_LINUX}.zip" in capsys.readouterr().err
    assert not (tmp_path / "escaped").exists() and not (tmp_path.parent / "escaped").exists()
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".")) == []
    assert not (out / "assets").exists()


def test_sad_the_linux_artifact_both_unpacked_and_zipped_is_refused(tmp_path, capsys):
    ci = make_ci_with_linux(tmp_path)
    (ci / f"{AR.CI_LINUX}.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
    assert run("--version", VERSION, "--ci", ci, "--out", tmp_path / "rel") == 1
    assert "keep one" in capsys.readouterr().err
