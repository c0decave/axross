"""axross-markdown 0.17.0: the signed update of its one-file programs (core.markdown_update,
ui.markdown_update_ui, core.ed25519_pure, scripts/sign_release.py of the standalone).

Against a fake GitHub (its API, its redirects to the asset host, signed and badly signed releases): a
verified update applies; a bad signature, a wrong SHA-256, a downgrade, an oversized file, a redirect off
GitHub and a failed self-test are each refused - the program untouched, nothing left beside it - and a
program that fails in place is rolled back. The settings, the scheduler (the start and every 24 hours),
the window's Help menu and that nothing of a check runs on the GUI thread (a heartbeat on it).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import ed25519_pure as ED  # noqa: E402
from core import markdown_update as MU  # noqa: E402

SECRET = bytes(range(1, 33))
PUBLIC = ED.public_key(SECRET)
CURRENT = "0.17.0"
NEW = "0.18.0"


@pytest.fixture(autouse=True)
def _own_key_and_settings(monkeypatch, tmp_path):
    monkeypatch.setattr(MU, "TRUSTED_KEYS", (base64.b64encode(PUBLIC).decode(),))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("AXROSS_MARKDOWN_SETTINGS", raising=False)
    monkeypatch.delenv(MU.NO_CHECK_ENV, raising=False)


# -- a fake GitHub ----------------------------------------------------------------------------------------

class _Body(io.BytesIO):
    def __init__(self, data: bytes, delay: float = 0.0):
        super().__init__(data)
        self.delay = delay

    def read(self, size=-1):
        if self.delay:
            time.sleep(self.delay)
        return super().read(size)


class FakeGitHub:
    """GitHub as the updater meets it: the API's latest release, each download URL answering 302 to the
    asset host, which serves the bytes. Every request is noted with the thread that made it."""

    def __init__(self, version=NEW, files=None, *, sign=True, signature=None, sums=None, sizes=None,
                 redirect_to="https://release-assets.githubusercontent.com/", delay: float = 0.0,
                 digests=None, tag=None):
        self.requests: list[tuple[str, str]] = []
        self.answers: dict[str, MU.Reply] = {}
        self.delay = delay
        tag = tag or f"v{version}"
        files = dict(files or {})
        if sums is None:
            sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items())
        sums_bytes = sums.encode() if isinstance(sums, str) else sums
        if signature is None and sign:
            signature = ED.sign(SECRET, sums_bytes)
        files[MU.SUMS_NAME] = sums_bytes
        if signature is not None:
            files[MU.SIG_NAME] = signature
        self.data: dict[str, bytes] = {}
        assets = []
        for number, (name, data) in enumerate(files.items()):
            url = f"{MU.DOWNLOAD_PREFIX}{tag}/{name}"
            host_url = f"{redirect_to}{number}?sig=x"
            self.redirect(url, host_url)
            self.data[host_url] = data
            asset = {"name": name, "size": (sizes or {}).get(name, len(data)), "browser_download_url": url}
            if digests and name in digests:
                asset["digest"] = "sha256:" + digests[name]
            assets.append(asset)
        self.data[MU.LATEST_URL] = json.dumps({"tag_name": tag, "draft": False, "prerelease": False,
                                               "body": "notes", "assets": assets}).encode()

    def redirect(self, url: str, location: str) -> None:
        self.answers[url] = MU.Reply(302, location)

    def get(self, url: str) -> MU.Reply:
        self.requests.append((url, threading.current_thread().name))
        if url in self.answers:
            return self.answers[url]
        if url in self.data:
            data = self.data[url]
            return MU.Reply(200, "", len(data), _Body(data, self.delay))
        return MU.Reply(404)


def _program(path: Path, version: str, *, ok: bool = True, program: str = "axross-markdown") -> bytes:
    """A program that answers --self-test as a release of *version* would (or fails)."""
    answer = f'echo "{program} {version} ok"' if ok else 'echo "libEGL.so.1: cannot open" >&2; exit 127'
    data = f"#!/bin/sh\n# {version}\n{answer}\n".encode()
    path.write_bytes(data)
    path.chmod(0o755)
    return data


def _binary(tmp_path) -> tuple[MU.Install, Path, bytes]:
    folder = tmp_path / "bin"
    folder.mkdir(exist_ok=True)  # (the heartbeat's measure_again runs a test again in the same tmp_path)
    for left in folder.iterdir():
        left.unlink()
    target = folder / "axross-markdown"
    old = _program(target, CURRENT)
    return MU.Install("binary", "linux", "axross-markdown", target), target, old


def _new_file(tmp_path, version=NEW, ok=True) -> bytes:
    return _program(tmp_path / f"new-{version}-{ok}", version, ok=ok)


def _leftovers(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir() if ".part" in p.name)


# -- Ed25519 ----------------------------------------------------------------------------------------------

def test_happy_ed25519_matches_rfc_8032():
    secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a3"
                              "3bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ED.public_key(secret) == public
    assert ED.sign(secret, b"") == signature
    assert ED.verify(public, b"", signature)
    assert not ED.verify(public, b"x", signature)


def test_happy_ed25519_agrees_with_the_cryptography_package():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    for size in (0, 1, 64, 1000):
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        message = os.urandom(size)
        assert ED.public_key(raw) == public
        assert ED.verify(public, message, key.sign(message))
        assert ED.sign(raw, message) == key.sign(message)


def test_sad_ed25519_refuses_what_is_malformed():
    signature = ED.sign(SECRET, b"m")
    s = int.from_bytes(signature[32:], "little")
    assert not ED.verify(PUBLIC, b"m", signature[:32] + int.to_bytes(s + ED.L, 32, "little"))  # (S >= L)
    assert not ED.verify(PUBLIC, b"m", signature[:63])
    assert not ED.verify(PUBLIC[:31], b"m", signature)
    assert not ED.verify(b"\xff" * 32, b"m", signature)  # (no point: y >= p)
    assert not ED.verify(PUBLIC, "m", signature)


def _pinned() -> tuple:
    """TRUSTED_KEYS as the updater's source has it (the fixture puts the tests' own key in its place)."""
    import ast

    tree = ast.parse(Path(MU.__file__).read_text(encoding="utf-8"))
    return next(ast.literal_eval(node.value) for node in tree.body
                if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "TRUSTED_KEYS")


def test_happy_the_pinned_key_is_one_key_of_32_bytes():
    pinned = _pinned()
    assert len(pinned) == 1 and len(base64.b64decode(pinned[0], validate=True)) == 32
    assert pinned[0] == "G+6OeUD/+0CE1UsDsnVTl7HBOOXtphDXycrBnk6EbGQ="


# -- what runs here ---------------------------------------------------------------------------------------

def test_happy_each_build_gets_its_own_version_bound_file(tmp_path):
    linux = MU.detect_install(frozen=True, executable="/opt/axross-markdown", environ={}, platform="linux",
                              machine="x86_64")
    assert linux.kind == "binary" and MU.asset_name(linux, "1.2.3") == "axross-markdown-1.2.3-linux-x86_64"
    windows = MU.detect_install(frozen=True, executable="C:/p/axross-markdown.exe", environ={}, platform="win32",
                                machine="AMD64")
    assert MU.asset_name(windows, "1.2.3") == "axross-markdown-1.2.3-windows-x64.exe"
    mdcat = MU.detect_install(frozen=True, executable="C:/p/axross-mdcat.exe", environ={}, platform="win32",
                              machine="AMD64")
    assert mdcat.program == "axross-mdcat" and MU.asset_name(mdcat, "1.2.3") == "axross-mdcat-1.2.3-windows-x64.exe"
    mac = MU.detect_install(frozen=True, executable="/usr/local/bin/axross-markdown", environ={},
                            platform="darwin", machine="arm64")
    assert MU.asset_name(mac, "1.2.3") == "axross-markdown-1.2.3-macos-arm64"
    image = tmp_path / "axross-markdown-x86_64.AppImage"
    image.write_bytes(b"AI")
    appdir = tmp_path / "mount"
    (appdir / "usr").mkdir(parents=True)
    appimage = MU.detect_install(frozen=True, executable=str(appdir / "usr" / "axross-markdown"),
                                 environ={"APPIMAGE": str(image), "APPDIR": str(appdir)}, platform="linux",
                                 machine="x86_64")
    assert appimage.kind == "appimage" and appimage.target == image
    assert MU.asset_name(appimage, "1.2.3") == "axross-markdown-1.2.3-x86_64.AppImage"
    for name in ("axross-markdown-1.2.3-linux-x86_64", "axross-mdcat-1.2.3-windows-x64.exe"):
        assert not name.endswith(MU.ARCHIVE_SUFFIXES)  # (no archive: the bare programs)


def test_sad_pip_the_mac_app_and_strangers_are_never_replaced(tmp_path):
    pip = MU.detect_install(frozen=False)
    assert pip.kind == "pip" and not pip.can_update and MU.PIP_HINT in pip.why_not()
    assert MU.asset_name(pip, "1.2.3") is None
    app = MU.detect_install(frozen=True, executable="/Applications/axross Markdown.app/Contents/MacOS/axross-markdown",
                            environ={}, platform="darwin", machine="arm64")
    assert app.kind == "macapp" and not app.can_update and "disk image" in app.why_not()
    arm_linux = MU.detect_install(frozen=True, executable="/x/axross-markdown", environ={}, platform="linux",
                                  machine="aarch64")
    assert arm_linux.kind == "unsupported" and not arm_linux.can_update
    # ($APPIMAGE of another program than the one running: not trusted)
    other = MU.detect_install(frozen=True, executable="/opt/axross-markdown",
                              environ={"APPIMAGE": str(tmp_path / "x.AppImage"), "APPDIR": str(tmp_path)},
                              platform="linux", machine="x86_64")
    assert other.kind == "binary" and other.target == Path("/opt/axross-markdown")


def test_happy_versions_and_their_order():
    assert MU.parse_version("v1.2.3") == (1, 2, 3) and MU.parse_version("1.2") is None
    assert MU.parse_version("1.2.3-rc1") is None and MU.parse_version("1.2.3.4") is None
    assert MU.is_newer("0.17.1", "0.17.0") and not MU.is_newer("0.17.0", "0.17.0")
    assert not MU.is_newer("0.16.11", "0.17.0") and MU.is_newer("0.17.10", "0.17.9")


# -- a verified update applies ----------------------------------------------------------------------------

def test_happy_a_verified_update_applies_and_keeps_the_old_one(tmp_path):
    inst, target, old = _binary(tmp_path)
    new = _new_file(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": new})
    said = MU.update(inst, CURRENT, github)
    assert said == f"axross-markdown {NEW} is installed - it starts the next time"
    assert target.read_bytes() == new and os.access(target, os.X_OK)
    assert MU.previous_of(target).read_bytes() == old
    assert _leftovers(target.parent) == []
    hosts = {url.split("/")[2] for url, _thread in github.requests}
    assert hosts <= MU.ALLOWED_HOSTS and "release-assets.githubusercontent.com" in hosts
    MU.cleanup_previous(target)
    assert not MU.previous_of(target).exists()


def test_happy_the_signature_is_checked_before_the_program_is_fetched(tmp_path):
    inst, target, _old = _binary(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": _new_file(tmp_path)},
                        signature=ED.sign(os.urandom(32), b"another"))
    with pytest.raises(MU.SignatureError):
        MU.update(inst, CURRENT, github)
    fetched = [url for url, _thread in github.requests if "githubusercontent" in url]
    assert len(fetched) == 2  # (the signature and SHA256SUMS - never the program)


def test_happy_an_appimage_update_replaces_the_appimage_file(tmp_path):
    image = tmp_path / "apps" / "axross-markdown-x86_64.AppImage"
    image.parent.mkdir()
    old = _program(image, CURRENT)
    inst = MU.Install("appimage", "linux", "axross-markdown", image)
    new = _new_file(tmp_path)
    MU.update(inst, CURRENT, FakeGitHub(files={f"axross-markdown-{NEW}-x86_64.AppImage": new,
                                               f"axross-markdown-{NEW}-linux-x86_64": b"the plain binary"}))
    assert image.read_bytes() == new and MU.previous_of(image).read_bytes() == old


def test_happy_windows_renames_the_running_program_aside(tmp_path):
    folder = tmp_path / "win"
    folder.mkdir()
    target = folder / "axross-mdcat.exe"
    old = _program(target, CURRENT, program="axross-mdcat")
    inst = MU.Install("binary", "windows", "axross-mdcat", target)
    new = _program(tmp_path / "new.exe", NEW, program="axross-mdcat")
    renames = []
    real = os.replace

    def replace(a, b):
        if Path(a).parent == folder:
            renames.append((Path(a).name, Path(b).name))
        return real(a, b)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(MU.os, "replace", replace)
        MU.update(inst, CURRENT, FakeGitHub(files={f"axross-mdcat-{NEW}-windows-x64.exe": new}))
    assert renames[0] == ("axross-mdcat.exe", "axross-mdcat.exe.previous")  # (renamed aside first)
    assert renames[1][1] == "axross-mdcat.exe" and renames[1][0].endswith(".part.exe")
    assert target.read_bytes() == new and MU.previous_of(target).read_bytes() == old


def test_sad_windows_puts_the_old_program_back_when_the_new_cannot_go_in(tmp_path):
    folder = tmp_path / "win"
    folder.mkdir()
    target = folder / "axross-markdown.exe"
    old = _program(target, CURRENT)
    inst = MU.Install("binary", "windows", "axross-markdown", target)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-windows-x64.exe": _new_file(tmp_path)})
    real = os.replace

    def replace(a, b):
        if ".part" in str(a) and Path(a).parent == folder:
            raise PermissionError(13, "in use")
        return real(a, b)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(MU.os, "replace", replace)
        with pytest.raises(MU.UpdateError, match="kept"):
            MU.update(inst, CURRENT, github)
    assert target.read_bytes() == old and not MU.previous_of(target).exists() and _leftovers(folder) == []


# -- refused --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("case", ["bad signature", "no signature", "short signature", "wrong hash",
                                  "no entry", "github digest", "short download", "same version", "downgrade",
                                  "oversized", "more than stated", "off github", "http redirect",
                                  "a user in the redirect", "a port", "too many redirects",
                                  "failed self-test", "old name in new release", "sums not text"])
def test_sad_an_update_that_is_not_the_signed_newer_program_is_refused(tmp_path, case):
    inst, target, old = _binary(tmp_path)
    name = f"axross-markdown-{NEW}-linux-x86_64"
    new = _new_file(tmp_path, ok=case != "failed self-test")
    digest = hashlib.sha256(new).hexdigest()
    kwargs: dict = {"files": {name: new}}
    if case == "bad signature":
        kwargs["signature"] = ED.sign(os.urandom(32), f"{digest}  {name}\n".encode())
    elif case == "no signature":
        kwargs["sign"] = False
    elif case == "short signature":
        kwargs["signature"] = b"x" * 63
    elif case == "wrong hash":
        kwargs["sums"] = f"{'0' * 64}  {name}\n"
    elif case == "no entry":
        kwargs["sums"] = f"{digest}  axross-markdown-{NEW}-macos-arm64\n"
    elif case == "github digest":
        kwargs["digests"] = {name: "1" * 64}
    elif case == "short download":
        kwargs["sizes"] = {name: len(new) + 10}
    elif case == "same version":
        kwargs = {"version": CURRENT, "files": {f"axross-markdown-{CURRENT}-linux-x86_64": new}}
    elif case == "downgrade":
        kwargs = {"version": "0.16.11", "files": {"axross-markdown-0.16.11-linux-x86_64": new}}
    elif case == "oversized":
        kwargs["sizes"] = {name: MU.MAX_ASSET_BYTES + 1}
    elif case == "more than stated":
        kwargs["sizes"] = {name: len(new) - 5}
    elif case == "off github":
        kwargs["redirect_to"] = "https://evil.example.org/"
    elif case == "http redirect":
        kwargs["redirect_to"] = "http://release-assets.githubusercontent.com/"
    elif case == "a user in the redirect":
        kwargs["redirect_to"] = "https://user@release-assets.githubusercontent.com/"
    elif case == "a port":
        kwargs["redirect_to"] = "https://release-assets.githubusercontent.com:8443/"
    elif case == "old name in new release":  # (a newer tag carrying an older release's signed file)
        old_name = "axross-markdown-0.16.11-linux-x86_64"
        kwargs = {"files": {old_name: new}}
    elif case == "sums not text":
        kwargs["sums"] = b"\xff\xfe" + digest.encode()
    github = FakeGitHub(**kwargs)
    if case == "too many redirects":
        github = FakeGitHub(files={name: new})
        url = f"{MU.DOWNLOAD_PREFIX}v{NEW}/{name}"
        for hop in range(MU.MAX_REDIRECTS + 1):
            nxt = f"https://github.com/hop/{hop}"
            github.redirect(url, nxt)
            url = nxt
    errors = {"bad signature": MU.SignatureError, "no signature": MU.SignatureError,
              "short signature": MU.SignatureError, "wrong hash": MU.ChecksumError, "no entry": MU.ChecksumError,
              "github digest": MU.ChecksumError, "short download": MU.ChecksumError,
              "oversized": MU.TooLarge, "more than stated": MU.TooLarge, "off github": MU.HostRefused,
              "http redirect": MU.HostRefused, "a user in the redirect": MU.HostRefused,
              "a port": MU.HostRefused, "failed self-test": MU.SelfTestFailed}
    if case in ("same version", "downgrade"):
        assert MU.update(inst, CURRENT, github) == f"axross-markdown {CURRENT} is up to date"
        result = MU.check(CURRENT, github)
        with pytest.raises(MU.DowngradeRefused):
            MU.download(result.release, inst, CURRENT, github)
    else:
        with pytest.raises(errors.get(case, MU.UpdateError)):
            MU.update(inst, CURRENT, github)
    assert target.read_bytes() == old, case
    assert not MU.previous_of(target).exists() and _leftovers(target.parent) == [], case


def test_sad_a_program_that_fails_in_place_is_rolled_back(tmp_path):
    inst, target, old = _binary(tmp_path)
    new = _new_file(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": new})

    def after(path):
        assert path == target and path.read_bytes() == new
        raise MU.SelfTestFailed("it ended at its start")

    with pytest.raises(MU.SelfTestFailed, match="the old one is back"):
        MU.update(inst, CURRENT, github, after=after)
    assert target.read_bytes() == old and not MU.previous_of(target).exists()


def test_sad_a_file_changed_after_its_check_is_not_installed(tmp_path):
    inst, target, old = _binary(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": _new_file(tmp_path)})
    result = MU.check(CURRENT, github)
    downloaded = MU.download(result.release, inst, CURRENT, github)
    downloaded.path.write_bytes(b"#!/bin/sh\necho swapped\n")
    with pytest.raises(MU.ChecksumError):
        MU.install(downloaded, inst)
    assert target.read_bytes() == old and _leftovers(target.parent) == []


def test_sad_an_unwritable_folder_keeps_the_program(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root writes any folder")
    inst, target, old = _binary(tmp_path)
    target.parent.chmod(0o555)
    try:
        with pytest.raises(MU.NotWritable):
            MU.update(inst, CURRENT, FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": b"x"}))
    finally:
        target.parent.chmod(0o755)
    assert target.read_bytes() == old


def test_sad_the_self_test_wants_the_exact_answer(tmp_path):
    good = tmp_path / "good"
    _program(good, NEW)
    MU.self_test(good, NEW)
    with pytest.raises(MU.SelfTestFailed):
        MU.self_test(good, "9.9.9")  # (another version's answer)
    bad = tmp_path / "bad"
    _program(bad, NEW, ok=False)
    with pytest.raises(MU.SelfTestFailed, match="libEGL"):
        MU.self_test(bad, NEW)
    slow = tmp_path / "slow"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o755)
    with pytest.raises(MU.SelfTestFailed, match="did not answer"):
        MU.self_test(slow, NEW, timeout=0.3)
    with pytest.raises(MU.SelfTestFailed, match="cannot be run"):
        MU.self_test(tmp_path / "missing", NEW)


def test_sad_old_partial_downloads_go_new_ones_stay(tmp_path):
    inst, target, _old = _binary(tmp_path)
    stale = target.parent / f".{target.name}.update-0.18.0-1.part"
    fresh = target.parent / f".{target.name}.update-0.18.0-2.part"
    stale.write_bytes(b"x")
    fresh.write_bytes(b"y")
    os.utime(stale, (time.time() - 7200, time.time() - 7200))
    MU.cleanup_partials(target)
    assert not stale.exists() and fresh.exists()


def test_sad_the_api_answer_is_bounded_and_its_urls_are_the_releases_own():
    class Huge:
        def get(self, url):
            return MU.Reply(200, "", MU.MAX_API_BYTES + 1, io.BytesIO(b"{}"))

    with pytest.raises(MU.TooLarge):
        MU.check(CURRENT, Huge())
    release = MU.parse_release({"tag_name": "v1.0.0", "assets": [
        {"name": "a", "size": 1, "browser_download_url": f"{MU.DOWNLOAD_PREFIX}v1.0.0/a"},
        {"name": "b", "size": 1, "browser_download_url": "https://evil.example.org/b"},
        {"name": "../c", "size": 1, "browser_download_url": f"{MU.DOWNLOAD_PREFIX}v1.0.0/../c"}]})
    assert set(release.assets) == {"a"}
    with pytest.raises(MU.UpdateError):
        MU.parse_release({"tag_name": "nightly"})
    with pytest.raises(MU.HostRefused):
        MU.check_url("file:///etc/passwd")


# -- the settings and the scheduler -----------------------------------------------------------------------

def test_happy_the_mode_is_notify_until_set_and_kept(tmp_path):
    assert MU.mode() == "notify"
    MU.set_mode("auto")
    assert MU.mode() == "auto"
    MU.set_mode("off")
    assert MU.mode() == "off"
    with pytest.raises(ValueError):
        MU.set_mode("sometimes")
    path = Path(os.environ["XDG_CONFIG_HOME"]) / "axross-markdown" / "settings.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text())
    data["update_mode"] = ["auto"]  # (hand-edited: a value of no meaning reads as the default)
    data["theme"] = "modern-dark"
    path.write_text(json.dumps(data))
    assert MU.mode() == "notify"
    MU.set_mode("auto")
    assert json.loads(path.read_text())["theme"] == "modern-dark"  # (the rest of the file kept)


def test_sad_a_check_writes_the_program_s_state_never_the_user_s_settings(tmp_path):
    """0.17.0 kept the time of every check (and the version found) in settings.json: a check at the start
    changed the user's settings file. It is the program's state (core.markdown_settings.state_path); the
    settings change only when the user sets something."""
    from core import markdown_settings as S

    settings = S.settings_path()
    MU.record_check(MU.CheckResult(MU.Release(NEW, f"v{NEW}"), CURRENT, True))
    assert not settings.exists()
    assert MU.last_check() is not None and MU.seen_newer(CURRENT) == NEW
    assert S.state_path().is_file() and S.state_path() != settings
    MU.set_mode("off")  # (the user's choice: the settings)
    assert json.loads(settings.read_text()) == {"update_mode": "off"}


def test_happy_axross_markdown_settings_names_the_settings_file(tmp_path, monkeypatch):
    from core import markdown_settings as S

    own = tmp_path / "portable" / "md.json"
    monkeypatch.setenv(S.ENV, str(own))
    assert S.settings_path() == own and S.state_path() == own.with_name("md.state.json")
    MU.set_mode("auto")
    MU.record_check(when=123.0)
    assert json.loads(own.read_text()) == {"update_mode": "auto"} and MU.last_check() == 123.0
    pytest.importorskip("PyQt6.QtWidgets")
    from ui import standalone_app

    assert standalone_app.settings_file("axross-markdown") == own
    assert standalone_app.settings_file("axross-amp") != own


def test_happy_the_scheduler_checks_at_the_start_and_every_24_hours():
    now, last, started = [1_000_000.0], [None], []
    scheduler = MU.Scheduler(lambda: started.append(threading.current_thread().name), clock=lambda: now[0],
                             get_mode=lambda: "notify", get_last=lambda: last[0],
                             record=lambda when: last.__setitem__(0, when), environ={},
                             start=lambda target: target())
    assert scheduler.tick() and len(started) == 1  # (the start: none yet)
    assert not scheduler.tick()  # (a moment later: not due)
    now[0] += MU.INTERVAL - 1
    assert not scheduler.tick() and scheduler.seconds_to_next() == 1
    now[0] += 1
    assert scheduler.tick() and len(started) == 2
    last[0] = now[0] + 3600  # (a clock put back: due at once)
    assert scheduler.tick()


def test_sad_the_scheduler_does_nothing_when_off_or_said_off_and_never_twice_at_once():
    started = []
    off = MU.Scheduler(lambda: started.append(1), get_mode=lambda: "off", get_last=lambda: None,
                       record=lambda when: None, environ={}, start=lambda target: target())
    assert not off.tick()
    said_off = MU.Scheduler(lambda: started.append(1), get_mode=lambda: "auto", get_last=lambda: None,
                            record=lambda when: None, environ={MU.NO_CHECK_ENV: "1"},
                            start=lambda target: target())
    assert not said_off.tick() and started == []
    held = threading.Event()
    threads = []
    busy = MU.Scheduler(lambda: held.wait(5), get_mode=lambda: "notify", get_last=lambda: None,
                        record=lambda when: None, environ={},
                        start=lambda target: threads.append(threading.Thread(target=target)) or threads[-1].start())
    assert busy.tick() and not busy.tick()  # (one running: none more)
    held.set()
    threads[0].join(5)
    assert busy.tick()
    threads[-1].join(5)


def test_sad_a_failing_check_is_recorded_and_ends_quietly():
    records = []

    def broken():
        raise MU.UpdateError("cannot reach GitHub")

    scheduler = MU.Scheduler(broken, get_mode=lambda: "notify", get_last=lambda: None, record=records.append,
                             environ={}, start=lambda target: target())
    assert scheduler.tick() and len(records) == 1 and not scheduler.running


# -- the command line --------------------------------------------------------------------------------------

def test_happy_check_update_and_update_on_the_command_line(tmp_path, monkeypatch, capsys):
    from core import markdown_cli as C

    inst, target, _old = _binary(tmp_path)
    new = _new_file(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": new})
    monkeypatch.setattr(MU, "Web", lambda *args, **kwargs: github)
    monkeypatch.setattr(MU, "detect_install", lambda: inst)
    monkeypatch.setattr(C, "program_version", lambda: CURRENT)
    assert C.main(["--check-update"]) == 0
    assert f"axross-markdown {NEW} is available (this is {CURRENT}) - axross-mdcat --update" in capsys.readouterr().out
    assert MU.seen_newer(CURRENT) == NEW
    assert C.main(["--update"]) == 0
    assert "is installed" in capsys.readouterr().out and target.read_bytes() == new
    assert C.main(["--update-mode", "off"]) == 0 and MU.mode() == "off"
    pip = MU.Install("pip", "linux")
    monkeypatch.setattr(MU, "detect_install", lambda: pip)
    assert C.main(["--check-update"]) == 0
    out = capsys.readouterr().out
    # (the release's own wheel: its versions since 0.17.0 are on GitHub only - "pip install -U" upgraded nothing)
    assert MU.pip_hint(NEW) in out and f"/releases/download/v{NEW}/axross_markdown-{NEW}-py3-none-any.whl" in out


def test_sad_check_update_says_why_it_failed(monkeypatch, capsys):
    from core import markdown_cli as C

    monkeypatch.setattr(MU, "Web", lambda *args, **kwargs: FakeGitHub(redirect_to="https://evil.example.org/",
                                                                     files={"x": b"y"}))

    class Down:
        def get(self, url):
            raise MU.UpdateError("cannot reach GitHub: no route")

    monkeypatch.setattr(MU, "Web", lambda *args, **kwargs: Down())
    assert C.main(["--check-update"]) == 1
    assert "cannot reach GitHub" in capsys.readouterr().err


def test_happy_the_terminal_says_a_newer_version_the_last_check_found(monkeypatch):
    from core import markdown_cli as C

    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(C, "program_version", lambda: CURRENT)
    assert C.newer_notice(Tty()) == ""
    MU.record_check(MU.CheckResult(MU.Release(NEW, f"v{NEW}"), CURRENT, True))
    assert f"axross-markdown {NEW} is available" in C.newer_notice(Tty())
    assert C.newer_notice(io.StringIO()) == ""  # (into a pipe: nothing)
    MU.set_mode("off")
    assert C.newer_notice(Tty()) == ""


def test_happy_self_test_answers_as_the_updater_waits_for(capsys):
    from core import markdown_cli as C

    assert C.main(["--self-test"]) == 0
    assert capsys.readouterr().out.strip() == MU.self_test_answer(C.program_version(), "axross-mdcat")


def test_happy_the_window_program_self_tests_without_a_window(capsys):
    pytest.importorskip("PyQt6.QtWidgets")
    from core.markdown_cli import program_version
    from ui import markdown_app

    assert markdown_app.main(["axross-markdown", "--self-test"]) == 0
    assert capsys.readouterr().out.strip() == f"axross-markdown {program_version()} ok"


# -- the window: Help, and nothing on the GUI thread -------------------------------------------------------

_APP: list = []


def _app():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    if not _APP:  # (kept: an application nobody holds is gone at once)
        _APP.append(QApplication.instance() or QApplication([]))
    return _APP[0]


def test_happy_help_has_check_for_updates_and_the_three_modes(tmp_path):
    _app()
    from ui import markdown_update_ui as UI

    inst, _target, _old = _binary(tmp_path)
    controller = UI.UpdateController(None, fetcher=FakeGitHub(), install=inst, current=CURRENT)
    from PyQt6.QtWidgets import QMenu

    menu = QMenu()
    controller.fill_help_menu(menu)
    texts = [action.text() for action in menu.actions()]
    assert texts[0] == "Check for Updates…" and texts[1] == "Updates"
    modes = menu.actions()[1].menu()
    modes.aboutToShow.emit()
    actions = {action.data(): action for action in modes.actions()}
    assert set(actions) == {"off", "notify", "auto"} and actions["notify"].isChecked()
    actions["auto"].trigger()
    assert MU.mode() == "auto"
    pip = UI.UpdateController(None, fetcher=FakeGitHub(), install=MU.Install("pip", "linux"), current=CURRENT)
    menu2 = QMenu()
    pip.fill_help_menu(menu2)
    auto = next(a for a in menu2.actions()[1].menu().actions() if a.data() == "auto")
    assert not auto.isEnabled() and MU.PIP_HINT in auto.toolTip()


def test_happy_the_viewer_of_the_program_has_a_help_button(tmp_path):
    _app()
    from ui.markdown_app import MarkdownApp

    viewer = MarkdownApp().open_paths([""])[0]
    try:
        assert viewer.help_button is not None and viewer.help_button.text() == "&Help"
        assert viewer.help_button.menu().actions()[0].text() == "Check for Updates…"
    finally:
        viewer.close()


def test_sad_axross_s_own_viewer_has_no_updates_of_its_own(tmp_path):
    _app()
    from core.local_fs import LocalFS
    from ui.markdown_viewer import MarkdownViewerDialog

    page = tmp_path / "a.md"
    page.write_text("# A\n")
    viewer = MarkdownViewerDialog(LocalFS(), str(page))
    try:
        assert viewer.help_button is None
    finally:
        viewer.close()


def _wait(predicate, seconds):
    from PyQt6.QtCore import QCoreApplication, QEventLoop

    end = time.monotonic() + seconds
    while time.monotonic() < end:
        QCoreApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


@pytest.mark.parametrize("mode", ["notify", "auto"])
def test_sad_a_check_and_an_update_never_run_on_the_gui_thread(tmp_path, mode):
    """The start's check (and in "auto" the download of 40 MB, its SHA-256, the signature, the self-test and
    the swap) on a slow network: every request from a worker, the window answering all the time."""
    _app()
    from tests import markdown_heartbeat as HB
    from ui import markdown_update_ui as UI

    MU.set_mode(mode)
    inst, target, old = _binary(tmp_path)
    big = _new_file(tmp_path) + (b"#" * (40 << 20) if mode == "auto" else b"")  # (notify fetches no program)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": big}, delay=0.0005)
    tested = []
    controller = UI.UpdateController(None, fetcher=github, install=inst, current=CURRENT,
                                     test=lambda path, version: tested.append(threading.current_thread().name))
    said = []
    controller.said.connect(lambda kind, text: said.append((kind, threading.current_thread().name)))
    shown = []
    controller.notice = lambda kind, text, parent=None: shown.append(kind)
    beat = HB.Heartbeat()
    assert controller.scheduler.tick()
    assert _wait(lambda: said, 120), "the check did not end"
    _wait(lambda: False, 0.05)
    _turn, gap = beat.stop()
    gui = threading.main_thread().name
    assert github.requests and all(thread != gui for _url, thread in github.requests)
    assert said[0] == ("installed" if mode == "auto" else "available", gui)  # (told on the GUI thread)
    assert shown == [said[0][0]]
    if mode == "auto":
        assert tested and tested[0] != gui and target.read_bytes() == big
    else:
        assert target.read_bytes() == old
    HB.assert_responsive(gap, ("update check", mode))


def test_happy_check_now_says_up_to_date_in_a_window_that_does_not_wait(tmp_path):
    _app()
    from PyQt6.QtWidgets import QMessageBox

    from ui import markdown_update_ui as UI

    inst, _target, _old = _binary(tmp_path)
    github = FakeGitHub(version=CURRENT, files={})
    controller = UI.UpdateController(None, fetcher=github, install=inst, current=CURRENT)
    controller.check_now()
    assert _wait(lambda: getattr(controller, "box", None) is not None, 20)
    box = controller.box
    assert isinstance(box, QMessageBox) and not box.isModal() and "up to date" in box.text()
    box.close()


def test_sad_the_cleanup_keeps_the_old_program_of_an_update_made_in_this_session(tmp_path):
    _app()
    from ui import markdown_update_ui as UI

    inst, target, old = _binary(tmp_path)
    MU.previous_of(target).write_bytes(b"an earlier update's old program")
    controller = UI.UpdateController(None, fetcher=FakeGitHub(), install=inst, current=CURRENT,
                                     start_thread=lambda work: work())
    controller.updating = True  # (an update installed a minute after the start: its .previous is kept)
    controller.cleanup()
    assert MU.previous_of(target).exists()
    controller.updating = False  # (none in this session: the earlier one's goes)
    controller.cleanup()
    assert not MU.previous_of(target).exists() and target.read_bytes() == old


def test_sad_a_background_check_tells_of_a_version_once():
    _app()
    from ui import markdown_update_ui as UI

    controller = UI.UpdateController(None, fetcher=FakeGitHub(), install=MU.Install("pip", "linux"),
                                     current=CURRENT, start_thread=lambda target: target())
    shown = []
    controller.notice = lambda kind, text, parent=None: shown.append(kind)
    result = MU.CheckResult(MU.Release(NEW, f"v{NEW}"), CURRENT, True)
    controller._arrived("available", result.text, result)
    controller._arrived("available", result.text, result)
    controller._arrived("error", "cannot reach GitHub", None)  # (a background failure: the log's)
    assert shown == ["available"]


# -- the release: its script and its workflow --------------------------------------------------------------

def _repo() -> Path:
    """The standalone repository's files: in axross its template, in the export the repository itself."""
    template = ROOT / "scripts" / "standalone_repo" / "axross-markdown"
    return template if template.is_dir() else ROOT


def _sign_release():
    import types

    path = _repo() / "scripts" / "sign_release.py"
    module = types.ModuleType("sign_release")  # (read, not imported: no __pycache__ in the repo's files)
    module.__file__ = str(path)
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)
    return module


def test_happy_sign_release_reads_the_pinned_key_of_the_updater():
    script = _sign_release()
    assert script.pinned_keys(Path(MU.__file__)) == [base64.b64decode(key) for key in _pinned()]


def test_happy_sign_release_signs_what_the_updater_verifies_and_refuses_an_unpinned_key(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    script = _sign_release()
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "key.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o644)
    with pytest.raises(SystemExit, match="others may read"):
        script.load_key(path)
    path.chmod(0o600)
    loaded = script.load_key(path)
    public = script.public_raw(loaded)
    sums = f"{'a' * 64}  axross-markdown-{NEW}-linux-x86_64\n".encode()
    signature = script.sign(sums, loaded, [public])
    MU.verify_signature(sums, signature, (base64.b64encode(public).decode(),))
    with pytest.raises(SystemExit, match="not pinned"):
        script.sign(sums, loaded, [b"\0" * 32])
    with pytest.raises(SystemExit, match="not '<sha256>"):
        script.sign(b"# a comment\n", loaded, [public])


def test_happy_the_release_is_a_draft_with_the_files_the_updater_fetches():
    yaml = pytest.importorskip("yaml")
    path = _repo() / ".github" / "workflows" / "release.yml"
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    assert "--draft" in text and "SHA256SUMS.sig" in text and "sign_release.py" in text
    steps = workflow["jobs"]["binaries"]["steps"]
    build = next(step["run"] for step in steps if step.get("name", "").startswith("One-file binary"))
    for suffix in ("linux-x86_64", "macos-arm64", "windows-x64.exe"):
        install = MU.Install("binary", {"linux-x86_64": "linux", "macos-arm64": "macos",
                                        "windows-x64.exe": "windows"}[suffix])
        assert MU.asset_name(install, "1.2.3") == f"axross-markdown-1.2.3-{suffix}"
    assert 'axross-markdown-${version}-${{ matrix.suffix }}' in build
    assert 'axross-mdcat-${version}-${{ matrix.suffix }}' in build
    image = next(step["run"] for step in steps if step.get("name", "") == "AppImage (Linux)")
    assert "axross-markdown-${version}-x86_64.AppImage" in image
    assert MU.asset_name(MU.Install("appimage", "linux"), "1.2.3") == "axross-markdown-1.2.3-x86_64.AppImage"
    uses = [line.strip() for line in text.splitlines() if "uses:" in line and "uses: ./.github/" not in line]
    assert uses and all("@" in line and len(line.split("@")[1].split()[0]) == 40 for line in uses)


# -- the twenty-seventh review: U1 (a network error outside UpdateError), U2 (TLS in the one-file programs) --

class _Breaking(io.BytesIO):
    """A body that gives *good* bytes, then raises *error* (a reset connection, a time-out, a cut answer)."""

    def __init__(self, data: bytes, error: BaseException, good: int = 100):
        super().__init__(data[:good])
        self.error = error

    def read(self, size=-1):
        chunk = super().read(size)
        if not chunk:
            raise self.error
        return chunk


class _BreakingGitHub(FakeGitHub):
    """The fake GitHub whose asset host breaks off in the body of the program's download (or every answer,
    *everything*), or whose connection fails at once (*at_once*)."""

    def __init__(self, error: BaseException, *, everything: bool = False, at_once: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.error, self.everything, self.at_once = error, everything, at_once
        self.broken = True

    def get(self, url: str) -> MU.Reply:
        if not self.broken:
            return super().get(url)
        if self.at_once:
            self.requests.append((url, threading.current_thread().name))
            raise self.error
        reply = super().get(url)
        program = url in self.data and self.data[url] not in (self.data.get(MU.LATEST_URL),) \
            and len(self.data[url]) > 1000
        if reply.status == 200 and (self.everything or program):
            data = self.data[url]
            return MU.Reply(200, "", len(data), _Breaking(data, self.error))
        return reply


def _breakers():
    import http.client

    return [ConnectionResetError(104, "Connection reset by peer"), TimeoutError("The read operation timed out"),
            http.client.IncompleteRead(b"x", 10), OSError(113, "No route to host")]


@pytest.mark.parametrize("error", _breakers(), ids=lambda error: type(error).__name__)
def test_sad_a_reset_or_a_time_out_is_an_update_error(tmp_path, error):
    """fetch wrapped only the request: a connection reset or a time-out in the body came out as itself - the
    worker died with no word, --update printed a traceback. Now an UpdateError that says what happened; the
    program untouched, nothing left beside it."""
    inst, target, old = _binary(tmp_path)
    new = _new_file(tmp_path) + b"#" * 5000
    github = _BreakingGitHub(error, files={f"axross-markdown-{NEW}-linux-x86_64": new})
    with pytest.raises(MU.UpdateError) as caught:
        MU.update(inst, CURRENT, github, test=lambda path, version: None)
    assert "try again" in str(caught.value)
    assert target.read_bytes() == old and _leftovers(target.parent) == []
    with pytest.raises(MU.UpdateError):
        MU.check(CURRENT, _BreakingGitHub(error, everything=True, version=NEW))
    with pytest.raises(MU.UpdateError):
        MU.check(CURRENT, _BreakingGitHub(error, at_once=True, version=NEW))


def test_sad_a_broken_connection_never_leaves_the_controller_stuck(tmp_path):
    """Install during a connection reset: the worker died, busy stayed True, and Help > Check for Updates did
    nothing for the rest of the session. Now "error" is said, and a second try works."""
    _app()
    from ui import markdown_update_ui as UI

    inst, target, _old = _binary(tmp_path)
    new = _new_file(tmp_path) + b"#" * 5000
    github = _BreakingGitHub(ConnectionResetError(104, "Connection reset by peer"),
                             files={f"axross-markdown-{NEW}-linux-x86_64": new})
    controller = UI.UpdateController(None, fetcher=github, install=inst, current=CURRENT,
                                     test=lambda path, version: None)
    said = []
    controller.said.connect(lambda kind, text: said.append((kind, text)))
    controller.notice = lambda kind, text, parent=None: None
    controller.check_now()
    assert _wait(lambda: said, 60) and said[-1][0] == "available"
    controller.install_now()
    assert _wait(lambda: len(said) == 2, 60), "the install said nothing"
    assert said[-1][0] == "error" and "broke off" in said[-1][1] and not controller.busy
    github.broken = False
    controller.install_now()
    assert _wait(lambda: len(said) == 3, 60) and said[-1][0] == "installed", said
    assert target.read_bytes() == new


def test_sad_any_failure_of_a_worker_is_said_and_frees_the_controller(tmp_path):
    """Not only an UpdateError: a bug, a full disk - said as "error", the controller free again."""
    _app()
    from ui import markdown_update_ui as UI

    class Bug:
        def get(self, url):
            raise RuntimeError("a bug in the fetcher")

    inst, _target, _old = _binary(tmp_path)
    controller = UI.UpdateController(None, fetcher=Bug(), install=inst, current=CURRENT)
    said = []
    controller.said.connect(lambda kind, text: said.append((kind, text)))
    controller.notice = lambda kind, text, parent=None: None
    controller.check_now()
    assert _wait(lambda: said, 30) and said[0][0] == "error" and "a bug" in said[0][1]
    assert not controller.busy


@pytest.mark.parametrize("option", ["--update", "--check-update"])
def test_sad_update_on_the_command_line_says_a_reset_without_a_traceback(tmp_path, monkeypatch, capsys, option):
    from core import markdown_cli as C

    inst, target, old = _binary(tmp_path)
    new = _new_file(tmp_path) + b"#" * 5000
    github = _BreakingGitHub(ConnectionResetError(104, "Connection reset by peer"),
                             everything=option == "--check-update",
                             files={f"axross-markdown-{NEW}-linux-x86_64": new})
    monkeypatch.setattr(MU, "Web", lambda *args, **kwargs: github)
    monkeypatch.setattr(MU, "detect_install", lambda: inst)
    monkeypatch.setattr(C, "program_version", lambda: CURRENT)
    assert C.main([option]) == 1
    err = capsys.readouterr().err
    assert "broke off" in err and "Traceback" not in err
    assert target.read_bytes() == old


def test_sad_an_install_folder_windows_will_not_write_is_not_writable(tmp_path, monkeypatch):
    """On Windows os.access says Program Files may be written: the PermissionError of the download's file came
    out as itself. Now NotWritable, the program as it is."""
    inst, target, old = _binary(tmp_path)
    new = _new_file(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": new})
    real_open = os.open

    def refusing(path, *args, **kwargs):
        if ".part" in os.fspath(path):
            raise PermissionError(13, "Access is denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(MU.os, "open", refusing)
    with pytest.raises(MU.NotWritable):
        MU.update(inst, CURRENT, github, test=lambda path, version: None)
    assert target.read_bytes() == old


def test_sad_a_download_left_by_the_same_process_is_no_file_exists_error(tmp_path):
    """Auto mode's background download and an Install click had the same pid and version - the same file name:
    FileExistsError. The name has a random part now."""
    inst, target, _old = _binary(tmp_path)
    new = _new_file(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": new})
    (target.parent / f"{MU._part_prefix(target)}{NEW}-{os.getpid()}.part").write_bytes(b"another download")
    MU.update(inst, CURRENT, github, test=lambda path, version: None)
    assert target.read_bytes() == new


def test_sad_auto_mode_installs_a_release_once_a_session(tmp_path):
    """After an install the controller still compared with the old version: 24 hours later it downloaded and
    installed the same release again (and on Linux .previous then held the new program)."""
    _app()
    from ui import markdown_update_ui as UI

    MU.set_mode("auto")
    inst, target, _old = _binary(tmp_path)
    new = _new_file(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": new})
    controller = UI.UpdateController(None, fetcher=github, install=inst, current=CURRENT,
                                     test=lambda path, version: None)
    said = []
    controller.said.connect(lambda kind, text: said.append(kind))
    controller.notice = lambda kind, text, parent=None: None
    controller._background_check()
    assert _wait(lambda: said, 30) and said == ["installed"]
    asked = len(github.requests)
    controller._background_check()
    _wait(lambda: False, 0.2)
    assert said == ["installed"]
    assert all(MU.LATEST_URL == url for url, _thread in github.requests[asked:])  # (the check only)
    assert MU.previous_of(target).read_bytes() != new


# -- TLS: a fake GitHub over https, with a CA of its own --------------------------------------------------

def _ca_and_server(folder: Path) -> tuple[Path, Path, Path]:
    """(the CA's certificate, the server's certificate, its key) - made with openssl, for "localhost"."""
    import shutil
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("no openssl to make a CA")
    folder.mkdir(parents=True, exist_ok=True)
    ca_key, ca, key, request, cert = (folder / name for name in ("ca.key", "ca.pem", "srv.key", "srv.csr", "srv.pem"))
    ext = folder / "ext.cnf"
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n")

    def run(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=60)

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca), "-days", "2",
        "-subj", "/CN=axross test CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(request), "-subj", "/CN=localhost")
    run("x509", "-req", "-in", str(request), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(cert), "-days", "2", "-extfile", str(ext))
    return ca, cert, key


@pytest.fixture
def https_server(tmp_path):
    """An https server on localhost with a certificate of a CA of the test's own: (its URL, the CA's file)."""
    import http.server
    import ssl

    ca, cert, key = _ca_and_server(tmp_path / "tls")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server's
            body = b'{"tag_name": "v9.9.9"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"https://localhost:{server.server_address[1]}/latest", ca
    server.shutdown()
    server.server_close()


def test_sad_the_updater_trusts_the_host_s_ca_bundle_when_its_openssl_finds_none(https_server, monkeypatch):
    """The one-file programs are built on Ubuntu; their OpenSSL looks for Ubuntu's bundle - on Fedora, Arch,
    openSUSE and macOS a default context held no CA certificate, and every check failed with
    CERTIFICATE_VERIFY_FAILED (said only in the log). Only a program that plays sound loaded the host's
    bundle. The updater's context now loads the host's bundle (here: the test's CA in its place) whenever the
    default store is empty - and a store without the CA is refused, as it must be."""
    url, ca = https_server
    empty = lambda context: 0  # noqa: E731 - (the default store as a frozen build finds it elsewhere)
    trusting = MU.tls_context({}, candidates=[str(ca)], count=empty, certifi_path="")
    reply = MU.Web(5, context=trusting).get(url)
    assert reply.status == 200 and b"v9.9.9" in reply.body.read()
    reply.close()
    blind = MU.tls_context({}, candidates=[], count=empty, certifi_path="")
    with pytest.raises(MU.UpdateError) as caught:
        MU.Web(5, context=blind).get(url)
    assert "certificate" in str(caught.value)
    # (the user's own SSL_CERT_FILE is the user's: left as it is)
    own = MU.tls_context({"SSL_CERT_FILE": "/x"}, candidates=[str(ca)], count=empty, certifi_path="")
    with pytest.raises(MU.UpdateError):
        MU.Web(5, context=own).get(url)
    # (the check and the update ask through it - the command line's too)
    made = []
    monkeypatch.setattr(MU, "tls_context", lambda *args, **kwargs: made.append(1) or trusting)
    assert MU.Web(5).context is trusting and made


def test_sad_every_standalone_program_loads_the_host_s_ca_bundle(monkeypatch):
    """ui.standalone_app.prepare_process called core.tls_env.apply_ca_bundle only for a program that plays
    sound: axross-markdown's window never did."""
    pytest.importorskip("PyQt6.QtWidgets")
    from core import i18n, tls_env
    from ui import standalone_app

    called = []
    monkeypatch.setattr(tls_env, "apply_ca_bundle", lambda *args, **kwargs: called.append(1))
    monkeypatch.setattr(i18n, "install", lambda *args, **kwargs: None)
    standalone_app.prepare_process()
    assert called


# -- U3: the updater's other edges -----------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_sad_a_symlink_planted_as_previous_is_never_written_through(tmp_path):
    """shutil.copy2 wrote the old program through a symlink planted at <target>.previous."""
    inst, target, old = _binary(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(b"not to be overwritten")
    MU.previous_of(target).symlink_to(elsewhere)
    new = _new_file(tmp_path)
    MU.update(inst, CURRENT, FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": new}),
              test=lambda path, version: None)
    assert elsewhere.read_bytes() == b"not to be overwritten"
    previous = MU.previous_of(target)
    assert not previous.is_symlink() and previous.read_bytes() == old and target.read_bytes() == new


def test_sad_windows_says_where_the_old_program_is_when_neither_rename_goes(tmp_path, monkeypatch):
    """Both renames failing (an antivirus' lock) left only .previous and .part.exe, and a raw PermissionError."""
    inst, target, old = _binary(tmp_path)
    inst = MU.Install("binary", "windows", "axross-markdown", target)
    new = _new_file(tmp_path)
    github = FakeGitHub(files={f"axross-markdown-{NEW}-windows-x64.exe": new})
    real = os.replace
    calls = []

    def replace(source, destination):
        if Path(destination) == target:  # (the new one in, and the old one back: both refused)
            calls.append(Path(source).name)
            raise PermissionError(13, "Access is denied")
        return real(source, destination)

    monkeypatch.setattr(MU.os, "replace", replace)
    monkeypatch.setattr(MU.time, "sleep", lambda seconds: None)
    with pytest.raises(MU.UpdateError) as caught:
        MU.update(inst, CURRENT, github, test=lambda path, version: None)
    assert str(MU.previous_of(target)) in str(caught.value) and "rename it" in str(caught.value)
    assert MU.previous_of(target).read_bytes() == old and len(calls) == 4  # (the old one tried three times)


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell")
def test_sad_a_self_test_that_hangs_ends_with_all_it_started(tmp_path):
    """The self-test's time-out killed the direct child only: a one-file program is the bootloader's child
    and stayed alive."""
    pids = tmp_path / "pids"
    program = tmp_path / "hangs"
    program.write_text(f"#!/bin/sh\nsleep 600 &\necho $! > {pids}\nwait\n")
    program.chmod(0o755)
    with pytest.raises(MU.SelfTestFailed):
        MU.self_test(program, NEW, timeout=2)
    child = int(pids.read_text())
    for _ in range(100):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        try:  # (a zombie reaped by nobody but init: its state says it is gone)
            if Path(f"/proc/{child}/stat").read_text().split()[2] == "Z":
                break
        except OSError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("the self-test's grandchild is still running")


@pytest.mark.skipif(os.name == "nt", reason="flock")
def test_sad_two_updates_of_one_program_never_run_at_once(tmp_path):
    """No lock between instances: two windows, or a window and --update, installed at once - one's cleanup
    deleted the other's download."""
    import fcntl

    inst, target, old = _binary(tmp_path)
    lock = target.with_name(f".{target.name}.update-lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(MU.UpdateError) as caught:
            MU.update(inst, CURRENT, FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": _new_file(tmp_path)}),
                      test=lambda path, version: None)
        assert "another axross-markdown" in str(caught.value) and target.read_bytes() == old
    finally:
        os.close(fd)
    MU.update(inst, CURRENT, FakeGitHub(files={f"axross-markdown-{NEW}-linux-x86_64": _new_file(tmp_path)}),
              test=lambda path, version: None)
    assert target.read_bytes() != old
