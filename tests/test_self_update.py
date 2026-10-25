"""The self-update of the one-file binaries (core.self_update).

Requested: an update function for axross-full and axross-slim that checks
once at start and downloads from GitHub, configurable. Everything here runs
offline against tests/fake_github.py: the real https URLs, the real
redirect chain github.com -> release-assets.githubusercontent.com, the real
SHA256SUMS of a release.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from axross._version import __version__  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import self_update as SU  # noqa: E402
from tests.fake_github import (  # noqa: E402
    API_HOST,
    ASSET_HOST,
    WEB_HOST,
    FakeGitHub,
    FakeHttpsHandler,
    FakeRelease,
    newer_than,
    older_than,
)

NEW = newer_than(__version__)
OLD_BYTES = b"\x7fELF old axross binary " * 100
NEW_BYTES = b"\x7fELF new axross binary " * 5000  # > one 64 KiB chunk


@pytest.fixture(autouse=True)
def _no_env_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy",
                 "ALL_PROXY", "no_proxy", "NO_PROXY", SU.NO_CHECK_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def settings(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    monkeypatch.setattr(OL, "SETTINGS_PATH", path)
    return path


@pytest.fixture
def fake():
    release = FakeRelease(NEW, {
        "axross-full": NEW_BYTES,
        "axross-slim": NEW_BYTES[: len(NEW_BYTES) // 2],
        "axross-slim-macos-arm64": b"mach-o new",
        "axross-slim-windows-x64.exe": b"MZ new windows binary" * 100,
    })
    server = FakeGitHub(release)
    yield server
    server.close()


def opener_for(server):
    return SU.build_opener(handlers=[FakeHttpsHandler(server.port)])


@pytest.fixture
def binary(tmp_path):
    folder = tmp_path / "apps"
    folder.mkdir()
    exe = folder / "axross-full"
    exe.write_bytes(OLD_BYTES)
    exe.chmod(0o755)
    return exe


def frozen_install(exe: Path, *, flavor="full", platform="linux", machine="x86_64"):
    bundle = exe.parent.parent / "_MEI1234"
    bundle.mkdir(exist_ok=True)
    (bundle / SU.FLAVOR_PATH[0]).mkdir(exist_ok=True)
    bundle.joinpath(*SU.FLAVOR_PATH).write_text(flavor + "\n")
    return SU.detect_install(frozen=True, executable=str(exe), bundle_dir=str(bundle),
                             platform=platform, machine=machine)


def leftovers(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir() if ".part" in p.name or ".update-" in p.name)


# --- versions ----------------------------------------------------------------


def test_happy_versions_parse_with_and_without_v():
    assert SU.parse_version("0.13.183") == (0, 13, 183)
    assert SU.parse_version("v1.2.3") == (1, 2, 3)
    assert SU.is_newer("0.13.200", "0.13.183")
    assert SU.is_newer("v0.14.0", "0.13.199")
    assert SU.is_newer("1.0.0", "0.99.99")


def test_edge_numeric_not_string_comparison():
    assert SU.is_newer("0.13.100", "0.13.99")
    assert not SU.is_newer("0.13.99", "0.13.100")


def test_edge_same_and_older_are_not_newer():
    assert not SU.is_newer(__version__, __version__)
    assert not SU.is_newer(older_than(__version__), __version__)


@pytest.mark.parametrize("text", ["", "1.2", "1.2.3.4", "1.2.3-rc1", "v", "x.y.z", "01.2.3x",
                                  " 1.2.3", "1.2.3\n", "１.2.3", None, 123])
def test_sad_malformed_versions_are_refused(text):
    assert SU.parse_version(text) is None
    assert not SU.is_newer(text, "0.0.1")


# --- which binary is this ----------------------------------------------------


def test_happy_frozen_full_on_linux_maps_to_axross_full(binary):
    inst = frozen_install(binary)
    assert (inst.frozen, inst.flavor, inst.asset) == (True, "full", "axross-full")
    assert inst.executable == binary.resolve()
    assert inst.can_self_replace


def test_happy_each_platform_has_its_asset(binary):
    assert frozen_install(binary, flavor="slim").asset == "axross-slim"
    assert frozen_install(binary, flavor="slim", platform="darwin",
                          machine="arm64").asset == "axross-slim-macos-arm64"
    win = frozen_install(binary, flavor="slim", platform="win32", machine="AMD64")
    assert win.asset == "axross-slim-windows-x64.exe"
    assert not win.can_self_replace  # a running exe cannot be replaced


def test_edge_flavor_from_the_file_name_without_the_marker(tmp_path):
    exe = tmp_path / "axross-slim"
    exe.write_bytes(b"x")
    inst = SU.detect_install(frozen=True, executable=str(exe), bundle_dir=str(tmp_path / "none"),
                             platform="linux", machine="x86_64")
    assert (inst.flavor, inst.asset) == ("slim", "axross-slim")


def test_edge_unknown_platform_or_flavor_has_no_asset(tmp_path):
    exe = tmp_path / "axross"
    exe.write_bytes(b"x")
    unknown = SU.detect_install(frozen=True, executable=str(exe), bundle_dir=None,
                                platform="linux", machine="x86_64")
    assert unknown.asset == "" and not unknown.can_self_replace
    arm = frozen_install(exe, platform="linux", machine="aarch64")
    assert arm.asset == "" and "no axross-full build" in arm.why_not().lower()
    mac_full = frozen_install(exe, platform="darwin", machine="arm64")
    assert mac_full.asset == ""


def test_sad_not_frozen_never_replaces_itself():
    inst = SU.detect_install(frozen=False)
    assert not inst.frozen and not inst.can_self_replace
    assert "pip install -U axross" in inst.why_not()


def test_sad_update_refuses_a_python_install(fake, tmp_path):
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.UpdateError, match="pip install -U axross"):
        SU.update(release, SU.detect_install(frozen=False), opener=opener_for(fake))


# --- the check ---------------------------------------------------------------


def test_happy_check_finds_the_newer_release(fake):
    result = SU.check(opener=opener_for(fake))
    assert result.newer and result.release.version == NEW
    assert result.release.page_url == f"https://github.com/c0decave/axross/releases/tag/v{NEW}"
    assert "faster" in result.release.notes
    assert result.release.asset("axross-full").size == len(NEW_BYTES)
    assert fake.hosts() == [API_HOST]  # one request, nothing downloaded


def test_edge_same_version_is_up_to_date(fake):
    fake.release.version = __version__
    result = SU.check(opener=opener_for(fake))
    assert not result.newer and result.release.version == __version__


def test_edge_older_release_is_not_offered(fake):
    fake.release.version = older_than(__version__)
    assert not SU.check(opener=opener_for(fake)).newer


@pytest.mark.parametrize("flag", ["prerelease", "draft"])
def test_edge_prerelease_and_draft_are_ignored(fake, flag):
    setattr(fake.release, flag, True)
    result = SU.check(opener=opener_for(fake))
    assert not result.newer and result.release is None
    assert flag in result.message


@pytest.mark.parametrize("status,headers", [
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 600)}),
    (429, {"Retry-After": "60"}),
])
def test_sad_rate_limit_is_named(fake, status, headers):
    fake.api_status, fake.api_headers = status, headers
    with pytest.raises(SU.RateLimited, match="rate limit"):
        SU.check(opener=opener_for(fake))


def test_sad_other_http_errors_name_the_status(fake):
    fake.api_status = 500
    with pytest.raises(SU.UpdateError, match="HTTP 500"):
        SU.check(opener=opener_for(fake))


@pytest.mark.parametrize("body", [b"{not json", b"[1, 2]", b'{"tag_name": "nightly"}',
                                  b'{"tag_name": "v1.2.3", "assets": "x"}', b"\xff\xfe",
                                  b'{"tag_name": "v1.2.3", "html_url": "https://evil.example/x",'
                                  b' "assets": []}'])
def test_sad_malformed_answers_are_refused(fake, body):
    fake.api_body = body
    with pytest.raises(SU.UpdateError):
        SU.check(opener=opener_for(fake))


def test_sad_an_oversized_answer_is_refused(fake):
    fake.api_body = b'{"pad": "' + b"x" * (SU.MAX_API_BYTES + 10) + b'"}'
    with pytest.raises(SU.UpdateError, match="larger"):
        SU.check(opener=opener_for(fake))


def test_sad_no_network_is_a_clear_error():
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens there any more
    with pytest.raises(SU.UpdateError, match="cannot reach"):
        SU.check(opener=SU.build_opener(handlers=[FakeHttpsHandler(port)]), timeout=3)


def test_sad_a_server_that_does_not_answer_times_out(fake):
    fake.api_delay = 2.0
    started = time.monotonic()
    with pytest.raises(SU.UpdateError, match="no answer|timed out"):
        SU.check(opener=opener_for(fake), timeout=0.5)
    assert time.monotonic() - started < 2.0


def test_sad_asset_urls_outside_the_release_are_refused(fake):
    data = fake.release.json()
    data["assets"][0]["browser_download_url"] = "https://evil.example/axross-full"
    fake.api_body = json.dumps(data).encode()
    release = SU.check(opener=opener_for(fake)).release
    assert release.asset(data["assets"][0]["name"]) is None  # dropped, not followed


# --- download, verify, replace -------------------------------------------------


def test_happy_e2e_download_verify_replace_keep_previous(fake, binary):
    inst = frozen_install(binary)
    release = SU.check(opener=opener_for(fake)).release
    seen: list[tuple[int, int]] = []
    result = SU.update(release, inst, opener=opener_for(fake),
                       progress=lambda done, total: seen.append((done, total)))
    assert result.replaced and result.path == binary.resolve()
    assert binary.read_bytes() == NEW_BYTES
    assert stat.S_IMODE(binary.stat().st_mode) == 0o755
    previous = binary.with_name("axross-full.previous")
    assert result.previous == previous and previous.read_bytes() == OLD_BYTES
    assert leftovers(binary.parent) == []
    assert seen[-1] == (len(NEW_BYTES), len(NEW_BYTES))
    assert [d for d, _ in seen] == sorted(d for d, _ in seen)
    # SHA256SUMS and the binary, each through github.com's redirect.
    assert fake.hosts() == [API_HOST, WEB_HOST, ASSET_HOST, WEB_HOST, ASSET_HOST]


def test_happy_the_original_mode_is_kept(fake, binary):
    binary.chmod(0o750)
    release = SU.check(opener=opener_for(fake)).release
    SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert stat.S_IMODE(binary.stat().st_mode) == 0o750


def test_sad_setuid_and_sticky_bits_are_not_carried_over(fake, binary):
    binary.chmod(0o4755 | stat.S_ISVTX)
    release = SU.check(opener=opener_for(fake)).release
    SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert stat.S_IMODE(binary.stat().st_mode) == 0o755


def test_sad_a_release_page_with_markup_is_refused(fake):
    data = fake.release.json()
    data["html_url"] = data["html_url"] + '"><img src="file:///etc/passwd">'
    fake.api_body = json.dumps(data).encode()
    with pytest.raises(SU.UpdateError, match="page"):
        SU.check(opener=opener_for(fake))


def test_happy_the_api_version_header_goes_to_the_api_only(fake, binary, monkeypatch):
    sent = []
    real_open = SU.urllib.request.OpenerDirector.open

    def spy(self, request, *args, **kwargs):
        sent.append((request.host, request.get_header("X-github-api-version")))
        return real_open(self, request, *args, **kwargs)

    monkeypatch.setattr(SU.urllib.request.OpenerDirector, "open", spy)
    release = SU.check(opener=opener_for(fake)).release
    SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert sent[0] == (API_HOST, "2022-11-28")
    assert all(value is None for host, value in sent[1:]) and len(sent) == 5


def test_edge_an_older_previous_is_replaced(fake, binary):
    binary.with_name("axross-full.previous").write_bytes(b"ancient")
    release = SU.check(opener=opener_for(fake)).release
    SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert binary.with_name("axross-full.previous").read_bytes() == OLD_BYTES


def test_edge_a_symlinked_binary_replaces_the_real_file(fake, binary, tmp_path):
    link = tmp_path / "axross"
    link.symlink_to(binary)
    inst = frozen_install(link)
    release = SU.check(opener=opener_for(fake)).release
    SU.update(release, inst, opener=opener_for(fake))
    assert link.is_symlink() and link.read_bytes() == NEW_BYTES
    assert binary.read_bytes() == NEW_BYTES


def test_sad_checksum_mismatch_is_refused_and_cleaned(fake, binary):
    fake.served_override["axross-full"] = NEW_BYTES[:-1] + b"X"  # same size, other bytes
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.ChecksumError, match="SHA-256"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert binary.read_bytes() == OLD_BYTES
    assert leftovers(binary.parent) == []
    assert not binary.with_name("axross-full.previous").exists()


@pytest.mark.parametrize("api_digest", [True, False], ids=["with-api-digest", "sums-only"])
def test_sad_missing_sha256sums_entry_is_refused(fake, binary, api_digest):
    fake.release.sums_override["axross-full"] = ""
    if not api_digest:  # the SHA256SUMS layer alone, without GitHub's digest behind it
        fake.release.digest_override["axross-full"] = ""
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.ChecksumError, match="no entry for axross-full"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert binary.read_bytes() == OLD_BYTES and leftovers(binary.parent) == []
    assert ASSET_HOST in fake.hosts() and fake.hosts().count(WEB_HOST) == 1  # binary not fetched


def test_sad_a_release_without_sha256sums_is_refused(fake, binary):
    fake.release.without_sums = True
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.ChecksumError, match="SHA256SUMS"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert fake.hosts() == [API_HOST]


def test_sad_api_digest_disagreeing_with_sha256sums_is_refused(fake, binary):
    fake.release.digest_override["axross-full"] = "0" * 64
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.ChecksumError, match="digest"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert binary.read_bytes() == OLD_BYTES


def test_sad_a_redirect_to_another_host_is_refused(fake, binary):
    fake.redirect_to = "https://evil.example"
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.UpdateError, match="evil.example"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert "evil.example" not in fake.hosts()
    assert binary.read_bytes() == OLD_BYTES and leftovers(binary.parent) == []


def test_sad_a_redirect_to_plain_http_is_refused(fake, binary):
    fake.redirect_to = f"http://{ASSET_HOST}"
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.UpdateError, match="https"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))


def test_sad_a_redirect_loop_ends(fake, binary):
    fake.redirect_loop = True
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.UpdateError, match="redirect"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert fake.hosts().count(WEB_HOST) == SU.MAX_REDIRECTS + 1


def test_sad_more_bytes_than_stated_are_refused(fake, binary):
    fake.release.size_override["axross-full"] = len(NEW_BYTES) - 100
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.UpdateError, match="larger"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert leftovers(binary.parent) == [] and binary.read_bytes() == OLD_BYTES


def test_sad_an_asset_above_the_bound_is_not_downloaded(fake, binary):
    fake.release.size_override["axross-full"] = SU.MAX_ASSET_BYTES + 1
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.UpdateError, match="larger"):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert fake.hosts().count(ASSET_HOST) <= 1  # at most SHA256SUMS


def test_edge_a_cut_download_leaves_nothing(fake, binary):
    fake.cut_after["axross-full"] = 70000
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.UpdateError):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert leftovers(binary.parent) == [] and binary.read_bytes() == OLD_BYTES


def test_edge_cancel_during_the_download_cleans_up(fake, binary):
    cancel = threading.Event()
    fake.on_chunk = lambda sent: cancel.set() if sent > 100000 else None
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.Cancelled):
        SU.update(release, frozen_install(binary), opener=opener_for(fake), cancel=cancel)
    assert leftovers(binary.parent) == [] and binary.read_bytes() == OLD_BYTES


def test_edge_stale_partial_files_of_an_earlier_run_are_removed(fake, binary):
    stale = binary.parent / ".axross-full.update-dead.part"
    stale.write_bytes(b"half")
    release = SU.check(opener=opener_for(fake)).release
    SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert not stale.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes into a read-only folder")
def test_sad_read_only_folder_downloads_to_the_cache_instead(fake, binary, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    binary.parent.chmod(0o555)
    try:
        release = SU.check(opener=opener_for(fake)).release
        result = SU.update(release, frozen_install(binary), opener=opener_for(fake))
    finally:
        binary.parent.chmod(0o755)
    assert not result.replaced
    assert binary.read_bytes() == OLD_BYTES
    assert result.path.parent == tmp_path / "cache" / "axross" / "update"
    assert result.path.read_bytes() == NEW_BYTES
    assert "not writable" in result.how_to_finish and "Save to" in result.how_to_finish
    saved = SU.save_copy(result, tmp_path / "saved-axross")
    assert saved.read_bytes() == NEW_BYTES
    assert stat.S_IMODE(saved.stat().st_mode) == 0o755


def test_sad_install_refuses_a_read_only_folder(fake, binary, tmp_path):
    release = SU.check(opener=opener_for(fake)).release
    downloaded = SU.download(release, frozen_install(binary), dest_dir=tmp_path,
                             opener=opener_for(fake))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(SU, "_writable", lambda folder: False)
        with pytest.raises(SU.NotWritable):
            SU.install(downloaded, frozen_install(binary))
    assert binary.read_bytes() == OLD_BYTES


def test_edge_windows_downloads_next_to_the_exe_and_says_how_to_finish(fake, tmp_path):
    folder = tmp_path / "win"
    folder.mkdir()
    exe = folder / "axross-slim-windows-x64.exe"
    exe.write_bytes(b"MZ old")
    inst = frozen_install(exe, flavor="slim", platform="win32", machine="AMD64")
    release = SU.check(opener=opener_for(fake)).release
    result = SU.update(release, inst, opener=opener_for(fake))
    assert not result.replaced and exe.read_bytes() == b"MZ old"
    assert result.path == folder / f"axross-slim-windows-x64-{NEW}.exe"
    assert result.path.read_bytes() == fake.release.files["axross-slim-windows-x64.exe"]
    assert exe.name in result.how_to_finish and result.path.name in result.how_to_finish
    assert not (folder / "axross-slim-windows-x64.exe.previous").exists()


def test_sad_nothing_runs_before_the_checksum_matched(fake, binary, monkeypatch):
    import subprocess

    started = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: started.append(a))
    monkeypatch.setattr(os, "execv", lambda *a: started.append(a))
    fake.served_override["axross-full"] = b"Y" * len(NEW_BYTES)
    release = SU.check(opener=opener_for(fake)).release
    with pytest.raises(SU.ChecksumError):
        SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert started == []


def test_happy_restart_starts_the_verified_binary_detached(binary, monkeypatch):
    calls = []

    class FakePopen:
        def __init__(self, args, **kwargs):
            calls.append((args, kwargs))

    monkeypatch.setenv("_PYI_APPLICATION_HOME_DIR", "/tmp/_MEIxyz")
    SU.restart(binary, popen=FakePopen)
    (args, kwargs), = calls
    assert args == [str(binary)]
    assert kwargs["start_new_session"] is True
    assert kwargs["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert "_PYI_APPLICATION_HOME_DIR" not in kwargs["env"]


def test_sad_restart_refuses_a_binary_changed_since_it_was_verified(fake, binary):
    release = SU.check(opener=opener_for(fake)).release
    result = SU.update(release, frozen_install(binary), opener=opener_for(fake))
    assert result.sha256 == hashlib.sha256(NEW_BYTES).hexdigest()
    started = []
    SU.restart(binary, expected_sha256=result.sha256, popen=lambda *a, **k: started.append(a))
    assert len(started) == 1
    binary.write_bytes(b"swapped after the check")
    with pytest.raises(SU.ChecksumError, match="changed"):
        SU.restart(binary, expected_sha256=result.sha256,
                   popen=lambda *a, **k: started.append(a))
    assert len(started) == 1


def test_sad_restart_refuses_a_file_that_is_not_executable(tmp_path):
    plain = tmp_path / "axross-full"
    plain.write_bytes(b"x")
    plain.chmod(0o644)
    with pytest.raises(SU.UpdateError):
        SU.restart(plain, popen=lambda *a, **k: None)


# --- the proxy -----------------------------------------------------------------


def test_happy_the_default_proxy_is_used(monkeypatch, tmp_path):
    from core import proxy_settings as PS

    monkeypatch.setattr(PS, "SETTINGS_PATH", tmp_path / "proxy.json")
    PS.save(PS.ProxyDefaults(proxy_type="http", host="proxy.example.org", port=3128))
    handler = SU.proxy_handler()
    assert handler.proxies["https"] == "http://proxy.example.org:3128"


def test_edge_without_a_default_proxy_the_environment_counts(monkeypatch, tmp_path):
    from core import proxy_settings as PS

    monkeypatch.setattr(PS, "SETTINGS_PATH", tmp_path / "proxy.json")
    monkeypatch.setenv("https_proxy", "http://envproxy.example.org:8080")
    assert SU.proxy_handler().proxies["https"] == "http://envproxy.example.org:8080"


def test_sad_an_unreadable_proxy_file_fails_closed(monkeypatch, tmp_path):
    from core import proxy_settings as PS

    bad = tmp_path / "proxy.json"
    bad.write_text("{broken")
    monkeypatch.setattr(PS, "SETTINGS_PATH", bad)
    with pytest.raises(SU.UpdateError, match="proxy"):
        SU.proxy_handler()


def test_happy_e2e_real_tls_through_the_default_proxy(monkeypatch, tmp_path):
    """The whole check over real TLS, through a real CONNECT proxy taken
    from Settings > Network & Proxy."""
    import ssl

    from core import proxy_settings as PS
    from tests.proxy_http_testkit import FakeHttpProxy, TestPki
    from tests.proxy_testkit import allow_loopback_proxy

    pki = TestPki()
    cert = pki.issue(API_HOST, WEB_HOST, ASSET_HOST)
    server = FakeGitHub(FakeRelease(NEW, {"axross-full": NEW_BYTES}), tls=cert)
    routes = {(h, 443): ("127.0.0.1", server.port) for h in (API_HOST, WEB_HOST, ASSET_HOST)}
    proxy = FakeHttpProxy(routes)
    monkeypatch.setattr(PS, "SETTINGS_PATH", tmp_path / "proxy.json")
    PS.save(PS.ProxyDefaults(proxy_type="http", host="127.0.0.1", port=proxy.port))
    context = ssl.create_default_context(cafile=pki.ca_file)
    try:
        with allow_loopback_proxy():
            opener = SU.build_opener(ssl_context=context)
            result = SU.check(opener=opener)
            exe = tmp_path / "axross-full"
            exe.write_bytes(OLD_BYTES)
            exe.chmod(0o755)
            SU.update(result.release, frozen_install(exe), opener=opener)
    finally:
        proxy.close()
        server.close()
    assert result.newer
    assert exe.read_bytes() == NEW_BYTES
    assert proxy.connects[0] == f"{API_HOST}:443"
    assert f"{ASSET_HOST}:443" in proxy.connects


# --- settings ------------------------------------------------------------------


def test_happy_settings_defaults_and_round_trip(settings):
    assert SU.check_at_start() is True
    assert SU.auto_download() is False
    assert SU.skipped_version() == ""
    SU.set_check_at_start(False)
    SU.set_auto_download(True)
    SU.set_skipped_version("0.14.2")
    data = json.loads(settings.read_text())
    assert data[SU.SETTING_CHECK] is False and data[SU.SETTING_AUTO] is True
    assert (SU.check_at_start(), SU.auto_download(), SU.skipped_version()) == \
        (False, True, "0.14.2")


def test_sad_hand_edited_values_read_as_defaults(settings):
    settings.write_text(json.dumps({SU.SETTING_CHECK: "no", SU.SETTING_AUTO: 1,
                                    SU.SETTING_SKIPPED: "../evil", SU.SETTING_LAST: [1]}))
    assert SU.check_at_start() is True and SU.auto_download() is False
    assert SU.skipped_version() == "" and SU.last_check() == (None, "")
    with pytest.raises(ValueError):
        SU.set_check_at_start("yes")
    with pytest.raises(ValueError):
        SU.set_skipped_version("1.2")


def test_edge_last_check_is_recorded_cleaned_and_bounded(settings):
    SU.record_check("Up to date\x1b[31m " + "x" * 1000, when=1792951335.0)
    when, text = SU.last_check()
    assert when == 1792951335.0
    assert "\x1b" not in text and len(text) <= SU.MAX_STATUS_CHARS


def test_happy_start_check_allowed_by_default(settings):
    assert SU.start_check_allowed() == (True, "")


def test_edge_start_check_switched_off_three_ways(settings, monkeypatch):
    from core import security_mode as SM

    SU.set_check_at_start(False)
    assert SU.start_check_allowed()[0] is False
    SU.set_check_at_start(True)
    monkeypatch.setenv(SU.NO_CHECK_ENV, "1")
    assert SU.start_check_allowed()[0] is False
    monkeypatch.delenv(SU.NO_CHECK_ENV)
    monkeypatch.setattr(SM, "_CURRENT", SM.policy_from_name("paranoid"))
    allowed, reason = SU.start_check_allowed()
    assert not allowed and "paranoid" in reason.lower()


def test_happy_the_bundle_records_its_flavor():
    """build/axross.spec writes the marker file this module reads, in the
    folder this module reads it from."""
    spec = (Path(__file__).resolve().parent.parent / "build" / "axross.spec").read_text()
    folder, name = SU.FLAVOR_PATH
    assert f'"{name}"' in spec
    assert f'datas.append((_flavor_file, "{folder}"))' in spec


def test_sad_the_flavor_marker_is_no_unclaimed_part_of_the_bundle():
    """The release gate (tests/test_third_party_bundle.py on a built binary)
    fails on every bundled file no entry and no first-party folder claims;
    the marker must sit in a first-party folder."""
    from core import third_party as T

    toc = [("x", "/".join(SU.FLAVOR_PATH))]
    report = T.classify_bundle([], "axross-full", toc, [], T.stdlib_modules())
    assert report.unclaimed == []
    at_root = T.classify_bundle([], "axross-full", [("x", SU.FLAVOR_FILE)], [],
                                T.stdlib_modules())
    assert at_root.unclaimed  # the negative control: the bundle root is not first-party


def test_happy_sha256sums_parse_like_sha256sum_writes_them():
    digest = hashlib.sha256(b"a").hexdigest()
    text = f"{digest}  axross-full\n{digest} *axross-slim\n\n# comment\nbad line\n"
    assert SU.parse_sums(text) == {"axross-full": digest, "axross-slim": digest}


# --- the docs ----------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
GUIDES = ("docs/USAGE.md", "docs/USAGE_de.md", "docs/USAGE_es.md")
UI_LABELS = ("Download and Install", "Skip This Version", "Remind Me Later", "Restart Now",
             "Save to…", "Check Now", "Check for updates at start",
             "Download updates automatically", "Check for Updates…")


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_documents_the_update(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    assert "\n| Updates | " in text and "\n## Updates\n" in text
    for needle in (SU.NO_CHECK_ENV, "SHA256SUMS", ".previous", "pip install -U axross",
                   "~/.cache/axross/update/", "release-assets.githubusercontent.com"):
        assert needle in text, needle


def test_happy_packaging_and_opsec_document_the_contract():
    packaging = (ROOT / "docs/PACKAGING.md").read_text(encoding="utf-8")
    for needle in (SU.FLAVOR_FILE, SU.NO_CHECK_ENV, SU.SUMS_NAME, "axross-slim-macos-arm64",
                   "axross-slim-windows-x64.exe", *sorted(SU.ALLOWED_HOSTS)):
        assert needle in packaging, needle
    assert SU.NO_CHECK_ENV in (ROOT / "docs/OPSEC.md").read_text(encoding="utf-8")


def test_sad_the_labels_the_docs_name_exist_in_the_code():
    """A renamed button fails here, not in a user's hands."""
    code = (ROOT / "ui/update_ui.py").read_text(encoding="utf-8") + \
        (ROOT / "ui/main_window.py").read_text(encoding="utf-8")
    english = " ".join((ROOT / "docs/USAGE.md").read_text(encoding="utf-8").split())
    for label in UI_LABELS:
        assert label.replace("Updates…", "&Updates…") in code or label in code, label
        assert label in english, label
