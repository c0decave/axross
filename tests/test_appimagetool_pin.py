"""--appimage fetches a pinned appimagetool and checks its SHA-256.

scripts/build_bundle.sh downloaded appimagetool from the ``continuous`` tag -
a file that changes under the same URL - with no checksum, and reused any
cached copy. scripts/fetch_appimagetool.sh pins release 1.9.1 by URL and
digest, verifies a cached copy on every build, and leaves nothing at the
destination when a download does not match.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FETCH = ROOT / "scripts" / "fetch_appimagetool.sh"
BUNDLE = ROOT / "scripts" / "build_bundle.sh"
APPIMAGE = ROOT / "scripts" / "build_appimage.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("curl") is None
    or shutil.which("sha256sum") is None,
    reason="needs bash, curl and sha256sum",
)


def _pin(name: str) -> str:
    match = re.search(rf'^{name}="([^"]+)"$', FETCH.read_text(encoding="utf-8"), re.M)
    assert match, name
    return match.group(1)


def _fetch(dest: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(FETCH), str(dest), *args],
                          capture_output=True, text=True, timeout=60, check=False)


def test_happy_the_pin_is_a_release_and_a_sha256() -> None:
    version = _pin("APPIMAGETOOL_VERSION")
    assert re.fullmatch(r"\d+\.\d+(\.\d+)?", version), version
    assert re.fullmatch(r"[0-9a-f]{64}", _pin("APPIMAGETOOL_SHA256"))
    url = _pin("APPIMAGETOOL_URL")
    assert url.startswith("https://github.com/AppImage/appimagetool/releases/download/")
    assert "continuous" not in FETCH.read_text(encoding="utf-8").split("set -euo")[1]


def test_happy_the_bundle_script_fetches_through_the_pin() -> None:
    text = BUNDLE.read_text(encoding="utf-8")
    assert "continuous" not in text
    assert 'bash "$SCRIPT_DIR/build_appimage.sh"' in text
    assert "curl" not in text.split("# AppImage wrap", 1)[1]
    image = APPIMAGE.read_text(encoding="utf-8")
    assert 'bash "$SCRIPT_DIR/fetch_appimagetool.sh" "$APPIMAGETOOL"' in image
    assert "curl" not in image and "wget" not in image


def test_happy_the_runtime_is_pinned_and_given_to_appimagetool() -> None:
    """The type-2 runtime is part of every AppImage built: appimagetool must
    not fetch its "continuous" build, so the pinned one goes in with
    --runtime-file."""
    assert re.fullmatch(r"\d{8}", _pin("APPIMAGE_RUNTIME_VERSION"))
    assert re.fullmatch(r"[0-9a-f]{64}", _pin("APPIMAGE_RUNTIME_SHA256"))
    assert _pin("APPIMAGE_RUNTIME_URL").startswith(
        "https://github.com/AppImage/type2-runtime/releases/download/${APPIMAGE_RUNTIME_VERSION}/")
    image = APPIMAGE.read_text(encoding="utf-8")
    assert 'fetch_appimagetool.sh" "$RUNTIME" --runtime' in image
    assert '--runtime-file "$RUNTIME"' in image
    call = next(line for line in image.splitlines() if '"$TOOL" --no-appstream' in line)
    assert not re.search(r" -(g|u)\b|--guess|--updateinformation|--sign", call)


def test_happy_the_dist_builds_the_appimages_through_the_script() -> None:
    dist = (ROOT / "scripts" / "build_dist.sh").read_text(encoding="utf-8")
    assert 'bash "$SRC/scripts/build_appimage.sh"' in dist
    assert '"$OUT/glibc-2.34/axross-$flavor" "$OUT/appimage/axross-$flavor-x86_64.AppImage"' in dist


def test_happy_runtime_mode_fetches_the_runtime_pin(tmp_path) -> None:
    """--runtime selects the runtime's pin; --url / --sha256 still override (tests)."""
    src = tmp_path / "runtime"
    src.write_bytes(b"runtime stand-in\n")
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    dest = tmp_path / "build" / "appimage-runtime-x86_64"
    done = _fetch(dest, "--runtime", "--url", src.as_uri(), "--sha256", digest)
    assert done.returncode == 0, done.stderr
    assert "AppImage runtime" in done.stdout
    assert dest.read_bytes() == src.read_bytes()


def test_happy_a_matching_download_lands_executable(tmp_path) -> None:
    src = tmp_path / "tool"
    src.write_bytes(b"appimagetool stand-in\n")
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    dest = tmp_path / "build" / "appimagetool-x86_64.AppImage"
    done = _fetch(dest, "--url", src.as_uri(), "--sha256", digest)
    assert done.returncode == 0, done.stderr
    assert dest.read_bytes() == src.read_bytes()
    assert dest.stat().st_mode & 0o111
    assert [p.name for p in dest.parent.iterdir()] == [dest.name]


def test_sad_a_mismatching_download_is_deleted_and_fails(tmp_path) -> None:
    src = tmp_path / "tool"
    src.write_bytes(b"something else\n")
    dest = tmp_path / "build" / "appimagetool-x86_64.AppImage"
    done = _fetch(dest, "--url", src.as_uri(), "--sha256", "0" * 64)
    assert done.returncode == 1
    assert "SHA-256 mismatch" in done.stderr
    assert not dest.exists()
    assert list(dest.parent.iterdir()) == []


def test_edge_a_cached_copy_with_another_digest_is_replaced(tmp_path) -> None:
    src = tmp_path / "tool"
    src.write_bytes(b"the pinned bytes\n")
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    dest = tmp_path / "appimagetool-x86_64.AppImage"
    dest.write_bytes(b"an old continuous build\n")
    dest.chmod(0o755)
    done = _fetch(dest, "--url", src.as_uri(), "--sha256", digest)
    assert done.returncode == 0, done.stderr
    assert dest.read_bytes() == src.read_bytes()


def test_edge_a_cached_copy_with_the_digest_is_reused_without_a_download(tmp_path) -> None:
    dest = tmp_path / "appimagetool-x86_64.AppImage"
    dest.write_bytes(b"cached\n")
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    done = _fetch(dest, "--url", (tmp_path / "missing").as_uri(), "--sha256", digest)
    assert done.returncode == 0, done.stderr
    assert "Downloading" not in done.stdout


def test_sad_a_malformed_digest_is_refused(tmp_path) -> None:
    done = _fetch(tmp_path / "x", "--sha256", "abc")
    assert done.returncode == 2
