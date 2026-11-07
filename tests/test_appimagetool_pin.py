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
    assert 'bash "$SCRIPT_DIR/fetch_appimagetool.sh" "$DL"' in text
    assert "curl" not in text.split("# AppImage wrap", 1)[1]


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
