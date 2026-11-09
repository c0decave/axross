"""scripts/python_licences.py: the licence texts of what python-build-standalone
links into libpython (OpenSSL, libffi, SQLite, ...), from the full archive
of the build scripts/build_dist.sh runs with, hash-pinned in
build/python-standalone.txt.

The archive comes from GitHub's release downloads: whoever could swap it
must not get a file of their choice into the binaries, so the pinned
SHA-256 is checked before anything is read, and only PYTHON.json and the
plain files of python/licenses/ are ever written. Made-up archives here,
no network.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import python_licences as PL  # noqa: E402

META = {"python_version": "3.12.8", "licenses": ["Python-2.0", "CNRI-Python"],
        "license_path": "licenses/LICENSE.cpython.txt"}


def archive(members, *, compress=gzip.compress) -> bytes:
    """A tar of (name, kind, payload); kind file, dir or symlink."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.type, info.linkname = tarfile.SYMTYPE, payload
                tar.addfile(info)
    return compress(out.getvalue())


def standalone(meta=META, extra=(), compress=gzip.compress) -> bytes:
    return archive([("python/", "dir", None),
                    ("python/PYTHON.json", "file", json.dumps(meta).encode()),
                    ("python/licenses/", "dir", None),
                    ("python/licenses/LICENSE.openssl-3.txt", "file", b"Apache-2.0\n"),
                    ("python/licenses/LICENSE.zlib.txt", "file", b"zlib\n"),
                    ("python/install/lib/libpython3.12.so.1.0", "file", b"\x7fELF"),
                    *extra], compress=compress)


def pin_file(tmp_path: Path, data: bytes, **override) -> Path:
    pin = {"version": "3.12.8", "release": "20250115",
           "url": "https://github.invalid/cpython-3.12.8%2B20250115-full.tar.zst",
           "sha256": hashlib.sha256(data).hexdigest(), **override}
    path = tmp_path / "python-standalone.txt"
    path.write_text("# comment\n" + "".join(f"{k} {v}\n" for k, v in pin.items()))
    return path


# --- happy -----------------------------------------------------------------


def test_happy_the_pinned_archive_gives_python_json_and_the_licences(tmp_path, monkeypatch):
    data = standalone()
    fetched = []
    monkeypatch.setattr(PL, "get", lambda url: fetched.append(url) or data)
    out = tmp_path / "python-licences"
    assert PL.main(["x", str(pin_file(tmp_path, data)), str(out)]) == 0
    assert fetched == ["https://github.invalid/cpython-3.12.8%2B20250115-full.tar.zst"]
    assert json.loads((out / "PYTHON.json").read_text())["python_version"] == "3.12.8"
    assert sorted(p.name for p in (out / "licenses").iterdir()) == \
        ["LICENSE.openssl-3.txt", "LICENSE.zlib.txt"]
    # the archive is kept: a second run checks it and fetches nothing
    monkeypatch.setattr(PL, "get", lambda url: pytest.fail("fetched again"))
    assert PL.main(["x", str(pin_file(tmp_path, data)), str(out)]) == 0


def test_happy_a_zstd_archive_as_github_publishes_it(tmp_path):
    zstandard = pytest.importorskip("zstandard")
    data = standalone(compress=lambda raw: zstandard.ZstdCompressor().compress(raw))
    assert PL.extract(data, tmp_path / "out") == [
        "PYTHON.json", "licenses/LICENSE.openssl-3.txt", "licenses/LICENSE.zlib.txt"]


def test_happy_the_pin_in_the_tree_names_3_12_8_of_its_release():
    pin = PL.read_pin(ROOT / "build" / "python-standalone.txt")
    assert pin["version"] == "3.12.8" and pin["release"] == "20250115"
    assert pin["url"].startswith("https://github.com/astral-sh/python-build-standalone/"
                                 "releases/download/20250115/cpython-3.12.8%2B20250115-")
    assert pin["url"].endswith("-full.tar.zst") and len(pin["sha256"]) == 64
    build_dist = (ROOT / "scripts" / "build_dist.sh").read_text()
    assert f'PYTHON_VERSION={pin["version"]}' in build_dist


# --- sad -------------------------------------------------------------------


def test_sad_an_archive_with_another_hash_is_refused_before_it_is_read(tmp_path, monkeypatch):
    good = standalone()
    swapped = standalone(extra=[("python/licenses/LICENSE.evil.txt", "file", b"x")])
    monkeypatch.setattr(PL, "get", lambda url: swapped)
    out = tmp_path / "python-licences"
    with pytest.raises(SystemExit, match="SHA-256"):
        PL.main(["x", str(pin_file(tmp_path, good)), str(out)])
    assert not out.exists()
    assert not (tmp_path / "python-licences.archive").exists()


def test_sad_members_outside_the_licences_never_land(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    data = standalone(extra=[
        ("python/licenses/../../escape.txt", "file", b"x"),
        ("python/licenses/sub/nested.txt", "file", b"x"),
        ("python/licenses/link.txt", "symlink", "/etc/passwd"),
        ("python/licenses/.hidden", "file", b"x"),
        ("/python/licenses/absolute.txt", "file", b"x"),
        ("python/install/PYTHON.json", "file", b"{}"),
        ("python/LICENSE.other.txt", "file", b"x")])
    out = tmp_path / "out"
    written = PL.extract(data, out)
    assert written == ["PYTHON.json", "licenses/LICENSE.openssl-3.txt",
                       "licenses/LICENSE.zlib.txt"]
    files = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file())
    assert files == ["out/PYTHON.json", "out/licenses/LICENSE.openssl-3.txt",
                     "out/licenses/LICENSE.zlib.txt"]
    assert not any(p.is_symlink() for p in out.rglob("*"))


def test_sad_a_pin_of_another_version_or_release_is_refused(tmp_path):
    pin = PL.read_pin(pin_file(tmp_path, b""))
    with pytest.raises(SystemExit, match="runs 3.12.16"):
        PL.check_matches(pin, "3.12.16", str(tmp_path))
    (tmp_path / "BUILD").write_text("20250106\n")  # uv records the release it installed
    with pytest.raises(SystemExit, match="20250106"):
        PL.check_matches(pin, "3.12.8", str(tmp_path))
    (tmp_path / "BUILD").write_text("20250115\n")
    PL.check_matches(pin, "3.12.8", str(tmp_path))


def test_sad_an_archive_without_python_json_or_of_another_version_is_refused(
        tmp_path, monkeypatch):
    bare = archive([("python/licenses/LICENSE.zlib.txt", "file", b"zlib\n")])
    with pytest.raises(SystemExit, match="no python/PYTHON.json"):
        PL.extract(bare, tmp_path / "bare")
    other = standalone(meta={**META, "python_version": "3.12.7"})
    monkeypatch.setattr(PL, "get", lambda url: other)
    with pytest.raises(SystemExit, match="3.12.7"):
        PL.main(["x", str(pin_file(tmp_path, other)), str(tmp_path / "out")])


# --- edge ------------------------------------------------------------------


def test_edge_a_rerun_leaves_no_file_of_an_earlier_archive(tmp_path):
    out = tmp_path / "out"
    PL.extract(standalone(extra=[("python/licenses/LICENSE.tcl.txt", "file", b"tcl")]), out)
    assert (out / "licenses/LICENSE.tcl.txt").exists()
    PL.extract(standalone(), out)
    assert sorted(p.name for p in (out / "licenses").iterdir()) == \
        ["LICENSE.openssl-3.txt", "LICENSE.zlib.txt"]


def test_edge_an_incomplete_pin_is_refused(tmp_path):
    path = tmp_path / "pin.txt"
    path.write_text("version 3.12.8\nurl https://x\n")
    with pytest.raises(SystemExit, match="release, sha256"):
        PL.read_pin(path)
