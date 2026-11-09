"""The licence texts of what python-build-standalone links into libpython.

scripts/build_dist.sh builds with uv's CPython, a python-build-standalone
"install_only" archive: it carries CPython's LICENSE.txt, but not the
licences of the libraries linked into libpython and its extension modules
(OpenSSL, libffi, SQLite, ...). The "full" archive of the same build has
them, in python/licenses/, and python/PYTHON.json names which belongs to
what. This fetches that archive as pinned in build/python-standalone.txt
and keeps only those files:

    python scripts/python_licences.py build/python-standalone.txt OUT --python PY

* the archive's SHA-256 must be the pinned one, before anything is read;
* the pin must name PY's version, and the release uv recorded in PY's
  installation (its BUILD file, where uv writes one);
* only ``python/PYTHON.json`` and regular files directly in
  ``python/licenses/`` are written, to OUT/PYTHON.json and OUT/licenses/;
  every other member - links, folders, anything with ".." - is skipped;
* PYTHON.json must name PY's version.

scripts/bundle_licenses.py bundles OUT (``AXROSS_PYTHON_LICENSES``) into
licenses/system/python/. A zstd-packed archive needs ``zstandard`` (the
build-tools venv has it).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sysroot_fetch import _stream, get, sha256  # noqa: E402

MEMBERS_PREFIX = "python/"


def read_pin(path: Path) -> dict[str, str]:
    """``key value`` lines (``#`` comments): version, release, url, sha256."""
    pin: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        pin[key] = value.strip()
    missing = [k for k in ("version", "release", "url", "sha256") if not pin.get(k)]
    if missing:
        raise SystemExit(f"{path}: no {', '.join(missing)}")
    return pin


def checked(data: bytes, expected: str) -> bytes:
    """*data* when its SHA-256 is *expected*; otherwise the fetch stops."""
    found = sha256(data)
    if found != expected.lower():
        raise SystemExit(f"the python-build-standalone archive has SHA-256 {found}, "
                         f"the pin says {expected}")
    return data


def _wanted(name: str) -> str | None:
    """The file below OUT that member *name* becomes, or None."""
    while name.startswith("./"):
        name = name[2:]
    if name == "python/PYTHON.json":
        return "PYTHON.json"
    if not name.startswith("python/licenses/"):
        return None
    rest = name[len("python/licenses/"):]
    if not rest or "/" in rest or "\\" in rest or rest in (".", "..") or rest.startswith("."):
        return None
    return f"licenses/{rest}"


def extract(data: bytes, out: Path) -> list[str]:
    """PYTHON.json and the licence files of the archive *data* into *out*;
    the names written, relative to *out*."""
    (out / "licenses").mkdir(parents=True, exist_ok=True)
    for old in [out / "PYTHON.json", *(out / "licenses").iterdir()]:
        if old.is_symlink() or old.is_file():
            old.unlink()  # an earlier run's: only this archive's files count
    written: list[str] = []
    with tarfile.open(fileobj=_stream(data), mode="r|") as archive:
        for member in archive:
            rel = _wanted(member.name)
            if rel is None or not member.isreg():
                continue
            target = out / rel
            if target.is_symlink() or target.exists():
                target.unlink()
            with archive.extractfile(member) as src, \
                    open(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "wb") as dst:
                dst.write(src.read())
            written.append(rel)
    if "PYTHON.json" not in written:
        raise SystemExit("the python-build-standalone archive has no python/PYTHON.json")
    return written


def python_facts(python: str) -> tuple[str, str]:
    """(version, installation folder) of the interpreter *python*."""
    out = subprocess.run([python, "-I", "-c", "import platform, sys; "
                          "print(platform.python_version()); print(sys.base_prefix)"],
                         capture_output=True, text=True, check=True).stdout.split("\n")
    return out[0].strip(), out[1].strip()


def check_matches(pin: dict[str, str], version: str, prefix: str) -> None:
    """The pin is of *version* and - where uv recorded it - of the release
    the installation at *prefix* came from."""
    if pin["version"] != version:
        raise SystemExit(f"build/python-standalone.txt pins CPython {pin['version']}, "
                         f"the build runs {version}: pin that version's archive")
    build = Path(prefix) / "BUILD"
    if build.is_file():
        release = build.read_text(encoding="utf-8").strip()
        if release and release != pin["release"]:
            raise SystemExit(f"the CPython at {prefix} is python-build-standalone {release}, "
                             f"the pin is of {pin['release']}")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    pin = read_pin(Path(argv[1]))
    out = Path(argv[2]).resolve()
    if "--python" in argv:
        version, prefix = python_facts(argv[argv.index("--python") + 1])
        check_matches(pin, version, prefix)
    cache = out.parent / (out.name + ".archive")
    data = cache.read_bytes() if cache.is_file() else b""
    if sha256(data) != pin["sha256"]:
        data = checked(get(pin["url"]), pin["sha256"])
        cache.write_bytes(data)
    written = extract(data, out)
    meta = json.loads((out / "PYTHON.json").read_text(encoding="utf-8"))
    if meta.get("python_version") != pin["version"]:
        raise SystemExit(f"PYTHON.json is of CPython {meta.get('python_version')}, "
                         f"not {pin['version']}")
    print(f"python-build-standalone {pin['release']}: {len(written)} files -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
