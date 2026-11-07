#!/usr/bin/env python3
"""Build the packs of a release: ``build_packs.py OUT_DIR VERSION [--platform linux-x86_64]``.

For every unit (core.units) the locked wheels of its distributions for the
platform - the very files the supply-chain gate checked (taken from its
cache by their SHA-256, downloaded and checked by it when missing) - are
copied into OUT_DIR, and ``packs-<VERSION>.json`` (core.packs) is written
next to them, with each wheel's size, SHA-256 and PyPI address. OUT_DIR's
``SHA256SUMS`` gets a line for each; signing it (scripts/sign_release.py)
signs the packs with the rest of the release.

Run by scripts/build_dist.sh after the gate passed.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import packs as P  # noqa: E402
from core import units as U  # noqa: E402
from security import supply_chain_gate as G  # noqa: E402


def _for_platform(marker: str, platform: str) -> bool:
    """Whether a lock marker can hold on *platform* (the markers the locks use)."""
    marker = marker.replace("'", '"')
    system = {"linux-x86_64": "linux", "macos-arm64": "darwin", "windows-amd64": "win32"}[platform]
    for other in ("linux", "darwin", "win32"):
        if f'sys_platform == "{other}"' in marker and other != system:
            return False
        if f'sys_platform != "{other}"' in marker and other == system:
            return False
    return True


def locked_wheels(platform: str, wheel_python: str = "", workdir: Path | None = None,
                  wanted: set | None = None, other_platform: set | None = None
                  ) -> dict[str, tuple[str, str, int, str, Path]]:
    """distribution -> (file name, sha256, size, PyPI url, cached path). A
    pin with only an sdist (reviewed by the gate, build hooks included) is
    built into a wheel with *wheel_python* (the build venv: no network, no
    build isolation) - its PyPI url is then ""."""
    import subprocess
    import tempfile

    out = {}
    for rel, pin in G.read_locks():
        if not rel.endswith("requirements-bundle.txt"):
            continue
        name = U.canonical(pin.name)
        if name in out or (wanted is not None and name not in wanted):
            continue
        if not _for_platform(pin.marker, platform):
            if other_platform is not None:
                other_platform.add(name)          # locked for another system only: not needed here
            continue
        release = G.pypi_release(pin.name, pin.version)
        files = G.files_for(release.get("urls", []), set(pin.hashes), [platform])
        wheels = [f for f in files if f["filename"].endswith(".whl")]
        if not wheels:
            sdists = [f for f in files if not f["filename"].endswith(".whl")]
            if not sdists or not wheel_python:
                continue
            f = sdists[0]
            src = G.download(f["url"], f["digests"]["sha256"], f["filename"])
            target = Path(tempfile.mkdtemp(prefix="packs-wheel-", dir=workdir))
            proc = subprocess.run([wheel_python, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
                                   "--no-index", "--wheel-dir", str(target), str(src)],
                                  capture_output=True, text=True, timeout=600)
            built = list(target.glob("*.whl"))
            if proc.returncode != 0 or len(built) != 1:
                raise SystemExit(f"{pin.name}: its wheel could not be built from the sdist:\n"
                                 f"{proc.stderr[-800:]}")
            data = built[0].read_bytes()
            out[name] = (built[0].name, hashlib.sha256(data).hexdigest(), len(data), "", built[0])
            continue
        f = wheels[0]
        sha = f["digests"]["sha256"]
        path = G.download(f["url"], sha, f["filename"])
        out[name] = (f["filename"], sha, f["size"], f["url"], path)
    return out


def _glibc_needed(filename: str) -> tuple[int, int]:
    """The glibc a manylinux wheel needs; (0, 0) for a pure one."""
    need = (0, 0)
    for tag in filename[:-4].split("-")[-1].split("."):
        m = re.match(r"manylinux_(\d+)_(\d+)_", tag)
        legacy = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}
        version = (int(m.group(1)), int(m.group(2))) if m else next(
            (v for k, v in legacy.items() if tag.startswith(k + "_")), None)
        if version is not None:
            need = version if need == (0, 0) else min(need, version)   # any one tag that fits
    return need


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", type=Path)
    ap.add_argument("version")
    ap.add_argument("--platform", default="linux-x86_64", choices=sorted(G.PLATFORMS))
    ap.add_argument("--wheel-python", default="",
                    help="a Python with pip, setuptools and wheel to build sdist-only pins")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    import dataclasses

    units = U.units()
    wanted = {d for u in units for d in u.distributions}
    elsewhere: set = set()
    wheels = locked_wheels(args.platform, args.wheel_python, wanted=wanted, other_platform=elsewhere)
    elsewhere -= set(wheels)
    units = [dataclasses.replace(u, distributions=u.distributions - elsewhere) for u in units]
    missing = sorted({d for u in units for d in u.distributions if d not in wheels})
    if missing:
        print(f"no {args.platform} wheel for: {', '.join(missing)} - their units are left out", file=sys.stderr)
        units = [u for u in units if not u.distributions & set(missing)]
    too_new = [w[0] for w in wheels.values() if _glibc_needed(w[0]) > (2, 34)]
    if too_new:
        raise SystemExit(f"wheels need a newer glibc than the base's 2.34: {', '.join(too_new)}")
    manifest = P.build_manifest(args.version, args.platform,
                                {d: w[:4] for d, w in wheels.items()}, units)
    for name in manifest["blobs"]:
        dist = manifest["blobs"][name]["distribution"]
        src = wheels[dist][4]
        if hashlib.sha256(src.read_bytes()).hexdigest() != manifest["blobs"][name]["sha256"]:
            raise SystemExit(f"{name}: the cached file is not the locked one")
        shutil.copyfile(src, args.out / name)
    mpath = P.write_manifest(manifest, args.out)
    lines = []
    for f in sorted(args.out.iterdir()):
        if f.is_file() and f.name not in ("SHA256SUMS", "SHA256SUMS.sig"):
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n")
    (args.out / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    print(f"{len(manifest['units'])} units, {len(manifest['blobs'])} wheels -> {mpath}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
