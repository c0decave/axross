"""Packs: units (core.units) added to an axross-base from its GitHub
release - and, for the build, the manifest that describes them.

The chain of trust is the release's, nothing new: the release key signs
``SHA256SUMS`` (core.self_update, scripts/sign_release.py); ``SHA256SUMS``
lists ``packs-<version>.json``; the manifest lists every blob (a wheel, as
locked and passed by the supply-chain gate) with its size and SHA-256, and
``SHA256SUMS`` lists the blobs as well. :func:`install` checks in that
order - the signature against the pinned key, the manifest against
``SHA256SUMS``, each blob's size and SHA-256 against the manifest and
``SHA256SUMS`` - and only then unpacks, member by member (no path outside
its folder, no link), into ``~/.local/share/axross/packs/<version>/``.
A blob comes from the release, else from PyPI (the same file: the hash
decides). :func:`activate` puts the installed units' folders on sys.path
at start; :func:`remove` deletes a unit's blobs no other unit uses.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

MANIFEST_FORMAT = 1
MAX_MANIFEST = 4 * 1024 * 1024
MAX_BLOB = 512 * 1024 * 1024
PYPI_HOSTS = frozenset({"files.pythonhosted.org"})


class PackError(Exception):
    """A pack could not be installed; nothing of it was activated."""


def manifest_name(version: str) -> str:
    return f"packs-{version}.json"


def packs_root() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "axross" / "packs"


# --- the build side -----------------------------------------------------------------------

def build_manifest(version: str, platform: str, wheels: dict[str, tuple[str, str, int, str]],
                   units) -> dict:
    """*wheels*: distribution -> (file name, sha256, size, PyPI url) of the
    locked wheel for *platform*; *units*: core.units.Unit list."""
    blobs = {}
    out_units = {}
    for u in units:
        names = []
        for dist in sorted(u.distributions):
            if dist not in wheels:
                raise PackError(f"{u.name}: no {platform} wheel for {dist} in the lock")
            fname, sha, size, url = wheels[dist]
            blobs[fname] = {"distribution": dist, "sha256": sha, "size": size, "pypi": url}
            names.append(fname)
        out_units[u.name] = {"kind": u.kind, "title": u.title, "needs": list(u.needs), "blobs": names}
    return {"format": MANIFEST_FORMAT, "version": version, "platform": platform,
            "units": out_units, "blobs": blobs}


def write_manifest(manifest: dict, folder: Path) -> Path:
    path = folder / manifest_name(manifest["version"])
    path.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


# --- reading and checking -----------------------------------------------------------------

def parse_manifest(data: bytes) -> dict:
    if len(data) > MAX_MANIFEST:
        raise PackError("the pack manifest is too large")
    try:
        m = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise PackError(f"the pack manifest is no JSON: {exc}") from None
    if not isinstance(m, dict) or m.get("format") != MANIFEST_FORMAT:
        raise PackError("the pack manifest has an unknown format")
    for name, b in (m.get("blobs") or {}).items():
        if not _safe_name(name) or not isinstance(b, dict) or len(str(b.get("sha256", ""))) != 64 \
                or not isinstance(b.get("size"), int) or not 0 < b["size"] <= MAX_BLOB:
            raise PackError(f"the pack manifest's entry {name!r} is broken")
    for uname, u in (m.get("units") or {}).items():
        if not isinstance(u, dict) or any(b not in m["blobs"] for b in u.get("blobs", [])):
            raise PackError(f"unit {uname!r} names a blob the manifest does not list")
    return m


def _safe_name(name: str) -> bool:
    return bool(name) and len(name) < 200 and "/" not in name and "\\" not in name \
        and not name.startswith(".") and all(c.isalnum() or c in "._-+" for c in name)


def needed_blobs(manifest: dict, unit: str, seen=None) -> set[str]:
    """The blobs of *unit* and of every unit it needs."""
    seen = set() if seen is None else seen
    if unit in seen:
        return set()
    seen.add(unit)
    u = manifest["units"].get(unit)
    if u is None:
        raise PackError(f"the release has no unit {unit!r}")
    out = set(u.get("blobs", []))
    for n in u.get("needs", []):
        out |= needed_blobs(manifest, n, seen)
    return out


def _unpack(blob: Path, dest: Path) -> None:
    """A wheel into *dest*: members only below it, no links, no absolute
    paths; written into a temporary folder first, renamed at the end."""
    tmp = Path(tempfile.mkdtemp(prefix=".unpack-", dir=dest.parent))
    try:
        with zipfile.ZipFile(blob) as z:
            total = 0
            for info in z.infolist():
                name = info.filename
                parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
                if not parts or ".." in parts or name.startswith("/") or ":" in parts[0]:
                    raise PackError(f"{blob.name}: member {name!r} leaves its folder")
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise PackError(f"{blob.name}: member {name!r} is a link")
                total += info.file_size
                if total > 4 * MAX_BLOB:
                    raise PackError(f"{blob.name}: unpacks to more than {4 * MAX_BLOB} bytes")
                target = tmp.joinpath(*parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out, 1 << 20)
                if (info.external_attr >> 16) & 0o111:
                    os.chmod(target, 0o700)
        os.chmod(tmp, 0o700)
        os.replace(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


@dataclass
class Fetcher:
    """How bytes are fetched: *get(url, max_bytes, hosts)* -> bytes. The
    default goes through core.self_update.fetch (https, allowed hosts, the
    default proxy, bounded)."""

    get: object = None

    def __call__(self, url: str, max_bytes: int, hosts=None) -> bytes:
        if self.get is not None:
            return self.get(url, max_bytes, hosts)
        from core import self_update as SU

        return SU.fetch(url, opener=SU.build_opener(), max_bytes=max_bytes, hosts=hosts,
                        deadline=time.monotonic() + 600)


def signed_manifest(release, fetch: Fetcher, *, verify=None, sums: bytes | None = None) -> tuple[dict, dict]:
    """(manifest, SHA256SUMS entries) of *release* (core.self_update.Release),
    the manifest checked against the signed SHA256SUMS."""
    from core import self_update as SU

    if sums is None:
        sums_asset, sig_asset = release.asset(SU.SUMS_NAME), release.asset(SU.SIG_NAME)
        if sums_asset is None or sig_asset is None:
            raise PackError(f"release {release.version} has no signed {SU.SUMS_NAME}")
        sums = fetch(sums_asset.url, SU.MAX_SUMS_BYTES)
        signature = fetch(sig_asset.url, SU.SIG_BYTES)
        (verify or SU.verify_signature)(sums, signature)
    entries = SU.parse_sums(sums.decode("utf-8", "replace"))
    name = manifest_name(release.version)
    asset = release.asset(name)
    if asset is None or name not in entries:
        raise PackError(f"release {release.version} has no pack manifest in its {SU.SUMS_NAME}")
    data = fetch(asset.url, MAX_MANIFEST)
    if hashlib.sha256(data).hexdigest() != entries[name]:
        raise PackError(f"{name} differs from the signed {SU.SUMS_NAME} - refused")
    manifest = parse_manifest(data)
    if manifest.get("version") != release.version:
        raise PackError(f"{name} is for version {manifest.get('version')}, not {release.version}")
    return manifest, entries


def install(release, units: list[str], *, fetch: Fetcher | None = None, root: Path | None = None,
            verify=None, progress=None) -> list[str]:
    """Install *units* (and what they need) of *release*; the blobs installed."""
    fetch = fetch or Fetcher()
    root = root or packs_root()
    manifest, entries = signed_manifest(release, fetch, verify=verify)
    folder = root / release.version
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    wanted = set()
    for u in units:
        wanted |= needed_blobs(manifest, u)
    done = []
    for i, name in enumerate(sorted(wanted)):
        entry = manifest["blobs"][name]
        dest = folder / name
        if dest.is_dir() and (dest / ".axross-sha256").read_text().strip() == entry["sha256"]:
            continue                                   # already there, the same file
        if entries.get(name) not in (None, entry["sha256"]):
            raise PackError(f"{name}: the manifest and SHA256SUMS disagree - refused")
        data = None
        errors = []
        asset = release.asset(name)
        for url, hosts in ((asset.url if asset else None, None), (entry.get("pypi"), PYPI_HOSTS)):
            if not url:
                continue
            try:
                data = fetch(url, entry["size"], hosts)
            except Exception as exc:  # noqa: BLE001 - the next source
                errors.append(str(exc))
                continue
            if len(data) == entry["size"] and hashlib.sha256(data).hexdigest() == entry["sha256"]:
                break
            errors.append(f"{url}: not the file the manifest names")
            data = None
        if data is None:
            raise PackError(f"{name} could not be fetched: {'; '.join(errors) or 'no source'}")
        with tempfile.NamedTemporaryFile(dir=folder, delete=False, suffix=".whl") as tmp:
            tmp.write(data)
        try:
            if dest.exists():
                shutil.rmtree(dest)
            _unpack(Path(tmp.name), dest)
            (dest / ".axross-sha256").write_text(entry["sha256"] + "\n")
        finally:
            os.unlink(tmp.name)
        done.append(name)
        if progress:
            progress(i + 1, len(wanted))
    state = _state(folder)
    state["units"] = sorted(set(state.get("units", [])) | set(units))
    state["manifest"] = manifest
    (folder / "installed.json").write_text(json.dumps(state, indent=1, sort_keys=True))
    return done


def _state(folder: Path) -> dict:
    try:
        return json.loads((folder / "installed.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}


def installed(version: str, root: Path | None = None) -> list[str]:
    return list(_state((root or packs_root()) / version).get("units", []))


def remove(version: str, unit: str, root: Path | None = None) -> list[str]:
    """Uninstall *unit*; the blobs deleted (those no remaining unit needs)."""
    folder = (root or packs_root()) / version
    state = _state(folder)
    units = [u for u in state.get("units", []) if u != unit]
    manifest = state.get("manifest") or {"units": {}}
    keep = set()
    for u in units:
        keep |= needed_blobs(manifest, u)
    gone = []
    for child in folder.iterdir() if folder.is_dir() else ():
        if child.is_dir() and child.name not in keep and _safe_name(child.name):
            shutil.rmtree(child)
            gone.append(child.name)
    state["units"] = units
    (folder / "installed.json").write_text(json.dumps(state, indent=1, sort_keys=True))
    return gone


def activate(version: str, root: Path | None = None, path: list | None = None) -> list[str]:
    """Put the installed blobs of *version* on sys.path (at start); the
    folders added. A blob whose marker does not match the manifest is left out."""
    folder = (root or packs_root()) / version
    state = _state(folder)
    manifest = state.get("manifest") or {}
    path = sys.path if path is None else path
    added = []
    for unit in state.get("units", []):
        try:
            names = needed_blobs(manifest, unit)
        except PackError:
            continue
        for name in sorted(names):
            dest = folder / name
            try:
                ok = (dest / ".axross-sha256").read_text().strip() == manifest["blobs"][name]["sha256"]
            except (OSError, KeyError):
                ok = False
            if ok and str(dest) not in path:
                path.append(str(dest))
                added.append(str(dest))
    return added


def prune(keep_version: str, root: Path | None = None) -> list[str]:
    """Remove the pack folders of other versions (after an update has started once)."""
    root = root or packs_root()
    gone = []
    for child in root.iterdir() if root.is_dir() else ():
        if child.is_dir() and child.name != keep_version:
            shutil.rmtree(child, ignore_errors=True)
            gone.append(child.name)
    return gone


def release_for(version: str, *, fetch: Fetcher | None = None):
    """The GitHub release of *version* (its assets: the binaries, SHA256SUMS,
    the manifest, the wheels) - the units must match the running binary."""
    from core import self_update as SU

    fetch = fetch or Fetcher()
    url = f"https://api.github.com/repos/c0decave/axross/releases/tags/v{version}"
    data = fetch(url, 2 * 1024 * 1024)
    return SU.parse_release(json.loads(data))


def unit_sizes(manifest: dict) -> dict[str, int]:
    """unit -> bytes to download for it alone (with what it needs)."""
    out = {}
    for unit in manifest.get("units", {}):
        out[unit] = sum(manifest["blobs"][b]["size"] for b in needed_blobs(manifest, unit))
    return out
