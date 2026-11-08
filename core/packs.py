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
at start; :func:`activate_now` does so at once for a unit just added whose
wheels are all pure Python (a native wheel waits for the next start);
:func:`remove` deletes a unit's blobs no other unit uses.

A release's manifest can be re-issued (same version, a pack fixed): the
signed ``SHA256SUMS`` then names the new manifest. :func:`stale_units`
compares the installed blobs against such a manifest and :func:`update`
brings them to it - through :func:`signed_manifest` and the same blob
checks as :func:`install`, there is no other path.

The running session has its blob folders on sys.path: nothing it may
import from is deleted or replaced while it runs. A blob re-issued under
its old name is unpacked into a folder of its own (``installed.json``
``dirs`` maps the blob to it), and a folder no unit needs any more
(:func:`update`, :func:`remove`) is only listed under ``retired``;
:func:`prune` at the next start deletes it.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import sys
import tempfile
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
    default proxy, bounded). Like the binary's download it has no overall
    deadline - a blob may be hundreds of MiB on a slow line - but each read
    times out (core.self_update.READ_TIMEOUT), and *cancel* (an Event)
    stops it between reads."""

    get: object = None
    cancel: object = None

    def __call__(self, url: str, max_bytes: int, hosts=None) -> bytes:
        if self.get is not None:
            return self.get(url, max_bytes, hosts)
        from core import self_update as SU

        return SU.fetch(url, opener=SU.build_opener(), max_bytes=max_bytes, hosts=hosts,
                        cancel=self.cancel)


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
    manifest, entries = signed_manifest(release, fetch, verify=verify)
    return _install_checked(release, manifest, entries, units, fetch, root or packs_root(), progress)


def split_available(manifest: dict, units: list[str]) -> tuple[list[str], list[str]]:
    """(*units* the manifest has, with everything they need; the others) -
    a unit a newer release dropped or renamed, or one that needs such a unit."""
    kept, dropped = [], []
    for unit in units:
        try:
            needed_blobs(manifest, unit)
        except PackError:
            dropped.append(unit)
        else:
            kept.append(unit)
    return kept, dropped


def install_available(release, units: list[str], *, fetch: Fetcher | None = None,
                      root: Path | None = None, verify=None,
                      progress=None) -> tuple[list[str], list[str]]:
    """Like :func:`install`, for the units of another version brought
    along by a self-update: (the blobs installed, the units *release* no
    longer has - left out instead of refusing the whole update)."""
    fetch = fetch or Fetcher()
    manifest, entries = signed_manifest(release, fetch, verify=verify)
    kept, dropped = split_available(manifest, units)
    done = _install_checked(release, manifest, entries, kept, fetch, root or packs_root(), progress)
    return done, dropped


def _dir_of(state: dict, name: str) -> str:
    """The folder (below the version's folder) blob *name* is unpacked in."""
    dirs = state.get("dirs")
    folder = dirs.get(name) if isinstance(dirs, dict) else None
    return folder if isinstance(folder, str) and _safe_name(folder) else name


def _fresh_dir(folder: Path, name: str, sha256: str) -> str:
    """A folder name for *name* that nothing uses yet (a re-issued blob
    must not be unpacked over the folder the running session imports from)."""
    base = f"{name}.{sha256[:12]}"
    candidate, n = base, 0
    while (folder / candidate).exists():
        n += 1
        candidate = f"{base}.{n}"
    return candidate


def _write_state(folder: Path, state: dict) -> None:
    (folder / "installed.json").write_text(json.dumps(state, indent=1, sort_keys=True))


def _install_checked(release, manifest: dict, entries: dict, units: list[str], fetch: Fetcher,
                     root: Path, progress) -> list[str]:
    """The blobs of *units*, each checked against *manifest* and *entries* -
    which only :func:`signed_manifest` hands out (install, update)."""
    folder = root / release.version
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    wanted = set()
    for u in units:
        wanted |= needed_blobs(manifest, u)
    state = _state(folder)
    dirs = dict(state.get("dirs") or {}) if isinstance(state.get("dirs"), dict) else {}
    retired = set(state.get("retired") or [])
    done = []
    for i, name in enumerate(sorted(wanted)):
        entry = manifest["blobs"][name]
        current = _dir_of(state, name)
        if _blob_ok(folder, manifest, name, current):
            retired.discard(current)                   # wanted again before the restart
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
            # Another file under the same name (a re-issue): a folder of its
            # own, the old one stays for the running session until the restart.
            target = name if not (folder / name).exists() else _fresh_dir(folder, name, entry["sha256"])
            dest = folder / target
            _unpack(Path(tmp.name), dest)
            (dest / ".axross-sha256").write_text(entry["sha256"] + "\n")
        finally:
            os.unlink(tmp.name)
        if (folder / current).is_dir() and current != target:
            retired.add(current)
        if target == name:
            dirs.pop(name, None)
        else:
            dirs[name] = target
        retired.discard(target)
        done.append(name)
        if progress:
            progress(i + 1, len(wanted))
    state["units"] = sorted(set(state.get("units", [])) | set(units))
    state["manifest"] = manifest
    state["dirs"] = dirs
    state["retired"] = sorted(retired)
    _write_state(folder, state)
    return done


def _state(folder: Path) -> dict:
    try:
        return json.loads((folder / "installed.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}


def installed(version: str, root: Path | None = None) -> list[str]:
    return list(_state((root or packs_root()) / version).get("units", []))


def remove(version: str, unit: str, root: Path | None = None) -> list[str]:
    """Uninstall *unit*; the blobs no remaining unit needs. Their folders
    go at the next start (:func:`prune`): this session may import from them."""
    folder = (root or packs_root()) / version
    state = _state(folder)
    units = [u for u in state.get("units", []) if u != unit]
    gone = _drop_unused(folder, state, state.get("manifest") or {"units": {}}, units)
    state["units"] = units
    _write_state(folder, state)
    return gone


def _drop_unused(folder: Path, state: dict, manifest: dict, units: list[str]) -> list[str]:
    """Retire the blob folders none of *units* needs (by *manifest*): listed
    in *state*'s ``retired`` (the caller writes it), deleted by :func:`prune`
    at the next start - never under the running session. Their names."""
    keep = set()
    for u in units:
        keep |= {_dir_of(state, b) for b in needed_blobs(manifest, u)}
    retired = set(state.get("retired") or [])
    gone = []
    for child in sorted(folder.iterdir()) if folder.is_dir() else ():
        if child.is_dir() and child.name not in keep and _safe_name(child.name):
            if child.name not in retired:
                gone.append(child.name)
            retired.add(child.name)
    state["retired"] = sorted(retired - keep)
    dirs = state.get("dirs")
    if isinstance(dirs, dict):
        state["dirs"] = {b: d for b, d in dirs.items() if d in keep}
    return gone


def _blob_ok(folder: Path, manifest: dict, name: str, directory: str | None = None) -> bool:
    """*name* is unpacked in *folder* (in *directory*, default its own
    name) and its marker names the manifest's SHA-256."""
    try:
        marker = folder / (directory or name) / ".axross-sha256"
        return marker.read_text().strip() == manifest["blobs"][name]["sha256"]
    except (OSError, KeyError, TypeError):
        return False


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
            directory = _dir_of(state, name)
            dest = folder / directory
            if _blob_ok(folder, manifest, name, directory) and str(dest) not in path:
                path.append(str(dest))
                added.append(str(dest))
    return added


def is_pure_python(blob: str) -> bool:
    """*blob* is a wheel for every Python and platform (``py3-none-any``,
    ``py2.py3-none-any``): nothing native to load, so it can be used at once."""
    if not blob.endswith(".whl"):
        return False
    parts = blob[:-4].split("-")
    if len(parts) < 5:
        return False
    python, abi, platform = parts[-3:]
    return abi == "none" and platform == "any" and all(t.startswith("py") for t in python.split("."))


def activate_now(version: str, units: list[str], root: Path | None = None,
                 path: list | None = None) -> tuple[list[str], list[str]]:
    """Use *units*, just installed, without a restart: (the folders put on
    sys.path, the native blobs that wait for the next start). Only when
    every blob the units need is pure Python (or already on the path since
    the start) is anything added - a unit is used whole or not at all."""
    folder = (root or packs_root()) / version
    state = _state(folder)
    manifest = state.get("manifest") or {}
    path = sys.path if path is None else path
    names: set[str] = set()
    for unit in units:
        names |= needed_blobs(manifest, unit)
    waiting = sorted(n for n in names
                     if not is_pure_python(n) and str(folder / _dir_of(state, n)) not in path)
    if waiting:
        return [], waiting
    if not all(_blob_ok(folder, manifest, n, _dir_of(state, n)) for n in names):
        raise PackError("an installed blob does not match the manifest - refused")
    added = []
    for name in sorted(names):
        dest = str(folder / _dir_of(state, name))
        if dest not in path:
            path.append(dest)
            added.append(dest)
    importlib.invalidate_caches()
    return added, []


def stale_units(version: str, manifest: dict, root: Path | None = None) -> list[str]:
    """The installed units of *version* whose blobs differ from *manifest*
    (a signed manifest of the same release, from :func:`signed_manifest`):
    what "Update packs" fetches. Empty when the manifest was not re-issued.
    A unit the manifest no longer has is left out - nothing to fetch for it."""
    folder = (root or packs_root()) / version
    state = _state(folder)
    out = []
    for unit in installed(version, root):
        try:
            names = needed_blobs(manifest, unit)
        except PackError:
            continue
        if not all(_blob_ok(folder, manifest, n, _dir_of(state, n)) for n in names):
            out.append(unit)
    return out


def check_reissued(version: str, *, fetch: Fetcher | None = None, root: Path | None = None,
                   verify=None):
    """(release, stale units) of the running *version*: the release's
    manifest as signed now against what is installed. (None, []) when no
    unit is installed - then nothing is fetched."""
    if not installed(version, root):
        return None, []
    fetch = fetch or Fetcher()
    release = release_for(version, fetch=fetch)
    manifest, _ = signed_manifest(release, fetch, verify=verify)
    return release, stale_units(version, manifest, root)


def update(release, *, fetch: Fetcher | None = None, root: Path | None = None, verify=None,
           progress=None) -> list[str]:
    """Bring the installed units of *release* (the running version) to its
    re-issued manifest: the signature, the manifest's and every blob's
    hash are checked as by :func:`install`. The blobs fetched; they are
    used from the next start. Until then the running session keeps the
    folders it imports from: a changed blob is unpacked beside the old
    one, and blobs no unit needs any more are retired, deleted by
    :func:`prune` at the next start."""
    fetch = fetch or Fetcher()
    root = root or packs_root()
    units = installed(release.version, root)
    if not units:
        return []
    manifest, entries = signed_manifest(release, fetch, verify=verify)
    keep, _dropped = split_available(manifest, units)
    done = _install_checked(release, manifest, entries, keep, fetch, root, progress)
    folder = root / release.version
    state = _state(folder)
    state["units"] = sorted(keep)
    _drop_unused(folder, state, manifest, keep)
    _write_state(folder, state)
    return done


def prune(keep_version: str, root: Path | None = None) -> list[str]:
    """At the start (main.py), after :func:`activate`: remove the pack
    folders of versions older than *keep_version* (an update has started
    once), and the blob folders of *keep_version* that an update or a
    removal retired. A newer version's packs stay: a self-update installs
    them before it replaces the binary, and this older binary may run once
    more (the replacement waits in ~/.cache, or a rollback to .previous).
    Folders that are no version are left alone. The names removed."""
    from core import self_update as SU

    root = root or packs_root()
    running = SU.parse_version(keep_version)
    gone = []
    for child in sorted(root.iterdir()) if root.is_dir() else ():
        if not child.is_dir() or child.name == keep_version:
            continue
        version = SU.parse_version(child.name)
        if running is not None and version is not None and version < running:
            shutil.rmtree(child, ignore_errors=True)
            gone.append(child.name)
    gone += _prune_retired(root / keep_version)
    return gone


def _prune_retired(folder: Path) -> list[str]:
    """Delete the retired blob folders of one version (see :func:`prune`);
    a folder the state uses again is kept. Their names, as ``<version>/<dir>``."""
    state = _state(folder)
    retired = state.get("retired") or []
    if not retired:
        return []
    manifest = state.get("manifest") or {}
    used = set()
    for unit in state.get("units", []):
        try:
            used |= {_dir_of(state, b) for b in needed_blobs(manifest, unit)}
        except PackError:
            continue
    gone = []
    for name in retired:
        if isinstance(name, str) and _safe_name(name) and name not in used:
            shutil.rmtree(folder / name, ignore_errors=True)
            gone.append(f"{folder.name}/{name}")
    state["retired"] = []
    try:
        _write_state(folder, state)
    except OSError:
        pass
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
