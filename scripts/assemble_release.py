#!/usr/bin/env python3
"""Put a release together from what was built, and check it as the updater will.

    assemble_release.py --out DIR [--dist DIST] [--ci CI] [--packs PACKS]
                        [--version X.Y.Z] [--key KEY.pem] [--require-all]
                        [--pack-wheels unhosted|all] [--changelog CHANGELOG.md]
    assemble_release.py --check DIR [--version X.Y.Z] [--require-all]
                        [--api-json RELEASE.json | --release-id ID]

Inputs (each may be missing; what is missing is named, ``--require-all``
refuses then):

* ``DIST`` - the folder ``scripts/build_dist.sh`` wrote (``dist/<version>/``):
  ``glibc-2.34/`` and ``glibc-2.36/`` with ``axross-{base,slim,full}`` and the
  tools ``axross-{media-player,system-info}``, the wheel
  ``axross-<version>-py3-none-any.whl`` and the sdist ``axross-<version>.tar.gz``,
  ``standalone/`` (the tools' sdists and wheels) and ``packs/``.
* ``CI`` - the macOS and Windows binaries of the tag's "Cross-platform"
  workflow (.github/workflows/cross-platform.yml, job ``bundle``): one
  artifact ``axross-<flavor>-<runner.os>-<runner.arch>`` per flavour and
  system, each with ``axross-<flavor>[.exe]`` and its ``.sha256``. As
  ``gh run download <run> -D CI`` writes them (a folder per artifact) or as
  the web page hands them out (``<artifact>.zip``).
* ``PACKS`` - ``packs-<version>.json`` and the wheels it lists
  (default ``DIST/packs``).
* ``DIST/NATIVE-COMPONENTS.md`` (scripts/native_inventory.py --notes) and
  the version's section of ``CHANGELOG.md`` - for the release notes.

Output, ``DIR`` (must not exist or be empty):

* ``DIR/assets/`` - the release assets, flat, under the names of the
  updater's contract (core.self_update.asset_name, docs/PACKAGING.md
  "Self-update: what a release must carry"): ``axross-full``,
  ``axross-full-glibc2.36``, ..., ``axross-slim-macos-arm64``,
  ``axross-slim-windows-x64.exe``; the tools and the macOS / Windows
  axross-full the same way (download only: the updater has no asset for
  them). The per-folder ``SHA256SUMS`` and the CI's ``.sha256`` files are
  checked against their files and dropped; one ``SHA256SUMS`` takes their
  place, first line ``# axross-release X.Y.Z``, a line for every asset.
  With ``--key`` it is signed (scripts/sign_release.py: ``SHA256SUMS.sig``).
* The pack wheels: ``--pack-wheels unhosted`` (the default) attaches only
  the wheels whose manifest entry names no PyPI address (built from an
  sdist); every other wheel stays off the release - an axross-base fetches
  it from files.pythonhosted.org and checks it against the SHA-256 and size
  of the signed manifest (core.packs). The local file is still checked
  against the manifest. ``--pack-wheels all`` attaches every wheel (about
  160: too many for the binaries of 0.14.136, see below - refused then).
* ``DIR/upload-1.txt``, ``DIR/upload-2.txt`` - the assets to upload: what
  the updater needs, then the pack wheels. The order of the upload does not
  decide where an asset is listed: GitHub lists a release's assets sorted
  by name, ignoring case.
* ``DIR/notes.md`` - the release notes: the version's CHANGELOG.md section,
  the native components, the assets and how to verify them.

Then the result is checked through core.self_update and core.packs
themselves: for every platform, machine, flavour and variant the release
serves, an installed binary of that kind (detect_install, with and without
the bundle's marker files - the binaries of 0.14.136 have no variant file)
must find its asset, the asset its line in SHA256SUMS; the release must
parse (parse_release), and the answer of the API stay within the updater's
1 MiB. The binaries in use (0.14.136) read only the first 100 assets of the
answer, so SHA256SUMS, SHA256SUMS.sig, the pack manifest and every asset
any updater picks (core.self_update.asset_name of 0.14.136 and of this
tree, every platform, flavour and variant) must be among the first 100 -
in GitHub's order (by name, ignoring case), folded to upper case instead,
in byte order and in the upload order alike; refused otherwise. The pack
manifest must be what signed_manifest accepts, every wheel what it names
(attached, or on PyPI); and the signature must verify with the keys the
binaries in use pin (scripts/sign_release.py FIELD_KEYS) -
``--allow-new-key`` checks against TRUSTED_KEYS instead,
``--allow-unpinned`` (a dry run with a throwaway key) against the signing
key alone, both with a warning.

``--check DIR`` repeats the checks on a folder of assets (an assembled one,
or a draft that ``gh release download`` fetched). With ``--api-json FILE``
(the release as ``gh api repos/c0decave/axross/releases/<id>`` returns it,
or its asset list, also ``--paginate``'d) or ``--release-id ID`` (runs that
``gh api`` itself, on github.com) the order, names, sizes and digests of the
assets are GitHub's own, not modelled: every file of the folder must be
listed, every listed asset be in the folder.

Nothing is uploaded. Exit status: 0 done, 1 refused, 2 usage.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from core import packs as P  # noqa: E402
from core import self_update as SU  # noqa: E402

#: The tools build_dist.sh builds as programs of their own (docs/STANDALONE.md).
TOOLS = ("media-player", "system-info")
#: runner.os / runner.arch of a CI artifact -> (sys.platform, machine, asset suffix).
CI_SYSTEMS = {
    ("macOS", "ARM64"): ("darwin", "arm64", "macos-arm64"),
    ("Windows", "X64"): ("win32", "amd64", "windows-x64"),
}
_CI_ARTIFACT = re.compile(r"axross-(base|slim|full)-([A-Za-z]+)-([A-Za-z0-9]+)")
#: The upload lists and the notes (never assets; a downloaded draft may hold them).
UPLOAD_LISTS = ("upload-1.txt", "upload-2.txt")
NOTES = "notes.md"
NOT_ASSETS = (*UPLOAD_LISTS, NOTES)
CHANGELOG = ROOT / "CHANGELOG.md"
#: What the binaries in use can reach: before 0.15.177 the updater read only
#: the first 100 assets of the API's answer (core.self_update.parse_release
#: of 0.14.136: ``raw_assets[:100]``). GitHub lists the assets sorted by
#: name, ignoring case - not in upload order - so what the old updater needs
#: must sort into the first 100.
API_ASSETS = 100
#: The asset names the updater of 0.14.136 (every binary in the field)
#: picks: its asset_name knew only full and slim, and no glibc variant.
FIELD_UPDATER_ASSETS = ("axross-full", "axross-slim", "axross-slim-macos-arm64",
                        "axross-slim-windows-x64.exe")
#: Bytes of an asset entry in GitHub's answer besides name, size, URL and
#: digest (ids, uploader, dates, labels: about 1.7 KB in all on cli/cli).
API_ENTRY_EXTRA = 1600
#: GitHub takes release notes of at most 125000 characters.
MAX_NOTES = 120000
PACK_WHEELS = ("unhosted", "all")
_CHUNK = 1 << 20

_ELF_X86_64 = 62
_MACHO_ARM64 = 0x0100000C


class Refused(Exception):
    """The release cannot be assembled or is not what the updater takes."""


@dataclass
class Item:
    """One release asset and where it comes from."""

    name: str
    kind: str  # "binary" (the updater's), "download" (a binary it does not update),
    #            "tool", "python", "manifest", "pack"
    origin: str  # for the summary: where it was found
    source: Path
    member: str = ""  # inside the zip *source*, "" for a plain file
    expected: str = ""  # sha256 the input's own checksum file names
    expected_size: int | None = None  # a pack wheel: the size its manifest names
    system: str = ""  # "linux", "darwin", "win32" for binaries: the header is checked
    sha256: str = ""
    size: int = 0

    @property
    def executable(self) -> bool:
        return self.kind in ("binary", "download", "tool")


@dataclass
class Plan:
    version: str
    items: list[Item] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # expected, not found
    dropped: list[str] = field(default_factory=list)  # checksum files replaced by SHA256SUMS
    skipped: list[str] = field(default_factory=list)  # found, not published (and why)
    manifest: dict | None = None
    from_pypi: list[str] = field(default_factory=list)  # pack wheels a base fetches from PyPI

    def add(self, item: Item) -> None:
        for other in self.items:
            if other.name == item.name:
                raise Refused(f"two inputs make the asset {item.name}: {other.origin} and "
                              f"{item.origin}")
        self.items.append(item)


# -- names ---------------------------------------------------------------------------


def variant_suffix(variant: str) -> str:
    """"" for glibc-2.34, "-glibc2.36" for glibc-2.36 - as asset_name names them."""
    return "" if variant in ("", "glibc-2.34") else "-" + variant.replace("-", "")


def ci_asset_name(flavor: str, suffix: str) -> str:
    """The asset of a macOS / Windows binary: asset_name's for slim, the same
    pattern for a flavour the updater does not serve there."""
    return f"axross-{flavor}-{suffix}" + (".exe" if suffix.startswith("windows") else "")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _folder_sums(folder: Path, plan: Plan, label: str) -> dict[str, str]:
    """The entries of *folder*/SHA256SUMS (build_dist.sh writes one per
    folder) - checked against the files, then dropped."""
    path = folder / SU.SUMS_NAME
    if not path.is_file():
        return {}
    plan.dropped.append(f"{label}/{SU.SUMS_NAME}")
    return SU.parse_sums(path.read_text(encoding="utf-8", errors="replace"))


# -- collecting ----------------------------------------------------------------------


def collect_linux(dist: Path, plan: Plan) -> None:
    for variant in SU.VARIANTS:
        folder = dist / variant
        if not folder.is_dir():
            plan.missing.append(f"{variant}/: the Linux binaries for {variant} "
                                f"(axross-{{{','.join(SU.FLAVORS)}}})")
            continue
        sums = _folder_sums(folder, plan, variant)
        known = {SU.SUMS_NAME}
        for flavor in SU.FLAVORS:
            name = f"axross-{flavor}"
            known.add(name)
            path = folder / name
            if not path.is_file():
                plan.missing.append(f"{variant}/{name}")
                continue
            plan.add(Item(SU.asset_name("linux", "x86_64", flavor, variant), "binary",
                          f"{variant}/{name}", path, expected=sums.get(name, ""),
                          system="linux"))
        for tool in TOOLS:
            name = f"axross-{tool}"
            known.add(name)
            path = folder / name
            if path.is_file():
                plan.add(Item(name + variant_suffix(variant), "tool", f"{variant}/{name}", path,
                              expected=sums.get(name, ""), system="linux"))
            else:
                plan.skipped.append(f"{variant}/{name}: not built (optional)")
        for path in sorted(folder.iterdir()):
            if path.name not in known:
                plan.skipped.append(f"{variant}/{path.name}: not a release asset")


def collect_python(dist: Path, plan: Plan) -> None:
    sums = _folder_sums(dist, plan, ".") if any(dist.glob("axross-*")) else {}
    for name in (f"axross-{plan.version}-py3-none-any.whl", f"axross-{plan.version}.tar.gz"):
        path = dist / name
        if path.is_file():
            plan.add(Item(name, "python", name, path, expected=sums.get(name, "")))
        else:
            plan.missing.append(f"{name} (PyPI)")
    for path in sorted(dist.glob("axross-*")):
        if path.is_file() and path.name not in {i.origin for i in plan.items}:
            plan.skipped.append(f"{path.name}: another version than {plan.version}")
    standalone = dist / "standalone"
    if standalone.is_dir():
        sums = _folder_sums(standalone, plan, "standalone")
        for path in sorted(standalone.iterdir()):
            if path.name == SU.SUMS_NAME:
                continue
            if path.is_file() and path.name.endswith((".whl", ".tar.gz")) \
                    and plan.version in path.name:
                plan.add(Item(path.name, "python", f"standalone/{path.name}", path,
                              expected=sums.get(path.name, "")))
            else:
                plan.skipped.append(f"standalone/{path.name}: not a release asset")


def pypi_address(blob: str, entry) -> str:
    """The PyPI address the manifest names for *blob*, when core.packs can
    fetch it there (https, files.pythonhosted.org, the file's own name);
    "" otherwise."""
    url = entry.get("pypi") if isinstance(entry, dict) else None
    if not isinstance(url, str) or not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return ""
    if parts.scheme != "https" or parts.hostname not in P.PYPI_HOSTS or port not in (None, 443) \
            or "@" in parts.netloc or parts.query or parts.fragment \
            or not parts.path.endswith("/" + blob):
        return ""
    return url


def collect_packs(packs: Path, plan: Plan, wheels: str = "unhosted") -> None:
    name = P.manifest_name(plan.version)
    manifest_path = packs / name
    if not packs.is_dir() or not manifest_path.is_file():
        plan.missing.append(f"packs/{name} and its wheels (what an axross-base adds)")
        return
    try:
        manifest = P.parse_manifest(manifest_path.read_bytes())
    except P.PackError as exc:
        raise Refused(f"packs/{name}: {exc}") from None
    if manifest.get("version") != plan.version:
        raise Refused(f"packs/{name} is for version {manifest.get('version')}, not {plan.version}")
    plan.manifest = manifest
    sums = _folder_sums(packs, plan, "packs")
    plan.add(Item(name, "manifest", f"packs/{name}", manifest_path, expected=sums.get(name, "")))
    blobs = manifest.get("blobs") or {}
    for blob, entry in sorted(blobs.items()):
        path = packs / blob
        if not path.is_file():
            raise Refused(f"packs/{blob}: named in {name} but not there - build the packs again")
        if sums.get(blob) not in (None, entry["sha256"]):
            raise Refused(f"packs/{blob}: packs/SHA256SUMS and {name} disagree")
        if wheels == "unhosted" and pypi_address(blob, entry):
            # Not attached: a base fetches it from PyPI and checks it against
            # the manifest - so the manifest must name this very file.
            if path.stat().st_size != entry["size"] or _sha256_file(path) != entry["sha256"]:
                raise Refused(f"packs/{blob} differs from {name} - build the packs again")
            plan.from_pypi.append(blob)
            continue
        plan.add(Item(blob, "pack", f"packs/{blob}", path, expected=entry["sha256"],
                      expected_size=entry["size"]))
    for path in sorted(packs.iterdir()):
        if path.name not in blobs and path.name not in (name, SU.SUMS_NAME):
            plan.skipped.append(f"packs/{path.name}: not in {name}")


def _ci_entries(ci: Path):
    """(artifact name, {file name: (path, member)}) of every artifact under *ci*."""
    for entry in sorted(ci.iterdir()):
        if entry.is_dir():
            yield entry.name, {p.name: (p, "") for p in entry.iterdir() if p.is_file()}
        elif entry.is_file() and entry.suffix == ".zip":
            try:
                with zipfile.ZipFile(entry) as zf:
                    members = {Path(m.filename).name: (entry, m.filename)
                               for m in zf.infolist() if not m.is_dir() and "/" not in m.filename}
            except zipfile.BadZipFile:
                raise Refused(f"{entry.name} is not a zip file") from None
            yield entry.name[:-len(".zip")], members
        else:
            yield entry.name, None


def _read_member(path: Path, member: str, limit: int = 4096) -> bytes:
    if not member:
        with open(path, "rb") as fh:
            return fh.read(limit)
    with zipfile.ZipFile(path) as zf, zf.open(member) as fh:
        return fh.read(limit)


def collect_ci(ci: Path, plan: Plan) -> None:
    found: set[tuple[str, str]] = set()
    for artifact, files in _ci_entries(ci):
        match = _CI_ARTIFACT.fullmatch(artifact)
        if match is None or files is None:
            plan.skipped.append(f"ci/{artifact}: not an artifact of the bundle job")
            continue
        flavor, runner_os, arch = match.groups()
        system = CI_SYSTEMS.get((runner_os, arch))
        if system is None:
            plan.skipped.append(f"ci/{artifact}: no release asset for {runner_os} {arch}")
            continue
        platform, machine, suffix = system
        binary = f"axross-{flavor}" + (".exe" if platform == "win32" else "")
        if binary not in files:
            raise Refused(f"ci/{artifact} has no {binary}")
        path, member = files[binary]
        expected = ""
        if binary + ".sha256" in files:
            spath, smember = files[binary + ".sha256"]
            expected = SU.parse_sums(_read_member(spath, smember).decode("utf-8", "replace")
                                     ).get(binary, "")
            if not expected:
                raise Refused(f"ci/{artifact}/{binary}.sha256 names no checksum of {binary}")
            plan.dropped.append(f"ci/{artifact}/{binary}.sha256")
        name = ci_asset_name(flavor, suffix)
        served = SU.asset_name(platform, machine, flavor)
        if served and served != name:
            raise Refused(f"internal: {name} is not the updater's {served}")
        plan.add(Item(name, "binary" if served else "download", f"ci/{artifact}/{binary}", path,
                      member, expected=expected, system=platform))
        found.add((platform, flavor))
        for other in sorted(set(files) - {binary, binary + ".sha256"}):
            plan.skipped.append(f"ci/{artifact}/{other}: not a release asset")
    for (runner_os, arch), (platform, machine, _suffix) in CI_SYSTEMS.items():
        for flavor in SU.FLAVORS:
            if SU.asset_name(platform, machine, flavor) and (platform, flavor) not in found:
                plan.missing.append(f"axross-{flavor}-{runner_os}-{arch} (the CI artifact)")


# -- writing -------------------------------------------------------------------------


def _check_header(item: Item, head: bytes) -> None:
    """A binary is the kind of file its system runs (a swapped artifact, an
    HTML error page saved under the name, are refused)."""
    if item.system == "linux":
        ok = head[:4] == b"\x7fELF" and len(head) >= 20 \
            and int.from_bytes(head[18:20], "little") == _ELF_X86_64
        what = "an x86-64 ELF executable"
    elif item.system == "darwin":
        ok = head[:4] == b"\xca\xfe\xba\xbe" or (
            head[:4] == b"\xcf\xfa\xed\xfe" and int.from_bytes(head[4:8], "little") == _MACHO_ARM64)
        what = "an arm64 Mach-O executable"
    elif item.system == "win32":
        ok = head[:2] == b"MZ"
        what = "a Windows executable"
    else:
        return
    if not ok:
        raise Refused(f"{item.origin} is not {what}")


def copy_item(item: Item, dest: Path) -> None:
    """*item* to *dest*, hashed on the way; checked against its own checksum."""
    digest = hashlib.sha256()
    size = 0
    head = b""
    if item.member:
        zf = zipfile.ZipFile(item.source)
        src = zf.open(item.member)
    else:
        zf = None
        src = open(item.source, "rb")
    try:
        with src, open(dest, "xb") as out:
            for chunk in iter(lambda: src.read(_CHUNK), b""):
                if len(head) < 64:
                    head += chunk[:64]
                digest.update(chunk)
                size += len(chunk)
                out.write(chunk)
    finally:
        if zf is not None:
            zf.close()
    item.sha256, item.size = digest.hexdigest(), size
    if item.expected and item.expected != item.sha256:
        raise Refused(f"{item.origin} differs from the checksum its build wrote "
                      f"({item.expected[:16]}... != {item.sha256[:16]}...): a broken copy?")
    if size == 0:
        raise Refused(f"{item.origin} is empty (the updater ignores an asset of 0 bytes)")
    limit = P.MAX_BLOB if item.kind == "pack" else P.MAX_MANIFEST if item.kind == "manifest" \
        else SU.MAX_ASSET_BYTES
    if size > limit:
        raise Refused(f"{item.origin} has {size} bytes, more than the {limit} the updater takes")
    if item.expected_size not in (None, size):
        raise Refused(f"{item.origin} has {size} bytes, the manifest says {item.expected_size}")
    _check_header(item, head)
    os.chmod(dest, 0o755 if item.executable else 0o644)


def sums_text(version: str, items: list[Item]) -> str:
    lines = [f"{SU.RELEASE_LINE_PREFIX}{version}"]
    lines += [f"{i.sha256}  {i.name}" for i in sorted(items, key=lambda i: i.name)]
    return "\n".join(lines) + "\n"


def upload_order(items: list[Item]) -> tuple[list[str], list[str]]:
    """(first, then): what the updater needs before the pack wheels."""
    first = [SU.SUMS_NAME, SU.SIG_NAME]
    rank = {"manifest": 0, "binary": 1, "download": 2, "tool": 3, "python": 4}
    first += [i.name for i in sorted((i for i in items if i.kind != "pack"),
                                     key=lambda i: (rank[i.kind], i.name))]
    return first, sorted(i.name for i in items if i.kind == "pack")


# -- checking ------------------------------------------------------------------------


def field_keys() -> tuple[str, ...]:
    import sign_release

    return sign_release.FIELD_KEYS


@dataclass
class Report:
    lines: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _bundle(tmp: Path, flavor: str | None, variant: str | None) -> Path:
    """A bundle folder (sys._MEIPASS) with the marker files of a build."""
    folder = Path(tempfile.mkdtemp(dir=tmp))
    marks = folder.joinpath(*SU.FLAVOR_PATH).parent
    marks.mkdir(parents=True)
    if flavor:
        (folder.joinpath(*SU.FLAVOR_PATH)).write_text(flavor + "\n", encoding="ascii")
    if variant:
        (folder.joinpath(*SU.VARIANT_PATH)).write_text(variant + "\n", encoding="ascii")
    return folder


def installs():
    """(label, platform, machine, flavor, variant marker or None, flavor marker?)
    of every kind of installed binary the updater serves."""
    for flavor in SU.FLAVORS:
        for variant in SU.VARIANTS:
            for machine in ("x86_64", "amd64"):
                yield (f"linux {machine} axross-{flavor} {variant}", "linux", machine, flavor,
                       variant, True)
        # the binaries of 0.15.165 and older: no variant file; before 0.14.50 no
        # flavour file either (recognised by the file name)
        yield (f"linux x86_64 axross-{flavor} (no variant file: before 0.15.166)", "linux",
               "x86_64", flavor, None, True)
        yield (f"linux x86_64 axross-{flavor} (no marker file: known by its name)", "linux",
               "x86_64", flavor, None, False)
    for (_os, _arch), (platform, machine, _suffix) in CI_SYSTEMS.items():
        for flavor in SU.FLAVORS:
            if SU.asset_name(platform, machine, flavor):
                yield (f"{platform} {machine} axross-{flavor}", platform, machine, flavor, None,
                       True)


def updater_assets(version: str) -> set[str]:
    """What an updater looks for in a release: SHA256SUMS, its signature, the
    pack manifest and the binary of every platform, flavour and variant -
    as the updater of 0.14.136 names them and as this tree's does."""
    names = {SU.SUMS_NAME, SU.SIG_NAME, P.manifest_name(version), *FIELD_UPDATER_ASSETS}
    for platform, machine in (("linux", "x86_64"), *((p, m) for p, m, _s in CI_SYSTEMS.values())):
        for flavor in SU.FLAVORS:
            for variant in SU.VARIANTS:
                name = SU.asset_name(platform, machine, flavor, variant)
                if name:
                    names.add(name)
    return names


#: The orders the API may list a release's assets in; the first is GitHub's
#: (measured: by name, ignoring case). The others are checked as well, so
#: that a detail of the collation (is "_" before or after a letter?) cannot
#: push an asset the updater needs past the first API_ASSETS.
MODELLED_ORDERS = {
    "GitHub's order (by name, ignoring case)": lambda n: (n.lower(), n),
    "by name, folded to upper case": lambda n: (n.upper(), n),
    "by name, byte order": lambda n: (n, ""),
}


def listing_orders(names, upload: list[str] | None = None) -> dict[str, list[str]]:
    """*names* in every order the API may list them in (and the upload order)."""
    names = set(names)
    orders = {label: sorted(names, key=key) for label, key in MODELLED_ORDERS.items()}
    if upload:
        listed = [n for n in dict.fromkeys(upload) if n in names]
        orders["the upload order"] = listed + sorted(names - set(listed))
    return orders


def read_api_assets(data) -> tuple[dict | None, list]:
    """(the release, its asset entries) of what ``gh api`` returned: a
    release object, its asset list, or the pages of that list (``--paginate``
    writes them one after the other, ``--slurp`` as a list of lists)."""
    if isinstance(data, dict):
        if not isinstance(data.get("assets"), list):
            raise Refused("the release JSON has no list of assets")
        return data, list(data["assets"])
    if isinstance(data, list):
        entries = []
        for entry in data:
            entries.extend(entry if isinstance(entry, list) else [entry])
        return None, entries
    raise Refused("the API JSON is neither a release nor a list of assets")


def load_api_json(text: str) -> tuple[dict | None, list]:
    decoder = json.JSONDecoder()
    docs, pos = [], 0
    try:
        while True:
            while pos < len(text) and text[pos].isspace():
                pos += 1
            if pos >= len(text):
                break
            doc, pos = decoder.raw_decode(text, pos)
            docs.append(doc)
    except ValueError as exc:
        raise Refused(f"the API JSON does not parse: {exc}") from None
    if not docs:
        raise Refused("the API JSON is empty")
    if len(docs) == 1:
        return read_api_assets(docs[0])
    if not all(isinstance(d, list) for d in docs):
        raise Refused("the API JSON holds more than one release")
    return read_api_assets(docs)


def check_release(assets: Path, version: str, *, keys: tuple[str, ...] | None,
                  order: tuple[list[str], list[str]] | None = None,
                  api: tuple[dict | None, list] | None = None, notes: str = "") -> Report:
    """Check the assets in *assets* through core.self_update and core.packs.
    *keys*: the signature must verify with them (None: no signature
    needed; one that is there is still checked against the field keys).
    *order*: the upload lists; *api*: GitHub's own listing of the release
    (read_api_assets) - else the order is modelled (listing_orders);
    *notes*: the release notes (they count to the API answer's size)."""
    report = Report()
    files = {p.name: p for p in assets.iterdir() if p.is_file() and p.name not in NOT_ASSETS}
    sums_path = files.pop(SU.SUMS_NAME, None)
    sig_path = files.pop(SU.SIG_NAME, None)
    if sums_path is None:
        report.problems.append(f"no {SU.SUMS_NAME}")
        return report
    data = sums_path.read_bytes()
    if len(data) > SU.MAX_SUMS_BYTES:
        report.problems.append(f"{SU.SUMS_NAME} has {len(data)} bytes; the updater takes at most "
                               f"{SU.MAX_SUMS_BYTES}")
    text = data.decode("utf-8", errors="replace")
    if not text.startswith(f"{SU.RELEASE_LINE_PREFIX}{version}\n"):
        report.problems.append(f"{SU.SUMS_NAME} does not start with "
                               f"'{SU.RELEASE_LINE_PREFIX}{version}'")
    if SU.release_of_sums(text) != version:
        report.problems.append(f"{SU.SUMS_NAME} names release {SU.release_of_sums(text)}, "
                               f"not {version}")
    sums = SU.parse_sums(text)
    digests = {name: _sha256_file(path) for name, path in sorted(files.items())}
    for name in sorted(set(files) - set(sums)):
        report.problems.append(f"{name}: no line in {SU.SUMS_NAME} the updater can read")
    for name in sorted(set(sums) - set(files)):
        report.problems.append(f"{SU.SUMS_NAME} names {name}, which is not among the assets")
    for name in sorted(set(sums) & set(files)):
        if sums[name] != digests[name]:
            report.problems.append(f"{name}: its {SU.SUMS_NAME} line does not match the file")

    paths = {**files, SU.SUMS_NAME: sums_path, **({SU.SIG_NAME: sig_path} if sig_path else {})}
    digests[SU.SUMS_NAME] = _sha256_file(sums_path)
    if sig_path is not None:
        digests[SU.SIG_NAME] = _sha256_file(sig_path)
    upload = [*order[0], *order[1]] if order else None
    orders = listing_orders(paths, upload)
    tag = f"v{version}"
    api_size = None
    if api is not None:
        # What GitHub holds: every asset of the folder, nothing else, the
        # same bytes - and its own order.
        release_json, entries = api
        real, seen = [], set()
        for entry in entries:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not isinstance(name, str):
                report.problems.append("GitHub lists an asset without a name")
                continue
            if name in seen:
                report.problems.append(f"GitHub lists {name} twice")
                continue
            seen.add(name)
            real.append(name)
            if name not in paths:
                report.problems.append(f"{name}: an asset on GitHub, not in {assets} "
                                       "(left over, or not downloaded)")
                continue
            if entry.get("size") != paths[name].stat().st_size:
                report.problems.append(f"{name}: GitHub states {entry.get('size')} bytes, the "
                                       f"file has {paths[name].stat().st_size}")
            digest = entry.get("digest")
            if isinstance(digest, str) and digest.startswith("sha256:") \
                    and digest[len("sha256:"):].lower() != digests[name]:
                report.problems.append(f"{name}: GitHub's digest is not the file's")
            if entry.get("state", "uploaded") != "uploaded":
                report.problems.append(f"{name}: its upload is {entry.get('state')!r}, "
                                       "not finished")
        for name in sorted(set(paths) - seen):
            report.problems.append(f"{name}: in the folder, not among GitHub's assets "
                                   "(not uploaded)")
        if release_json is not None:
            if release_json.get("tag_name") != tag:
                report.problems.append(f"the release's tag is {release_json.get('tag_name')!r}, "
                                       f"not {tag}")
            api_size = len(json.dumps(release_json, separators=(",", ":")).encode())
            notes = notes or str(release_json.get("body") or "")
        modelled = orders[next(iter(MODELLED_ORDERS))]
        if [n for n in real if n in paths] != [n for n in modelled if n in seen]:
            report.warnings.append("GitHub lists the assets in another order than the modelled "
                                   "one (by name, ignoring case): checked in both")
        orders = {"GitHub's answer": real + [n for n in modelled if n not in seen], **orders}
    else:
        report.warnings.append("the order of the assets is modelled, not GitHub's: "
                               "check the uploaded draft with --api-json or --release-id")

    # The release as the new updater reads it (every asset): parse_release
    # checks every name, size and URL.
    listed = [n for n in next(iter(orders.values())) if n in paths]
    api_answer = {"tag_name": tag, "html_url": f"{SU.RELEASES_PREFIX}tag/{tag}", "body": notes,
                  "assets": [{"name": n, "size": paths[n].stat().st_size,
                              "browser_download_url": f"{SU.DOWNLOAD_PREFIX}{tag}/{n}",
                              "digest": "sha256:" + digests[n]} for n in listed]}
    if len(listed) > SU.MAX_ASSETS:
        report.problems.append(f"{len(listed)} assets: the updater reads at most {SU.MAX_ASSETS}")
    estimate = len(json.dumps(api_answer, separators=(",", ":")).encode()) \
        + API_ENTRY_EXTRA * len(listed)
    for size, what in ((estimate, "about"), (api_size, "")):
        if size is not None and size > SU.MAX_API_BYTES:
            report.problems.append(f"the API's answer for the release has {what} {size} bytes "
                                   f"({len(listed)} assets and the notes); the updater takes at "
                                   f"most {SU.MAX_API_BYTES}")
    try:
        release = SU.parse_release(api_answer)
    except SU.UpdateError as exc:
        report.problems.append(f"the release does not parse: {exc}")
        return report
    if release.version != version:
        report.problems.append(f"the tag {tag} parses as {release.version}")
    reachable = {a.name for a in release.assets}
    for name in listed:
        if name not in reachable:
            report.problems.append(f"{name}: a name the updater refuses")

    # The binaries in use (0.14.136) read the first API_ASSETS of the answer
    # only: what any updater needs must be among them, in every order.
    needed = updater_assets(version) & set(paths)
    late: dict[str, list[str]] = {}
    for label, names in orders.items():
        first = set(names[:API_ASSETS])
        for name in sorted(needed - first):
            late.setdefault(name, []).append(f"asset {names.index(name) + 1} of {len(names)} "
                                             f"in {label}")
    for name, where in sorted(late.items()):
        report.problems.append(
            f"{name}: {'; '.join(where)} - the updater of 0.14.136 (every binary in use) reads "
            f"only the first {API_ASSETS} assets and misses it (attach fewer files: "
            "--pack-wheels unhosted)")
    if not late:
        report.lines.append(f"{len(listed)} assets: everything an updater needs is among the "
                            f"first {API_ASSETS} in {', '.join(orders)}")

    # The signature, with the keys the binaries in use pin.
    if sig_path is not None:
        check_keys = keys if keys is not None else field_keys()
        try:
            SU.verify_signature(data, sig_path.read_bytes(), keys=check_keys)
        except SU.SignatureError as exc:
            report.problems.append(f"{SU.SIG_NAME}: {exc}")
        else:
            report.lines.append(f"{SU.SIG_NAME}: verifies with {', '.join(check_keys)}")
    elif keys is not None:
        report.problems.append(f"no {SU.SIG_NAME}: no installed binary takes the release")
    else:
        report.warnings.append(f"not signed: no installed binary takes the release before "
                               f"scripts/sign_release.py --version {version} <field key> "
                               f"{SU.SUMS_NAME} has written {SU.SIG_NAME}")

    # Every kind of installed binary the updater serves finds its asset.
    with tempfile.TemporaryDirectory(prefix="axross-assemble-") as tmp:
        for label, platform, machine, flavor, variant, marked in installs():
            want = SU.asset_name(platform, machine, flavor, variant or "glibc-2.34")
            exe = Path(tmp, "bin", f"axross-{flavor}" + (".exe" if platform == "win32" else ""))
            exe.parent.mkdir(exist_ok=True)
            exe.touch()
            bundle = _bundle(Path(tmp), flavor if marked else None,
                             variant if marked and platform == "linux" else None)
            inst = SU.detect_install(frozen=True, executable=str(exe), bundle_dir=str(bundle),
                                     platform=platform, machine=machine)
            if inst.asset != want or not inst.can_download:
                report.problems.append(f"{label}: detect_install gives {inst.asset!r}, "
                                       f"not {want!r}")
            elif want not in files:
                report.missing.append(f"{label}: no {want} - it gets only the release page")
            elif release.asset(want) is None:
                pass  # reported above
            elif sums.get(want) != digests[want]:
                pass  # reported above
            else:
                report.lines.append(f"{label:62s} -> {want}")

    # The packs, as core.packs reads them.
    manifests = [n for n in files if re.fullmatch(r"packs-.+\.json", n)]
    name = P.manifest_name(version)
    for other in manifests:
        if other != name:
            report.problems.append(f"{other}: a pack manifest of another version")
    if name in files:
        # The signature was checked above, with the keys that count; here
        # core.packs reads the release as a base does (an unsigned dry run
        # gets a stand-in .sig asset so that the manifest is checked too).
        pack_release = release
        if release.asset(SU.SIG_NAME) is None:
            pack_release = dataclasses.replace(release, assets=(*release.assets, SU.Asset(
                SU.SIG_NAME, f"{SU.DOWNLOAD_PREFIX}{tag}/{SU.SIG_NAME}", SU.SIG_BYTES)))

        def fetch(url, max_bytes, hosts=None):
            asset = next((a for a in pack_release.assets if a.url == url), None)
            if asset is None:
                raise P.PackError(f"no asset at {url}")
            if asset.name not in paths:
                return b"\0" * SU.SIG_BYTES  # the stand-in signature
            data = paths[asset.name].read_bytes()
            if len(data) > max_bytes:
                raise P.PackError(f"{asset.name} is larger than {max_bytes} bytes")
            return data
        try:
            manifest, entries = P.signed_manifest(pack_release, fetch,
                                                  verify=lambda _data, _sig: None)
        except P.PackError as exc:
            report.problems.append(f"packs: {exc}")
        else:
            blobs = manifest.get("blobs") or {}
            hosted = 0
            for blob, entry in sorted(blobs.items()):
                if blob not in files:
                    if pypi_address(blob, entry):
                        hosted += 1  # core.packs fetches it there, checked by the manifest
                    else:
                        report.problems.append(f"packs: {blob} is in {name} but neither an "
                                               "asset nor on PyPI: no base can fetch it")
                elif entries.get(blob) != entry["sha256"] or digests[blob] != entry["sha256"] \
                        or files[blob].stat().st_size != entry["size"]:
                    report.problems.append(f"packs: {blob} differs from {name}")
            report.lines.append(f"{name}: {len(manifest.get('units') or {})} units, "
                                f"{len(blobs)} wheels: {len(blobs) - hosted} attached (each in "
                                f"{SU.SUMS_NAME}), {hosted} fetched from PyPI against the "
                                "manifest")
    else:
        report.missing.append(f"no {name}: an axross-base of {version} cannot add anything")
    return report


# -- the release notes ---------------------------------------------------------------


def changelog_section(text: str, version: str) -> tuple[str, str] | None:
    """(heading, body) of *version*'s section of CHANGELOG.md: ``## X.Y.Z -
    <date>``, or still ``## Unreleased (X.Y.Z)``."""
    heading = re.compile(rf"## (?:{re.escape(version)}(?![0-9.])|Unreleased \({re.escape(version)}\))")
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if heading.match(line)), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start], "\n".join(lines[start + 1:end]).strip()


def release_notes(version: str, plan: Plan, section: str, native: str, signer: str) -> str:
    """notes.md: the CHANGELOG section, the native components, the assets
    and how to check them."""
    def names(kind):
        return ", ".join(f"`{i.name}`" for i in sorted(plan.items, key=lambda i: i.name)
                         if i.kind == kind)
    parts = [section or f"axross {version}."]
    if native:
        parts.append(native.strip())
    assets = ["## Assets", ""]
    for kind, what in (("binary", "One-file binaries (they update themselves)"),
                       ("download", "One-file binaries to download (no self-update)"),
                       ("tool", "The tools as programs of their own"),
                       ("python", "Python packages (the same as on PyPI)")):
        if names(kind):
            assets.append(f"- {what}: {names(kind)}")
    if plan.manifest is not None:
        attached = sum(1 for i in plan.items if i.kind == "pack")
        assets.append(f"- Packs, what an axross-base adds: `{P.manifest_name(version)}` and "
                      f"{attached} wheels attached here; {len(plan.from_pypi)} more come from "
                      "PyPI (files.pythonhosted.org), each checked against the SHA-256 and "
                      "size the signed manifest names")
    assets.append(f"- `{SU.SUMS_NAME}`: the SHA-256 of every asset; `{SU.SIG_NAME}`: its "
                  "Ed25519 signature")
    parts.append("\n".join(assets))
    verify = ["## How to verify", "", "```bash", f"sha256sum --check --ignore-missing {SU.SUMS_NAME}"]
    if signer:
        verify += [
            "# the signature: the raw Ed25519 signature of SHA256SUMS by the release key",
            "{ printf '\\060\\052\\060\\005\\006\\003\\053\\145\\160\\003\\041\\000'; "
            f"printf '%s' '{signer}' | base64 -d; }} > axross-release-key.der",
            "openssl pkeyutl -verify -pubin -keyform DER -inkey axross-release-key.der -rawin "
            f"-in {SU.SUMS_NAME} -sigfile {SU.SIG_NAME}",
            "```", "",
            f"The release key `{signer}` is the one the binaries pin "
            "(`TRUSTED_KEYS` in `core/self_update.py`); the binaries check the signature "
            "themselves before an update."]
    else:
        verify += ["```", "", f"This release is not signed: no {SU.SIG_NAME}."]
    sums = [f"{i.sha256}  {i.name}" for i in sorted(plan.items, key=lambda i: i.name)
            if i.kind in ("binary", "download", "tool", "python")]
    if sums:
        verify += ["", "The binaries and packages:", "", "```", *sums, "```"]
    parts.append("\n".join(verify))
    return "\n\n".join(parts) + "\n"


# -- the run ---------------------------------------------------------------------------


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{size} B"
        value /= 1024
    return f"{size} B"


def _print_report(report: Report) -> None:
    print("The updater's view (core.self_update, core.packs):")
    for line in report.lines:
        print(f"  ok  {line}")
    for line in report.missing:
        print(f"  --  {line}")
    for line in report.warnings:
        print(f"  !!  {line}")
    for line in report.problems:
        print(f"  XX  {line}")


def _verify_keys(args, signer: str | None) -> tuple[str, ...] | None:
    if args.allow_unpinned and signer:
        return (signer,)
    if args.allow_new_key:
        return SU.TRUSTED_KEYS
    return field_keys() if args.key else None


def _notes_inputs(args, plan: Plan) -> tuple[str, str]:
    """(the CHANGELOG section, the native components) for notes.md; what is
    missing goes into plan.missing (--require-all refuses then)."""
    path = args.changelog or CHANGELOG
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        text = ""
        plan.missing.append(f"{path}: {exc.strerror} (the release notes)")
    found = changelog_section(text, plan.version) if text else None
    section = ""
    if found is None and text:
        plan.missing.append(f"no section '## {plan.version} - <date>' in {path} (the release "
                            "notes start from it)")
    elif found is not None:
        heading, section = found
        if heading.startswith("## Unreleased"):
            plan.missing.append(f"{path}: '{heading}' - turn it into '## {plan.version} - "
                                "<date>' first (step 1 of the release flow)")
    native = ""
    if args.dist is not None and any(i.kind == "binary" and i.system == "linux"
                                     for i in plan.items):
        native_path = args.dist / "NATIVE-COMPONENTS.md"
        if native_path.is_file():
            native = native_path.read_text(encoding="utf-8")
        else:
            plan.missing.append(f"{native_path} (scripts/native_inventory.py --notes: the native "
                                "components of the release notes)")
    return section, native


def assemble(args) -> int:
    version = args.version
    plan = Plan(version)
    dist = args.dist
    if dist is not None:
        if not dist.is_dir():
            raise Refused(f"{dist} is not a folder")
        collect_linux(dist, plan)
        collect_python(dist, plan)
    else:
        plan.missing.append("the Linux binaries, wheel and sdist (--dist: build_dist.sh's folder)")
    packs = args.packs or (dist / "packs" if dist is not None else None)
    if packs is not None:
        collect_packs(packs, plan, args.pack_wheels)
    else:
        plan.missing.append(f"packs/{P.manifest_name(version)} (--packs)")
    if args.ci is not None:
        if not args.ci.is_dir():
            raise Refused(f"{args.ci} is not a folder")
        collect_ci(args.ci, plan)
    else:
        plan.missing.append("the macOS and Windows binaries (--ci: the bundle job's artifacts)")
    if not plan.items:
        raise Refused("nothing to assemble")
    notes_inputs = _notes_inputs(args, plan)
    if plan.missing and args.require_all:
        raise Refused("--require-all: missing " + "; ".join(plan.missing))
    out = args.out
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise Refused(f"{out} exists and is not empty: assemble into a new folder")
    assets = out / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    try:
        return _write_and_check(args, plan, out, assets, notes_inputs)
    except BaseException:
        shutil.rmtree(assets, ignore_errors=True)  # nothing half-assembled is left to upload
        for name in NOT_ASSETS:
            (out / name).unlink(missing_ok=True)
        raise


def _signing_key(data: bytes, sig: Path, signer: str | None) -> str:
    """The public key *sig* verifies with (TRUSTED_KEYS, or the dry run's)."""
    if not sig.is_file():
        return ""
    for key in (*([signer] if signer else []), *SU.TRUSTED_KEYS):
        try:
            SU.verify_signature(data, sig.read_bytes(), keys=(key,))
        except SU.SignatureError:
            continue
        return key
    return ""


def _write_and_check(args, plan: Plan, out: Path, assets: Path,
                     notes_inputs: tuple[str, str]) -> int:
    version = plan.version
    for item in plan.items:
        copy_item(item, assets / item.name)
    sums = assets / SU.SUMS_NAME
    sums.write_text(sums_text(version, plan.items), encoding="utf-8")
    first, then = upload_order(plan.items)

    signer = None
    if args.key is not None:
        import sign_release

        kwargs = {"allow_unpinned": args.allow_unpinned, "allow_new_key": args.allow_new_key,
                  "version": version}
        if args.packs_issue is not None:
            kwargs["packs_issue"] = args.packs_issue
        try:
            sign_release.sign_release(args.key, sums, **kwargs)
        except sign_release.Refused as exc:
            raise Refused(f"signing: {exc}") from None
        signer = sign_release.public_key_b64(
            sign_release.load_private_key(sign_release.read_key_file(args.key))) \
            if args.allow_unpinned else None
    if not (assets / SU.SIG_NAME).exists():
        first.remove(SU.SIG_NAME)
    (out / "upload-1.txt").write_text("".join(f"assets/{n}\n" for n in first), encoding="utf-8")
    (out / "upload-2.txt").write_text("".join(f"assets/{n}\n" for n in then), encoding="utf-8")
    section, native = notes_inputs
    notes = release_notes(version, plan, section, native,
                          _signing_key(sums.read_bytes(), assets / SU.SIG_NAME, signer))
    if len(notes) > MAX_NOTES:
        raise Refused(f"the release notes have {len(notes)} characters; GitHub takes 125000 "
                      f"(this script at most {MAX_NOTES})")
    (out / NOTES).write_text(notes, encoding="utf-8")

    total = sum(i.size for i in plan.items)
    packs_count = sum(1 for i in plan.items if i.kind == "pack")
    print(f"axross {version} -> {assets}")
    print(f"  {len(plan.items) - packs_count} assets + {packs_count} pack wheels, "
          f"{_human(total)}, {SU.SUMS_NAME} with {len(plan.items)} lines")
    if plan.from_pypi:
        print(f"  {len(plan.from_pypi)} more pack wheels not attached: an axross-base fetches "
              "them from PyPI, checked against the manifest (--pack-wheels all attaches them)")
    for item in sorted((i for i in plan.items if i.kind != "pack"), key=lambda i: i.name):
        note = " (download only: the updater has none for it)" if item.kind == "download" else ""
        print(f"  {item.name:38s} {_human(item.size):>10s}  {item.sha256[:16]}  "
              f"<- {item.origin}{note}")
    for title, entries in (("Missing", plan.missing), ("Dropped (replaced by SHA256SUMS)",
                                                         plan.dropped),
                           ("Not published", plan.skipped)):
        if entries:
            print(f"{title}:")
            for entry in entries:
                print(f"  {entry}")

    keys = _verify_keys(args, signer)
    report = check_release(assets, version, keys=keys, order=(first, then), notes=notes)
    if args.allow_new_key or args.allow_unpinned:
        report.warnings.append("checked against " + ("the signing key alone"
                               if args.allow_unpinned else "TRUSTED_KEYS") +
                               ", not the field keys: installed binaries of 0.14.136 and older "
                               "refuse this release")
    _print_report(report)
    print(f"Upload: upload-1.txt ({len(first)} files), upload-2.txt ({len(then)} pack wheels), "
          f"notes {out / NOTES}; docs/PACKAGING.md, \"Release flow\"")
    why = ""
    if report.problems:
        why = f"{len(report.problems)} problems"
    elif args.require_all and report.missing:
        why = "--require-all and an installed binary finds no asset"
    if why:
        for name in UPLOAD_LISTS:  # the documented upload commands then fail
            (out / name).unlink(missing_ok=True)
        print(f"assemble_release: refused: {why} (assets/ kept to look at, no upload lists)",
              file=sys.stderr)
        return 1
    return 0


def github_release_json(release_id: str) -> str:
    """``gh api repos/c0decave/axross/releases/<id>`` on github.com (read only)."""
    if not release_id.isascii() or not release_id.isdigit():
        raise Refused(f"--release-id {release_id!r}: the release's number (gh release view "
                      "TAG --json databaseId --jq .databaseId)")
    gh = shutil.which("gh")
    if gh is None:
        raise Refused("--release-id needs the GitHub CLI (gh); or pass --api-json FILE")
    env = {**os.environ, "GH_HOST": "github.com"}
    try:
        proc = subprocess.run([gh, "api", f"repos/{SU.REPOSITORY}/releases/{release_id}"],
                              capture_output=True, text=True, timeout=120, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused(f"gh api: {exc}") from None
    if proc.returncode != 0:
        raise Refused(f"gh api repos/{SU.REPOSITORY}/releases/{release_id}: "
                      f"{proc.stderr.strip()[-400:]}")
    return proc.stdout


def check_only(args) -> int:
    folder = args.check
    assets = folder / "assets" if (folder / "assets").is_dir() else folder
    order = None
    lists = folder if (folder / "upload-1.txt").is_file() else assets
    if (lists / "upload-1.txt").is_file():
        def names(path):
            return [Path(line).name for line in path.read_text(encoding="utf-8").split()]
        order = (names(lists / "upload-1.txt"), names(lists / "upload-2.txt")
                 if (lists / "upload-2.txt").is_file() else [])
    api = None
    if args.api_json is not None:
        try:
            api = load_api_json(args.api_json.read_text(encoding="utf-8"))
        except OSError as exc:
            raise Refused(f"{args.api_json}: {exc.strerror}") from None
    elif args.release_id is not None:
        api = load_api_json(github_release_json(args.release_id))
    notes = ""
    for place in (folder, assets):
        if (place / NOTES).is_file():
            notes = (place / NOTES).read_text(encoding="utf-8")
            break
    keys = SU.TRUSTED_KEYS if args.allow_new_key else field_keys()
    report = check_release(assets, args.version, keys=keys if (assets / SU.SIG_NAME).exists()
                           or args.require_all else None, order=order, api=api, notes=notes)
    print(f"axross {args.version}: {assets}")
    _print_report(report)
    if report.problems or (args.require_all and report.missing):
        print("assemble_release: refused", file=sys.stderr)
        return 1
    return 0


def _default_version() -> str:
    text = (ROOT / "axross" / "_version.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    return match.group(1) if match else ""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble the GitHub release assets and check them as the updater will.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path, help="new folder for assets/, the upload lists and "
                      "notes.md")
    mode.add_argument("--check", type=Path, metavar="DIR",
                      help="only check an assembled folder (DIR or DIR/assets) or a downloaded "
                           "draft")
    parser.add_argument("--version", default=None,
                        help="the release's version (default: axross/_version.py)")
    parser.add_argument("--dist", type=Path, help="scripts/build_dist.sh's folder, dist/<version>")
    parser.add_argument("--ci", type=Path, help="the bundle job's artifacts (folders or .zip)")
    parser.add_argument("--packs", type=Path, help="the packs folder (default: DIST/packs)")
    parser.add_argument("--pack-wheels", choices=PACK_WHEELS, default="unhosted",
                        help="unhosted (default): attach only the pack wheels without a PyPI "
                             "address, a base fetches the others from PyPI; all: attach every "
                             "wheel")
    parser.add_argument("--changelog", type=Path, default=None,
                        help="the CHANGELOG.md the release notes start from (default: this "
                             "tree's)")
    parser.add_argument("--key", type=Path, help="sign SHA256SUMS with this key "
                        "(scripts/sign_release.py; a key of FIELD_KEYS)")
    parser.add_argument("--packs-issue", type=int, default=None, metavar="N",
                        help="passed to sign_release.py: the pack manifest's re-issue number")
    parser.add_argument("--allow-new-key", action="store_true",
                        help="passed to sign_release.py; checks against TRUSTED_KEYS")
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="passed to sign_release.py (a dry run with a throwaway key); "
                             "checks against that key alone")
    parser.add_argument("--require-all", action="store_true",
                        help="refuse unless every binary, the packs, wheel and sdist are there")
    github = parser.add_mutually_exclusive_group()
    github.add_argument("--api-json", type=Path, metavar="FILE",
                        help="--check: GitHub's release JSON (gh api repos/c0decave/axross/"
                             "releases/<id>) or asset list - its order, sizes and digests")
    github.add_argument("--release-id", metavar="ID",
                        help="--check: read that JSON with gh api on github.com")
    args = parser.parse_args(argv)
    args.version = args.version or _default_version()
    if SU.parse_version(args.version) is None or args.version.startswith("v"):
        parser.error(f"--version {args.version!r}: X.Y.Z")
    if args.check is None and (args.api_json is not None or args.release_id is not None):
        parser.error("--api-json and --release-id go with --check")
    try:
        return check_only(args) if args.check is not None else assemble(args)
    except Refused as exc:
        print(f"assemble_release: refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
