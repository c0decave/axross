#!/usr/bin/env python3
"""Put a release together from what was built, and check it as the updater will.

    assemble_release.py --out DIR [--dist DIST] [--ci CI] [--packs PACKS]
                        [--version X.Y.Z] [--key KEY.pem] [--require-all]
    assemble_release.py --check DIR [--version X.Y.Z] [--require-all]

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
* ``DIR/upload-1.txt``, ``DIR/upload-2.txt`` - the assets in upload order:
  first what the updater needs, then the pack wheels. The updater reads only
  the first 100 assets the API lists (core.self_update.parse_release); a
  pack wheel past them is fetched from PyPI instead.

Then the result is checked through core.self_update and core.packs
themselves: for every platform, machine, flavour and variant the release
serves, an installed binary of that kind (detect_install, with and without
the bundle's marker files - the binaries of 0.14.136 have no variant file)
must find its asset, the asset its line in SHA256SUMS; the release must
parse (parse_release) with every asset the updater needs among the first
100; the pack manifest must be what signed_manifest accepts, every wheel
what it names; and the signature must verify with the keys the binaries in
use pin (scripts/sign_release.py FIELD_KEYS) - ``--allow-new-key`` checks
against TRUSTED_KEYS instead, ``--allow-unpinned`` (a dry run with a
throwaway key) against the signing key alone, both with a warning.

Nothing is uploaded. Exit status: 0 done, 1 refused, 2 usage.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import os
import re
import shutil
import sys
import tempfile
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
#: The upload order (never assets; a downloaded draft may hold them).
UPLOAD_LISTS = ("upload-1.txt", "upload-2.txt")
#: What the binaries in use can reach: before 0.15.177 the updater read only
#: the first 100 assets of the API's answer (0.15.177 reads the asset pages,
#: but the release that brings it must reach the older ones first).
API_ASSETS = 100
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


def collect_packs(packs: Path, plan: Plan) -> None:
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


def check_release(assets: Path, version: str, *, keys: tuple[str, ...] | None,
                  order: tuple[list[str], list[str]] | None = None) -> Report:
    """Check the assets in *assets* through core.self_update and core.packs.
    *keys*: the signature must verify with them (None: no signature
    needed; one that is there is still checked against the field keys)."""
    report = Report()
    files = {p.name: p for p in assets.iterdir() if p.is_file() and p.name not in UPLOAD_LISTS}
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

    # The release as the API will list it, in upload order: parse_release
    # checks every name, size and URL, and reads the first API_ASSETS only.
    paths = {**files, SU.SUMS_NAME: sums_path, **({SU.SIG_NAME: sig_path} if sig_path else {})}
    first, then = order or (sorted(paths), [])
    listed = [n for n in dict.fromkeys([*first, *then]) if n in paths]
    listed += sorted(set(paths) - set(listed))
    tag = f"v{version}"
    api = {"tag_name": tag, "html_url": f"{SU.RELEASES_PREFIX}tag/{tag}", "body": "",
           "assets": [{"name": n, "size": paths[n].stat().st_size,
                       "browser_download_url": f"{SU.DOWNLOAD_PREFIX}{tag}/{n}",
                       "digest": "sha256:" + (digests.get(n) or _sha256_file(paths[n]))}
                      for n in listed][:API_ASSETS]}  # what an installed binary sees
    try:
        release = SU.parse_release(api)
    except SU.UpdateError as exc:
        report.problems.append(f"the release does not parse: {exc}")
        return report
    if release.version != version:
        report.problems.append(f"the tag {tag} parses as {release.version}")
    reachable = {a.name for a in release.assets}
    for name in listed:
        if name not in reachable and name not in then:
            report.problems.append(f"{name}: the updater does not see it (one of more than "
                                   f"{API_ASSETS} assets, or a name it refuses)")

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
            for blob, entry in sorted(blobs.items()):
                if blob not in files:
                    report.problems.append(f"packs: {blob} is in {name} but not an asset")
                elif entries.get(blob) != entry["sha256"] or digests[blob] != entry["sha256"] \
                        or files[blob].stat().st_size != entry["size"]:
                    report.problems.append(f"packs: {blob} differs from {name}")
                elif blob not in reachable and not entry.get("pypi"):
                    report.problems.append(f"packs: {blob} is past the first {API_ASSETS} assets "
                                           "and has no PyPI address: no base can fetch it")
                elif blob not in reachable:
                    report.warnings.append(f"packs: {blob} is past the first {API_ASSETS} "
                                           "assets: a base fetches it from PyPI")
            report.lines.append(f"{name}: {len(manifest.get('units') or {})} units, "
                                f"{len(blobs)} wheels, every one in {SU.SUMS_NAME}")
    else:
        report.missing.append(f"no {name}: an axross-base of {version} cannot add anything")
    return report


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
        collect_packs(packs, plan)
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
    if plan.missing and args.require_all:
        raise Refused("--require-all: missing " + "; ".join(plan.missing))
    out = args.out
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise Refused(f"{out} exists and is not empty: assemble into a new folder")
    assets = out / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    try:
        return _write_and_check(args, plan, out, assets)
    except BaseException:
        shutil.rmtree(assets, ignore_errors=True)  # nothing half-assembled is left to upload
        for name in UPLOAD_LISTS:
            (out / name).unlink(missing_ok=True)
        raise


def _write_and_check(args, plan: Plan, out: Path, assets: Path) -> int:
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

    total = sum(i.size for i in plan.items)
    packs_count = sum(1 for i in plan.items if i.kind == "pack")
    print(f"axross {version} -> {assets}")
    print(f"  {len(plan.items) - packs_count} assets + {packs_count} pack wheels, "
          f"{_human(total)}, {SU.SUMS_NAME} with {len(plan.items)} lines")
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
    report = check_release(assets, version, keys=keys, order=(first, then))
    if args.allow_new_key or args.allow_unpinned:
        report.warnings.append("checked against " + ("the signing key alone"
                               if args.allow_unpinned else "TRUSTED_KEYS") +
                               ", not the field keys: installed binaries of 0.14.136 and older "
                               "refuse this release")
    _print_report(report)
    print(f"Upload: upload-1.txt ({len(first)} files) first, then upload-2.txt "
          f"({len(then)} pack wheels); docs/PACKAGING.md, \"Release flow\"")
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


def check_only(args) -> int:
    folder = args.check
    assets = folder / "assets" if (folder / "assets").is_dir() else folder
    order = None
    if (folder / "upload-1.txt").is_file():
        def names(path):
            return [Path(line).name for line in path.read_text(encoding="utf-8").split()]
        order = (names(folder / "upload-1.txt"), names(folder / "upload-2.txt")
                 if (folder / "upload-2.txt").is_file() else [])
    else:  # the order upload_order gives: the manifest's wheels last
        manifest_path = assets / P.manifest_name(args.version)
        try:
            blobs = set(P.parse_manifest(manifest_path.read_bytes()).get("blobs") or {})
        except (OSError, P.PackError):
            blobs = set()
        rest = sorted(p.name for p in assets.iterdir()
                      if p.is_file() and p.name not in blobs and p.name not in UPLOAD_LISTS)
        order = (sorted(rest, key=lambda n: n not in (SU.SUMS_NAME, SU.SIG_NAME)), sorted(blobs))
    keys =SU.TRUSTED_KEYS if args.allow_new_key else field_keys()
    report = check_release(assets, args.version, keys=keys if (assets / SU.SIG_NAME).exists()
                           or args.require_all else None, order=order)
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
    mode.add_argument("--out", type=Path, help="new folder for assets/ and the upload lists")
    mode.add_argument("--check", type=Path, metavar="DIR",
                      help="only check an assembled folder (DIR or DIR/assets)")
    parser.add_argument("--version", default=None,
                        help="the release's version (default: axross/_version.py)")
    parser.add_argument("--dist", type=Path, help="scripts/build_dist.sh's folder, dist/<version>")
    parser.add_argument("--ci", type=Path, help="the bundle job's artifacts (folders or .zip)")
    parser.add_argument("--packs", type=Path, help="the packs folder (default: DIST/packs)")
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
    args = parser.parse_args(argv)
    args.version = args.version or _default_version()
    if SU.parse_version(args.version) is None or args.version.startswith("v"):
        parser.error(f"--version {args.version!r}: X.Y.Z")
    try:
        return check_only(args) if args.check is not None else assemble(args)
    except Refused as exc:
        print(f"assemble_release: refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
