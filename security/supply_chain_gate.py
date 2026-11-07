#!/usr/bin/env python3
"""The supply-chain gate: no dependency reaches an axross dist unless it was
reviewed, and nothing about it changed since.

``scripts/build_dist.sh`` runs ``check`` before it builds anything and stops
on any problem; there is no switch to skip it. What ``check`` does, for
every pin of every lock the build installs from (build/requirements-*.txt):

1. **PyPI**: each locked sha256 is a file PyPI lists for exactly that
   release (a hash of anything else - another index, a re-built file - is
   refused); the release and the files used are not yanked, the project is
   not quarantined; the release is at least ``MIN_AGE_DAYS`` old (most
   malicious uploads are found and removed within days), unless the
   package's baseline names a reason (a security fix).
2. **OSV** (api.osv.dev): no advisory, and no malicious-package entry
   (``MAL-*``, the OpenSSF malicious-packages feed). The gate fails closed
   when OSV cannot be reached.
3. **Names**: a package new to the baseline must not look like a typo of
   a popular package (edit distance, separators, look-alike characters,
   prefixes and suffixes; security/top_pypi_packages.txt) or of another
   locked one. The build must not use an extra index (dependency confusion).
4. **Provenance**: PyPI's attestations (PEP 740) - who published the file
   from which repository and workflow. A publisher different from the
   baseline's, or a file without attestations where the baseline had
   them, fails.
5. **Content** (security/package_inspect.py, nothing executed): the files
   the build would install (the wheel for the target platform, or the
   sdist) are downloaded, checked against the lock's hash and inspected:
   every member's SHA-256, native binaries, ``.pth`` start-up code, build
   hooks, the wheel's RECORD, suspicious lines. Compared with the reviewed
   baseline (security/supply_chain_baseline/<package>.json): a package or
   version that was never reviewed, an archive whose members differ from
   the reviewed ones, a finding the review did not accept - each fails.
6. **Scanners** (``scan``, run from a venv of the vetted tool lock
   build/requirements-scan-tools.txt): GuardDog's source and metadata rules
   for malicious packages, YARA (security/yara_rules), capa on every native
   binary the baseline does not know yet. New results fail like findings.

The baseline lives in git, so its history is the record over time: every
reviewed version, who reviewed it, why its findings are acceptable.

Commands:

    check   [--platform linux-x86_64] [--report DIR]   the gate
    review  NAME[==VERSION] ...     everything about a pin, and the source diff
                                    against the reviewed version
    accept  NAME==VERSION --by WHO --note TEXT [--young REASON]
                                    record a reviewed pin as the baseline
    status                          which pins are not (or no longer) reviewed

Exit codes: 0 clean, 1 a problem, 2 the gate could not run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

#: The project whose locks are checked (axross: this repository; another
#: project sets it in its config file, see configure()).
ROOT = Path(__file__).resolve().parents[1]
#: The gate's own files: the scanner, YARA rules, the list of top packages.
HERE = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security import package_inspect as PI  # noqa: E402
from security.dep_floor_audit import LockedPin, parse_lock  # noqa: E402

BASELINE_DIR = ROOT / "security" / "supply_chain_baseline"
#: Downloaded archives, by hash (a build points it at its work folder).
CACHE_DIR = Path(os.environ.get("AXROSS_SUPPLY_CHAIN_CACHE") or (ROOT / "build" / "supply-chain-cache"))
TOP_PACKAGES = HERE / "top_pypi_packages.txt"
SCANNER = HERE / "supply_chain_scan.py"
#: The locks the release build installs from.
LOCKS = ("build/requirements-bootstrap.txt", "build/requirements-dist-tools.txt",
         "build/requirements-bundle.txt", "build/requirements-scan-tools.txt")
#: Files that configure where pip and uv fetch from.
INDEX_CONFIG = ("scripts/build_dist.sh", "scripts/build_bundle.sh", "scripts/lock_bundle_deps.sh",
                "Dockerfile.build", "build/requirements-bundle.in")
MIN_AGE_DAYS = 14
#: Reviewed security fixes the lock scripts may take before MIN_AGE_DAYS.
YOUNG_FILE = ROOT / "build" / "young-release-exceptions.txt"


def _young_exceptions() -> dict[str, str]:
    out = {}
    try:
        for line in YOUNG_FILE.read_text(encoding="utf-8").splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and not line.startswith("#"):
                out[canonical(parts[0])] = parts[2].strip()
    except OSError:
        pass
    return out

PYPI = "https://pypi.org"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
USER_AGENT = "axross-supply-chain-gate/1"
#: The target the Linux bundles are built for.
PLATFORMS = {
    "linux-x86_64": {"python": "cp312", "platform_re": r"^(?:manylinux\w*_x86_64|linux_x86_64)$"},
    "macos-arm64": {"python": "cp312", "platform_re": r"^macosx_\d+_\d+_(?:arm64|universal2)$"},
    "windows-amd64": {"python": "cp312", "platform_re": r"^win_amd64$"},
}


# --- results ------------------------------------------------------------------------------

@dataclass
class Problem:
    package: str
    message: str
    check: str

    def line(self) -> str:
        return f"[{self.check}] {self.package}: {self.message}"


@dataclass
class PinResult:
    pin: LockedPin
    lock: str
    files: list = field(default_factory=list)          # inspected archive names
    reports: dict = field(default_factory=dict)        # archive -> PI.Report
    provenance: dict = field(default_factory=dict)     # archive -> publisher or None
    provenance_raw: dict = field(default_factory=dict)  # archive -> PEP 740 document or None
    paths: dict = field(default_factory=dict)          # archive -> local cached file
    scans: dict = field(default_factory=dict)          # archive -> scanner results
    release: dict = field(default_factory=dict)        # PyPI release JSON (info + urls)
    problems: list = field(default_factory=list)
    used_hashes: list = field(default_factory=list)    # SHA-256 of every inspected archive


class GateError(Exception):
    """The gate could not run (network, a broken lock): fails closed."""


# --- network -----------------------------------------------------------------------------

def _get(url: str, *, timeout: float = 60.0, accept: str = "application/json") -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt == 2:
                raise GateError(f"{url}: {exc}") from exc
            time.sleep(2 * (attempt + 1))
    raise GateError(url)


def _get_json(url: str) -> dict:
    return json.loads(_get(url))


def pypi_release(name: str, version: str) -> dict:
    try:
        return _get_json(f"{PYPI}/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
    except urllib.error.HTTPError as exc:
        raise GateError(f"PyPI has no {name}=={version} ({exc.code})") from exc


def pypi_project(name: str) -> dict:
    try:
        return _get_json(f"{PYPI}/pypi/{urllib.parse.quote(name)}/json")
    except urllib.error.HTTPError as exc:
        raise GateError(f"PyPI has no project {name} ({exc.code})") from exc


def provenance(name: str, version: str, filename: str) -> dict | None:
    """The publisher of *filename*'s attestations, or None when it has none."""
    raw = provenance_raw(name, version, filename)
    return publisher_of(raw)


def provenance_raw(name: str, version: str, filename: str) -> dict | None:
    """PyPI's provenance document of *filename* (PEP 740), or None."""
    url = (f"{PYPI}/integrity/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/"
           f"{urllib.parse.quote(filename)}/provenance")
    try:
        data = json.loads(_get(url, accept="application/vnd.pypi.integrity.v1+json"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise GateError(f"{url}: HTTP {exc.code}") from exc
    return data


def publisher_of(data: dict | None) -> dict | None:
    if not data:
        return None
    publishers = []
    for bundle in data.get("attestation_bundles", []) or []:
        pub = bundle.get("publisher") or {}
        publishers.append({k: pub.get(k) for k in ("kind", "repository", "workflow", "environment",
                                                   "project", "namespace") if pub.get(k)})
    if not publishers:
        return None
    return publishers[0] if len(publishers) == 1 else {"publishers": publishers}


def osv_batch(pairs: list[tuple[str, str]]) -> list[list[str]]:
    """Advisory ids of each (name, version) on PyPI; fails closed."""
    out: list[list[str]] = []
    for start in range(0, len(pairs), 500):
        chunk = pairs[start:start + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                                       for n, v in chunk]}).encode()
        request = urllib.request.Request(OSV_BATCH, data=body, headers={
            "Content-Type": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                results = json.loads(response.read()).get("results", [])
        except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as exc:
            raise GateError(f"OSV ({OSV_BATCH}) cannot be asked: {exc} - the gate does not pass "
                            "without it") from exc
        if len(results) != len(chunk):
            raise GateError("OSV answered a different number of queries")
        for result in results:
            out.append(sorted({v.get("id", "?") for v in result.get("vulns", []) or []}))
    return out


def osv_batch_ecosystem(queries: list[tuple[str, str, str]]) -> list[list[str]]:
    """Advisory ids of each (ecosystem, name, version); fails closed."""
    out: list[list[str]] = []
    for start in range(0, len(queries), 500):
        chunk = queries[start:start + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": e}, "version": v}
                                       for e, n, v in chunk]}).encode()
        request = urllib.request.Request(OSV_BATCH, data=body, headers={
            "Content-Type": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                results = json.loads(response.read()).get("results", [])
        except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as exc:
            raise GateError(f"OSV cannot be asked: {exc}") from exc
        if len(results) != len(chunk):
            raise GateError("OSV answered a different number of queries")
        out.extend(sorted({v.get("id", "?") for v in r.get("vulns", []) or []}) for r in results)
    return out


def osv_fixed(vuln_id: str, ecosystem: str, package: str) -> bool:
    """Whether OSV knows a fixed version of *package* for advisory *vuln_id*
    in exactly this *ecosystem* - its release included ("Debian:12"): a fix
    that only Debian 13 has is no fix a Debian 12 build lacks."""
    data = _get_json(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vuln_id)}")
    for affected in data.get("affected", []) or []:
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "") != ecosystem or pkg.get("name") != package:
            continue
        for r in affected.get("ranges", []) or []:
            if any("fixed" in event for event in r.get("events", [])):
                return True
    return False


def check_system(packages_json: Path, *, osv=osv_batch_ecosystem, fixed=osv_fixed) -> tuple[list[Problem], list[str]]:
    """The system packages of a bundle (scripts/sysroot_fetch.py's
    PACKAGES.json): an advisory OSV knows a fix for fails, one without a
    fix yet is a warning; a package whose file differs from the baseline's
    for the same version fails."""
    data = json.loads(packages_json.read_text(encoding="utf-8"))
    ecosystem, system = data["ecosystem"], data["system"]
    queries: dict[tuple[str, str, str], list[str]] = {}
    for p in data["packages"]:
        queries.setdefault((ecosystem, p["source"], p["source_version"]), []).append(p["name"])
        if ecosystem.startswith("AlmaLinux"):
            queries.setdefault((ecosystem, p["name"], p["version"]), []).append(p["name"])
    keys = list(queries)
    problems, warnings = [], []
    for (eco, name, version), ids in zip(keys, osv(keys)):
        for vid in ids:
            if fixed(vid, eco, name):
                problems.append(Problem(f"{system}:{name}", f"{version}: {vid} has a fix this package lacks", "system"))
            else:
                warnings.append(f"{system}:{name} {version}: {vid} (no fix yet)")
    try:
        base = json.loads(baseline_path(f"system-{system}").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        base = {}
    known = base.get("packages", {}) if isinstance(base, dict) else {}
    for p in data["packages"]:
        old = known.get(p["name"])
        if old and old["version"] == p["version"] and old["sha256"] != p["sha256"]:
            problems.append(Problem(f"{system}:{p['name']}", f"{p['version']} is not the file of the baseline "
                                    "(same version, other content)", "system"))
        elif old is None:
            warnings.append(f"{system}:{p['name']} {p['version']}: new in the bundle")
        elif old["version"] != p["version"]:
            warnings.append(f"{system}:{p['name']}: {old['version']} -> {p['version']}")
    return problems, warnings


def accept_system(packages_json: Path) -> Path:
    data = json.loads(packages_json.read_text(encoding="utf-8"))
    entry = {"name": f"system-{data['system']}", "ecosystem": data["ecosystem"],
             "date": dt.date.today().isoformat(),
             "packages": {p["name"]: {"version": p["version"], "sha256": p["sha256"], "source": p["source"]}
                          for p in data["packages"]}}
    path = baseline_path(f"system-{data['system']}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entry, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


_ENV_PROBE = r"""
import base64, hashlib, json, os, sys
from importlib import metadata
out = []
for dist in metadata.distributions():
    name = dist.metadata["Name"] or ""
    bad = []
    for f in dist.files or []:
        if f.hash is None or f.hash.mode != "sha256":
            continue
        path = f.locate()
        try:
            with open(path, "rb") as fh:
                digest = base64.urlsafe_b64encode(hashlib.sha256(fh.read()).digest()).rstrip(b"=").decode()
        except OSError:
            bad.append(f"{f} missing")
            continue
        if digest != f.hash.value:
            bad.append(f"{f} changed")
    out.append({"name": name, "version": dist.version, "bad": bad[:20]})
print(json.dumps(out))
"""


def verify_env(python: str, locks: list[Path]) -> list[Problem]:
    """Everything installed in the venv of *python* is a pin of *locks*,
    in the locked version, and its files are as the wheel's RECORD says."""
    import subprocess

    pins: dict[str, set[str]] = {}
    for lock in locks:
        for pin in parse_lock(lock.read_text(encoding="utf-8")):
            pins.setdefault(pin.name, set()).add(pin.version)
    proc = subprocess.run([python, "-I", "-c", _ENV_PROBE], capture_output=True, timeout=600)
    if proc.returncode != 0:
        raise GateError("cannot list the venv: " + proc.stderr.decode("utf-8", "replace")[-500:])
    problems = []
    for dist in json.loads(proc.stdout):
        name = canonical(dist["name"])
        if name not in pins:
            problems.append(Problem(name, f"{dist['version']} is installed but in no lock", "env"))
        elif dist["version"] not in pins[name]:
            problems.append(Problem(name, f"{dist['version']} is installed, the lock has {sorted(pins[name])}", "env"))
        for bad in dist["bad"]:
            problems.append(Problem(name, f"installed file {bad} against its RECORD", "env"))
    return problems


def download(url: str, sha256: str, filename: str) -> Path:
    """The file at *url*, cached by its hash; refused unless its SHA-256 is *sha256*."""
    if "/" in filename or filename.startswith("."):
        raise GateError(f"odd file name {filename!r}")
    target = CACHE_DIR / sha256[:2] / sha256 / filename
    if target.exists() and _sha256(target) == sha256:
        return target
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "files.pythonhosted.org":
        raise GateError(f"{filename}: PyPI points to {parts.hostname}, not files.pythonhosted.org")
    target.parent.mkdir(parents=True, exist_ok=True)
    data = _get(url, timeout=600, accept="*/*")
    if hashlib.sha256(data).hexdigest() != sha256:
        raise GateError(f"{filename}: the download does not have the locked hash")
    tmp = target.with_suffix(target.suffix + ".part")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    return target


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --- which files the build uses ---------------------------------------------------------------

def wheel_tags(filename: str) -> tuple[set[str], set[str], set[str]] | None:
    """(python tags, abi tags, platform tags) of a wheel file name."""
    if not filename.endswith(".whl"):
        return None
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        return None
    py, abi, plat = parts[-3], parts[-2], parts[-1]
    return set(py.split(".")), set(abi.split(".")), set(plat.split("."))


def _python_ok(py: set[str], abi: set[str], target: str) -> bool:
    minor = int(target[3:])
    for tag in py:
        if tag in (target, "py3", f"py3{minor}") or tag.startswith("py2.py3"):
            return True
        if tag.startswith("cp3") and "abi3" in abi:
            try:
                if int(tag[3:]) <= minor:
                    return True
            except ValueError:
                pass
        if tag == "py2" and "py3" in py:
            return True
    return False


FROM_SOURCE_FILE = HERE / "build_from_source.txt"


def built_from_source() -> set[str]:
    """Packages the release build compiles from their sdist (their sdist is
    reviewed as well as the wheel)."""
    try:
        return {canonical(l.strip()) for l in FROM_SOURCE_FILE.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


def files_for(release_files: list[dict], hashes: set[str], platforms: list[str],
              with_sdist: bool = False) -> list[dict]:
    """The locked files of a release a build for *platforms* can install:
    matching wheels, else the sdist (and the sdist too with *with_sdist*)."""
    locked = [f for f in release_files if f.get("digests", {}).get("sha256") in hashes]
    chosen: dict[str, dict] = {}
    if with_sdist:
        for f in locked:
            if f.get("packagetype") == "sdist":
                chosen[f["filename"]] = f
    for name in platforms:
        spec = PLATFORMS[name]
        pattern = re.compile(spec["platform_re"])
        wheels = []
        for f in locked:
            tags = wheel_tags(f["filename"])
            if tags is None:
                continue
            py, abi, plat = tags
            if not _python_ok(py, abi, spec["python"]):
                continue
            if "any" in plat or any(pattern.match(p) for p in plat):
                wheels.append(f)
        if wheels:
            # the most specific one pip would prefer: a platform wheel over "any"
            wheels.sort(key=lambda f: ("any" in wheel_tags(f["filename"])[2], f["filename"]))
            chosen[wheels[0]["filename"]] = wheels[0]
        else:
            for f in locked:
                if f.get("packagetype") == "sdist":
                    chosen[f["filename"]] = f
    return list(chosen.values())


# --- names --------------------------------------------------------------------------------------

def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "i": "l", "5": "s", "3": "e", "4": "a", "7": "t", "$": "s"})
_AFFIXES = ("python-", "py-", "py", "-python", "-py", "-dev", "-lib", "lib", "-sdk", "-client", "-api",
            "-tools", "-utils", "-core", "-cli", "2", "3", "-async", "async-", "-ng", "-new", "-official")


def _distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein distance, stopping early above *limit*."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


_PREPARED: dict[tuple, list[tuple[str, str, str]]] = {}


def _prepare(known: list[str]) -> list[tuple[str, str, str]]:
    key = (len(known), tuple(known[:3]), tuple(known[-3:]))
    prepared = _PREPARED.get(key)
    if prepared is None:
        prepared = []
        for k in known:
            kc = canonical(k)
            kflat = kc.replace("-", "")
            prepared.append((kc, kflat, kflat.translate(_LOOKALIKE)))
        _PREPARED.clear()
        _PREPARED[key] = prepared
    return prepared


def typosquat_of(name: str, known: list[str]) -> str | None:
    """The popular package *name* could be a typo of, or None. *known* is in
    popularity order; a name that is itself popular is no squat."""
    c = canonical(name)
    if not c.isascii() or any(unicodedata.category(ch).startswith("C") for ch in name):
        return f"(non-ASCII or control characters in {name!r})"
    prepared = _prepare(known)
    if any(kc == c for kc, _, _ in prepared):
        return None
    flat = c.replace("-", "")
    look = flat.translate(_LOOKALIKE)
    candidates: set[str] = set()
    for affix in _AFFIXES:
        if c.startswith(affix) and len(c) > len(affix) + 2:
            candidates.add(c[len(affix):].strip("-"))
        if c.endswith(affix) and len(c) > len(affix) + 2:
            candidates.add(c[: -len(affix)].strip("-"))
    for one in list(candidates):
        for affix in _AFFIXES:
            if one.startswith(affix) and len(one) > len(affix) + 2:
                candidates.add(one[len(affix):].strip("-"))
            if one.endswith(affix) and len(one) > len(affix) + 2:
                candidates.add(one[: -len(affix)].strip("-"))
    candidates.discard(c)
    for k, kflat, klook in prepared:
        if kflat == flat or klook == look:
            return k                                   # only separators or look-alikes differ
        if k in candidates and len(k) >= 4:
            return k                                   # a popular name with a prefix/suffix
        limit = 1 if len(k) < 8 else 2
        if len(k) >= 4 and _distance(flat, kflat, limit) <= limit:
            return k
    return None


def publishable_names(names: list[str], root: Path | None = None) -> tuple[list[str], int]:
    """*names* without those the leak check of axross's public mirror
    (scripts/_scrub_rules.py, when the project has it) would flag - a few
    popular names look like an API key or an internal marker to it. The
    typosquatting check loses those reference names; nothing else does."""
    rules = (root or ROOT) / "scripts" / "_scrub_rules.py"
    if not rules.is_file():
        return names, 0
    import importlib.util

    spec = importlib.util.spec_from_file_location("_scrub_rules", rules)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    kept = [n for n in names if not module.find_leaks(n, include_paths=True)]
    return kept, len(names) - len(kept)


def load_top_packages() -> list[str]:
    if not TOP_PACKAGES.exists():
        return []
    return [line.strip() for line in TOP_PACKAGES.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


def index_problems(root: Path | None = None) -> list[str]:
    """Places that would let pip or uv fetch from another index than PyPI."""
    root = root or ROOT
    out = []
    pattern = re.compile(r"--(?:extra-)?index-url(?:=|\s+)(\S+)|--find-links|PIP_EXTRA_INDEX_URL|"
                         r"UV_EXTRA_INDEX_URL|extra-index-url", re.I)
    for rel in INDEX_CONFIG:
        path = root / rel
        if not path.exists():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for m in pattern.finditer(line):
                url = m.group(1)
                if url and url.rstrip("/").strip("'\"") in ("https://pypi.org/simple", "https://pypi.org/simple/"):
                    continue
                out.append(f"{rel}:{number}: {line.strip()[:160]}")
    for var in ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX_URL",
                "UV_EXTRA_INDEX_URL", "UV_INDEX", "PIP_CONFIG_FILE", "UV_CONFIG_FILE"):
        value = os.environ.get(var)
        if value and value.rstrip("/") != "https://pypi.org/simple":
            out.append(f"environment: {var}={value[:160]}")
    return out


# --- the baseline --------------------------------------------------------------------------

def baseline_path(name: str) -> Path:
    return BASELINE_DIR / f"{canonical(name)}.json"


def _baseline_file(name: str) -> dict | None:
    try:
        data = json.loads(baseline_path(name).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("versions"), dict) else None


def load_baseline(name: str, version: str) -> dict | None:
    """The reviewed entry of *name* in *version*, or None."""
    data = _baseline_file(name)
    entry = (data or {}).get("versions", {}).get(version)
    return entry if isinstance(entry, dict) else None


def reviewed_versions(name: str) -> list[str]:
    data = _baseline_file(name) or {}
    return sorted(data.get("versions", {}), key=_version_key)


def _version_key(version: str) -> tuple:
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-+]", version))


def known_package(name: str) -> bool:
    return bool(reviewed_versions(name))


def latest_other(name: str, version: str) -> dict | None:
    """The newest reviewed entry of *name* other than *version* (what a new
    version is compared with)."""
    others = [v for v in reviewed_versions(name) if v != version]
    return load_baseline(name, others[-1]) if others else None


#: Credential-shaped strings (API keys of the common services) found in a
#: third-party binary are not copied into the committed baseline: it is
#: published with the source, and it must not spread a vendor's leaked key
#: further. Each is replaced by a marker with its SHA-256, so a changed
#: string still shows in a review diff.
_CREDENTIAL_SHAPES = re.compile(
    r"sk-(?:ant-|or-|proj-)?[A-Za-z0-9_-]{16,}"      # Anthropic, OpenAI, OpenRouter
    r"|AKIA[0-9A-Z]{16}"                            # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{30,}"                  # GitHub tokens
    r"|glpat-[A-Za-z0-9_-]{20,}"                    # GitLab
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"                # Slack
)


def withhold_credentials(value):
    """*value* (a string, or lists / dicts of them) with every
    credential-shaped string replaced by ``[withheld sha256:<12 hex>]``."""
    if isinstance(value, str):
        return _CREDENTIAL_SHAPES.sub(
            lambda m: f"[withheld sha256:{hashlib.sha256(m.group(0).encode()).hexdigest()[:12]}]", value)
    if isinstance(value, list):
        return [withhold_credentials(v) for v in value]
    if isinstance(value, dict):
        return {k: withhold_credentials(v) for k, v in value.items()}
    return value


def save_baseline(entry: dict, locked: set[tuple[str, str]] | None = None) -> Path:
    """Add *entry* to its package's file; versions no lock has any more
    are dropped (git keeps them)."""
    name = canonical(entry["name"])
    data = _baseline_file(name) or {"name": name, "versions": {}}
    data["versions"][entry["version"]] = entry
    if locked is not None:
        data["versions"] = {v: e for v, e in data["versions"].items()
                            if (name, v) in locked or v == entry["version"]}
    path = baseline_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def manifest_digest(files: dict) -> str:
    text = "\n".join(f"{p}\x00{h}" for p, h in sorted(files.items()))
    return hashlib.sha256(text.encode()).hexdigest()


def compare_with_baseline(result: PinResult, base: dict | None) -> None:
    pin = result.pin
    if base is None:
        others = reviewed_versions(pin.name)
        if others:
            result.problems.append(Problem(pin.name, f"version changed from the reviewed {', '.join(others)} to "
                                           f"{pin.version}: review the difference and accept it", "baseline"))
        else:
            result.problems.append(Problem(pin.name, f"{pin.version} was never reviewed "
                                           f"({_shown(baseline_path(pin.name))}): review and accept it", "baseline"))
        return
    accepted = set(base.get("accepted_findings", []))
    for archive, report in result.reports.items():
        known = (base.get("archives") or {}).get(archive)
        if known is None:
            result.problems.append(Problem(pin.name, f"{archive} was not part of the review", "baseline"))
            continue
        if known.get("sha256") != report.sha256:
            result.problems.append(Problem(pin.name, f"{archive} is not the file that was reviewed", "baseline"))
        if known.get("manifest") != manifest_digest(report.files):
            result.problems.append(Problem(pin.name, f"{archive}: its members differ from the reviewed ones", "baseline"))
        for finding in report.findings:
            if finding.key() not in accepted:
                result.problems.append(Problem(pin.name, f"new {finding.severity} finding {finding.rule} in "
                                               f"{finding.path}:{finding.line}: {finding.text[:120]}", "content"))
        for problem in report.errors + report.record_problems:
            result.problems.append(Problem(pin.name, f"{archive}: {problem}", "content"))
        want_pub = (base.get("provenance") or {}).get(archive)
        got_pub = result.provenance.get(archive)
        if want_pub and not got_pub:
            result.problems.append(Problem(pin.name, f"{archive} had attestations at review, now none", "provenance"))
        elif want_pub and got_pub != want_pub:
            result.problems.append(Problem(pin.name, f"{archive} was published by {got_pub}, the review saw "
                                           f"{want_pub}", "provenance"))


def baseline_entry(result: PinResult, by: str, note: str, young: str = "",
                   scans: dict | None = None) -> dict:
    info = result.release.get("info", {})
    archives = {}
    for archive, report in result.reports.items():
        archives[archive] = {
            "sha256": report.sha256, "kind": report.kind, "manifest": manifest_digest(report.files),
            "files": dict(sorted(report.files.items())), "native": dict(sorted(report.native.items())),
            "pth": report.pth, "hooks": sorted(report.hooks), "entry_points": report.entry_points,
        }
    findings = sorted({f.key() for r in result.reports.values() for f in r.findings})
    entry = {
        "name": result.pin.name, "version": result.pin.version,
        "reviewed": {"date": dt.date.today().isoformat(), "by": by, "note": note},
        "pypi": {k: info.get(k) for k in ("author", "author_email", "maintainer", "maintainer_email",
                                          "home_page", "license", "license_expression", "summary")
                 if info.get(k)} | {"project_urls": info.get("project_urls") or {}},
        "provenance": result.provenance, "archives": archives, "accepted_findings": findings,
    }
    if young:
        entry["young_release"] = young
    if scans:
        entry["scans"] = scans
        entry["accepted_findings"] = sorted(set(findings) | set(scans.get("keys", [])))
    return entry


# --- the scanner stage -----------------------------------------------------------------------------

def known_native(name: str) -> set[str]:
    """SHA-256 of every native binary of any reviewed version of *name*."""
    out = set()
    for version in reviewed_versions(name):
        base = load_baseline(name, version) or {}
        for archive in (base.get("archives") or {}).values():
            files = archive.get("files", {})
            out.update(files[p] for p in archive.get("native", {}) if p in files)
        out.update((base.get("scans") or {}).get("capa", {}).keys())
    return out


CAPA_RULES_FILE = ROOT / "build" / "capa-rules.txt"
CAPA_SIGS_FILE = ROOT / "build" / "capa-sigs.txt"


def _pinned_tarball(pin_file: Path, folder: str, suffix: str, minimum: int, what: str) -> str:
    """A github.com tarball pinned in *pin_file* ("url sha256"): downloaded
    once, checked against the pinned SHA-256, only *suffix* files unpacked,
    no path outside the folder."""
    import io
    import tarfile

    line = next(l for l in pin_file.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#"))
    url, sha = line.split()
    target = CACHE_DIR / folder / sha
    done = target / ".complete"
    if done.exists():
        return str(target)
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "github.com":
        raise GateError(f"{what} from {parts.hostname}, not github.com")
    data = _get(url, timeout=300, accept="*/*")
    if hashlib.sha256(data).hexdigest() != sha:
        raise GateError(f"the {what} do not have the pinned hash")
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf:
            name = member.name.split("/", 1)[-1]
            if not member.isfile() or not name.endswith(suffix) or not PI._safe_path(name):
                continue
            dest = target / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(tf.extractfile(member).read())
            count += 1
    if count < minimum:
        raise GateError(f"only {count} {what} unpacked")
    done.write_text(sha, encoding="utf-8")
    return str(target)


def capa_rules() -> str:
    """capa's rules (build/capa-rules.txt), only .yml files."""
    return _pinned_tarball(CAPA_RULES_FILE, "capa-rules", ".yml", 500, "capa rules")


def capa_sigs() -> str:
    """capa's FLIRT signatures (build/capa-sigs.txt), only .sig files, in
    their sigs/ folder: the flare-capa wheel carries none, and without them
    capa refuses every PE file."""
    return str(Path(_pinned_tarball(CAPA_SIGS_FILE, "capa-sigs", ".sig", 3, "capa signatures")) / "sigs")


def run_scanners(results: list[PinResult], scan_python: str, *, capa: bool, strict: bool = True) -> None:
    """GuardDog's and axross's YARA rules, capa and the attestation check
    (security/supply_chain_scan.py in the scanner venv) over every archive."""
    import subprocess

    archives, known = [], set()
    for r in results:
        known |= known_native(r.pin.name)
        for archive, path in r.paths.items():
            archives.append({"path": path, "name": archive, "provenance": r.provenance_raw.get(archive)})
    if not archives:
        return
    with tempfile.TemporaryDirectory() as tmp:
        job, out = Path(tmp) / "job.json", Path(tmp) / "result.json"
        job.write_text(json.dumps({"archives": archives, "known_native": sorted(known),
                                   "skip_capa": not capa, "capa_rules": capa_rules() if capa else "",
                                   "capa_sigs": capa_sigs() if capa else "",
                                   "capa_cache": str(CACHE_DIR / "capa-results")}),
                       encoding="utf-8")
        proc = subprocess.run([scan_python, "-I", str(SCANNER), str(job),
                               str(out)], capture_output=True, timeout=6 * 3600)
        if proc.returncode != 0 or not out.exists():
            raise GateError("the scanners failed: " + proc.stderr.decode("utf-8", "replace")[-800:])
        data = json.loads(out.read_text(encoding="utf-8"))
    for r in results:
        for archive in r.paths:
            r.scans[archive] = data["archives"].get(archive, {})
    if capa and strict:
        # a binary capa should have read but could not is no reviewed binary
        broken = [f"{r.pin.name}: {e['path']}: {e['error'][:200]}" for r in results for scan in r.scans.values()
                  for e in scan.get("capa", []) if e.get("error")]
        if broken:
            raise GateError("capa failed on: " + "; ".join(broken[:10]))


def scan_keys(scans: dict) -> set[str]:
    return {hit["key"] for result in scans.values() for hit in result.get("yara", [])}


def compare_scans(result: PinResult, base: dict | None) -> None:
    pin = result.pin
    if base is None:
        return  # already a problem: not reviewed
    accepted = set(base.get("accepted_findings", []))
    for archive, scan in result.scans.items():
        for hit in scan.get("yara", []):
            if hit["key"] not in accepted:
                result.problems.append(Problem(pin.name, f"new YARA {hit['kind']} hit {hit['rule']} "
                                               f"({hit['severity']}) in {hit['path']}: {hit['description']}", "yara"))
        for entry in scan.get("capa", []):
            result.problems.append(Problem(pin.name, f"native binary {entry['path']} ({entry['sha256'][:16]}…) "
                                           "is not in the reviewed baseline", "capa"))
        att = scan.get("attestation", {})
        if att.get("attested") and not att.get("verified"):
            result.problems.append(Problem(pin.name, f"{archive}: its attestation does not verify: "
                                           f"{att.get('error', '')}", "provenance"))


# --- check -------------------------------------------------------------------------------------

def read_locks(root: Path | None = None, locks=None) -> list[tuple[str, LockedPin]]:
    root, locks = root or ROOT, locks or LOCKS
    out = []
    for rel in locks:
        path = root / rel
        if not path.exists():
            if rel.endswith("scan-tools.txt"):
                raise GateError(f"{rel} is missing - the scanner tools must be locked and hashed")
            continue
        try:
            for pin in parse_lock(path.read_text(encoding="utf-8")):
                out.append((rel, pin))
        except ValueError as exc:
            raise GateError(f"{rel}: {exc}") from exc
    return out


def check_pin(rel: str, pin: LockedPin, platforms: list[str], *, now: float | None = None,
              inspect_files: bool = True) -> PinResult:
    result = PinResult(pin=pin, lock=rel)
    release = pypi_release(pin.name, pin.version)
    result.release = release
    info, files = release.get("info", {}), release.get("urls", [])
    by_hash = {f.get("digests", {}).get("sha256"): f for f in files}
    for h in pin.hashes:
        if h not in by_hash:
            result.problems.append(Problem(pin.name, f"--hash={h[:16]}… is not a file of {pin.version} on PyPI",
                                           "pypi"))
    if info.get("yanked"):
        result.problems.append(Problem(pin.name, f"{pin.version} is yanked: {info.get('yanked_reason') or ''}", "pypi"))
    status = (info.get("project_status") or {}).get("status") if isinstance(info.get("project_status"), dict) else None
    if status in ("quarantined", "archived", "deprecated"):
        result.problems.append(Problem(pin.name, f"the project is {status} on PyPI", "pypi"))
    used = files_for(files, set(pin.hashes), platforms, with_sdist=canonical(pin.name) in built_from_source())
    if not used:
        result.problems.append(Problem(pin.name, "no locked file fits the target platforms", "pypi"))
    base = load_baseline(pin.name, pin.version)
    now = time.time() if now is None else now
    for f in used:
        if f.get("yanked"):
            result.problems.append(Problem(pin.name, f"{f['filename']} is yanked", "pypi"))
        uploaded = dt.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")).timestamp()
        age_days = (now - uploaded) / 86400
        if age_days < MIN_AGE_DAYS and not (base and base.get("young_release")):
            result.problems.append(Problem(pin.name, f"{f['filename']} was uploaded {age_days:.1f} days ago "
                                           f"(minimum {MIN_AGE_DAYS})", "age"))
        result.files.append(f["filename"])
        result.used_hashes.append(f["digests"]["sha256"])
        raw = provenance_raw(pin.name, pin.version, f["filename"])
        result.provenance_raw[f["filename"]] = raw
        result.provenance[f["filename"]] = publisher_of(raw)
        if inspect_files:
            path = download(f["url"], f["digests"]["sha256"], f["filename"])
            result.paths[f["filename"]] = str(path)
            result.reports[f["filename"]] = PI.inspect(str(path))
    if inspect_files:
        compare_with_baseline(result, base)
    return result


def reduce_lock(text: str, keep: dict[tuple[str, str], set[str]]) -> str:
    """*text* (a hashed lock) with each pin's hashes cut down to *keep*
    [(name, version)]: the archives the gate inspected. pip with
    --require-hashes then installs exactly those - not a sibling wheel of
    the same release with a more specific tag that nobody looked at. A pin
    with none left is a GateError (it would be installed unchecked)."""
    out = ["# Reduced by security/supply_chain_gate.py check --reduced-locks: only the",
           "# archives the gate inspected."]
    for pin in parse_lock(text):
        hashes = [h for h in pin.hashes if h in keep.get((pin.name, pin.version), set())]
        if not hashes:
            raise GateError(f"{pin.name}=={pin.version}: no inspected archive left in the reduced lock")
        head = f"{pin.name}=={pin.version}" + (f" ; {pin.marker}" if pin.marker else "")
        out.append(head + " \\")
        out.extend(f"    --hash=sha256:{h}" + (" \\" if i < len(hashes) - 1 else "")
                   for i, h in enumerate(hashes))
    return "\n".join(out) + "\n"


def write_reduced_locks(results: list[PinResult], out_dir: Path, root: Path | None = None,
                        locks=None) -> list[Path]:
    """One reduced copy (reduce_lock) of every lock, named as the lock, in
    *out_dir*. A pin two locks share was checked once: its inspected
    archives count for both."""
    root, locks = root or ROOT, locks or LOCKS
    keep: dict[tuple[str, str], set[str]] = {}
    for res in results:
        keep.setdefault((res.pin.name, res.pin.version), set()).update(res.used_hashes)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for rel in locks:
        source = root / rel
        if not source.exists():
            continue
        target = out_dir / Path(rel).name
        target.write_text(reduce_lock(source.read_text(encoding="utf-8"), keep), encoding="utf-8")
        written.append(target)
    return written


def run_check(platforms: list[str], *, root: Path | None = None, locks=None, top: list[str] | None = None,
              osv=osv_batch, checker=check_pin, scan_python: str | None = None,
              ) -> tuple[list[PinResult], list[Problem]]:
    pins = read_locks(root, locks)
    general: list[Problem] = []
    for line in index_problems(root):
        general.append(Problem("(build)", f"another package index can be used: {line}", "index"))
    pairs = list(dict.fromkeys((p.name, p.version) for _, p in pins))
    for (name, version), ids in zip(pairs, osv(pairs)):
        if ids:
            malicious = [i for i in ids if i.startswith("MAL-")]
            text = ("MALICIOUS PACKAGE " + ", ".join(malicious)) if malicious else "advisories " + ", ".join(ids)
            general.append(Problem(name, f"{version}: {text}", "osv"))
    known = top if top is not None else load_top_packages()
    locked_names = sorted({p.name for _, p in pins})
    for name in locked_names:
        if known_package(name):
            continue
        squat = typosquat_of(name, known + [n for n in locked_names if n != name])
        if squat:
            general.append(Problem(name, f"the name looks like a typo of {squat!r} (typosquatting?)", "name"))
    results = []
    seen: set[tuple[str, str]] = set()
    for rel, pin in pins:
        if (pin.name, pin.version) in seen:
            continue
        seen.add((pin.name, pin.version))
        try:
            results.append(checker(rel, pin, platforms))
        except GateError as exc:
            r = PinResult(pin=pin, lock=rel)
            r.problems.append(Problem(pin.name, str(exc), "pypi"))
            results.append(r)
    if scan_python:
        run_scanners(results, scan_python, capa=False)
        for r in results:
            compare_scans(r, load_baseline(r.pin.name, r.pin.version))
    general.extend(deep_problems(pins))
    return results, general


def write_report(results: list[PinResult], general: list[Problem], out_dir: Path, platforms: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    problems = general + [p for r in results for p in r.problems]
    data = {
        "date": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "platforms": platforms, "passed": not problems,
        "problems": [p.__dict__ for p in problems],
        "pins": [{"name": r.pin.name, "version": r.pin.version, "lock": r.lock, "files": r.files,
                  "sha256": {a: rep.sha256 for a, rep in r.reports.items()},
                  "provenance": r.provenance} for r in results],
    }
    (out_dir / "SUPPLY-CHAIN.json").write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    lines = [f"# Supply-chain gate - {'PASSED' if not problems else 'FAILED'}", "",
             f"{data['date']}, platforms {', '.join(platforms)}, {len(results)} pins "
             f"(security/supply_chain_gate.py).", ""]
    if problems:
        lines += ["## Problems", ""] + [f"- {p.line()}" for p in problems] + [""]
    lines += ["## Pins", "", "| Package | Version | Lock | Reviewed | Files | Attested by |", "|---|---|---|---|---|---|"]
    for r in results:
        base = load_baseline(r.pin.name, r.pin.version) or {}
        reviewed = base.get("reviewed", {})
        pubs = {json.dumps(v, sort_keys=True) if v else "-" for v in r.provenance.values()} or {"-"}
        lines.append(f"| {r.pin.name} | {r.pin.version} | {r.lock.rsplit('/', 1)[-1]} | "
                     f"{reviewed.get('date', '-')} {reviewed.get('by', '')} | {len(r.files)} | "
                     f"{'; '.join(sorted(pubs))[:120]} |")
    (out_dir / "SUPPLY-CHAIN.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- review / accept ---------------------------------------------------------------------------

def _pin_from_locks(spec: str, root: Path | None = None) -> tuple[str, LockedPin]:
    name, _, version = spec.partition("==")
    for rel, pin in read_locks(root):
        if pin.name == canonical(name) and (not version or pin.version == version):
            return rel, pin
    raise GateError(f"{spec} is not in the locks")


def _source_diff(old: Path, new: Path, limit: int = 4000) -> list[str]:
    """Unified diff of the Python sources of two archives."""
    def texts(path: Path) -> dict[str, list[str]]:
        out = {}
        for name, read in PI._members(str(path)):
            if name.endswith((".py", ".pth", ".cfg", ".toml", ".txt")) and PI._safe_path(name):
                data = read()
                if len(data) <= PI.MAX_TEXT_MEMBER:
                    out[name.split("/", 1)[-1] if path.name.endswith(".tar.gz") else name] = \
                        data.decode("utf-8", "replace").splitlines()
        return out
    a, b = texts(old), texts(new)
    lines: list[str] = []
    for name in sorted(set(a) | set(b)):
        if a.get(name) == b.get(name):
            continue
        lines.extend(difflib.unified_diff(a.get(name, []), b.get(name, []), f"old/{name}", f"new/{name}", lineterm=""))
        if len(lines) > limit:
            lines.append(f"… (diff cut at {limit} lines)")
            break
    return lines


def review(spec: str, platforms: list[str], out=print, scan_python: str = "") -> PinResult:
    rel, pin = _pin_from_locks(spec)
    result = check_pin(rel, pin, platforms)
    if scan_python:
        run_scanners([result], scan_python, capa=True)
    info = result.release.get("info", {})
    base = load_baseline(pin.name, pin.version)
    previous = None if base else latest_other(pin.name, pin.version)
    project = pypi_project(pin.name)
    releases = project.get("releases", {})
    out(f"== {pin.name} {pin.version}  ({rel})")
    out(f"   summary: {info.get('summary')}")
    out(f"   author: {info.get('author')} <{info.get('author_email')}>  maintainer: {info.get('maintainer')}")
    out(f"   urls: {json.dumps(info.get('project_urls') or {}, sort_keys=True)}")
    out(f"   license: {info.get('license_expression') or (info.get('license') or '')[:80]}")
    firsts = sorted(f["upload_time_iso_8601"] for files in releases.values() for f in files)
    out(f"   project: {len(releases)} releases, first upload {firsts[0][:10] if firsts else '?'}")
    if base:
        out(f"   reviewed: {base.get('version')} on {base['reviewed']['date']} by {base['reviewed']['by']}: "
            f"{base['reviewed']['note']}")
    elif previous:
        out(f"   reviewed before: {previous.get('version')} on {previous['reviewed']['date']} - "
            f"the changes against it follow")
    for archive in result.files:
        out(f"   file {archive}: attested by {result.provenance.get(archive)}")
    for archive, report in result.reports.items():
        out(f"   -- {archive}: {len(report.files)} members, {len(report.native)} native, hooks {report.hooks[:5]}")
        for name, lines in report.pth.items():
            out(f"      .pth {name}: {lines}")
        for problem in report.errors + report.record_problems:
            out(f"      PROBLEM {problem}")
        known_keys = set((base or previous or {}).get("accepted_findings", []))
        for f in report.findings:
            mark = "known" if f.key() in known_keys else "NEW"
            out(f"      {mark:5} {f.severity:6} {f.rule:24} {f.path}:{f.line}  {f.text[:160]}")
        if previous:
            base_old = previous
            old_archives = base_old.get("archives") or {}
            out(f"      changes against the reviewed {base_old.get('version')}:")
            old_files = next(iter(old_archives.values()), {}).get("files", {}) if old_archives else {}
            strip = (lambda n: n.split("/", 1)[-1]) if report.kind == "sdist" else (lambda n: n)
            old_map = {strip(k): v for k, v in old_files.items()}
            new_map = {strip(k): v for k, v in report.files.items()}
            for n in sorted(set(new_map) - set(old_map))[:200]:
                out(f"        + {n}")
            for n in sorted(set(old_map) - set(new_map))[:200]:
                out(f"        - {n}")
            for n in sorted(k for k in set(new_map) & set(old_map) if new_map[k] != old_map[k])[:400]:
                out(f"        ~ {n}")
            old_release = pypi_release(pin.name, base_old["version"]).get("urls", [])
            old_used = [f for f in old_release if f["filename"] in old_archives]
            if old_used:
                old_path = download(old_used[0]["url"], old_used[0]["digests"]["sha256"], old_used[0]["filename"])
                new_file = next(f for f in result.release["urls"] if f["filename"] == archive)
                new_path = download(new_file["url"], new_file["digests"]["sha256"], archive)
                for line in _source_diff(old_path, new_path):
                    out("        " + line)
    for archive, scan in result.scans.items():
        att = scan.get("attestation", {})
        out(f"   -- scanners on {archive}: attestation {att}")
        accepted = set((base or previous or {}).get("accepted_findings", []))
        for hit in scan.get("yara", []):
            mark = "known" if hit["key"] in accepted else "NEW"
            out(f"      {mark:5} {hit['kind']:10} {hit['severity']:6} {hit['rule']} {hit['path']}  "
                f"{' | '.join(hit['strings'])[:160]}")
        old_profiles = {v.get("path"): v.get("profile", {}) for v in
                        ((previous or {}).get("scans") or {}).get("capa", {}).values()}
        for entry in scan.get("capa", []):
            caps = entry.get("capabilities")
            prof = entry.get("profile", {})
            out(f"      native {entry['path']} ({entry['kind']}, {entry['size']} bytes)")
            out(f"         imports: {json.dumps(prof.get('categories', {}), sort_keys=True)[:300]}")
            if prof.get("urls") or prof.get("ipv4"):
                out(f"         urls: {prof.get('urls', [])[:10]}  ipv4: {prof.get('ipv4', [])[:10]}")
            out("         capa: " + (", ".join(caps) if caps else entry.get("skipped") or entry.get("error")
                                    or "no capabilities"))
            old = old_profiles.get(entry["path"])
            if old is not None:
                new_imports = {f for v in prof.get("categories", {}).values() for f in v} - \
                    {f for v in old.get("categories", {}).values() for f in v}
                new_urls = set(withhold_credentials(prof.get("urls", []))) - set(old.get("urls", []))
                if new_imports or new_urls:
                    out(f"         NEW against {previous.get('version')}: imports {sorted(new_imports)} urls {sorted(new_urls)[:10]}")
    for p in result.problems:
        out(f"   problem: {p.line()}")
    return result


def accept(spec: str, by: str, note: str, platforms: list[str], young: str = "", scan_python: str = "") -> Path:
    if not by.strip() or len(note.strip()) < 10:
        raise GateError("accept needs --by and a --note of at least 10 characters that says what was checked")
    rel, pin = _pin_from_locks(spec)
    result = check_pin(rel, pin, platforms)
    hard = [p for p in result.problems if p.check in ("pypi",)]
    if hard:
        raise GateError("cannot accept: " + "; ".join(p.line() for p in hard))
    young_problems = [p for p in result.problems if p.check == "age"]
    if young_problems and not young:
        raise GateError("cannot accept a release younger than the minimum age without --young REASON: "
                        + "; ".join(p.message for p in young_problems))
    if not scan_python:
        raise GateError("accept needs --scan-python: no baseline without the scanners' results")
    run_scanners([result], scan_python, capa=True)
    failed = [a for a, scan in result.scans.items()
              if scan.get("attestation", {}).get("attested") and not scan["attestation"].get("verified")]
    if failed:
        raise GateError(f"cannot accept: the attestation of {failed} does not verify")
    scans = {"keys": sorted(scan_keys(result.scans)),
             "capa": {e["sha256"]: {"path": e["path"], "capabilities": e.get("capabilities", []),
                                    "note": e.get("skipped") or e.get("error", ""),
                                    "profile": withhold_credentials(e.get("profile", {}))}
                      for scan in result.scans.values() for e in scan.get("capa", [])},
             "yara": sorted({f"{h['rule']} {h['path']}" for scan in result.scans.values()
                             for h in scan.get("yara", [])})}
    for version in reviewed_versions(pin.name):
        old = load_baseline(pin.name, version) or {}
        for sha, entry in ((old.get("scans") or {}).get("capa") or {}).items():
            scans["capa"].setdefault(sha, entry)
    entry = baseline_entry(result, by.strip(), note.strip(), young.strip(), scans)
    locked = {(p.name, p.version) for _, p in read_locks()}
    return save_baseline(entry, locked)


# --- deep scan: capa on every binary, in night sessions ------------------------------------------

#: capa rule namespaces (the start of a rule's name in its report) whose hit
#: in a binary needs a review note before the gate passes.
DEEP_ALARM = ("anti-analysis", "persistence", "inject", "credential", "keylog", "screenshot", "capture screen",
              "hook", "hide", "steal", "exfiltrat", "encrypt file", "delete volume shadow", "bypass uac",
              "terminate process", "reverse shell", "download and execute", "self delete")


def deep_pending() -> list[tuple[str, str, str, str, str]]:
    """(package, version, archive, member, sha256) of every native binary of
    the locked pins without a full (deep) capa analysis."""
    out = []
    locked = {(p.name, p.version) for _, p in read_locks()}
    for name, version in sorted(locked):
        base = load_baseline(name, version) or {}
        capa = (base.get("scans") or {}).get("capa", {})
        for archive, data in (base.get("archives") or {}).items():
            for member in data.get("native", {}):
                sha = data["files"].get(member)
                entry = capa.get(sha, {})
                if sha and not entry.get("deep") and not entry.get("capabilities"):
                    out.append((name, version, archive, member, sha))
    return out


def deep_scan(scan_python: str, budget_minutes: float, workers: int = 2, out=print) -> int:
    """capa without a size limit on pending binaries until the budget is used;
    results go into the baseline (resumable: the next run continues)."""
    import subprocess

    rules = capa_rules()
    sigs = capa_sigs()
    pending = deep_pending()
    out(f"deep scan: {len(pending)} binaries pending, budget {budget_minutes:.0f} min, {workers} at a time")
    deadline = time.monotonic() + budget_minutes * 60
    done = 0
    script = r"""
import json, os, resource, subprocess, sys, tempfile, zipfile, tarfile
archive, member, rules, timeout, sigs = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5]
if archive.endswith(".whl"):
    data = zipfile.ZipFile(archive).read(member)
else:
    with tarfile.open(archive) as tf:
        data = tf.extractfile(member).read()
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "sample")
    open(path, "wb").write(data)
    lim = 6 * 1024 ** 3
    capa = os.path.join(os.path.dirname(sys.executable), "capa")
    try:
        proc = subprocess.run([capa, "-j", "-q", "-r", rules, "-s", sigs, path], capture_output=True, timeout=timeout,
                              env={"PATH": os.environ.get("PATH", ""), "HOME": tmp},
                              preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS, (lim, lim)))
        caps = sorted(json.loads(proc.stdout or b"{}").get("rules", {}))
        if not caps and proc.returncode in (14, 16, 17, 18):   # capa: not a file it analyses
            print(json.dumps({"capabilities": [], "unsupported": f"capa exit {proc.returncode}: "
                              "file, type, architecture or OS it does not analyse"}))
            sys.exit(0)
        print(json.dumps({"capabilities": caps, "error": "" if caps or proc.returncode == 0
                          else proc.stderr.decode("utf-8", "replace")[-300:]}))
    except subprocess.TimeoutExpired:
        print(json.dumps({"capabilities": [], "error": f"capa took longer than {timeout:.0f} s"}))
"""
    from concurrent.futures import ThreadPoolExecutor

    def one(item):
        name, version, archive, member, sha = item
        remaining = deadline - time.monotonic()
        if remaining < 120:
            return item, None
        cached = CACHE_DIR / "capa-results" / Path(rules).name / sha[:2] / f"{sha}.json"
        if cached.exists():
            try:
                return item, {"capabilities": json.loads(cached.read_text(encoding="utf-8"))["capabilities"]}
            except (ValueError, KeyError):
                pass
        path = next(iter(CACHE_DIR.glob(f"*/*/{archive}")), None)
        if path is None:
            return item, {"error": f"{archive} not in the cache (run check first)"}
        proc = subprocess.run([scan_python, "-I", "-c", script, str(path), member, rules, str(remaining), sigs],
                              capture_output=True, timeout=remaining + 60)
        try:
            return item, json.loads(proc.stdout.decode().strip().splitlines()[-1])
        except (ValueError, IndexError):
            return item, {"error": proc.stderr.decode("utf-8", "replace")[-300:]}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for item, result in pool.map(one, pending):
            if result is None:
                continue
            name, version, archive, member, sha = item
            data = _baseline_file(name)
            entry = data["versions"][version]
            capa = entry.setdefault("scans", {}).setdefault("capa", {})
            record = capa.setdefault(sha, {"path": member})
            if result.get("error"):
                out(f"  ERROR {name} {member}: {result['error'][:200]}")
                record["deep_error"] = result["error"][:300]
                continue
            record.update({"capabilities": result["capabilities"], "deep": dt.date.today().isoformat()})
            if result.get("unsupported"):
                # nothing capa can say about it; the native profile stays the evidence
                record["unsupported"] = result["unsupported"]
                record.pop("deep_error", None)
                baseline_path(name).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n",
                                               encoding="utf-8")
                done += 1
                continue
            cached = CACHE_DIR / "capa-results" / Path(rules).name / sha[:2] / f"{sha}.json"
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_text(json.dumps({"capabilities": result["capabilities"]}), encoding="utf-8")
            record.pop("deep_error", None)
            alarms = [c for c in result["capabilities"] if any(a in c.lower() for a in DEEP_ALARM)]
            if alarms:
                record["alarms"] = alarms
                out(f"  REVIEW {name}=={version} {member}: {', '.join(alarms)}")
            path = baseline_path(name)
            path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            done += 1
    out(f"deep scan: {done} analysed, {len(deep_pending())} still pending")
    return done


def deep_problems(pins: list[tuple[str, LockedPin]] | None = None) -> list[Problem]:
    """Deep-scan alarms without a review note fail the gate (*pins*: the
    checked ones, by default the configured project's)."""
    out = []
    for _, pin in (read_locks() if pins is None else pins):
        base = load_baseline(pin.name, pin.version) or {}
        for sha, record in ((base.get("scans") or {}).get("capa") or {}).items():
            if record.get("alarms") and not record.get("alarms_reviewed"):
                out.append(Problem(pin.name, f"capa (deep scan) found {', '.join(record['alarms'])} in "
                                   f"{record.get('path')}: review it and note why it is acceptable "
                                   f"(accept-deep)", "capa"))
    return out


def accept_deep(spec: str, member: str, note: str, by: str) -> None:
    name, _, version = spec.partition("==")
    data = _baseline_file(name)
    if data is None or version not in data["versions"]:
        raise GateError(f"{spec} has no baseline")
    if len(note.strip()) < 20 or not by.strip():
        raise GateError("accept-deep needs --by and a note that says why the capabilities are acceptable")
    for record in (data["versions"][version].get("scans") or {}).get("capa", {}).values():
        if record.get("path") == member and record.get("alarms"):
            record["alarms_reviewed"] = {"date": dt.date.today().isoformat(), "by": by.strip(), "note": note.strip()}
            baseline_path(name).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            return
    raise GateError(f"{spec}: no deep-scan alarm for {member}")


# --- survey: the first review of many pins at once -----------------------------------------------

def survey(out_dir: Path, platforms: list[str], scan_python: str, only: set[str] | None = None,
           batch: int = 20) -> int:
    """Everything the review of each pin needs, written to *out_dir*: a
    candidate baseline entry (``<name>.json``) and what to read
    (``<name>.todo.json``: threat hits, high findings, .pth, hooks, capa,
    attestation). Pins already reviewed in their locked version are skipped."""
    out_dir.mkdir(parents=True, exist_ok=True)
    pending = []
    seen = set()
    for rel, pin in read_locks():
        if (pin.name, pin.version) in seen or (only and pin.name not in only):
            continue
        seen.add((pin.name, pin.version))
        if load_baseline(pin.name, pin.version) is not None:
            continue
        if (out_dir / f"{canonical(pin.name)}=={pin.version}.json").exists():
            continue
        pending.append((rel, pin))
    done = 0
    for start in range(0, len(pending), batch):
        results = []
        for rel, pin in pending[start:start + batch]:
            try:
                results.append(check_pin(rel, pin, platforms))
            except GateError as exc:
                (out_dir / f"{canonical(pin.name)}=={pin.version}.error").write_text(str(exc), encoding="utf-8")
        run_scanners(results, scan_python, capa=True, strict=False)
        for r in results:
            scans = {"keys": sorted(scan_keys(r.scans)),
                     "capa": {e["sha256"]: {"path": e["path"], "capabilities": e.get("capabilities", []),
                                            "note": e.get("skipped") or e.get("error", ""),
                                            "profile": withhold_credentials(e.get("profile", {}))}
                              for scan in r.scans.values() for e in scan.get("capa", [])},
                     "yara": sorted({f"{h['rule']} {h['path']}" for scan in r.scans.values()
                                     for h in scan.get("yara", [])})}
            entry = baseline_entry(r, "", "", "", scans)
            todo = {
                "pin": f"{r.pin.name}=={r.pin.version}", "lock": r.lock,
                "problems": [p.line() for p in r.problems if p.check != "baseline"],
                "summary": (r.release.get("info") or {}).get("summary"),
                "urls": (r.release.get("info") or {}).get("project_urls"),
                "attestation": {a: s.get("attestation") for a, s in r.scans.items()},
                "pth": {a: rep.pth for a, rep in r.reports.items() if rep.pth},
                "hooks": {a: rep.hooks for a, rep in r.reports.items() if rep.hooks},
                "high": [f"{f.rule} {f.path}:{f.line} {f.text[:200]}" for rep in r.reports.values()
                         for f in rep.findings if f.severity == "high"],
                "medium": len([f for rep in r.reports.values() for f in rep.findings if f.severity == "medium"]),
                "threats": [f"{h['rule'].split(':')[-1]} {h['path']} | {' | '.join(h['strings'])[:200]}"
                            for scan in r.scans.values() for h in scan.get("yara", []) if h["kind"] == "threat"],
                "capabilities": sorted({h["rule"].split(":")[-1] for scan in r.scans.values()
                                        for h in scan.get("yara", []) if h["kind"] == "capability"}),
                "native": sum(len(rep.native) for rep in r.reports.values()),
                "capa": sorted({c for scan in r.scans.values() for e in scan.get("capa", [])
                                for c in e.get("capabilities", [])}),
                "capa_skipped": [f"{e['path']}: {e.get('skipped') or e.get('error')}" for scan in r.scans.values()
                                 for e in scan.get("capa", []) if e.get("skipped") or e.get("error")],
                "capa_errors": [f"{e['path']}: {e['error'][:300]}" for scan in r.scans.values()
                                for e in scan.get("capa", []) if e.get("error")],
                "native_profiles": [
                    {"path": e["path"], "size": e["size"], "categories": e["profile"].get("categories", {}),
                     "urls": e["profile"].get("urls", [])[:15], "ipv4": e["profile"].get("ipv4", [])[:15],
                     "capa": e.get("capabilities", [])}
                    for scan in r.scans.values() for e in scan.get("capa", [])
                    if e.get("profile") and (set(e["profile"].get("categories", {})) - {"dynamic-code"}
                                             or e["profile"].get("urls") or e["profile"].get("ipv4"))],
            }
            name = f"{canonical(r.pin.name)}=={r.pin.version}"
            (out_dir / f"{name}.todo.json").write_text(json.dumps(todo, indent=1, sort_keys=True), encoding="utf-8")
            (out_dir / f"{name}.json").write_text(json.dumps(entry, indent=1, sort_keys=True), encoding="utf-8")
            done += 1
        print(f"survey: {min(start + batch, len(pending))}/{len(pending)}", flush=True)
    return done


def accept_survey(out_dir: Path, verdicts: dict[str, str], by: str) -> list[str]:
    """Baselines from a survey for the pins of *verdicts* (``name==version`` ->
    what the review found); refused for a pin the locks no longer have in
    that version, or whose cached archive is not the surveyed one."""
    if not by.strip():
        raise GateError("--by is needed")
    locked = {(pin.name, pin.version) for _, pin in read_locks()}
    written = []
    for spec, note in verdicts.items():
        name, _, version = spec.partition("==")
        name = canonical(name)
        if (name, version) not in locked:
            raise GateError(f"{spec} is not in the locks")
        if len(note.strip()) < 10:
            raise GateError(f"{spec}: the verdict says too little")
        entry = json.loads((out_dir / f"{name}=={version}.json").read_text(encoding="utf-8"))
        if entry["version"] != version:
            raise GateError(f"{spec}: the survey has {entry['version']}")
        todo = json.loads((out_dir / f"{name}=={version}.todo.json").read_text(encoding="utf-8"))
        if todo.get("capa_errors"):
            raise GateError(f"{spec}: capa failed on {todo['capa_errors'][:3]} - survey it again")
        young = [p for p in todo["problems"] if p.startswith("[age]")]
        if young and not entry.get("young_release"):
            reason = _young_exceptions().get(name)
            if not reason:
                raise GateError(f"{spec} is younger than {MIN_AGE_DAYS} days and not in {YOUNG_FILE.name}")
            entry["young_release"] = reason
        for archive, data in entry["archives"].items():
            cached = list(CACHE_DIR.glob(f"{data['sha256'][:2]}/{data['sha256']}/{archive}"))
            if not cached or _sha256(cached[0]) != data["sha256"]:
                raise GateError(f"{spec}: {archive} is not the surveyed file")
        entry["reviewed"] = {"date": dt.date.today().isoformat(), "by": by.strip(), "note": note.strip()}
        save_baseline(entry, locked)
        written.append(spec)
    return written


# --- configuration: the gate for another project ----------------------------------------------

#: The file the gate reads when it is started in a folder that has one.
CONFIG_NAME = "supply-chain-gate.toml"
#: Without a config the gate checks axross; an exported copy
#: (scripts/export_supply_chain_gate.py) has no default project.
REQUIRE_CONFIG = False
_CONFIG_PATHS = {"root", "baseline_dir", "cache_dir", "top_packages", "young_exceptions",
                 "build_from_source", "capa_rules", "capa_sigs"}
_CONFIG_KEYS = _CONFIG_PATHS | {"locks", "scanner_lock", "index_config", "min_age_days", "user_agent"}


def configure(path: Path) -> None:
    """Point the gate at another project (TOML, or JSON for a .json file).
    Paths are relative to the config file; ``root`` is the project, ``locks``
    and ``index_config`` are relative to it. Without a config the gate checks
    axross (this repository's layout).

        root = "."                          # the project
        locks = ["requirements.txt"]        # hash-pinned locks (pip-compile / uv --generate-hashes)
        scanner_lock = "requirements-scan-tools.txt"   # the scanners' own lock, checked too
        index_config = ["pyproject.toml"]   # files that must not name another index
        baseline_dir = "supply_chain_baseline"
        cache_dir = ".supply-chain-cache"   # downloads, by hash
        young_exceptions = "young-release-exceptions.txt"
        min_age_days = 14
        user_agent = "my-project-supply-chain-gate/1"
    """
    global ROOT, LOCKS, INDEX_CONFIG, BASELINE_DIR, CACHE_DIR, TOP_PACKAGES, YOUNG_FILE
    global FROM_SOURCE_FILE, CAPA_RULES_FILE, CAPA_SIGS_FILE, MIN_AGE_DAYS, USER_AGENT
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
    else:
        import tomllib

        data = tomllib.loads(text)
    unknown = sorted(set(data) - _CONFIG_KEYS)
    if unknown:
        raise GateError(f"{path}: unknown settings {', '.join(unknown)}")
    if not data.get("locks"):
        raise GateError(f"{path}: 'locks' names no lock")
    base = path.resolve().parent

    def where(key: str, default: Path) -> Path:
        return (base / data[key]).resolve() if key in data else default

    ROOT = where("root", base)
    locks = [str(x) for x in data["locks"]]
    if data.get("scanner_lock"):
        locks.append(str(data["scanner_lock"]))
    LOCKS = tuple(locks)
    INDEX_CONFIG = tuple(str(x) for x in data.get("index_config", ()))
    BASELINE_DIR = where("baseline_dir", ROOT / "supply_chain_baseline")
    CACHE_DIR = Path(os.environ["AXROSS_SUPPLY_CHAIN_CACHE"]) if os.environ.get("AXROSS_SUPPLY_CHAIN_CACHE") \
        else where("cache_dir", ROOT / ".supply-chain-cache")
    TOP_PACKAGES = where("top_packages", HERE / "top_pypi_packages.txt")
    YOUNG_FILE = where("young_exceptions", ROOT / "young-release-exceptions.txt")
    FROM_SOURCE_FILE = where("build_from_source", ROOT / "build_from_source.txt")
    CAPA_RULES_FILE = where("capa_rules", _packaged("capa-rules.txt", CAPA_RULES_FILE))
    CAPA_SIGS_FILE = where("capa_sigs", _packaged("capa-sigs.txt", CAPA_SIGS_FILE))
    MIN_AGE_DAYS = int(data.get("min_age_days", MIN_AGE_DAYS))
    USER_AGENT = str(data.get("user_agent", USER_AGENT))


def _packaged(name: str, default: Path) -> Path:
    """A pin file shipped next to the gate (a project of its own), else axross's."""
    return HERE / name if (HERE / name).exists() else default


def _shown(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


# --- main -------------------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path,
                        help=f"the project to check (default: ./{CONFIG_NAME} if there is one, else axross)")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check")
    c.add_argument("--platform", default="linux-x86_64")
    c.add_argument("--report", type=Path)
    c.add_argument("--scan-python", default="", help="python of the scanner venv (the full gate)")
    c.add_argument("--reduced-locks", type=Path, default=None,
                   help="when it passes: write each lock cut down to the inspected archives here")
    r = sub.add_parser("review")
    r.add_argument("specs", nargs="+")
    r.add_argument("--platform", default="linux-x86_64")
    r.add_argument("--scan-python", default="")
    a = sub.add_parser("accept")
    a.add_argument("spec")
    a.add_argument("--by", required=True)
    a.add_argument("--note", required=True)
    a.add_argument("--young", default="")
    a.add_argument("--scan-python", required=True)
    a.add_argument("--platform", default="linux-x86_64")
    sub.add_parser("top-packages")
    dsc = sub.add_parser("deep-scan", help="capa on every binary without a size limit (night sessions)")
    dsc.add_argument("--scan-python", required=True)
    dsc.add_argument("--budget-minutes", type=float, default=420)
    dsc.add_argument("--workers", type=int, default=2)
    ad = sub.add_parser("accept-deep")
    ad.add_argument("spec")
    ad.add_argument("member")
    ad.add_argument("--by", required=True)
    ad.add_argument("--note", required=True)
    sv = sub.add_parser("survey")
    sv.add_argument("out", type=Path)
    sv.add_argument("--scan-python", required=True)
    sv.add_argument("--only", default="")
    sv.add_argument("--platform", default="linux-x86_64")
    asv = sub.add_parser("accept-survey")
    asv.add_argument("out", type=Path)
    asv.add_argument("verdicts", type=Path, help="JSON: name==version -> what the review found")
    asv.add_argument("--by", required=True)
    cs = sub.add_parser("check-system")
    cs.add_argument("packages", type=Path)
    cs.add_argument("--accept", action="store_true", help="record these packages as the baseline")
    ve = sub.add_parser("verify-env")
    ve.add_argument("--python", required=True)
    ve.add_argument("--lock", type=Path, action="append", required=True)
    s = sub.add_parser("status")
    s.add_argument("--platform", default="linux-x86_64")
    args = parser.parse_args(argv)
    config = args.config or (Path.cwd() / CONFIG_NAME if (Path.cwd() / CONFIG_NAME).is_file() else None)
    if config is None and REQUIRE_CONFIG:
        print(f"supply-chain gate could not run: no ./{CONFIG_NAME} and no --config", file=sys.stderr)
        return 2
    if config is not None:
        try:
            configure(config)
        except (OSError, ValueError, GateError) as exc:
            print(f"supply-chain gate could not run: {exc}", file=sys.stderr)
            return 2
    platforms = [p.strip() for p in getattr(args, "platform", "linux-x86_64").split(",") if p.strip()]
    for p in platforms:
        if p not in PLATFORMS:
            parser.error(f"unknown platform {p}")
    try:
        if args.command == "check":
            results, general = run_check(platforms, scan_python=args.scan_python or None)
            problems = general + [p for res in results for p in res.problems]
            if args.report:
                write_report(results, general, args.report, platforms)
            if args.reduced_locks is not None and not problems:
                for path in write_reduced_locks(results, args.reduced_locks):
                    print(f"reduced lock: {_shown(path)}")
            for p in problems:
                print("FAIL", p.line())
            print(f"supply-chain gate: {len(results)} pins, {len(problems)} problems - "
                  f"{'PASSED' if not problems else 'FAILED'}")
            return 1 if problems else 0
        if args.command == "review":
            for spec in args.specs:
                review(spec, platforms, scan_python=args.scan_python)
            return 0
        if args.command == "accept":
            path = accept(args.spec, args.by, args.note, platforms, args.young, args.scan_python)
            print(f"baseline written: {_shown(path)}")
            return 0
        if args.command == "deep-scan":
            deep_scan(args.scan_python, args.budget_minutes, args.workers)
            return 0
        if args.command == "accept-deep":
            accept_deep(args.spec, args.member, args.note, args.by)
            print("noted")
            return 0
        if args.command == "survey":
            only = {canonical(n) for n in args.only.split(",") if n.strip()} or None
            print(f"surveyed {survey(args.out, platforms, args.scan_python, only)} pins into {args.out}")
            return 0
        if args.command == "accept-survey":
            verdicts = json.loads(args.verdicts.read_text(encoding="utf-8"))
            for spec in accept_survey(args.out, verdicts, args.by):
                print("baseline written:", spec)
            return 0
        if args.command == "check-system":
            problems, warnings = check_system(args.packages)
            for w in warnings:
                print("note", w)
            for p in problems:
                print("FAIL", p.line())
            if args.accept and not problems:
                print(f"baseline written: {_shown(accept_system(args.packages))}")
            print(f"system packages: {len(problems)} problems, {len(warnings)} notes - "
                  f"{'PASSED' if not problems else 'FAILED'}")
            return 1 if problems else 0
        if args.command == "verify-env":
            problems = verify_env(args.python, args.lock)
            for p in problems:
                print("FAIL", p.line())
            print(f"installed packages: {'PASSED' if not problems else 'FAILED'}")
            return 1 if problems else 0
        if args.command == "top-packages":
            data = json.loads(_get("https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/"
                                   "top-pypi-packages.min.json"))
            names = [row["project"] for row in data.get("rows", [])][:15000]
            if len(names) < 5000 or not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", n) for n in names):
                raise GateError("the list of top packages does not look right; not written")
            names, dropped = publishable_names(names)
            TOP_PACKAGES.write_text(
                "# The most downloaded PyPI projects, most popular first: the reference of the typosquatting\n"
                f"# check of security/supply_chain_gate.py. From hugovk/top-pypi-packages (30 days, "
                f"{data.get('last_update')}),\n# refresh with: python -I security/supply_chain_gate.py top-packages\n"
                + (f"# {dropped} names left out: they look like a credential or an internal marker to the\n"
                   "# leak check of the public mirror (scripts/_scrub_rules.py)\n" if dropped else "")
                + "\n".join(names) + "\n", encoding="utf-8")
            print(f"{len(names)} names written to {_shown(TOP_PACKAGES)}")
            return 0
        if args.command == "status":
            for rel, pin in read_locks():
                others = reviewed_versions(pin.name)
                state = "ok" if pin.version in others else (
                    f"reviewed {', '.join(others)}, locked {pin.version}" if others else "not reviewed")
                print(f"{pin.name:32} {pin.version:16} {state}")
            return 0
    except GateError as exc:
        print(f"supply-chain gate could not run: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
