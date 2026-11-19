#!/usr/bin/env python3
"""The supply-chain gate for Rust: every crate of a Cargo.lock reviewed, and
nothing about it changed since - the principles of
security/supply_chain_gate.py (docs/SUPPLY_CHAIN_GATE.md), for crates.io.

``check`` fails on any problem; for every package of the lock:

1. **Source**: crates.io only - no git, path or other registry source (a
   path package must be one of the project's own, ``own`` in the config).
2. **crates.io**: the lock's checksum is the one crates.io's index publishes
   for that version, the version is not yanked; the .crate file is
   downloaded from static.crates.io and must have that checksum.
3. **Age**: published at least ``MIN_AGE_DAYS`` ago (the API's created_at),
   unless the crate's baseline names a reason (a security fix).
4. **Advisories**: RustSec's advisory-db (github.com/rustsec/advisory-db,
   its informational notices too: unmaintained, unsound) and OSV
   (api.osv.dev, ecosystem crates.io: RustSec's and GitHub's). A
   vulnerability fails; a notice fails until the baseline says why it is
   acceptable. Without either source the gate does not run (fails closed);
   ``--require-osv`` (CI) fails closed without OSV alone.
5. **Names**: a crate new to the baseline must not look like a typo of a
   popular crate (security/top_crates.txt) or of another locked one.
6. **Content** (nothing built, nothing run): every member's SHA-256; build
   scripts and proc-macro crates (code that runs on the build machine)
   listed with the lines that reach the network, start programs, read the
   environment or the home folder; bundled binaries and prebuilt libraries
   (ELF, PE, Mach-O, ar archives / import libraries, objects, WebAssembly);
   vendored C/C++/assembly sources; lines typical of malware (the
   language-independent rules of security/package_inspect.py: key, wallet
   and browser-data paths, webhooks, paste sites, encoded blobs ...).
7. **Scanners** (``--scan-python``, the gate's scanner venv): GuardDog's and
   axross's YARA rules over every member, capa on every new ELF / PE binary.

What was reviewed is kept per crate in the project's baseline folder
(``baseline_dir``, one JSON file per crate, every reviewed version): the
.crate's SHA-256, its manifest, build scripts, binaries, findings, accepted
notices and the publisher. A crate or version that was never reviewed, a
different archive, a new finding, binary or YARA hit fails.

    check   [--report DIR] [--scan-python PY] [--require-osv]
    status                          which crates are not (or no longer) reviewed
    review  NAME==VERSION ...       everything about a crate, and the diff against
                                    the reviewed version
    accept  NAME==VERSION --by WHO --note TEXT --scan-python PY [--advisory ID=NOTE] [--young REASON]
    survey  DIR --scan-python PY    the first review of many crates: candidate entries
                                    and what to read
    accept-survey DIR VERDICTS.json --by WHO
    upstream NAME==VERSION --prefix DIR/ --url URL --sha256 SHA
                                    compare vendored sources with an upstream release
    top-crates                      refresh security/top_crates.txt

The settings (``--config FILE``, TOML; paths relative to it):

    lock = "../Cargo.lock"
    own = ["axross-amp"]            # the project's own (path) packages
    baseline_dir = "cargo_baseline"
    cache_dir = "../target/supply-chain-cache"
    min_age_days = 14

Exit codes: 0 clean, 1 a problem, 2 the gate could not run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from security import package_inspect as PI  # noqa: E402
from security import supply_chain_gate as G  # noqa: E402
from security.supply_chain_gate import GateError, Problem  # noqa: E402

CRATES_IO = {"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}
API = "https://crates.io/api/v1/crates"
INDEX = "https://index.crates.io"
STATIC = "https://static.crates.io/crates"
RUSTSEC = "https://github.com/rustsec/advisory-db/archive/refs/heads/main.tar.gz"
USER_AGENT = "axross-supply-chain"
TOP_CRATES = HERE / "top_crates.txt"
#: crates.io's crawler policy: at most one API request a second.
API_INTERVAL = 1.0

# settings (configure())
LOCK = Path("Cargo.lock")
OWN: set[str] = set()
BASELINE_DIR = Path("cargo_baseline")
CACHE_DIR = Path(os.environ.get("AXROSS_SUPPLY_CHAIN_CACHE") or "supply-chain-cache")
MIN_AGE_DAYS = 14

#: Prefixes and suffixes of Rust crate names (the typosquatting check).
RUST_AFFIXES = ("rust-", "rs-", "-rs", "-rust", "lib", "-sys", "-derive", "-macros", "-macro", "-impl",
                "-core", "-shared", "-internal", "-utils", "-util", "-cli", "-api", "-client", "-ng",
                "-async", "async-", "-2", "2", "3", "-next", "-fork", "-patched", "-fixed", "-dev")

#: Native file kinds by their first bytes (beyond package_inspect's ELF / PE / Mach-O).
EXTRA_MAGIC = ((b"!<arch>\n", "ar"), (b"\x00asm", "wasm"), (b"\x64\x86", "coff-x86_64"),
               (b"\x4c\x01", "coff-i386"), (b"\x64\xaa", "coff-arm64"))
#: extensions a coff magic counts for (two bytes are no proof elsewhere)
COFF_EXT = (".o", ".obj")
NATIVE_SOURCE = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".s", ".asm", ".inc")
CODE_EXT = (".rs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".py", ".sh", ".ps1", ".bat", ".cmd", ".pl",
            ".cmake", ".s", ".asm", ".toml", ".js", ".mk")
CODE_NAMES = ("cmakelists.txt", "makefile", "configure", "build.ninja")

#: package_inspect's rules that are about the data malware reaches for, not
#: about Python: they hold for any language.
GENERIC_RULES = {"discord-telegram-webhook", "paste-site", "raw-ip-url", "secret-paths", "gpg-keys", "ssh-keys",
                 "keyring-stores", "system-secrets", "browser-data", "messenger-tokens", "wallets",
                 "crontab-autostart", "b64-in-subprocess", "hidden-process"}

#: (rule, severity in code that runs at build time, severity elsewhere or
#: None: only at build time, pattern) over Rust sources. Build time: a build
#: script, or any source of a proc-macro crate.
RUST_RULES = (
    ("rs-network", "high", None,
     re.compile(r"\b(?:TcpStream|UdpSocket|TcpListener|ToSocketAddrs)\b|\b(?:reqwest|ureq|attohttpc|minreq|isahc|"
                r"curl|hyper|tokio::net)::")),
    ("rs-download-tool", "high", "medium",
     re.compile(r"Command::new\(\s*\"(?:curl|wget|powershell|pwsh|certutil|bitsadmin|nc|ncat|socat|scp|"
                r"ssh|ftp|tftp)(?:\.exe)?\"")),
    ("rs-shell", "high", None, re.compile(r"Command::new\(\s*\"(?:sh|bash|zsh|cmd|cmd\.exe|python3?|perl)\"")),
    ("rs-command", "medium", None, re.compile(r"\bCommand::new\(")),
    ("rs-url", "medium", None, re.compile(r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s\"')]*")),
    ("rs-env-dump", "high", None, re.compile(r"\benv::vars(?:_os)?\(\)")),
    ("rs-home", "medium", None, re.compile(r"\bhome_dir\(\)|env::var(?:_os)?\(\s*\"(?:HOME|USERPROFILE|APPDATA)\"")),
    ("rs-fs-write", "medium", None, re.compile(r"\bfs::(?:write|remove_file|remove_dir_all|rename|copy)\(|"
                                               r"\bFile::create\(|\bOpenOptions::new\(")),
    ("rs-fs-read-outside", "medium", None,
     re.compile(r"\"/(?:etc|home|root|Users|var|tmp)/|~/\.|\\\\Users\\\\")),
    ("rs-include-bytes", "medium", "medium", re.compile(r"\binclude_bytes!\(")),
    ("rs-exec-memory", "high", "high",
     re.compile(r"PROT_EXEC|PAGE_EXECUTE_READWRITE|VirtualAlloc\b.*EXECUTE|mprotect\(.*EXEC")),
    ("rs-cargo-secrets", "high", "high",
     re.compile(r"\.cargo/credentials|CARGO_REGISTRY_TOKEN|GITHUB_TOKEN|\.git-credentials|\.docker/config\.json")),
)


@dataclass
class CratePin:
    name: str
    version: str
    source: str
    checksum: str

    @property
    def spec(self) -> str:
        return f"{self.name}=={self.version}"


@dataclass
class CrateReport:
    archive: str
    sha256: str = ""
    files: dict = field(default_factory=dict)          # path (without the name-version/ prefix) -> sha256
    sizes: dict = field(default_factory=dict)
    build_scripts: dict = field(default_factory=dict)  # path -> sha256 (the script and its modules)
    proc_macro: bool = False
    links: str = ""
    native: dict = field(default_factory=dict)         # path -> kind
    native_sources: dict = field(default_factory=dict)  # top folder -> count of C/C++/asm files
    vcs: dict = field(default_factory=dict)            # .cargo_vcs_info.json
    findings: list = field(default_factory=list)       # package_inspect.Finding
    errors: list = field(default_factory=list)
    native_profiles: dict = field(default_factory=dict)  # ar / COFF file -> the DLLs, objects, symbols it names


@dataclass
class CrateResult:
    pin: CratePin
    report: CrateReport | None = None
    path: str = ""
    meta: dict = field(default_factory=dict)           # crates.io's facts (created_at, publisher ...)
    advisories: list = field(default_factory=list)     # {"id", "kind", "title", "source"}
    scans: dict = field(default_factory=dict)
    problems: list = field(default_factory=list)


# --- settings ----------------------------------------------------------------------------

_KEYS = {"lock", "own", "baseline_dir", "cache_dir", "min_age_days", "top_crates", "user_agent"}


def configure(path: Path) -> None:
    global LOCK, OWN, BASELINE_DIR, CACHE_DIR, MIN_AGE_DAYS, TOP_CRATES, USER_AGENT
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    unknown = sorted(set(data) - _KEYS)
    if unknown:
        raise GateError(f"{path}: unknown settings {', '.join(unknown)}")
    base = path.resolve().parent
    LOCK = (base / data.get("lock", "Cargo.lock")).resolve()
    OWN = set(data.get("own", []))
    BASELINE_DIR = (base / data.get("baseline_dir", "cargo_baseline")).resolve()
    if os.environ.get("AXROSS_SUPPLY_CHAIN_CACHE"):
        CACHE_DIR = Path(os.environ["AXROSS_SUPPLY_CHAIN_CACHE"])
    else:
        CACHE_DIR = (base / data.get("cache_dir", "supply-chain-cache")).resolve()
    G.CACHE_DIR = CACHE_DIR            # capa's rules and results go there too
    MIN_AGE_DAYS = int(data.get("min_age_days", MIN_AGE_DAYS))
    if "top_crates" in data:
        TOP_CRATES = (base / data["top_crates"]).resolve()
    USER_AGENT = str(data.get("user_agent", USER_AGENT))


# --- the lock ------------------------------------------------------------------------------

def read_lock(path: Path | None = None) -> tuple[list[CratePin], list[Problem]]:
    """The crates.io packages of a Cargo.lock, and the packages that come
    from anywhere else (each a problem, unless one of the project's own)."""
    path = path or LOCK
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GateError(f"{path}: {exc}") from exc
    pins, problems = [], []
    for pkg in data.get("package", []):
        name, version, source = pkg.get("name", ""), pkg.get("version", ""), pkg.get("source")
        if source is None:
            if name not in OWN:
                problems.append(Problem(name, f"{version} is a path package, not one of the project's own "
                                        f"({', '.join(sorted(OWN)) or 'none named'})", "source"))
            continue
        if source not in CRATES_IO:
            kind = source.split("+", 1)[0]
            problems.append(Problem(name, f"{version} comes from {kind} {source.split('+', 1)[-1][:120]}, "
                                    "not crates.io", "source"))
            continue
        checksum = pkg.get("checksum") or data.get("metadata", {}).get(
            f"checksum {name} {version} ({source})", "")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum or ""):
            problems.append(Problem(name, f"{version} has no checksum in the lock", "source"))
            continue
        pins.append(CratePin(name, version, source, checksum))
    if not pins:
        raise GateError(f"{path}: no crates.io package")
    return pins, problems


# --- network ---------------------------------------------------------------------------------

_last_api = [0.0]


def _get(url: str, *, timeout: float = 120.0, accept: str = "application/json") -> bytes:
    host = urllib.parse.urlsplit(url).hostname
    if host == "crates.io":
        wait = _last_api[0] + API_INTERVAL - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_api[0] = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 502, 503, 504) and attempt < 3:
                time.sleep(5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt == 3:
                raise GateError(f"{url}: {exc}") from exc
            time.sleep(2 * (attempt + 1))
    raise GateError(url)


def index_path(name: str) -> str:
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def index_entry(name: str, version: str) -> dict:
    """crates.io's index record of *name* *version* (checksum, yanked) - asked
    every run: a yank is news."""
    try:
        text = _get(f"{INDEX}/{index_path(name)}", accept="*/*").decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise GateError(f"crates.io's index has no {name} ({exc.code})") from exc
    for line in text.splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("vers") == version and record.get("name", "").lower() == name.lower():
            return record
    raise GateError(f"crates.io's index has no {name} {version}")


def api_version(name: str, version: str) -> dict:
    """crates.io's facts about a version that never change (when, by whom,
    the checksum, the licence, the repository), cached."""
    cache = CACHE_DIR / "crates-io-api" / name / f"{version}.json"
    try:
        return json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    try:
        data = json.loads(_get(f"{API}/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}"))["version"]
    except urllib.error.HTTPError as exc:
        raise GateError(f"crates.io has no {name} {version} ({exc.code})") from exc
    publisher = data.get("published_by") or {}
    keep = {"created_at": data.get("created_at"), "checksum": data.get("checksum"),
            "license": data.get("license"), "repository": data.get("repository"),
            "description": (data.get("description") or "")[:300], "lib_links": data.get("lib_links"),
            "bin_names": data.get("bin_names") or [], "crate_size": data.get("crate_size"),
            "published_by": publisher.get("login"), "trustpub": data.get("trustpub_data"),
            "rust_version": data.get("rust_version")}
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(keep, sort_keys=True), encoding="utf-8")
    return keep


def download(pin: CratePin) -> Path:
    """The .crate of *pin* from static.crates.io, cached by its checksum,
    refused unless its SHA-256 is the lock's."""
    target = CACHE_DIR / "crates" / pin.checksum[:2] / f"{pin.name}-{pin.version}.crate"
    if target.exists() and G._sha256(target) == pin.checksum:
        return target
    data = _get(f"{STATIC}/{urllib.parse.quote(pin.name)}/{urllib.parse.quote(pin.name)}-"
                f"{urllib.parse.quote(pin.version)}.crate", timeout=600, accept="*/*")
    if hashlib.sha256(data).hexdigest() != pin.checksum:
        raise GateError(f"{pin.spec}: the download does not have the lock's checksum")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".part")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    return target


# --- advisories ------------------------------------------------------------------------------

def _version_tuple(text: str) -> tuple:
    core, _, pre = text.strip().lstrip("=v").partition("-")
    core = core.split("+", 1)[0]
    parts = [int(p) if p.isdigit() else 0 for p in core.split(".")[:3]]
    parts += [0] * (3 - len(parts))
    # a pre-release sorts before its release
    pre_key = (0, tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))) if pre else (1, ())
    return (*parts, pre_key)


def _comparators(req: str) -> list[tuple[str, tuple]]:
    """A semver requirement as (operator, version) pairs that must all hold."""
    out = []
    for part in req.split(","):
        part = part.strip()
        if not part or part == "*":
            continue
        m = re.fullmatch(r"(>=|<=|>|<|=|\^|~)?\s*v?([0-9*xX]+(?:\.[0-9*xX]+){0,2}(?:-[0-9A-Za-z.-]+)?)", part)
        if not m:
            raise ValueError(f"cannot read the version requirement {req!r}")
        op, ver = m.group(1) or "^", m.group(2)
        nums = re.split(r"[.]", ver.split("-", 1)[0])
        wild = [n for n in nums if n in ("*", "x", "X")]
        nums = [n for n in nums if n not in ("*", "x", "X")]
        given = len(nums)
        major, minor, patch = (list(map(int, nums)) + [0, 0, 0])[:3]
        if wild and op in ("^", "="):
            op = "~" if given >= 2 else "^"
        low = _version_tuple(ver if given == 3 else f"{major}.{minor}.{patch}")
        if op in (">=", ">", "<", "<=", "="):
            if op == "=" and given < 3:
                out.append((">=", low))
                upper = (major + 1, 0, 0) if given == 1 else (major, minor + 1, 0)
                out.append(("<", (*upper, (0, ()))))
            else:
                out.append((op, low))
            continue
        if op == "~":
            upper = (major + 1, 0, 0) if given == 1 else (major, minor + 1, 0)
        elif major > 0 or given == 1:
            upper = (major + 1, 0, 0)
        elif minor > 0 or given == 2:
            upper = (0, minor + 1, 0)
        else:
            upper = (0, 0, patch + 1)
        out.append((">=", low))
        out.append(("<", (*upper, (0, ()))))    # below every pre-release of the bound
    return out


def matches(version: str, req: str) -> bool:
    v = _version_tuple(version)
    for op, bound in _comparators(req):
        ok = {">=": v >= bound, ">": v > bound, "<": v < bound, "<=": v <= bound, "=": v == bound}[op]
        if not ok:
            return False
    return True


def rustsec_db(url: str = RUSTSEC, minimum: int = 300) -> dict[str, list[dict]]:
    """RustSec's advisories by crate: {"id", "kind" (vulnerability, unmaintained,
    unsound, notice), "title", "patched", "unaffected", "withdrawn", "aliases"}."""
    data = _get(url, timeout=300, accept="*/*")
    out: dict[str, list[dict]] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf:
            parts = member.name.split("/")
            if not member.isfile() or len(parts) != 4 or parts[1] != "crates" or not parts[3].endswith(".md"):
                continue
            text = tf.extractfile(member).read().decode("utf-8", "replace")
            m = re.match(r"\s*```toml\n(.*?)\n```\s*\n(.*)", text, re.S)
            if not m:
                continue
            try:
                front = tomllib.loads(m.group(1))
            except tomllib.TOMLDecodeError:
                continue
            adv, versions = front.get("advisory", {}), front.get("versions", {})
            title = next((l[2:].strip() for l in m.group(2).splitlines() if l.startswith("# ")), "")
            out.setdefault(adv.get("package", parts[2]), []).append({
                "id": adv.get("id", parts[3][:-3]), "kind": adv.get("informational") or "vulnerability",
                "title": title, "patched": versions.get("patched", []),
                "unaffected": versions.get("unaffected", []), "withdrawn": adv.get("withdrawn"),
                "aliases": adv.get("aliases", []), "url": adv.get("url", "")})
    if len(out) < minimum:
        raise GateError(f"RustSec's advisory-db has advisories for only {len(out)} crates - not read right")
    return out


def rustsec_hits(db: dict[str, list[dict]], name: str, version: str) -> list[dict]:
    hits = []
    for adv in db.get(name, []):
        if adv.get("withdrawn"):
            continue
        try:
            safe = any(matches(version, r) for r in adv["patched"] + adv["unaffected"])
        except ValueError:
            safe = False      # a requirement it cannot read: counted as affected
        if not safe:
            hits.append({"id": adv["id"], "kind": adv["kind"], "title": adv["title"], "source": "rustsec",
                         "aliases": adv.get("aliases", [])})
    return hits


def osv_hits(pins: list[CratePin]) -> list[list[dict]]:
    """OSV's advisories of each pin (crates.io), each id's kind and aliases
    from its record; GateError when OSV cannot be asked."""
    ids = G.osv_batch_ecosystem([("crates.io", p.name, p.version) for p in pins])
    out = []
    details: dict[str, dict] = {}
    for found in ids:
        hits = []
        for vid in found:
            if vid not in details:
                record = json.loads(_get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid)}"))
                info = ((record.get("database_specific") or {}).get("informational")
                        or next(((a.get("database_specific") or {}).get("informational")
                                 for a in record.get("affected", []) if a.get("database_specific")), None))
                details[vid] = {"id": vid, "kind": info or ("malicious" if vid.startswith("MAL-") else "vulnerability"),
                                "title": (record.get("summary") or "")[:200], "source": "osv",
                                "aliases": record.get("aliases", [])}
            hits.append(details[vid])
        out.append(hits)
    return out


def merge_advisories(*lists: list[dict]) -> list[dict]:
    """One entry per advisory, however many ids name it (RUSTSEC / GHSA / CVE)."""
    out: list[dict] = []
    for hits in lists:
        for hit in hits:
            names = {hit["id"], *hit.get("aliases", [])}
            same = next((o for o in out if names & ({o["id"]} | set(o.get("aliases", [])))), None)
            if same is None:
                out.append(dict(hit))
            else:
                same["aliases"] = sorted(set(same.get("aliases", [])) | names - {same["id"]})
                same["source"] = ",".join(sorted(set(same["source"].split(",")) | {hit["source"]}))
                if same["kind"] != "malicious" and hit["kind"] in ("malicious", "vulnerability"):
                    same["kind"] = hit["kind"]
    return out


# --- content ---------------------------------------------------------------------------------

def _native_kind(path: str, data: bytes) -> str | None:
    for magic, label in PI.NATIVE_MAGIC:
        if data.startswith(magic):
            return label
    for magic, label in EXTRA_MAGIC:
        if data.startswith(magic) and (not label.startswith("coff") or path.lower().endswith(COFF_EXT)):
            return label
    if path.lower().endswith((".dll", ".so", ".dylib", ".exe", ".lib", ".a", ".o", ".obj")) and b"\0" in data[:4096]:
        return "binary"
    return None


def ar_names(data: bytes) -> list[str]:
    """What an ar archive holds: its members' names, and for a Windows import
    library the DLLs its short import objects name."""
    names: list[str] = []
    dlls: set[str] = set()
    pos = 8
    longnames = b""
    while pos + 60 <= len(data) and len(names) < 100000:
        header = data[pos:pos + 60]
        name = header[:16].decode("ascii", "replace").strip()
        try:
            size = int(header[48:58].decode("ascii").strip() or 0)
        except ValueError:
            break
        body = data[pos + 60:pos + 60 + size]
        if name == "//":
            longnames = body
        elif name.startswith("/") and name[1:].isdigit() and longnames:
            off = int(name[1:])
            end = longnames.find(b"\n", off)
            name = longnames[off:end if end >= 0 else None].decode("ascii", "replace").rstrip("/")
        if body[:4] == b"\x00\x00\xff\xff" and len(body) > 20:      # IMPORT_OBJECT_HEADER
            strings = body[20:].split(b"\0")
            if len(strings) > 1:
                dlls.add(strings[1].decode("ascii", "replace").lower())
        elif name not in ("/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            names.append(name.rstrip("/"))
            # GNU import libraries: each object names its DLL as a string
            for m in re.finditer(rb"([A-Za-z0-9_.-]{1,64}\.(?:dll|DLL))\0", body[:8192]):
                dlls.add(m.group(1).decode().lower())
        pos += 60 + size + (size & 1)
    out = sorted(f"dll:{d}" for d in dlls)
    return out + (sorted(set(names))[:200] if not dlls else [f"({len(names)} objects)"])


#: Lines that only name a thing (a constant of an FFI binding, an import):
#: no use of it, no finding for the rules about what code does.
_DECLARATION = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static|use|type)\b|^\s*[A-Z][A-Z0-9_]*\s*[:=,]")


def coff_undefined(data: bytes) -> list[str]:
    """The external symbols a COFF object (a prebuilt .o / .obj) calls but
    does not define - what it reaches outside itself."""
    import struct

    try:
        _mach, _nsec, _ts, psym, nsym, _opt, _ch = struct.unpack_from("<HHIIIHH", data, 0)
        strtab, out, i = psym + nsym * 18, [], 0
        while i < nsym and len(out) < 500:
            entry = data[psym + i * 18: psym + i * 18 + 18]
            if entry[:4] == b"\0\0\0\0":
                off = strtab + struct.unpack_from("<I", entry, 4)[0]
                name = data[off: data.index(b"\0", off)].decode("latin-1")
            else:
                name = entry[:8].rstrip(b"\0").decode("latin-1")
            _value, section, _type, storage, aux = struct.unpack_from("<IhHBB", entry, 8)
            if section == 0 and storage == 2:
                out.append(f"undefined:{name}")
            i += 1 + aux
        return sorted(set(out))
    except (struct.error, ValueError):
        return ["(no COFF symbol table)"]


def _scan_rust(path: str, text: str, build_time: bool) -> list[PI.Finding]:
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or _DECLARATION.match(line):
            continue
        snippet = stripped[:300] if len(line) <= 5000 else line[:200] + " …"
        for rule, sev_build, sev_other, pattern in RUST_RULES:
            severity = sev_build if build_time else sev_other
            if severity and pattern.search(line):
                out.append(PI.Finding(rule, severity, path, number, snippet))
    return out


def _scan_generic(path: str, data: bytes) -> list[PI.Finding]:
    out = []
    text = data.decode("utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), 1):
        for rule, severity, pattern in PI.RULES:
            if rule in GENERIC_RULES and pattern.search(line):
                out.append(PI.Finding(rule, severity, path, number, line.strip()[:300]))
    for pattern, rule in ((PI._B64_BLOB, "encoded-blob"), (PI._HEX_BLOB, "hex-blob")):
        m = pattern.search(data)
        if m:
            out.append(PI.Finding(rule, "medium", path, data.count(b"\n", 0, m.start()) + 1,
                                  f"{len(m.group(0))} encoded characters"))
    return out


def inspect_crate(path: str, name: str, version: str) -> CrateReport:
    """A .crate (a gzip tar of NAME-VERSION/...) read without running anything."""
    report = CrateReport(archive=f"{name}-{version}.crate", sha256=G._sha256(Path(path)))
    prefix = f"{name}-{version}/"
    texts: dict[str, bytes] = {}
    try:
        for member, read in PI._members(path):
            if not PI._safe_path(member) or not member.startswith(prefix):
                report.errors.append(f"member outside {prefix}: {member!r}")
                continue
            rel = member[len(prefix):]
            data = read()
            if data.startswith(b"LINK -> "):
                report.errors.append(f"link {rel}: {data[:200].decode('utf-8', 'replace')}")
            report.files[rel] = hashlib.sha256(data).hexdigest()
            report.sizes[rel] = len(data)
            kind = _native_kind(rel, data)
            if kind:
                report.native[rel] = kind
                if kind == "ar":
                    report.native_profiles[rel] = ar_names(data)
                elif kind.startswith("coff"):
                    report.native_profiles[rel] = coff_undefined(data)
                continue
            lower = rel.lower()
            if lower.endswith(NATIVE_SOURCE):
                top = rel.split("/", 1)[0] if "/" in rel else "."
                report.native_sources[top] = report.native_sources.get(top, 0) + 1
            base = lower.rsplit("/", 1)[-1]
            if rel == ".cargo_vcs_info.json" or ((lower.endswith(CODE_EXT) or base in CODE_NAMES)
                                                 and len(data) <= PI.MAX_TEXT_MEMBER):
                texts[rel] = data
    except (tarfile.TarError, OSError, PI.InspectError, EOFError, ValueError) as exc:
        report.errors.append(f"cannot read the archive: {type(exc).__name__}: {exc}")
        return report
    manifest = {}
    try:
        manifest = tomllib.loads(texts.get("Cargo.toml", b"").decode("utf-8", "replace"))
    except tomllib.TOMLDecodeError as exc:
        report.errors.append(f"Cargo.toml: {exc}")
    package = manifest.get("package", {})
    build = package.get("build")
    if build is None and "build.rs" in report.files:
        build = "build.rs"
    report.links = str(package.get("links") or "")
    report.proc_macro = bool((manifest.get("lib") or {}).get("proc-macro") or (manifest.get("lib") or {}).get("proc_macro"))
    if isinstance(build, str) and build:
        folder = build.rsplit("/", 1)[0] + "/" if "/" in build else None
        for rel in report.files:
            if rel == build or (folder and rel.startswith(folder) and rel.endswith(".rs")):
                report.build_scripts[rel] = report.files[rel]
    try:
        report.vcs = json.loads(texts.pop(".cargo_vcs_info.json", b"{}") or b"{}")
    except ValueError:
        report.errors.append(".cargo_vcs_info.json is no JSON")
    for rel, data in sorted(texts.items()):
        if rel.endswith(".rs"):
            build_time = rel in report.build_scripts or report.proc_macro
            report.findings.extend(_scan_rust(rel, data.decode("utf-8", "replace"), build_time))
        report.findings.extend(_scan_generic(rel, data))
    return report


# --- the baseline ------------------------------------------------------------------------------

def baseline_path(name: str) -> Path:
    return BASELINE_DIR / f"{name}.json"


def _baseline_file(name: str) -> dict | None:
    try:
        data = json.loads(baseline_path(name).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("versions"), dict) else None


def load_baseline(name: str, version: str) -> dict | None:
    entry = ((_baseline_file(name) or {}).get("versions") or {}).get(version)
    return entry if isinstance(entry, dict) else None


def reviewed_versions(name: str) -> list[str]:
    return sorted((_baseline_file(name) or {}).get("versions", {}), key=_version_tuple)


def save_baseline(entry: dict, locked: set[tuple[str, str]]) -> Path:
    name = entry["name"]
    data = _baseline_file(name) or {"name": name, "versions": {}}
    data["versions"][entry["version"]] = entry
    data["versions"] = {v: e for v, e in data["versions"].items() if (name, v) in locked or v == entry["version"]}
    path = baseline_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def baseline_entry(result: CrateResult, by: str, note: str, advisories: dict[str, str], young: str = "") -> dict:
    r = result.report
    entry = {
        "name": result.pin.name, "version": result.pin.version,
        "reviewed": {"date": dt.date.today().isoformat(), "by": by, "note": note},
        "crates_io": {k: v for k, v in result.meta.items() if v not in (None, "", [])},
        "archive": {"sha256": r.sha256, "manifest": G.manifest_digest(r.files), "files": len(r.files),
                    "build_scripts": dict(sorted(r.build_scripts.items())), "proc_macro": r.proc_macro,
                    "links": r.links, "native": {p: {"kind": k, "sha256": r.files[p]} for p, k in sorted(r.native.items())},
                    "native_profiles": r.native_profiles, "native_sources": dict(sorted(r.native_sources.items())),
                    "vcs": r.vcs},
        "accepted_findings": sorted({f.key() for f in r.findings}),
    }
    if result.scans:
        entry["scans"] = {"keys": sorted(h["key"] for h in result.scans.get("yara", [])),
                          "yara": sorted({f"{h['rule']} {h['path']}" for h in result.scans.get("yara", [])}),
                          "capa": {e["sha256"]: {"path": e["path"], "capabilities": e.get("capabilities", []),
                                                 "note": e.get("skipped") or e.get("error", ""),
                                                 "profile": G.withhold_credentials(e.get("profile", {}))}
                                   for e in result.scans.get("capa", [])}}
        entry["accepted_findings"] = sorted(set(entry["accepted_findings"]) | set(entry["scans"]["keys"]))
    if advisories:
        entry["accepted_advisories"] = dict(sorted(advisories.items()))
    if young:
        entry["young_release"] = young
    return entry


def compare(result: CrateResult, base: dict | None) -> None:
    pin, r = result.pin, result.report
    if base is None:
        others = reviewed_versions(pin.name)
        result.problems.append(Problem(pin.name, (
            f"version changed from the reviewed {', '.join(others)} to {pin.version}: review the difference "
            "and accept it") if others else f"{pin.version} was never reviewed: review and accept it", "baseline"))
        return
    arch = base.get("archive") or {}
    if r is not None:
        if arch.get("sha256") != r.sha256:
            result.problems.append(Problem(pin.name, f"{r.archive} is not the file that was reviewed", "baseline"))
        if arch.get("manifest") != G.manifest_digest(r.files):
            result.problems.append(Problem(pin.name, f"{r.archive}: its members differ from the reviewed ones", "baseline"))
        accepted = set(base.get("accepted_findings", []))
        for f in r.findings:
            if f.key() not in accepted:
                result.problems.append(Problem(pin.name, f"new {f.severity} finding {f.rule} in {f.path}:{f.line}: "
                                               f"{f.text[:120]}", "content"))
        for e in r.errors:
            result.problems.append(Problem(pin.name, e, "content"))
    want = (base.get("crates_io") or {}).get("published_by")
    if want and result.meta.get("published_by") and result.meta["published_by"] != want:
        result.problems.append(Problem(pin.name, f"published by {result.meta['published_by']}, the review saw {want}",
                                       "provenance"))
    accepted_adv = base.get("accepted_advisories") or {}
    for adv in result.advisories:
        names = {adv["id"], *adv.get("aliases", [])}
        if adv["kind"] in ("malicious", "vulnerability") and not (names & set(accepted_adv)):
            continue        # already a problem, see advisory_problems
        if adv["kind"] not in ("malicious", "vulnerability") and not (names & set(accepted_adv)):
            result.problems.append(Problem(pin.name, f"{pin.version}: {adv['kind']} notice {adv['id']} "
                                           f"({adv['title'][:100]}) - not accepted in the baseline", "advisory"))
    if result.scans:
        accepted = set(base.get("accepted_findings", []))
        known_capa = set(((base.get("scans") or {}).get("capa") or {}))
        for hit in result.scans.get("yara", []):
            if hit["key"] not in accepted:
                result.problems.append(Problem(pin.name, f"new YARA {hit['kind']} hit {hit['rule']} ({hit['severity']}) "
                                               f"in {hit['path']}: {hit['description']}", "yara"))
        for e in result.scans.get("capa", []):
            if e["sha256"] not in known_capa:
                result.problems.append(Problem(pin.name, f"native binary {e['path']} is not in the reviewed baseline",
                                               "capa"))
    known_native = {v.get("sha256") for v in (arch.get("native") or {}).values()}
    if r is not None:
        for p in r.native:
            if r.files[p] not in known_native:
                result.problems.append(Problem(pin.name, f"native file {p} ({r.native[p]}) is not in the reviewed "
                                               "baseline", "native"))


def advisory_problem(pin: CratePin, adv: dict, base: dict | None) -> Problem | None:
    """A vulnerability or malicious entry fails unless the crate's baseline
    accepted exactly that advisory (with its reason)."""
    if adv["kind"] not in ("malicious", "vulnerability"):
        return None
    accepted = (base or {}).get("accepted_advisories") or {}
    if adv["kind"] == "vulnerability" and ({adv["id"], *adv.get("aliases", [])} & set(accepted)):
        return None
    label = "MALICIOUS CRATE" if adv["kind"] == "malicious" else "vulnerability"
    return Problem(pin.name, f"{pin.version}: {label} {adv['id']} ({adv['title'][:120]})", "advisory")


# --- the scanners -------------------------------------------------------------------------------

def run_scanners(results: list[CrateResult], scan_python: str, *, capa: bool) -> None:
    import subprocess

    items = [r for r in results if r.path]
    if not items:
        return
    known: set[str] = set()
    for r in items:
        for version in reviewed_versions(r.pin.name):
            base = load_baseline(r.pin.name, version) or {}
            known |= set(((base.get("scans") or {}).get("capa") or {}))
    scanner = HERE / "supply_chain_scan.py"
    with tempfile.TemporaryDirectory() as tmp:
        job, out = Path(tmp) / "job.json", Path(tmp) / "result.json"
        job.write_text(json.dumps({
            "archives": [{"path": r.path, "name": r.report.archive, "provenance": None} for r in items],
            "known_native": sorted(known), "skip_capa": not capa,
            "capa_rules": G.capa_rules() if capa else "", "capa_sigs": G.capa_sigs() if capa else "",
            "capa_cache": str(CACHE_DIR / "capa-results")}), encoding="utf-8")
        proc = subprocess.run([scan_python, "-I", str(scanner), str(job), str(out)], capture_output=True,
                              timeout=6 * 3600)
        if proc.returncode != 0 or not out.exists():
            raise GateError("the scanners failed: " + proc.stderr.decode("utf-8", "replace")[-800:])
        data = json.loads(out.read_text(encoding="utf-8"))
    prefix_len = {r.report.archive: len(f"{r.pin.name}-{r.pin.version}/") for r in items}
    for r in items:
        scan = data["archives"].get(r.report.archive, {})
        cut = prefix_len[r.report.archive]
        for hit in scan.get("yara", []):
            hit["path"] = hit["path"][cut:]
            hit["key"] = f"yara|{hit['rule'].split(':')[-1]}|{hit['path']}|{hit['member_sha256'][:16]}"
        for e in scan.get("capa", []):
            e["path"] = e["path"][cut:]
        r.scans = {"yara": scan.get("yara", []), "capa": scan.get("capa", [])}


# --- check ----------------------------------------------------------------------------------------

def load_top_crates() -> list[str]:
    try:
        return [l.strip() for l in TOP_CRATES.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def name_problems(pins: list[CratePin], top: list[str]) -> list[Problem]:
    names = sorted({p.name for p in pins})
    out = []
    for name in names:
        if reviewed_versions(name):
            continue
        others = [n for n in names if n != name]
        squat = G.typosquat_of(name, top + others, RUST_AFFIXES)
        # a crate of a family in the lock (zbus / zbus_macros): reviewed together
        if squat and G.canonical(squat) in {G.canonical(n) for n in others} and \
                (G.canonical(name).startswith(G.canonical(squat)) or G.canonical(squat).startswith(G.canonical(name))):
            continue
        if squat:
            out.append(Problem(name, f"the name looks like a typo of {squat!r} (typosquatting?)", "name"))
    return out


def check_crate(pin: CratePin, *, now: float | None = None, inspect: bool = True) -> CrateResult:
    result = CrateResult(pin=pin)
    record = index_entry(pin.name, pin.version)
    if record.get("cksum") != pin.checksum:
        result.problems.append(Problem(pin.name, f"{pin.version}: the lock's checksum is not the one crates.io "
                                       "publishes", "crates.io"))
    if record.get("yanked"):
        result.problems.append(Problem(pin.name, f"{pin.version} is yanked on crates.io", "crates.io"))
    meta = api_version(pin.name, pin.version)
    result.meta = meta
    if meta.get("checksum") and meta["checksum"] != pin.checksum:
        result.problems.append(Problem(pin.name, f"{pin.version}: crates.io's API names another checksum", "crates.io"))
    base = load_baseline(pin.name, pin.version)
    created = dt.datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00")).timestamp()
    age = ((time.time() if now is None else now) - created) / 86400
    if age < MIN_AGE_DAYS and not (base and base.get("young_release")):
        result.problems.append(Problem(pin.name, f"{pin.version} was published {age:.1f} days ago "
                                       f"(minimum {MIN_AGE_DAYS})", "age"))
    if inspect:
        path = download(pin)
        result.path = str(path)
        result.report = inspect_crate(str(path), pin.name, pin.version)
    return result


def advisories_for(pins: list[CratePin], *, require_osv: bool, notes: list[str]) -> list[list[dict]]:
    """Each pin's advisories from RustSec and OSV; GateError without either
    (or without OSV when *require_osv*)."""
    rustsec, osv = None, None
    try:
        rustsec = rustsec_db()
    except (GateError, urllib.error.HTTPError, tarfile.TarError) as exc:
        notes.append(f"RustSec's advisory-db could not be read: {exc}")
    try:
        osv = osv_hits(pins)
    except (GateError, urllib.error.HTTPError) as exc:
        notes.append(f"OSV could not be asked: {exc}")
        if require_osv:
            raise GateError(f"OSV cannot be asked and --require-osv: {exc}") from exc
    if rustsec is None and osv is None:
        raise GateError("neither RustSec's advisory-db nor OSV can be read - the gate does not pass without "
                        "advisories")
    notes.append("advisories from " + " and ".join(s for s, d in (("RustSec", rustsec), ("OSV", osv)) if d is not None))
    out = []
    for i, pin in enumerate(pins):
        a = rustsec_hits(rustsec, pin.name, pin.version) if rustsec is not None else []
        b = osv[i] if osv is not None else []
        out.append(merge_advisories(a, b))
    return out


def run_check(*, scan_python: str | None = None, require_osv: bool = False, top: list[str] | None = None,
              notes: list[str] | None = None, checker=check_crate, advisories=advisories_for,
              ) -> tuple[list[CrateResult], list[Problem]]:
    notes = [] if notes is None else notes
    pins, general = read_lock()
    general += name_problems(pins, load_top_crates() if top is None else top)
    advs = advisories(pins, require_osv=require_osv, notes=notes)
    results = []
    for pin, found in zip(pins, advs):
        try:
            result = checker(pin)
        except GateError as exc:
            result = CrateResult(pin=pin)
            result.problems.append(Problem(pin.name, str(exc), "crates.io"))
        result.advisories = found
        results.append(result)
    if scan_python:
        run_scanners(results, scan_python, capa=False)
    for r in results:
        base = load_baseline(r.pin.name, r.pin.version)
        compare(r, base)
        for adv in r.advisories:
            p = advisory_problem(r.pin, adv, base)
            if p:
                r.problems.append(p)
    return results, general


def write_report(results: list[CrateResult], general: list[Problem], out_dir: Path, notes: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    problems = general + [p for r in results for p in r.problems]
    data = {"date": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "passed": not problems,
            "notes": notes, "problems": [p.__dict__ for p in problems],
            "crates": [{"name": r.pin.name, "version": r.pin.version, "checksum": r.pin.checksum,
                        "published_by": r.meta.get("published_by"), "created_at": r.meta.get("created_at"),
                        "advisories": r.advisories,
                        "build_script": bool(r.report and r.report.build_scripts),
                        "proc_macro": bool(r.report and r.report.proc_macro),
                        "native": sorted(r.report.native) if r.report else []} for r in results]}
    (out_dir / "SUPPLY-CHAIN-CARGO.json").write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    lines = [f"# Supply-chain gate (Cargo) - {'PASSED' if not problems else 'FAILED'}", "",
             f"{data['date']}, {len(results)} crates (security/supply_chain_cargo.py).", ""]
    lines += [f"- {n}" for n in notes] + [""]
    if problems:
        lines += ["## Problems", ""] + [f"- {p.line()}" for p in problems] + [""]
    accepted = [(r, a) for r in results for a in r.advisories]
    if accepted:
        lines += ["## Advisories (accepted in the baseline with a reason, or failing above)", ""]
        lines += [f"- {r.pin.name} {r.pin.version}: {a['kind']} {a['id']} {a['title'][:100]}" for r, a in accepted]
        lines.append("")
    lines += ["## Code that runs at build time", ""]
    lines += [f"- {r.pin.name} {r.pin.version}: " + ", ".join(
        (["build script"] if r.report.build_scripts else []) + (["proc-macro"] if r.report.proc_macro else []))
        for r in results if r.report and (r.report.build_scripts or r.report.proc_macro)]
    lines += ["", "## Crates", "", "| Crate | Version | Published | By | Reviewed |", "|---|---|---|---|---|"]
    for r in results:
        reviewed = (load_baseline(r.pin.name, r.pin.version) or {}).get("reviewed", {})
        lines.append(f"| {r.pin.name} | {r.pin.version} | {(r.meta.get('created_at') or '')[:10]} | "
                     f"{r.meta.get('published_by') or '-'} | {reviewed.get('date', '-')} {reviewed.get('by', '')} |")
    (out_dir / "SUPPLY-CHAIN-CARGO.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- review / accept / survey ------------------------------------------------------------------------

def _pin(spec: str) -> CratePin:
    name, _, version = spec.partition("==")
    for pin in read_lock()[0]:
        if pin.name == name and (not version or pin.version == version):
            return pin
    raise GateError(f"{spec} is not in {LOCK}")


def _texts(path: str, name: str, version: str) -> dict[str, list[str]]:
    prefix = f"{name}-{version}/"
    out = {}
    for member, read in PI._members(path):
        rel = member[len(prefix):] if member.startswith(prefix) else member
        lower = rel.lower()
        if (lower.endswith(CODE_EXT) or lower.rsplit("/", 1)[-1] in CODE_NAMES) and PI._safe_path(member):
            data = read()
            if len(data) <= PI.MAX_TEXT_MEMBER:
                out[rel] = data.decode("utf-8", "replace").splitlines()
    return out


def todo_of(result: CrateResult) -> dict:
    r = result.report
    return {
        "pin": result.pin.spec, "problems": [p.line() for p in result.problems if p.check != "baseline"],
        "meta": result.meta, "advisories": result.advisories,
        "build_scripts": sorted(r.build_scripts), "proc_macro": r.proc_macro, "links": r.links,
        "native": {p: k for p, k in r.native.items()}, "native_profiles": r.native_profiles,
        "native_sources": r.native_sources, "vcs": r.vcs, "errors": r.errors,
        "high": [f"{f.rule} {f.path}:{f.line} {f.text[:200]}" for f in r.findings if f.severity == "high"],
        "medium": [f"{f.rule} {f.path}:{f.line} {f.text[:160]}" for f in r.findings if f.severity == "medium"],
        "yara_threats": [f"{h['rule'].split(':')[-1]} {h['path']} | {' | '.join(h['strings'])[:200]}"
                         for h in result.scans.get("yara", []) if h["kind"] == "threat"],
        "yara_capabilities": sorted({h["rule"].split(":")[-1] for h in result.scans.get("yara", [])
                                     if h["kind"] == "capability"}),
        "capa": [{"path": e["path"], "kind": e["kind"], "size": e["size"],
                  "capabilities": e.get("capabilities", []), "skipped": e.get("skipped") or e.get("error", ""),
                  "categories": e.get("profile", {}).get("categories", {}),
                  "needed": e.get("profile", {}).get("needed", []), "urls": e.get("profile", {}).get("urls", [])[:15]}
                 for e in result.scans.get("capa", [])],
    }


def review(spec: str, scan_python: str = "", out=print) -> CrateResult:
    pin = _pin(spec)
    result = check_crate(pin)
    notes: list[str] = []
    result.advisories = advisories_for([pin], require_osv=False, notes=notes)[0]
    if scan_python:
        run_scanners([result], scan_python, capa=True)
    base = load_baseline(pin.name, pin.version)
    others = [v for v in reviewed_versions(pin.name) if v != pin.version]
    out(f"== {pin.spec}  {json.dumps(result.meta, sort_keys=True)}")
    for n in notes:
        out(f"   {n}")
    if base:
        out(f"   reviewed {base['reviewed']['date']} by {base['reviewed']['by']}: {base['reviewed']['note']}")
    todo = todo_of(result)
    for key in ("advisories", "build_scripts", "proc_macro", "links", "native", "native_profiles", "native_sources",
                "vcs", "errors", "high", "medium", "yara_threats", "yara_capabilities", "capa", "problems"):
        if todo[key]:
            out(f"   {key}: {json.dumps(todo[key], indent=1)[:4000]}")
    if others and not base:
        old = load_baseline(pin.name, others[-1])
        out(f"   changes against the reviewed {others[-1]} ({old['reviewed']['note'][:200]}):")
        old_pin = CratePin(pin.name, others[-1], pin.source, old["archive"]["sha256"])
        a = _texts(str(download(old_pin)), pin.name, others[-1])
        b = _texts(result.path, pin.name, pin.version)
        shown = 0
        for rel in sorted(set(a) | set(b)):
            if a.get(rel) != b.get(rel):
                for line in difflib.unified_diff(a.get(rel, []), b.get(rel, []), f"old/{rel}", f"new/{rel}", lineterm=""):
                    out("     " + line)
                    shown += 1
                if shown > 4000:
                    out("     … (diff cut)")
                    break
    for p in result.problems:
        out(f"   problem: {p.line()}")
    return result


def _parse_advisory_notes(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items:
        vid, sep, note = item.partition("=")
        if not sep or len(note.strip()) < 20:
            raise GateError(f"--advisory {item!r}: ID=why it is acceptable (20 characters at least)")
        out[vid.strip()] = note.strip()
    return out


def accept(spec: str, by: str, note: str, scan_python: str, advisories: list[str], young: str = "") -> Path:
    if not by.strip() or len(note.strip()) < 10:
        raise GateError("accept needs --by and a --note of at least 10 characters that says what was checked")
    pin = _pin(spec)
    result = check_crate(pin)
    hard = [p for p in result.problems if p.check == "crates.io"]
    if hard:
        raise GateError("cannot accept: " + "; ".join(p.line() for p in hard))
    if [p for p in result.problems if p.check == "age"] and not young:
        raise GateError("cannot accept a release younger than the minimum age without --young REASON")
    run_scanners([result], scan_python, capa=True)
    broken = [e for e in result.scans.get("capa", []) if e.get("error")]
    if broken:
        raise GateError(f"capa failed on {[e['path'] for e in broken]}")
    entry = baseline_entry(result, by.strip(), note.strip(), _parse_advisory_notes(advisories), young.strip())
    locked = {(p.name, p.version) for p in read_lock()[0]}
    return save_baseline(entry, locked)


def survey(out_dir: Path, scan_python: str, only: set[str] | None = None, batch: int = 40) -> int:
    """Candidate entries (``NAME==VERSION.json``) and what to read
    (``.todo.json``) for every crate not reviewed in its locked version."""
    out_dir.mkdir(parents=True, exist_ok=True)
    pins = [p for p in read_lock()[0] if (not only or p.name in only) and load_baseline(p.name, p.version) is None
            and not (out_dir / f"{p.spec}.json").exists()]
    notes: list[str] = []
    advs = dict(zip([p.spec for p in pins], advisories_for(pins, require_osv=False, notes=notes))) if pins else {}
    (out_dir / "NOTES.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
    done = 0
    for start in range(0, len(pins), batch):
        results = []
        for pin in pins[start:start + batch]:
            try:
                r = check_crate(pin)
            except GateError as exc:
                (out_dir / f"{pin.spec}.error").write_text(str(exc), encoding="utf-8")
                continue
            r.advisories = advs.get(pin.spec, [])
            results.append(r)
        run_scanners(results, scan_python, capa=True)
        for r in results:
            (out_dir / f"{r.pin.spec}.todo.json").write_text(json.dumps(todo_of(r), indent=1, sort_keys=True),
                                                             encoding="utf-8")
            (out_dir / f"{r.pin.spec}.json").write_text(json.dumps(baseline_entry(r, "", "", {}), indent=1,
                                                                   sort_keys=True), encoding="utf-8")
            done += 1
        print(f"survey: {min(start + batch, len(pins))}/{len(pins)}", flush=True)
    return done


def accept_survey(out_dir: Path, verdicts: dict, by: str) -> list[str]:
    """Baselines from a survey. *verdicts*: ``name==version`` -> a note, or
    {"note": ..., "advisories": {ID: why}, "young": reason, "wait_for_age": true}."""
    if not by.strip():
        raise GateError("--by is needed")
    locked = {(p.name, p.version) for p in read_lock()[0]}
    written = []
    for spec, verdict in verdicts.items():
        if isinstance(verdict, str):
            verdict = {"note": verdict}
        name, _, version = spec.partition("==")
        if (name, version) not in locked:
            raise GateError(f"{spec} is not in the lock")
        if len(verdict.get("note", "").strip()) < 10:
            raise GateError(f"{spec}: the verdict says too little")
        entry = json.loads((out_dir / f"{spec}.json").read_text(encoding="utf-8"))
        todo = json.loads((out_dir / f"{spec}.todo.json").read_text(encoding="utf-8"))
        if [c for c in todo.get("capa", []) if c.get("skipped", "").startswith("Traceback")]:
            raise GateError(f"{spec}: capa failed - survey it again")
        cached = CACHE_DIR / "crates" / entry["archive"]["sha256"][:2] / f"{spec.replace('==', '-')}.crate"
        if not cached.exists() or G._sha256(cached) != entry["archive"]["sha256"]:
            raise GateError(f"{spec}: the cached .crate is not the surveyed one")
        for p in todo.get("problems", []):
            # a young release: its content may be reviewed now, the age check
            # keeps failing until it is old enough ("wait_for_age"), unless a
            # security fix names its reason ("young")
            if p.startswith("[age]") and not verdict.get("young") and not verdict.get("wait_for_age"):
                raise GateError(f"{spec}: {p} - say young (a security fix's reason) or wait_for_age")
        advisories = verdict.get("advisories") or {}
        for adv in todo.get("advisories", []):
            if not ({adv["id"], *adv.get("aliases", [])} & set(advisories)):
                raise GateError(f"{spec}: {adv['kind']} {adv['id']} needs a reason in the verdict")
        if advisories:
            entry["accepted_advisories"] = advisories
        if verdict.get("young"):
            entry["young_release"] = verdict["young"]
        entry["reviewed"] = {"date": dt.date.today().isoformat(), "by": by.strip(), "note": verdict["note"].strip()}
        save_baseline(entry, locked)
        written.append(spec)
    return written


def upstream(spec: str, prefix: str, url: str, sha256: str, strip: int = 1) -> dict:
    """Compare the vendored sources under *prefix* of a crate with an
    upstream release tarball (pinned by *sha256*): the result goes into the
    crate's baseline entry."""
    pin = _pin(spec)
    entry = load_baseline(pin.name, pin.version)
    if entry is None:
        raise GateError(f"{spec} has no baseline yet")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise GateError("upstream: https only")
    data = _get(url, timeout=600, accept="*/*")
    if hashlib.sha256(data).hexdigest() != sha256:
        raise GateError(f"upstream: {url} does not have the SHA-256 {sha256}")
    theirs = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if m.isfile():
                rel = "/".join(m.name.split("/")[strip:])
                theirs[rel] = hashlib.sha256(tf.extractfile(m).read()).hexdigest()
    ours = {p[len(prefix):]: h for p, h in inspect_crate(str(download(pin)), pin.name, pin.version).files.items()
            if p.startswith(prefix)}
    same = sorted(p for p in ours if theirs.get(p) == ours[p])
    result = {"url": url, "sha256": sha256, "prefix": prefix, "identical": len(same),
              "differ": sorted(p for p in ours if p in theirs and theirs[p] != ours[p]),
              "only_in_crate": sorted(p for p in ours if p not in theirs),
              "only_upstream": len([p for p in theirs if p not in ours]),
              "date": dt.date.today().isoformat()}
    entry["upstream"] = result
    save_baseline(entry, {(p.name, p.version) for p in read_lock()[0]})
    return result


def top_crates(count: int = 5000) -> int:
    names: list[str] = []
    page = 1
    while len(names) < count:
        data = json.loads(_get(f"{API}?sort=downloads&per_page=100&page={page}"))
        batch = [c["id"] for c in data.get("crates", [])]
        if not batch:
            break
        names += batch
        page += 1
    if len(names) < 1000 or not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", n) for n in names):
        raise GateError("the list of top crates does not look right; not written")
    names, dropped = G.publishable_names(names[:count], HERE.parent)
    TOP_CRATES.write_text(
        "# The most downloaded crates on crates.io, most popular first: the reference of the typosquatting\n"
        f"# check of security/supply_chain_cargo.py ({dt.date.today().isoformat()}),\n"
        "# refresh with: python -I security/supply_chain_cargo.py top-crates\n"
        + (f"# {dropped} names left out: the public mirror's leak check flags them\n" if dropped else "")
        + "\n".join(names) + "\n", encoding="utf-8")
    return len(names)


# --- main --------------------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, help="the project's settings (TOML)")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check")
    c.add_argument("--report", type=Path)
    c.add_argument("--scan-python", default="")
    c.add_argument("--require-osv", action="store_true", help="fail closed when OSV cannot be asked")
    sub.add_parser("status")
    r = sub.add_parser("review")
    r.add_argument("specs", nargs="+")
    r.add_argument("--scan-python", default="")
    a = sub.add_parser("accept")
    a.add_argument("spec")
    a.add_argument("--by", required=True)
    a.add_argument("--note", required=True)
    a.add_argument("--scan-python", required=True)
    a.add_argument("--advisory", action="append", default=[], help="ID=why this notice is acceptable")
    a.add_argument("--young", default="")
    sv = sub.add_parser("survey")
    sv.add_argument("out", type=Path)
    sv.add_argument("--scan-python", required=True)
    sv.add_argument("--only", default="")
    asv = sub.add_parser("accept-survey")
    asv.add_argument("out", type=Path)
    asv.add_argument("verdicts", type=Path)
    asv.add_argument("--by", required=True)
    up = sub.add_parser("upstream")
    up.add_argument("spec")
    up.add_argument("--prefix", required=True)
    up.add_argument("--url", required=True)
    up.add_argument("--sha256", required=True)
    up.add_argument("--strip", type=int, default=1)
    sub.add_parser("top-crates")
    args = parser.parse_args(argv)
    try:
        if args.config:
            configure(args.config)
        elif args.command not in ("top-crates",):
            raise GateError("--config is needed (the project's lock and baseline)")
        if args.command == "check":
            notes: list[str] = []
            results, general = run_check(scan_python=args.scan_python or None, require_osv=args.require_osv,
                                         notes=notes)
            problems = general + [p for res in results for p in res.problems]
            if args.report:
                write_report(results, general, args.report, notes)
            for n in notes:
                print("note", n)
            for p in problems:
                print("FAIL", p.line())
            print(f"supply-chain gate (Cargo): {len(results)} crates, {len(problems)} problems - "
                  f"{'PASSED' if not problems else 'FAILED'}")
            return 1 if problems else 0
        if args.command == "status":
            pins, problems = read_lock()
            for p in problems:
                print("FAIL", p.line())
            for pin in pins:
                others = reviewed_versions(pin.name)
                state = "ok" if pin.version in others else (
                    f"reviewed {', '.join(others)}, locked {pin.version}" if others else "not reviewed")
                print(f"{pin.name:40} {pin.version:16} {state}")
            return 0
        if args.command == "review":
            for spec in args.specs:
                review(spec, args.scan_python)
            return 0
        if args.command == "accept":
            print("baseline written:", accept(args.spec, args.by, args.note, args.scan_python, args.advisory,
                                              args.young))
            return 0
        if args.command == "survey":
            only = {n.strip() for n in args.only.split(",") if n.strip()} or None
            print(f"surveyed {survey(args.out, args.scan_python, only)} crates into {args.out}")
            return 0
        if args.command == "accept-survey":
            for spec in accept_survey(args.out, json.loads(args.verdicts.read_text(encoding="utf-8")), args.by):
                print("baseline written:", spec)
            return 0
        if args.command == "upstream":
            print(json.dumps(upstream(args.spec, args.prefix, args.url, args.sha256, args.strip), indent=1))
            return 0
        if args.command == "top-crates":
            print(f"{top_crates()} names written to {TOP_CRATES}")
            return 0
    except GateError as exc:
        print(f"supply-chain gate (Cargo) could not run: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
