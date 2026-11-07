#!/usr/bin/env python3
"""The scanner stage of the supply-chain gate: runs in the venv of the vetted
tool lock (build/requirements-scan-tools.txt), called by
security/supply_chain_gate.py with a job file, writes its results as JSON.

For every archive of the job:

* **YARA** over every member: GuardDog's rules for malicious packages
  (``threat-*``: exfiltration, reverse shells, download-and-exec,
  obfuscation, install hooks ...; ``capability-*``: what the code can do -
  network, processes, files) and axross's own (security/yara_rules), each
  rule only on the paths its ``path_include`` names. Nothing is executed;
  members are matched from memory.
* **capa** on every native binary (ELF/PE/Mach-O) whose SHA-256 the
  baseline does not know: its capabilities (network, process creation,
  persistence, anti-analysis ...), with a time and size limit.
* **PEP 740 attestations** verified with Sigstore (pypi-attestations,
  offline trust root): the file is the one the attested workflow built.

    python -I security/supply_chain_scan.py JOB.json RESULT.json

JOB: {"archives": [{"path": ..., "name": ..., "provenance": {...} | null}],
      "known_native": [sha256, ...]}
"""

from __future__ import annotations

import fnmatch
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security import package_inspect as PI  # noqa: E402

#: capa: largest binary analysed (the survey; the night scan has no limit),
#: how many at once (vivisect needs gigabytes for a large library; every
#: binary gets the native profile below in any case).
CAPA_MAX_BYTES = int(os.environ.get("AXROSS_CAPA_MAX_MB", "2")) * 1024 * 1024
CAPA_TIMEOUT = 900
CAPA_MEMORY = int(os.environ.get("AXROSS_CAPA_MEMORY_MB", "2048")) * 1024 * 1024
CAPA_WORKERS = int(os.environ.get("AXROSS_CAPA_WORKERS", "3"))
#: YARA: members larger than this are not matched (binaries of that size
#: are hash-pinned and go to capa).
YARA_MAX_BYTES = 32 * 1024 * 1024
#: archives scanned at once, and members of them matched at once (threads:
#: YARA matches outside the GIL; one compiled rule set serves them all)
SCAN_WORKERS = int(os.environ.get("AXROSS_SCAN_WORKERS", str(min(8, os.cpu_count() or 1))))


def rule_files() -> list[str]:
    # find GuardDog's rules without importing it: its package fetches
    # popularity lists from the network on import
    import importlib.util

    spec = importlib.util.find_spec("guarddog")
    if spec is None or not spec.submodule_search_locations:
        raise SystemExit("GuardDog is not installed in the scanner venv")
    base = Path(list(spec.submodule_search_locations)[0]) / "analyzer" / "sourcecode"
    files = sorted(glob.glob(str(base / "*.yar")))
    files += sorted(glob.glob(str(Path(__file__).resolve().parent / "yara_rules" / "**" / "*.yar*"), recursive=True))
    return files


def compile_rules():
    import yara

    sources = {}
    for path in rule_files():
        namespace = Path(path).stem.replace("-", "_")
        if "yara_rules" in path:
            namespace = "axross_" + namespace
        sources[namespace] = path
    rules = yara.compile(filepaths=sources)
    # each rule's own path filter and severity (GuardDog's meta), per file
    meta = {}
    for namespace, path in sources.items():
        for rule in yara.compile(filepath=path):
            meta[(namespace, rule.identifier)] = dict(rule.meta)
    if len(meta) < 40:
        raise SystemExit(f"only {len(meta)} YARA rules - GuardDog's rules are missing")
    return rules, meta


def _path_ok(member: str, meta: dict) -> bool:
    patterns = str(meta.get("path_include", "") or "")
    if not patterns:
        return True
    base = member.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(base, p.strip()) or fnmatch.fnmatch(member, p.strip())
               for p in patterns.split(",") if p.strip())


def _match_member(rules, meta, name: str, data: bytes) -> list[dict]:
    hits = []
    digest = hashlib.sha256(data).hexdigest()
    for match in rules.match(data=data, timeout=60):
        m = meta.get((match.namespace, match.rule), {})
        if not _path_ok(name, m):
            continue
        severity = str(m.get("severity", "medium")).lower()
        kind = "threat" if match.rule.startswith("threat") or match.namespace.startswith("axross") else "capability"
        strings = []
        for s in match.strings[:5]:
            for inst in s.instances[:2]:
                strings.append(bytes(inst.matched_data[:120]).decode("utf-8", "replace"))
        hits.append({"rule": f"{match.namespace}:{match.rule}", "kind": kind, "severity": severity,
                     "path": name, "member_sha256": digest, "strings": strings,
                     "description": str(m.get("description", ""))[:200],
                     "key": f"yara|{match.rule}|{name}|{digest[:16]}"})
    return hits


def yara_scan(archive: str, rules, meta, pool=None) -> list[dict]:
    """YARA over every member of *archive*. With *pool* (threads: yara
    matches outside the GIL) the members are matched in parallel, at most
    twice the pool's size in memory at once; the hits keep the member order."""
    hits: list[dict] = []
    pending: list = []
    limit = 2 * getattr(pool, "_max_workers", 1)
    for name, read in PI._members(archive):
        if not PI._safe_path(name):
            continue
        data = read()
        if len(data) > YARA_MAX_BYTES:
            continue
        if pool is None:
            hits.extend(_match_member(rules, meta, name, data))
            continue
        pending.append(pool.submit(_match_member, rules, meta, name, data))
        while len(pending) >= limit:
            hits.extend(pending.pop(0).result())
    for future in pending:
        hits.extend(future.result())
    return hits


def _cache_file(cache: str, digest: str, rules: str) -> str:
    # results per binary and rule set (the rules' folder is named by their hash)
    return os.path.join(cache, os.path.basename(rules.rstrip("/")), digest[:2], digest + ".json")


def _cached_capa(cache: str, digest: str, rules: str) -> dict | None:
    if not cache or not rules:
        return None
    try:
        with open(_cache_file(cache, digest, rules), encoding="utf-8") as f:
            data = json.load(f)
        return {k: data[k] for k in ("capabilities", "skipped") if k in data}
    except (OSError, ValueError):
        return None


def _store_capa(cache: str, digest: str, rules: str, entry: dict) -> None:
    if not cache or not rules or "capabilities" not in entry:
        return
    path = _cache_file(cache, digest, rules)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump({"capabilities": entry["capabilities"]}, f)
    os.replace(path + ".tmp", path)


def _limit_memory() -> None:  # in the capa child
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (CAPA_MEMORY, CAPA_MEMORY))


#: capa's compiled rules, shared by every run (parsing 1 000 rules took ~40 s a run).
RULE_CACHE = ""


def _capa_env(home: str) -> dict:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": home}
    if RULE_CACHE:
        env["XDG_CACHE_HOME"] = RULE_CACHE
    return env


#: capa's FLIRT signatures (the job's "capa_sigs"): without them capa refuses every PE file.
SIGS = ""

#: capa's exit codes for a file it cannot analyse (capa.main E_FILE_LIMITATION,
#: E_INVALID_FILE_TYPE, E_INVALID_FILE_ARCH, E_INVALID_FILE_OS): no failure of
#: the scan - the binary keeps its native profile, the reason is recorded.
CAPA_UNSUPPORTED = {
    14: "a file capa declines to analyse (packed, .NET, an installer ...)",
    16: "a file type capa does not analyse",
    17: "an architecture capa does not analyse (x86 and x86-64 only)",
    18: "an operating system capa does not analyse",
}


def _capa_one(capa: str, rules: str, path: str, entry: dict) -> dict:
    try:
        sigs = ["-s", SIGS] if SIGS else []
        proc = subprocess.run([capa, "-j", "-q", "-r", rules, *sigs, path], capture_output=True, timeout=CAPA_TIMEOUT,
                              env=_capa_env(os.path.dirname(path)), preexec_fn=_limit_memory)
        report = json.loads(proc.stdout or b"{}")
        entry["capabilities"] = sorted(report.get("rules", {}).keys())
        if proc.returncode in CAPA_UNSUPPORTED and not entry["capabilities"]:
            del entry["capabilities"]
            entry["skipped"] = f"capa: {CAPA_UNSUPPORTED[proc.returncode]}"
        elif not entry["capabilities"] and b"MemoryError" in proc.stderr:
            # as a binary over the size limit: the night scan (more memory,
            # no time limit) analyses it, and lists it until it has
            del entry["capabilities"]
            entry["skipped"] = (f"capa ran out of memory ({CAPA_MEMORY >> 20} MB) - the night scan "
                                "analyses it")
        elif proc.returncode != 0 and not entry["capabilities"]:
            entry["error"] = proc.stderr.decode("utf-8", "replace")[-300:]
    except subprocess.TimeoutExpired:
        entry["skipped"] = f"capa took longer than {CAPA_TIMEOUT} s"
    except ValueError:
        entry["error"] = "capa gave no JSON"
    return entry


# --- native profile: every binary, fast -------------------------------------------------

#: Imported functions by what they let a binary do.
NATIVE_CATEGORIES = {
    "network": {"socket", "connect", "bind", "listen", "accept", "accept4", "getaddrinfo", "gethostbyname",
                "send", "sendto", "sendmsg", "recv", "recvfrom", "SSL_connect", "curl_easy_perform",
                "curl_easy_init", "WSAStartup", "InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
                "InternetOpenUrlW", "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen", "URLDownloadToFileA",
                "URLDownloadToFileW"},
    "process": {"execve", "execv", "execvp", "execvpe", "execl", "execlp", "fork", "vfork", "posix_spawn",
                "posix_spawnp", "system", "popen", "CreateProcessA", "CreateProcessW", "ShellExecuteA",
                "ShellExecuteW", "ShellExecuteExW", "WinExec"},
    "injection": {"ptrace", "process_vm_writev", "process_vm_readv", "VirtualAllocEx", "WriteProcessMemory",
                  "CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookExA", "SetWindowsHookExW",
                  "QueueUserAPC", "memfd_create"},
    "anti-analysis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                      "prctl"},
    "dynamic-code": {"dlopen", "dlsym", "mprotect", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW",
                     "GetProcAddress", "VirtualProtect"},
    "credentials": {"getpwuid", "getpwnam", "CryptUnprotectData", "CredReadW", "CredEnumerateW",
                    "SecKeychainFindGenericPassword", "LsaRetrievePrivateData"},
}
_URL_B = re.compile(rb"https?://[A-Za-z0-9.\-]{3,253}(?::\d{2,5})?(?:/[\x21-\x7e]{0,200})?")
_IPV4_B = re.compile(rb"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")


def native_profile(data: bytes, kind: str) -> dict:
    """What a native binary imports (by category), links and contains (URLs,
    IPv4 addresses) - read from the file, nothing run."""
    imports: set[str] = set()
    needed: list[str] = []
    rpath: list[str] = []
    try:
        if kind == "elf":
            import io as _io

            from elftools.elf.dynamic import DynamicSection
            from elftools.elf.elffile import ELFFile

            elf = ELFFile(_io.BytesIO(data))
            for section in elf.iter_sections():
                if section.name == ".dynsym":
                    for sym in section.iter_symbols():
                        if sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                            imports.add(sym.name.split("@", 1)[0])
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(tag.needed)
                        elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                            rpath.append(getattr(tag, "rpath", "") or getattr(tag, "runpath", ""))
        elif kind == "pe":
            import pefile

            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                needed.append(dll.dll.decode("ascii", "replace"))
                for imp in dll.imports:
                    if imp.name:
                        imports.add(imp.name.decode("ascii", "replace"))
    except Exception as exc:  # noqa: BLE001 - recorded, the strings below still count
        error = f"{type(exc).__name__}: {exc}"[:200]
    else:
        error = ""
    categories = {cat: sorted(imports & names) for cat, names in NATIVE_CATEGORIES.items() if imports & names}
    urls = sorted({m.group(0).decode("ascii", "replace") for m in _URL_B.finditer(data)})[:200]
    # version strings such as 1.2.3.4 look like addresses: every part 20 or less is skipped
    # ASN.1 object identifiers (1.3.6.1..., 2.5.4...) are no addresses either
    ips = sorted({m.group(0).decode() for m in _IPV4_B.finditer(data)
                  if max(int(x) for x in m.group(0).split(b".")) > 20
                  and not m.group(0).startswith((b"1.2.", b"1.3.", b"2.5.", b"2.16.", b"0."))})[:100]
    return {"categories": categories, "needed": sorted(set(needed))[:100], "rpath": rpath[:10],
            "urls": urls, "ipv4": ips, "error": error}


def capa_scan(archives: list[str], known: set[str], workers: int | None = None,
              rules: str = "", cache: str = "") -> dict[str, list[dict]]:
    """capa on every native member of *archives* not in *known*, several at once."""
    from concurrent.futures import ThreadPoolExecutor

    capa = str(Path(sys.executable).with_name("capa"))
    out: dict[str, list[dict]] = {a: [] for a in archives}
    jobs = []
    with tempfile.TemporaryDirectory() as tmp:
        seen: dict[str, dict] = {}
        for archive in archives:
            for name, read in PI._members(archive):
                data = read()
                kind = next((label for magic, label in PI.NATIVE_MAGIC if data.startswith(magic)), None)
                if kind is None:
                    continue
                digest = hashlib.sha256(data).hexdigest()
                if digest in known:
                    continue
                entry = {"path": name, "sha256": digest, "kind": kind, "size": len(data),
                         "profile": native_profile(data, kind)}
                out[archive].append(entry)
                if digest in seen:          # the same binary twice: analyse once
                    entry["same_as"] = seen[digest]["path"]
                    continue
                seen[digest] = entry
                cached = _cached_capa(cache, digest, rules)
                if cached is not None:
                    entry.update(cached)
                    continue
                if len(data) > CAPA_MAX_BYTES or not rules or kind not in ("elf", "pe"):
                    entry["skipped"] = (f"larger than {CAPA_MAX_BYTES // (1024 * 1024)} MiB" if rules and kind in ("elf", "pe")
                                        else "no capa for this kind" if rules else "capa not asked")
                    continue
                d = os.path.join(tmp, digest)
                os.makedirs(d)
                path = os.path.join(d, "sample")
                with open(path, "wb") as f:
                    f.write(data)
                jobs.append((path, entry))
        workers = workers or CAPA_WORKERS
        if jobs and RULE_CACHE:
            # one run first, alone: it writes the compiled rules the others read
            _capa_one(capa, rules, *jobs[0])
            if not jobs[0][1].get("error"):
                _store_capa(cache, jobs[0][1]["sha256"], rules, jobs[0][1])
            jobs = jobs[1:]

        def run(job):
            entry = _capa_one(capa, rules, *job)
            if not entry.get("error"):
                _store_capa(cache, entry["sha256"], rules, entry)
            return entry
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(run, jobs))
        for entries in out.values():
            for entry in entries:
                if "same_as" in entry:
                    twin = seen[entry["sha256"]]
                    for k in ("capabilities", "skipped", "error"):
                        if k in twin:
                            entry[k] = twin[k]
    return out


def verify_attestations(archive: str, provenance: dict | None) -> dict:
    if not provenance:
        return {"attested": False}
    from pypi_attestations import Distribution, Provenance

    try:
        prov = Provenance.model_validate(provenance)
        dist = Distribution.from_file(Path(archive))
        publishers = []
        for bundle in prov.attestation_bundles:
            for attestation in bundle.attestations:
                attestation.verify(bundle.publisher, dist, offline=True)
            publishers.append(bundle.publisher.model_dump(exclude_none=True))
        return {"attested": True, "verified": True, "publishers": publishers}
    except Exception as exc:  # noqa: BLE001 - any failure is a failed verification
        return {"attested": True, "verified": False, "error": str(exc)[:300]}


def _scan_all(items: list[dict], rules, meta) -> list[dict]:
    """YARA and the attestations of every archive: the archives SCAN_WORKERS
    at a time, and their members matched in a pool of the same size (one
    large archive - Qt's libraries - would otherwise take as long as all)."""
    from concurrent.futures import ThreadPoolExecutor

    workers = max(1, SCAN_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as members, ThreadPoolExecutor(max_workers=workers) as archives:
        def scan(item: dict) -> dict:
            return {"yara": yara_scan(item["path"], rules, meta, members if workers > 1 else None),
                    "attestation": verify_attestations(item["path"], item.get("provenance"))}
        return list(archives.map(scan, items))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__)
        return 2
    job = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    known = set(job.get("known_native", []))
    rules, meta = compile_rules()
    results = {"rules": len(meta), "archives": {}}
    global RULE_CACHE, SIGS
    if job.get("capa_sigs"):
        SIGS = job["capa_sigs"]
    if job.get("capa_cache"):
        RULE_CACHE = os.path.join(job["capa_cache"], "rule-cache")
        os.makedirs(RULE_CACHE, exist_ok=True)
    capa = {} if job.get("skip_capa") else capa_scan([i["path"] for i in job["archives"]], known,
                                                     rules=job.get("capa_rules", ""),
                                                     cache=job.get("capa_cache", ""))
    for item, result in zip(job["archives"], _scan_all(job["archives"], rules, meta)):
        if not job.get("skip_capa"):
            result["capa"] = capa.get(item["path"], [])
        results["archives"][item["name"]] = result
    Path(args[1]).write_text(json.dumps(results, indent=1, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
