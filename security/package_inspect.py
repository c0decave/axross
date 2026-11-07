#!/usr/bin/env python3
"""Look inside a Python package archive (wheel or sdist) without running
any of it: what files it has (each with its SHA-256), which of them run
code on their own (``.pth`` start-up lines, build hooks, console scripts),
which are native binaries, whether the wheel's RECORD matches its content,
and which lines look like the tricks malicious packages use (obfuscated
``exec``, code pulled from the network at import, secrets read and sent,
long encoded blobs).

Standard library only, so it can vet the very tools (GuardDog, YARA,
capa) the supply-chain gate installs afterwards. Used by
security/supply_chain_gate.py; also runnable on one file:

    python -I security/package_inspect.py FILE.whl|FILE.tar.gz [--json]

A finding is not a verdict: many honest packages ``exec`` or decode base64.
What the gate fails on is a finding the package's reviewed baseline does
not already contain (security/supply_chain_baseline/).
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import lzma
import re
import sys
import tarfile
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath

#: Members larger than this are hashed but not read as text.
MAX_TEXT_MEMBER = 4 * 1024 * 1024
#: An archive with more members than this, or more bytes uncompressed, is refused.
MAX_MEMBERS = 200_000
MAX_TOTAL = 6 * 1024 * 1024 * 1024
#: Encoded blobs at least this long in source are a finding.
BLOB_LEN = 2000

NATIVE_MAGIC = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
)

#: (rule id, severity, pattern) over the text of Python files. Severity
#: "high": typical of malware, rare in honest code; "medium": worth a look.
RULES = (
    ("exec-decoded", "high",
     re.compile(r"\b(?:exec|eval)\s*\(\s*(?:[\w.]+\.)?(?:b64decode|b32decode|b16decode|a85decode|decompress|"
                r"loads|unhexlify|fromhex|decode)\s*\(")),
    ("exec-compile-decoded", "high",
     re.compile(r"\bexec\s*\(\s*compile\s*\(\s*(?:[\w.]+\.)?(?:b64decode|decompress|loads)")),
    ("marshal-exec", "high", re.compile(r"\bmarshal\.loads\s*\(")),
    ("import-os-system", "high", re.compile(r"__import__\s*\(\s*['\"](?:os|subprocess|socket|urllib\.request|requests)['\"]\s*\)\s*\.")),
    ("download-exec", "high",
     re.compile(r"(?:urlopen|requests\.get|httpx\.get|urlretrieve)\s*\([^)]*\)[^\n]{0,80}\b(?:exec|eval|system|Popen)\b")),
    ("discord-telegram-webhook", "high",
     re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services", re.I)),
    ("paste-site", "medium", re.compile(r"\b(?:pastebin\.com|paste\.ee|hastebin|transfer\.sh|ngrok\.io|"
                                        r"pipedream\.net|requestbin|webhook\.site|oast\.(?:fun|pro|live|site|me)|"
                                        r"interact\.sh|burpcollaborator)", re.I)),
    ("raw-ip-url", "medium", re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/")),
    ("secret-paths", "medium",
     re.compile(r"(?:\.ssh/id_|\.aws/credentials|\.npmrc|\.pypirc|\.git-credentials|\.docker/config\.json|"
                r"Login Data|Local State|wallet\.dat|\.kube/config|\.netrc|\.bash_history|keychain-db)")),
    ("env-dump", "medium", re.compile(r"(?:dict|json\.dumps|str)\s*\(\s*os\.environ\s*\)")),
    # keys and secrets malware copies
    ("gpg-keys", "high", re.compile(r"\.gnupg|secring\.gpg|private-keys-v1\.d|pubring\.kbx|trustdb\.gpg")),
    ("ssh-keys", "high", re.compile(r"\.ssh/(?:id_[a-z0-9_]+|authorized_keys|known_hosts|config)\b|"
                                    r"(?:glob|listdir|walk|iterdir)\s*\([^)]*\.ssh")),
    ("keyring-stores", "medium", re.compile(r"\.local/share/keyrings|login\.keychain|\.password-store|"
                                            r"KeePass|\.kdbx\b|1Password|Bitwarden", re.I)),
    ("system-secrets", "high", re.compile(r"/etc/shadow\b|/etc/sudoers\b|SAM\\\\|\\SYSTEM32\\\\config\\\\SAM", re.I)),
    # browser profiles, cookies and saved passwords
    ("browser-data", "high", re.compile(
        r"(?:google-chrome|chromium|BraveSoftware|Microsoft[/\\]Edge|opera|vivaldi|Yandex)[^'\"\n]{0,80}"
        r"(?:Login Data|Cookies|Web Data|Local State|History|Bookmarks)|"
        r"\.mozilla/firefox|Firefox[/\\]Profiles|logins\.json|key[34]\.db|cookies\.sqlite|"
        r"Library/Safari|Cookies\.binarycookies", re.I)),
    ("messenger-tokens", "high", re.compile(r"discord(?:canary|ptb)?[/\\]Local Storage[/\\]leveldb|"
                                            r"Telegram Desktop[/\\]tdata|Signal[/\\]sql|Slack[/\\]Cookies", re.I)),
    ("wallets", "high", re.compile(r"wallet\.dat|Exodus[/\\]exodus\.wallet|Electrum[/\\]wallets|"
                                   r"atomic[/\\]Local Storage|nkbihfbeogaeaoehlefnkodbefgpgknn|"
                                   r"Ethereum[/\\]keystore|\.bitcoin|monero[/\\]wallets", re.I)),
    ("clipboard-hijack", "medium", re.compile(r"(?:pyperclip|clipboard)\.(?:paste|copy)\s*\(.{0,120}"
                                              r"(?:bc1|0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})")),
    # encodings used to hide code
    ("rot13-or-reversed", "medium", re.compile(r"codecs\.decode\s*\([^)]*rot.?13|\[\s*::\s*-1\s*\]\s*\)\s*\)")),
    ("b64-in-subprocess", "high", re.compile(r"(?:python[23]?|powershell)[^\n]{0,40}(?:-c|-e|-enc)[^\n]{0,40}"
                                             r"(?:base64|b64decode|FromBase64String)", re.I)),
    ("browser-or-wallet", "medium", re.compile(r"(?:Chrome|Chromium|Brave|Edge)[/\\]User Data|Exodus|Electrum|MetaMask", re.I)),
    ("hidden-process", "medium", re.compile(r"(?:CREATE_NO_WINDOW|DETACHED_PROCESS|creationflags\s*=\s*0x08000000|nohup\s)")),
    ("crontab-autostart", "medium",
     re.compile(r"crontab\s+-|/etc/cron|\.config/autostart|CurrentVersion\\\\Run|LaunchAgents|systemctl\s+enable")),
    ("chr-join", "medium", re.compile(r"(?:chr\(\s*\d+\s*\)\s*\+\s*){8,}")),
    ("setup-network", "medium", re.compile(r"\b(?:urlopen|requests\.|socket\.|http\.client)")),
)
#: Only in build hooks (setup.py, build backends of sdists) these count high.
SETUP_ESCALATE = {"setup-network", "hidden-process", "crontab-autostart"}

_B64_BLOB = re.compile(rb"[A-Za-z0-9+/=]{%d,}" % BLOB_LEN)
_HEX_BLOB = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){%d,}" % (BLOB_LEN // 4))


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    text: str

    def key(self) -> str:
        """Identity across versions: the rule, the file and the line's text
        (not its number, which moves with every edit above it)."""
        return f"{self.rule}|{self.path}|{hashlib.sha256(self.text.encode()).hexdigest()[:16]}"


@dataclass
class Report:
    archive: str
    sha256: str
    kind: str                     # wheel | sdist
    files: dict = field(default_factory=dict)       # path -> sha256
    sizes: dict = field(default_factory=dict)       # path -> bytes
    native: dict = field(default_factory=dict)      # path -> elf|pe|macho
    pth: dict = field(default_factory=dict)         # path -> executable lines
    hooks: list = field(default_factory=list)       # files a build or install runs
    entry_points: list = field(default_factory=list)
    record_problems: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def to_json(self) -> dict:
        data = asdict(self)
        data["findings"] = [asdict(f) | {"key": f.key()} for f in self.findings]
        return data


class InspectError(Exception):
    pass


def _members(path: str):
    """(name, bytes reader) of every regular file in the archive."""
    if path.endswith(".whl") or path.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                raise InspectError(f"{len(infos)} members")
            total = 0
            for info in infos:
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_TOTAL:
                    raise InspectError("uncompressed size beyond the limit (a zip bomb?)")
                yield info.filename, (lambda i=info: zf.read(i))
        return
    mode = "r:gz" if path.endswith((".tar.gz", ".tgz")) else "r:*"
    with tarfile.open(path, mode) as tf:
        count, total = 0, 0
        for info in tf:
            count += 1
            if count > MAX_MEMBERS:
                raise InspectError("too many members")
            if info.issym() or info.islnk():
                yield info.name, (lambda i=info: f"LINK -> {i.linkname}".encode())
                continue
            if not info.isfile():
                continue
            total += info.size
            if total > MAX_TOTAL:
                raise InspectError("uncompressed size beyond the limit")
            yield info.name, (lambda i=info: tf.extractfile(i).read())


def _safe_path(name: str) -> bool:
    p = PurePosixPath(name)
    return not p.is_absolute() and ".." not in p.parts and "\\" not in name


def _record_check(files: dict, record_text: str, record_path: str) -> list[str]:
    problems = []
    listed = set()
    for row in csv.reader(io.StringIO(record_text)):
        if not row:
            continue
        name = row[0]
        listed.add(name)
        if name == record_path or name.endswith((".jws", ".p7s")):
            continue
        digest = row[1] if len(row) > 1 else ""
        if name not in files:
            problems.append(f"RECORD lists {name}, which is not in the wheel")
            continue
        if not digest.startswith("sha256="):
            problems.append(f"RECORD has no sha256 for {name}")
            continue
        want = digest[7:]
        got = base64.urlsafe_b64encode(bytes.fromhex(files[name])).rstrip(b"=").decode()
        if want != got:
            problems.append(f"{name} does not match its RECORD hash")
    for name in files:
        if name not in listed and name != record_path:
            problems.append(f"{name} is in the wheel but not in RECORD")
    return problems


def _scan_text(path: str, data: bytes, *, hook: bool) -> list[Finding]:
    out: list[Finding] = []
    text = data.decode("utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:
            snippet = line[:200] + " …"
        else:
            snippet = line.strip()[:300]
        for rule, severity, pattern in RULES:
            if rule == "setup-network" and not hook:
                continue
            if pattern.search(line):
                sev = "high" if hook and rule in SETUP_ESCALATE else severity
                out.append(Finding(rule, sev, path, number, snippet))
    for pattern, rule in ((_B64_BLOB, "encoded-blob"), (_HEX_BLOB, "hex-blob")):
        m = pattern.search(data)
        if m:
            line = data.count(b"\n", 0, m.start()) + 1
            out.append(Finding(rule, "medium", path, line, f"{len(m.group(0))} encoded characters"))
    return out


def _pth_exec_lines(data: bytes) -> list[str]:
    """Lines of a .pth file Python executes at every start (``import ...``)."""
    lines = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "import\t")):
            lines.append(stripped[:500])
    return lines


def _parse_metadata(data: bytes) -> dict:
    out: dict = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            break
        key, sep, value = line.partition(":")
        if not sep or line[:1] in " \t":
            continue
        key = key.strip()
        if key in ("Name", "Version", "Summary", "Home-page", "Author", "Author-email", "Maintainer",
                   "Maintainer-email", "License", "License-Expression"):
            out[key] = value.strip()[:300]
        elif key in ("Requires-Dist", "Project-URL"):
            out.setdefault(key, []).append(value.strip()[:300])
    return out


def inspect(path: str) -> Report:
    with open(path, "rb") as f:
        digest = hashlib.sha256()
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    kind = "wheel" if path.endswith(".whl") else "sdist"
    report = Report(archive=path.rsplit("/", 1)[-1], sha256=digest.hexdigest(), kind=kind)
    record_text, record_path = None, ""
    try:
        for name, read in _members(path):
            if not _safe_path(name):
                report.errors.append(f"unsafe member path {name!r}")
                continue
            data = read()
            report.files[name] = hashlib.sha256(data).hexdigest()
            report.sizes[name] = len(data)
            for magic, label in NATIVE_MAGIC:
                if data.startswith(magic):
                    report.native[name] = label
                    break
            lower = name.lower()
            base = lower.rsplit("/", 1)[-1]
            if lower.endswith(".pth"):
                lines = _pth_exec_lines(data)
                if lines:
                    report.pth[name] = lines
            if kind == "wheel" and lower.endswith(".dist-info/record"):
                record_text, record_path = data.decode("utf-8", errors="replace"), name
            if lower.endswith(".dist-info/entry_points.txt"):
                report.entry_points = [l.strip() for l in data.decode("utf-8", "replace").splitlines()
                                       if "=" in l][:200]
            if lower.endswith((".dist-info/metadata", "/pkg-info")) and not report.metadata:
                report.metadata = _parse_metadata(data)
            hook = kind == "sdist" and base in ("setup.py", "build.py", "conftest.py", "setup.cfg",
                                                "pyproject.toml", "hatch_build.py", "build_backend.py")
            if kind == "wheel" and ".data/scripts/" in lower:
                hook = True
                report.hooks.append(name)
            if hook and kind == "sdist":
                report.hooks.append(name)
            if len(data) <= MAX_TEXT_MEMBER and (lower.endswith((".py", ".pyw", ".pth", ".cfg", ".toml"))
                                                  or hook):
                report.findings.extend(_scan_text(name, data, hook=hook))
    except (zipfile.BadZipFile, tarfile.TarError, OSError, InspectError, EOFError, zlib.error,
            lzma.LZMAError, RuntimeError, NotImplementedError, ValueError) as exc:
        # A truncated .tar.gz (EOFError) or a corrupt member (zlib.error)
        # is this archive's problem, recorded - not the end of the gate run.
        report.errors.append(f"cannot read the archive: {type(exc).__name__}: {exc}")
    if kind == "wheel":
        if record_text is None:
            report.record_problems.append("the wheel has no RECORD")
        else:
            report.record_problems = _record_check(report.files, record_text, record_path)
    for name, lines in report.pth.items():
        for line in lines:
            report.findings.append(Finding("pth-executes-at-start", "high", name, 0, line))
    return report


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in args
    paths = [a for a in args if a != "--json"]
    if not paths:
        print(__doc__.strip().splitlines()[0])
        return 2
    worst = 0
    for path in paths:
        report = inspect(path)
        if as_json:
            print(json.dumps(report.to_json(), indent=1))
            continue
        print(f"{report.archive}  sha256 {report.sha256}  {report.kind}, {len(report.files)} files, "
              f"{len(report.native)} native")
        for problem in report.errors + report.record_problems:
            print("  PROBLEM", problem)
            worst = max(worst, 1)
        for f in report.findings:
            print(f"  {f.severity.upper():6} {f.rule:24} {f.path}:{f.line}  {f.text[:120]}")
    return worst


if __name__ == "__main__":
    sys.exit(main())
