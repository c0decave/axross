# The supply-chain gate

No dependency reaches an axross dist unless it was reviewed and nothing about
it changed since. `scripts/build_dist.sh` runs the gate before it builds
anything and stops on any problem; there is no switch to skip it. The gate is
`security/supply_chain_gate.py` (standard library only), its scanners run from
a venv of their own (`security/supply_chain_scan.py`), and what was reviewed is
kept in `security/supply_chain_baseline/` - one JSON file per package, every
reviewed version, committed, so git's history of that folder is the record
over time.

## What runs, and when

| Stage | When | What |
|---|---|---|
| `check` (standard library) | first thing in every dist build | every pin of `build/requirements-bootstrap.txt`, `-dist-tools.txt`, `-bundle.txt` and `-scan-tools.txt` |
| scanner venv | next | installed from `build/requirements-scan-tools.txt` with `--require-hashes`, then `verify-env` |
| `check --scan-python` | next | the scanners over every archive; the report goes into `dist/<version>/SUPPLY-CHAIN.md` and `.json` |
| `verify-env` | after each venv of the build | everything installed is a locked pin in its version, every file matches the wheel's RECORD |
| bootloader | before the first bundle | PyInstaller's bootloader compiled from its reviewed sdist (zig cc, glibc 2.34), its SHA-256 in BUILD-INFO.md |
| `check-system` | after each variant's packages are fetched | the AlmaLinux / Debian packages bundled into the binaries |
| tests | every test run | `tests/test_supply_chain_gate_axross.py`: a lock change without a reviewed baseline fails already there; `tests/test_supply_chain_gate.py`: the gate itself |
| `deep-scan` | night sessions (`scripts/supply_chain_nightly.sh`) | capa on every native binary, however large |

## What a pin has to pass

1. **PyPI** - each locked sha256 is a file of exactly that release on PyPI;
   the release and the files used are not yanked, the project not quarantined.
2. **Age** - the files are at least 14 days old: most malicious uploads are
   found and removed within days. The lock scripts only resolve releases that
   old (`uv --exclude-newer`). A security fix may be younger: it is listed in
   `build/young-release-exceptions.txt` with its advisory and needs a reviewed
   baseline that says so.
3. **OSV** (api.osv.dev) - no advisory, and no malicious-package entry
   (`MAL-*`, the OpenSSF malicious-packages feed). Without OSV the gate fails.
4. **Names** - a package new to the baseline must not look like a typo of a
   popular one (edit distance, separators, look-alike characters, prefixes and
   suffixes against `security/top_pypi_packages.txt`, the 15 000 most
   downloaded projects) or of another locked one; no extra package index may
   be configured (dependency confusion).
5. **Provenance** - PyPI's attestations (PEP 740): who published the file
   from which repository and workflow, verified with Sigstore. A publisher
   other than the baseline's, or attestations gone, fails.
6. **Content** - the files the build installs are downloaded, checked against
   the lock's hash and inspected without running anything
   (`security/package_inspect.py`): every member's SHA-256, `.pth` start-up
   code, build hooks, the wheel's RECORD, and lines typical of malware -
   obfuscated `exec`, encoded payloads, code fetched at import, environment
   dumps, SSH/GPG key, keyring, browser profile, messenger token and wallet
   paths, webhooks and paste sites, persistence.
7. **YARA** - Datadog GuardDog's rules for malicious packages (read as rule
   files; GuardDog itself is never imported or run - it fetches lists from the
   network) and axross's own in `security/yara_rules/` (reverse shells,
   download-and-execute, pipe to shell, Windows LOLBins, persistence, key and
   browser data theft, beacons, install hooks, decompress-and-exec chains).
8. **Native binaries** - every ELF / PE file gets a profile (imported
   functions by category: network, process start, injection, anti-analysis,
   dynamic code, credentials; linked libraries; embedded URLs and addresses);
   capa analyses binaries up to 2 MB in the survey and all of them in the
   night sessions. capa's rules (`build/capa-rules.txt`) and its FLIRT
   signatures (`build/capa-sigs.txt`, from the capa source release - the
   flare-capa wheel has none, and without them capa refuses every PE file)
   are pinned by SHA-256. A file capa does not analyse (an ARM64 launcher, a
   .NET or packed file: capa's exit codes 14, 16, 17, 18) is recorded as
   skipped with the reason and keeps its native profile; so is one capa runs
   out of memory on (2 GB in the survey, `AXROSS_CAPA_MEMORY_MB`) or needs more
   than 15 minutes for - the night sessions analyse those. Any other capa
   failure is an error that `accept-survey` refuses.

A credential-shaped string inside a binary (an API key of a common service:
`sk-…`, `AKIA…`, `ghp_…`, `glpat-…`, `xox…-`) is not copied into the baseline,
which is published with the source: it is stored as `[withheld sha256:…]`.

Every finding of a reviewed version is part of its baseline; the gate fails
on anything the baseline does not contain - a new package, a new version, an
archive whose members differ, a new finding or YARA hit, a new binary.

## Adding or updating a dependency

1. Change `pyproject.toml` / `build/requirements-bundle.in`, then
   `scripts/lock_bundle_deps.sh --here` (scanners: `scripts/lock_scan_tools.sh`,
   build tools: `scripts/build_dist.sh --lock-tools`).
2. `python -I security/supply_chain_gate.py status` lists what is new.
3. A scanner venv: `python3.12 -m venv V && V/bin/pip install --require-hashes
   --only-binary=:all: -r build/requirements-scan-tools.txt`.
4. `python -I security/supply_chain_gate.py review NAME==VERSION --scan-python
   V/bin/python` shows everything about it: metadata, attestations, findings
   and YARA hits marked NEW or known, native profiles and capa, and for a new
   version the files added, removed and changed and the source diff against
   the reviewed one.
5. Read every NEW item in the code. Then
   `... accept NAME==VERSION --by WHO --note "what was checked and why it is
   acceptable" --scan-python V/bin/python` writes the baseline entry (a young
   security fix also `--young REASON`). For many pins at once: `survey DIR`,
   then `accept-survey DIR VERDICTS.json --by WHO`.
6. Commit the baseline with the lock.

## The tools exported as programs of their own

A tool axross writes out as a project of its own (`scripts/export_standalone.py
APP`) installs its dependencies from PyPI on the user's machine, not from
axross's bundle. For axross-markdown those are locked like axross's own:
`scripts/lock_standalone_deps.sh markdown` writes
`build/requirements-standalone-markdown.txt` (the exported pyproject's
dependencies and every extra, `export_standalone.py --requirements markdown`;
uv `--universal --python-version 3.11 --generate-hashes`, only releases at
least 14 days old, axross's own pins preferred). The lock is one of the gate's
`LOCKS`: every pin needs a reviewed baseline here, the tests fail without one,
and `build_dist.sh` checks it with the rest before it builds the tool's sdist
and wheel. The exporter refuses a lock made for other requirements (its
header records the input's SHA-256) and ships it as `requirements.lock.txt`
with a `supply-chain-gate.toml`; the exported CI installs exactly those files
(`pip install --require-hashes -r requirements.lock.txt`, then
`pip install --no-build-isolation --no-deps .`, its build backend pinned in the
lock too) and runs this gate on them in a job of its own: a
sparse checkout of axross's `security/` and scanners' lock into `.axross`,
the standard-library check, the scanners installed from the lock cut down to
what the check inspected, `verify-env`, then the check with the scanners - the
same order as `build_dist.sh`, against axross's reviewed baseline.

First review (2026-11-17): axross-markdown's lock holds 9 pins (PyQt6, PyQt6-Qt6,
PyQt6-sip, markdown-it-py, mdurl, Pygments, Pillow - already reviewed for axross in
the same versions - and linkify-it-py 2.2.0 and mdit-py-plugins 0.6.1, new: pure
Python, nothing flagged, every module identical to the upstream release tag;
linkify-it-py's attestation verifies, mdit-py-plugins has none). OSV: no advisory.

## Rust: crates from crates.io (`security/supply_chain_cargo.py`)

The same principles for a `Cargo.lock` (axross-amp, the player rewritten in
Rust). Standard library only; the YARA and capa stage runs from the same
scanner venv (`--scan-python`). A project points it at its lock and its own
baseline with a small TOML file (`lock`, `own`, `baseline_dir`, `cache_dir`,
`min_age_days`); the baseline lives in the project, next to its lock, so a
dependency change and its review are one commit there.

| Check | What fails |
|---|---|
| source | a package from git, a path (other than the project's own) or another registry |
| crates.io | the lock's checksum is not the one crates.io's index publishes; a yanked version; a .crate download with another SHA-256 |
| age | published less than 14 days ago (crates.io's `created_at`), unless the baseline names a security fix (`--young`) |
| advisories | RustSec's advisory-db (read from its GitHub archive every run) and OSV (`crates.io`): a vulnerability or a `MAL-*` entry fails; a notice (unmaintained, unsound) fails until the crate's baseline says why it is acceptable (`--advisory ID=WHY`). Without both sources the gate does not run; `--require-osv` (CI) also fails without OSV alone |
| names | a crate new to the baseline that looks like a typo of a popular crate (`security/top_crates.txt`, the 5 000 most downloaded, `top-crates` refreshes it; Rust's prefixes and suffixes: `-rs`, `-sys`, `-derive`, `-macros` ...) or of another locked crate - a family in the same lock (`zbus` / `zbus_macros`) is reviewed together |
| content | anything the review did not see: the .crate's SHA-256 and members, its build script (and the modules it includes) and whether it is a proc macro - code that runs on the build machine; bundled binaries and prebuilt libraries (ELF, PE, Mach-O, ar archives with the DLLs an import library names, COFF objects, WebAssembly); vendored C/C++/assembly by folder; findings: in build-time code network use, programs started (`curl`, a shell ...), the environment dumped, the home folder, files written; anywhere the language-independent rules of `package_inspect.py` (key, wallet, browser-data paths, webhooks, paste sites, encoded blobs) and memory made executable |
| scanners | GuardDog's and axross's YARA rules over every member, capa on every ELF / PE file |
| publisher | the crates.io account that published the version differs from the one the review saw |

`review NAME==VERSION` shows everything about a crate (and the source diff
against the reviewed version), `accept` records it, `survey DIR` and
`accept-survey DIR VERDICTS.json` do the first review of a whole lock, and
`upstream NAME==VERSION --prefix DIR/ --url URL --sha256 SHA` compares vendored
sources with an upstream release tarball and records the result in the
crate's baseline entry.

## Night sessions

`scripts/supply_chain_nightly.sh [BUDGET_MINUTES] [WORKERS]` runs capa
without a size limit on every bundled binary that has no full analysis yet
(vivisect needs 15+ minutes and 2-3 GB for a large library, so 2 at a time by
default, 6 GB address space each), within the budget, and continues the next
night. Capabilities in the alarm namespaces (anti-analysis, persistence,
injection, credential access, keylogging, screen capture ...) fail the gate
until `accept-deep NAME==VERSION MEMBER --by WHO --note ...` records why they
are acceptable.

## As a project of its own

The gate is not tied to axross: a config file points it at any project with
hash-pinned locks, and `scripts/export_supply_chain_gate.py` writes it as a
standalone, installable project. axross keeps its copy in `security/` and runs
it by default in every dist build; the export is the same code.

    python3 -I scripts/export_supply_chain_gate.py ../supply-chain-gate
    cd ../supply-chain-gate && python -m pytest tests && git init && git add -A && git commit -m "supply-chain-gate"

The project gets `src/supply_chain_gate/` (the gate, the scanner, the archive
inspector, the lock reader, the top-packages list, the pinned capa rules and
signatures, the YARA rules), its generic tests, `pyproject.toml` with the
`supply-chain-gate` command, a README (quick start, commands, settings, what a
pin has to pass), `supply-chain-gate.example.toml` and the scanners' lock. Not
copied: axross's baselines and locks - a project reviews its own pins. Imports,
environment variables (`AXROSS_*` -> `SUPPLY_CHAIN_GATE_*`) and the user agent
are rewritten, each rewrite checked; without a config the exported gate refuses
to run instead of checking axross. `tests/test_export_supply_chain_gate.py`
exports it and runs its tests, so a change here that breaks the export fails at
once. Re-export after changing the gate here, or develop it there from now on
and copy back - the files are the same apart from the rewrites.

Settings (`supply-chain-gate.toml` in the project, or `--config FILE`): `root`,
`locks`, `scanner_lock`, `index_config`, `baseline_dir`, `cache_dir`,
`young_exceptions`, `build_from_source`, `min_age_days`, `user_agent`,
`capa_rules`, `capa_sigs`, `top_packages`.

## The first review (2026-11-04 / 2026-11-05)

All 254 pins of the four locks: OSV knows no malicious-package entry and,
after the locks were moved to releases at least 14 days old, no advisory.
GuardDog's and axross's threat rules (YARA) flagged 44 packages; each flagged location
was read in the code (impacket's pentest functions, PyInstaller's bytecode
loader, docstrings, test fixtures ...): all benign. 118 files carry
attestations, every one verifies. Findings that are no malware:

* **onnxruntime** (Piper voices, faster-whisper's VAD) contains Microsoft's
  telemetry client, on by default (`mobile.events.data.microsoft.com`). axross
  turns it off in every process (`ORT_DISABLE_TELEMETRY=1` at start and in the
  voice child, plus onnxruntime's own switch; `tests/test_dependency_review_findings.py`).
* **impacket**: importing `impacket.examples` replaces
  `ssl.create_default_context` for the whole process with one that checks no
  certificate. axross never imports it (a test holds it).
* **pywinpty**'s sdist carries a complete, PSF-signed Windows ARM64 Python
  swept in by its build; the bundles install the wheel.
* **piper-tts** unpacks one download without checking member paths
  (hardening, not malware).
* **sift-summarizer** and **pyinstaller** have no attestations: the content
  review is the only evidence. PyInstaller's bootloader is therefore compiled
  from its sdist (reproducibly: the same SHA-256 on every build).
