# Supply-chain security audit

**Last updated**: 2026-10-26 (axross 0.14.60 plus the supply-chain branch).

**Scope**: everything axross ships - the Linux one-file binaries
`axross-full` and `axross-slim` (AlmaLinux 9 builder image,
`Dockerfile.build`), the macOS and Windows `axross-slim` binaries built in
GitHub CI (`.github/workflows/cross-platform.yml`), and the wheel / sdist on
PyPI (whose dependency floors decide what a `pip install axross` can
resolve).

**Goal** (operator): no compromised software and no software with known
CVEs or other hard bugs in any of them.

---

## How the bundles get their dependencies (2026-10-26)

| Layer | What pins it | Checked by |
|---|---|---|
| Python packages of every bundle (145 pins) | `build/requirements-bundle.txt`: one exact version per package and the sha256 of every file PyPI has for it; installed with `pip install --require-hashes --only-binary=:all:` in the builder and in the macOS / Windows CI job | `tests/test_bundle_lock.py` (offline), `python -m security.dep_floor_audit --lock` (OSV, malicious packages included), osv-scanner v2.7.0 in CI (`osv-scanner.yml` reads the lock on every push) |
| The lock itself | `scripts/lock_bundle_deps.sh`: uv 0.13.5 (hash-pinned) in a digest-pinned `python:3.12-slim` container, `uv pip compile --universal --python-version 3.12 --generate-hashes` over `build/requirements-bundle.in` | `scripts/lock_bundle_deps.sh --check` (is it current?) |
| pip and setuptools in the builder | `build/requirements-bootstrap.txt` (the lock's own two entries), installed by the distro pip before the lock; the distro's pip 23.2.1 and setuptools 68.2.2 rpms are then removed | `tests/test_bundle_lock.py` (same pins as the lock) |
| Packages without a Python 3 wheel (adb-shell, fusepy, manuf) | hashed sdists, built with `--no-build-isolation` against the hashed setuptools: no build backend is fetched unhashed | `tests/test_bundle_lock.py` |
| System libraries in the Linux bundles (libssl, libcrypto, libexpat, libpcre2, libxml2, libsqlite3, libz, libglib ...) | `dnf upgrade` in both dnf layers of `Dockerfile.build` | `scripts/build_bundle_docker.sh` refuses an image where `dnf updateinfo list --security` is not empty (a cached layer from an older build would be); `scripts/bundle_smoke.py --system-libs` keeps the glibc floor at 2.34 |
| Qt | PyQt6 6.11.0 with PyQt6-Qt6 6.11.2 (was 6.10.2) | `tests/test_bundle_lock.py::test_sad_no_known_vulnerable_qt_is_locked` |
| Qt platform plugins | `scripts/bundle_options.DROPPED`: vnc, eglfs (+ device integrations), linuxfb, minimal, minimalegl, vkkhrdisplay leave the Linux bundles; xcb, wayland, offscreen stay | `tests/test_bundle_options.py`, `tests/test_bundle_platform_plugins.py` (built binary) |
| ripgrep / fd in axross-full | version + SHA-256 `ARG`s in `Dockerfile.build` | `tests/test_bundled_search_tools.py` |
| GitHub Actions | every `uses:` pinned to a 40-hex commit SHA with a `# vX.Y.Z` comment | `tests/test_workflow_action_pins.py` |
| Wheel / sdist floors | `pyproject.toml` | `python -m security.dep_floor_audit` (OSV, per floor) |

Refresh procedure: `docs/PACKAGING.md`, section "Pinned, hashed
dependencies".

## Measured state on 2026-10-26

Bundles built from this tree in the new builder image (both flavours, local
build, 2026-10-26):

| Check | Result |
|---|---|
| `dnf updateinfo list --security` in the builder image | empty (the previous image listed openssl, expat, pcre2, vim: Important; ca-certificates: Critical; curl: Moderate) |
| Bundled `libssl.so.3`, `libcrypto.so.3`, `libexpat.so.1`, `libpcre2-8.so.0` | byte-identical to the image's openssl-libs 3.5.8-2.el9_8, expat 2.5.0-6.el9_8.7, pcre2 10.40-7.el9_8 (sha256); the 0.14.50 bundles carried other files |
| Qt inside the binaries (`qVersion()`) | 6.11.2, PyQt6 6.11.0 |
| Qt platform plugins in the binaries | libqxcb, libqwayland, libqoffscreen; no libqvnc, eglfs, linuxfb, minimal, minimalegl, vkkhrdisplay; no dangling link |
| watchdog, Pygments in the PYZ | present (`watchdog.observers.inotify`, `pygments.lexers.python`); both import inside the binaries |
| Highest `GLIBC_` symbol version needed by any bundled ELF (`objdump -T`, 433 ELF files in full, 315 in slim) | GLIBC_2.34 |
| `scripts/bundle_smoke.py` (smoke, `--system-libs`, `--libs`) | ok |
| `tests/test_third_party_bundle.py`, `tests/test_bundle_platform_plugins.py` against each binary | pass |
| OSV over the builder image's `pip list` (139 packages) | 0 advisories; one package below its newest release: python-dateutil 2.9.0.post0, held below 3.0 by botocore (`python-dateutil<3.0.0`) |
| `python -m security.dep_floor_audit --lock build/requirements-bundle.txt` (145 pins) | no advisories, no malicious package |
| osv-scanner v2.7.0 (the CI action's image, `scan source -r ./`) over the tree | scans `build/requirements-bundle.txt` (145), `build/requirements-bootstrap.txt` (2) and `dev-requirements.txt` (11): no issues. Before, `build/*` in `.gitignore` hid the lock from it, and its resolution of `dev-requirements.txt` picked certifi and idna releases with advisories (floors added) |
| `python -m security.dep_floor_audit` (wheel floors) | one floor left: Pillow (see Open items); cryptography, pymongo, dulwich and pypdf floors were raised |

Also changed by Qt 6.11.2: its TIFF plugin links its own libtiff and its
QtPdf no longer needs libatomic, so the system libtiff.so.5, JBIG-KIT
(GPL-2.0-or-later) and libatomic are no longer in the bundles
(`resources/credits/third_party.json` updated).

## Qt advisories still open in 6.11.2

Source: wiki.qt.io/List_of_known_vulnerabilities_in_Qt_products, read
2026-10-26. PyPI's newest PyQt6-Qt6 is 6.11.2; 6.11.3 is not published.

| Advisory | Component | Reached by axross? |
|---|---|---|
| CVE-2026-79680 | Qt VNC server password authentication bypass | No longer shipped: libqvnc is removed from the Linux bundles (`bundle_options.DROPPED`); the macOS / Windows wheels carry no VNC plugin |
| CVE-2026-95620, CVE-2026-96432 | QNetworkAccessManager HTTP/2 | No: axross does not use QtNetwork (`grep -rn "QtNetwork\|QNetwork" core ui models main.py axross resources`: no hit) |
| CVE-2026-101201 | QJsonDocument out-of-bounds read | No: axross parses JSON with Python's `json`, no `QJsonDocument` in the tree |
| CVE-2026-105923 | QTriangulator through the VectorImage QML type | No: axross uses no QML / Qt Quick |
| CVE-2026-15037 | QDom serialization XML injection (fixed only in 6.12.0) | No: axross does not use QtXml / QDom |

Fixed in 6.11.2 and reachable before (SVG thumbnails of untrusted files go
through QtSvg, which parses with QXmlStreamReader): CVE-2026-6210 (SVG
marker heap overflow), CVE-2026-8168 (SVG recursion), CVE-2026-78253 and
CVE-2026-16762 (QXmlStreamReader), plus CVE-2026-76151 (QtNetwork, not
reached).

## Open items

* **Pillow floor of the wheel** - closed 2026-10-26: `Pillow>=13.0.0`, the first
  release free of the 41 advisories of 12.3.0. It needs Python >= 3.11, and
  Python 3.10 reached its end of life on 2026-10-01, so axross requires 3.11
  (`requires-python >=3.11`, CI on 3.11).
* **Qt 6.11.3** fixes the advisories above; none is reached by axross, and
  PyPI has no 6.11.3 wheel yet. Re-lock when it appears.
* The CI smoke job (`cross-platform.yml`, job `smoke`) and
  `python-app.yml` install `pip install .` unpinned on purpose: they test
  what a pip user gets. Nothing from them ships.

## Method of the 2026-10-26 round

* Builder image: `pip list` and `dnf updateinfo list --security` of the
  previous image (`axross-builder:alma9-glibc2.34`, 138 packages): PyQt6
  6.10.2, ctranslate2 4.8.3, setuptools 68.2.2 (seven OSV advisories), four
  unapplied Important / Critical rpm advisories.
* Every package pin and every pyproject floor queried against OSV
  (`api.osv.dev/v1/querybatch` and `/v1/query`), with a negative control
  (setuptools 68.2.2: flagged) and a malicious-package control
  (credential-sdk 0.0.2: flagged `MAL-2024-5000`).
* Qt: the Qt project's vulnerability list against the bundled Qt version and
  a grep of the tree for every affected module.
* GitHub Actions: release tags resolved to commit SHAs through the GitHub
  REST API (annotated tags dereferenced to their commit).

---

## Earlier audits

The sections below are the first audit and its round 2 (2026-04-27). Version
numbers in them are those of their date; the current pins are in
`build/requirements-bundle.txt`.

### Our own code (`core/`, `ui/`, `main.py`)

| Check | Result |
|---|---|
| `exec(` / `eval(` of user input | Clean. All hits are `re.compile`, Qt `.exec()` (menu / dialog), or `self._exec()` method names (SSH / Telnet / SCP remote shell). |
| Dynamic imports | One `__import__(import_probe)` in `core.backend_registry._check_available` — reviewed, checks a known string list; no user input. |
| Hardcoded credentials | None. All PW / key material goes through `core.credentials` (OS keyring). |
| Embedded base64 blobs | None over 60 characters. |
| Direct outbound HTTP / sockets | Zero `urllib.request.urlopen`, `requests.get`, `http.client.HTTPConnection`, `socket.connect` calls in our code. All network traffic is routed through auditable SDK libraries (paramiko, boto3, msal, google-auth, dropbox, etc.). |
| Suspicious URLs | None. All hardcoded URLs are Azure / Microsoft / Google / AWS / SharePoint official OAuth + API endpoints (documented in each backend's docstring). |
| Subprocess invocations | All targets are documented system tools: `rsync`, `iscsiadm`, `mount.nfs` / `umount`, `fusermount`, `jmtpfs` / `simple-mtpfs` / `go-mtpfs`, `cat` / `tee` (via `sudo` for iSCSI CHAP). No external-URL CLI calls. |

---

### Dependencies — provenance check

Every package from `.venv/bin/pip list` was checked for
author + homepage + version. All critical libs come from
canonical upstream maintainers:

| Package | Version | Maintainer | Status |
|---|---|---|---|
| paramiko | 4.0.0 | Jeff Forcier (bitprophet.org) | ✓ canonical |
| cryptography | 46.0.5 | Python Cryptographic Authority | ✓ canonical |
| boto3 / botocore | 1.42.68 | Amazon Web Services | ✓ canonical |
| smbprotocol | 1.16.0 | Jordan Borean (Ansible core dev) | ✓ canonical |
| defusedxml | 0.7.x | Christian Heimes (PSF) | ✓ canonical |
| msal | 1.35.1 | Microsoft Corporation | ✓ canonical |
| dropbox | 12.0.2 | Dropbox (dev-platform@dropbox.com) | ✓ canonical |
| py7zr | 1.1.0 | Hiroshi Miura | ✓ canonical |
| adb-shell | 0.4.4 | Jeff Irion (active maintainer) | ✓ canonical |
| PyQt6 | 6.10.2 | Riverbank Computing | ✓ canonical |
| requests / urllib3 | 2.32.5 / 2.6.3 | Python Software Foundation | ✓ canonical |
| keyring / SecretStorage | 25.7.0 / 3.5.0 | Jason R. Coombs | ✓ canonical |

Full list of 138 installed packages reviewed for typosquat
look-alikes (`ctx`, `phpass`, fake `colorama-3.0.1`, dashed
`urllib-3`, `requset`, etc.) — none present.

---

### Bundle exclusion invariants (verified)

`tests/test_packaging.py::PackagingImportPresenceTests` locks
the exclusion lists into regression tests. Current state
measured against the shipped ELFs:

#### Slim bundle (`dist/axross-slim`, 114 MB)

| Excluded package | Presence in bundle | Reason |
|---|---|---|
| `semgrep` | ✗ absent | Dev tool, 305 MB on its own |
| `bandit` | ✗ absent | Dev security scanner |
| `opentelemetry.*` (all submodules) | ✗ absent | Semgrep-only transitive |
| `googleapiclient` | ✗ absent | Cloud OAuth, full-only |
| `msal` | ✗ absent | OneDrive / SharePoint, full-only |
| `dropbox` | ✗ absent | Full-only |
| `azure.storage.*` | ✗ absent | Full-only |
| `exchangelib` | ✗ absent | Full-only |
| `winrm` (pywinrm) | ✗ absent | Full-only |
| `impacket` | ✗ absent | Full-only |

#### Full bundle (`dist/axross-full`, 132 MB)

The Azure SDK chain brings `opentelemetry.*` via
`azure.core.tracing.opentelemetry`. This is an **opt-in**
tracing hook — no telemetry is sent unless the operator
explicitly wires up an exporter. No `azure.core` code paths
we actually call (SAS-token / connection-string
auth) trigger the opentelemetry bridge.

---

### Known-exploited CVE review

Second-pass check against the critical libs at current
versions:

| Library | Version | Known-exploited CVE? |
|---|---|---|
| cryptography | 46.0.5 | None. Current branch addresses all known issues. |
| paramiko | 4.0.0 | None. |
| requests | 2.32.5 | None. 2.32.x addresses CVE-2024-35195 (session verification). |
| urllib3 | 2.6.3 | None. 2.x branch addresses all known issues. |
| lxml | 6.0.2 | None. |
| pycryptodomex | 3.23.0 | None. |
| pydantic | 2.13.2 | None. |

---

### Import-time side effects (second-pass)

Checked the top-level `__init__.py` of every directly-used
dep for network calls fired at import time. None found.
`paramiko`, `cryptography`, `boto3`, `msal`, `adb_shell`,
`smbprotocol`, `requests`, `defusedxml` all initialise cleanly
without phoning home.

### Post-install hooks

Every `setup.py` / `pyproject.toml` in `site-packages` was
checked for custom `cmdclass`, `entry_points` hooks that
run at install time, or unusual `scripts` entries. None
suspicious — standard console-script shims (pytest,
coverage, pyinstaller, etc.) only.

---

### Observations (informational, no security impact)

#### 1. `ruamel.yaml` in slim bundle (~1 MB over-include)

`ruamel.yaml` is pulled in by `semgrep` transitively. Our
slim bundle excludes `semgrep` itself but `ruamel.yaml`
landed in the bundle anyway (likely via
`PyInstaller.collect_submodules` picking up what pip
resolved into site-packages). No security impact — it's a
canonical YAML library. Future cleanup could add
`"ruamel.yaml"` to the slim excludes list to shed
another ~1 MB.

#### 2. `a1_coverage.pth` in dev venv

Python installs a `.pth` that runs
`coverage.process_startup()` when the
`COVERAGE_PROCESS_START` environment variable is set. Dev-
only; the shipped ELFs do NOT include this .pth file
(PyInstaller only bundles actual Python modules, not site-
init hooks). Informational — verify
`COVERAGE_PROCESS_START` is unset in the release
environment, as standard hygiene.

#### 3. PyQt6 bundle size

PyQt6 dominates every flavour at ~256 MB installed /
~110 MB compressed. This is Qt itself (C++ runtime + ~250
.so plugins covering X11, Wayland, SVG, imageformats,
platform themes, a11y). All plugins are canonical Qt
output from Riverbank Computing. No fork / injection.

---

### Assertions we DON'T make

Honest limits on this audit:

* We did NOT decompile or binary-diff any shipped `.so`.
  Provenance checks relied on the pip metadata + canonical
  homepage match. A compromised maintainer account on
  PyPI could in theory ship malicious code that our
  methodology wouldn't catch — `scripts/build_bundle.sh`
  could add `pip install --require-hashes` against a
  pinned `requirements.lock` to tighten this. (Done
  2026-10-26: `build/requirements-bundle.txt`, see above.
  Hashes prove the file is the one locked, not that the
  release is benign; the OSV malicious-package check and
  the lock review are the layers for that.)

* We did NOT reverse-engineer the Qt C++ libraries. Qt is
  an attack surface large enough that it demands its own
  audit; we took it as a trusted upstream.

* We did NOT fuzz the MCP HTTP server for protocol-level
  auth bypasses (past red-team passes did static review
  only — ff5ae9b, 5779d96, etc.).

### Reproduction

Every check here is re-runnable:

```bash
# Dep inventory
.venv/bin/pip list --format=freeze

# Typosquat check — compare against a known-malicious list
# (maintain at docs/MALICIOUS_PACKAGES.md or equivalent).

# Bundle content check — exclude invariants
QT_QPA_PLATFORM=offscreen .venv/bin/pytest tests/test_packaging.py

# Own-code dangerous-construct check
grep -rEn "exec\(|eval\(|compile\(.*[^r]['\"]" core/ ui/ main.py \
    | grep -vE "re\.compile|\.exec\(\)|_exec\("
```

### Round 2 (2026-04-27) — typo-squat audit after the API_GAPS expansion

After the API_GAPS rounds shipped (~25 new public methods + 8
generic helpers + 6 Tier-2 helpers, pulling in 6 additional pip
packages: dnspython / puremagic / chardet / ldap3 / ipwhois /
ntplib / pysnmp / manuf), a focused typo-squat re-audit:

#### Method

Scripted Python over ``importlib.metadata``: pull (Name, Author,
Maintainer, Project-URL, Homepage) for every top-level dep
declared in pyproject.toml + Dockerfile.build, then Levenshtein-1
scan every installed dist for one-character-off matches against
a known-popular allow-list (``requests`` / ``urllib3`` /
``paramiko`` / ``cryptography`` / ``redis`` / ``pymongo`` / …).

#### Findings

* **Three Levenshtein-1 hits**, all confirmed legitimate:
  * ``psycopg`` v3.3.3 by Daniele Varrazzo — psycopg's
    intentional v3 rename (drops the ``2`` suffix). Same author
    as psycopg2; not a squat.
  * ``psycopg-binary`` — matching binary build of psycopg v3.
  * ``pycryptodomex`` v3.23.0 by Helder Eijs —  pycryptodome's
    co-installable variant (lets it sit alongside the original
    ``pycrypto`` namespace). Same maintainer as pycryptodome.

* **One maintainer-handover note**: ``pysnmp`` v7.x is now
  published by LeXtudio Inc. (``Repository: github.com/lextudio/
  pysnmp``). The original maintainer Ilya Etingof died in 2022;
  LeXtudio (Lex Li, of SharpSnmp on the .NET side) took over
  publication of the official ``pysnmp`` PyPI name circa 2023-24.
  This is a **public, non-malicious transition** discussed in
  the upstream issue tracker, but it IS a maintainer change worth
  knowing about. Re-evaluated alternatives:

  * ``puresnmp`` — pure-Python, but only SNMPv1/v2c (we want
    v3 for our enterprise targets).
  * ``easysnmp`` — wraps net-snmp C lib (heavy + non-portable).
  * Sticking with ``pysnmp`` 7.x under LeXtudio's stewardship is
    the pragmatic call; we re-pin if a concrete concern appears.

* **Every other top-level dep traces to its original / official
  maintainer or vendor**: Riverbank for PyQt6, AWS for boto3,
  Microsoft for azure/msal, Google for google-api-*, Dropbox
  Inc. for dropbox, MongoDB Inc. for pymongo, Redis Inc. for
  redis-py, paramiko's Jeff Forcier, requests' Kenneth Reitz,
  defusedxml's Christian Heimes, dulwich's Jelmer Vernooij,
  dnspython's Bob Halley, ldap3's Giovanni Cannata,
  ipwhois' Philip Hane, ntplib's Charles-Francois Natali,
  manuf's Michael Huang — all match their upstream identities.

#### Conclusion

* No typo-squat hits in the installed dependency tree.
* One legitimate maintainer transition (pysnmp → LeXtudio)
  documented as known.
* Re-runnable via the snippet at the top of this file.
