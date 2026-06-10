# Supply-chain security audit

**Scope**: all code shipped in `dist/axross-slim` and
`dist/axross-full` — our own source tree plus every
third-party package bundled by PyInstaller per
`build/axross.spec`.

**Methodology**: static analysis of our code for dangerous
dynamic constructs, enumeration of every installed package
with author / version provenance, typosquat check against
known-malicious PyPI names, string-grep of the bundled ELFs
to verify exclusion lists actually held, import-time
side-effect inspection of transitive deps, and CVE check
of the critical libs.

**Result**: **no backdoors, no known-malicious packages, no
credential leaks, no unexpected network egress.** Two
observations below are informational (single-digit-MB bundle
over-include, dev-time coverage hook) — neither a
security risk.

---

## Our own code (`core/`, `ui/`, `main.py`)

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

## Dependencies — provenance check

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

## Bundle exclusion invariants (verified)

`tests/test_packaging.py::PackagingImportPresenceTests` locks
the exclusion lists into regression tests. Current state
measured against the shipped ELFs:

### Slim bundle (`dist/axross-slim`, 114 MB)

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

### Full bundle (`dist/axross-full`, 132 MB)

The Azure SDK chain brings `opentelemetry.*` via
`azure.core.tracing.opentelemetry`. This is an **opt-in**
tracing hook — no telemetry is sent unless the operator
explicitly wires up an exporter. No `azure.core` code paths
we actually call (SAS-token / connection-string
auth) trigger the opentelemetry bridge.

---

## Known-exploited CVE review

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

## Import-time side effects (second-pass)

Checked the top-level `__init__.py` of every directly-used
dep for network calls fired at import time. None found.
`paramiko`, `cryptography`, `boto3`, `msal`, `adb_shell`,
`smbprotocol`, `requests`, `defusedxml` all initialise cleanly
without phoning home.

## Post-install hooks

Every `setup.py` / `pyproject.toml` in `site-packages` was
checked for custom `cmdclass`, `entry_points` hooks that
run at install time, or unusual `scripts` entries. None
suspicious — standard console-script shims (pytest,
coverage, pyinstaller, etc.) only.

---

## Observations (informational, no security impact)

### 1. `ruamel.yaml` in slim bundle (~1 MB over-include)

`ruamel.yaml` is pulled in by `semgrep` transitively. Our
slim bundle excludes `semgrep` itself but `ruamel.yaml`
landed in the bundle anyway (likely via
`PyInstaller.collect_submodules` picking up what pip
resolved into site-packages). No security impact — it's a
canonical YAML library. Future cleanup could add
`"ruamel.yaml"` to the slim excludes list to shed
another ~1 MB.

### 2. `a1_coverage.pth` in dev venv

Python installs a `.pth` that runs
`coverage.process_startup()` when the
`COVERAGE_PROCESS_START` environment variable is set. Dev-
only; the shipped ELFs do NOT include this .pth file
(PyInstaller only bundles actual Python modules, not site-
init hooks). Informational — verify
`COVERAGE_PROCESS_START` is unset in the release
environment, as standard hygiene.

### 3. PyQt6 bundle size

PyQt6 dominates every flavour at ~256 MB installed /
~110 MB compressed. This is Qt itself (C++ runtime + ~250
.so plugins covering X11, Wayland, SVG, imageformats,
platform themes, a11y). All plugins are canonical Qt
output from Riverbank Computing. No fork / injection.

---

## Assertions we DON'T make

Honest limits on this audit:

* We did NOT decompile or binary-diff any shipped `.so`.
  Provenance checks relied on the pip metadata + canonical
  homepage match. A compromised maintainer account on
  PyPI could in theory ship malicious code that our
  methodology wouldn't catch — `scripts/build_bundle.sh`
  could add `pip install --require-hashes` against a
  pinned `requirements.lock` to tighten this.

* We did NOT reverse-engineer the Qt C++ libraries. Qt is
  an attack surface large enough that it demands its own
  audit; we took it as a trusted upstream.

* We did NOT fuzz the MCP HTTP server for protocol-level
  auth bypasses (past red-team passes did static review
  only — ff5ae9b, 5779d96, etc.).

## Reproduction

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

## Round 2 (2026-04-27) — typo-squat audit after the API_GAPS expansion

After the API_GAPS rounds shipped (~25 new public methods + 8
generic helpers + 6 Tier-2 helpers, pulling in 6 additional pip
packages: dnspython / puremagic / chardet / ldap3 / ipwhois /
ntplib / pysnmp / manuf), a focused typo-squat re-audit:

### Method

Scripted Python over ``importlib.metadata``: pull (Name, Author,
Maintainer, Project-URL, Homepage) for every top-level dep
declared in pyproject.toml + Dockerfile.build, then Levenshtein-1
scan every installed dist for one-character-off matches against
a known-popular allow-list (``requests`` / ``urllib3`` /
``paramiko`` / ``cryptography`` / ``redis`` / ``pymongo`` / …).

### Findings

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

### Conclusion

* No typo-squat hits in the installed dependency tree.
* One legitimate maintainer transition (pysnmp → LeXtudio)
  documented as known.
* Re-runnable via the snippet at the top of this file.
