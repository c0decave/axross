#!/usr/bin/env python3
"""Write the supply-chain gate as a project of its own: ``export_supply_chain_gate.py OUT_DIR``.

axross keeps its copy in security/ and runs it in every dist build
(docs/SUPPLY_CHAIN_GATE.md). This writes the same code as a standalone,
installable project that checks any Python project's hash-pinned locks:

    OUT_DIR/
      pyproject.toml          supply-chain-gate, standard library only, CLI supply-chain-gate
      README.md               what it checks, quick start, settings, the review workflow
      LICENSE                 Apache-2.0, as axross
      supply-chain-gate.example.toml
      requirements-scan-tools.in / .txt   the scanners' venv (GuardDog's rules, YARA, capa,
                                          pypi-attestations), hash-pinned
      src/supply_chain_gate/  the gate, the scanner, the archive inspector, the lock reader,
                              the top-packages list, the pinned capa rules and signatures,
                              the YARA rules
      tests/                  the gate's generic tests

Nothing of axross's own review (its baselines, its locks) is copied: a new
project starts with an empty baseline and reviews its own pins. The code is
the same; only imports, environment variable names (AXROSS_* ->
SUPPLY_CHAIN_GATE_*) and the user agent are rewritten, each rewrite checked
to apply, so a change in security/ that breaks the export fails its test
(tests/test_export_supply_chain_gate.py).
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "supply_chain_gate"
VERSION = "0.1.0"

#: file in OUT_DIR -> its source in axross
MODULES = {
    "supply_chain_gate.py": "security/supply_chain_gate.py",
    "supply_chain_scan.py": "security/supply_chain_scan.py",
    "package_inspect.py": "security/package_inspect.py",
    "dep_floor_audit.py": "security/dep_floor_audit.py",
}
DATA = {
    "top_pypi_packages.txt": "security/top_pypi_packages.txt",
    "capa-rules.txt": "build/capa-rules.txt",
    "capa-sigs.txt": "build/capa-sigs.txt",
}
TOP_FILES = {
    "LICENSE": "LICENSE",
    "requirements-scan-tools.in": "build/requirements-scan-tools.in",
    "requirements-scan-tools.txt": "build/requirements-scan-tools.txt",
}
TESTS = {"test_supply_chain_gate.py": "tests/test_supply_chain_gate.py"}

_IMPORTS = [("from security import ", f"from {PACKAGE} import "),
            ("from security.dep_floor_audit import", f"from {PACKAGE}.dep_floor_audit import")]
#: (old, new, required): each required rewrite must apply at least once.
REWRITES: dict[str, list[tuple[str, str, bool]]] = {
    "supply_chain_gate.py": [
        *[(o, n, True) for o, n in _IMPORTS],
        ("AXROSS_SUPPLY_CHAIN_CACHE", "SUPPLY_CHAIN_GATE_CACHE", True),
        ('USER_AGENT = "axross-supply-chain-gate/1"', 'USER_AGENT = "supply-chain-gate/1"', True),
        ("REQUIRE_CONFIG = False", "REQUIRE_CONFIG = True", True),
        ("no dependency reaches an axross dist unless", "no dependency reaches a dist unless", True),
    ],
    "supply_chain_scan.py": [
        (_IMPORTS[0][0], _IMPORTS[0][1], True),
        ("AXROSS_CAPA_", "SUPPLY_CHAIN_GATE_CAPA_", True),
        ("AXROSS_SCAN_WORKERS", "SUPPLY_CHAIN_GATE_SCAN_WORKERS", True),
        ('"axross_" + namespace', '"own_" + namespace', True),
        ('namespace.startswith("axross")', 'namespace.startswith("own_")', True),
    ],
    "package_inspect.py": [],
    "dep_floor_audit.py": [],
    "test_supply_chain_gate.py": [
        *[(o, n, True) for o, n in _IMPORTS],
        ("sys.path.insert(0, str(ROOT))", 'sys.path.insert(0, str(ROOT / "src"))', True),
        ("AXROSS_TEST_SCAN_PYTHON", "SUPPLY_CHAIN_GATE_TEST_SCAN_PYTHON", True),
        ("AXROSS_SUPPLY_CHAIN_CACHE", "SUPPLY_CHAIN_GATE_CACHE", True),
    ],
}
#: what must not be left in an exported Python file
LEFTOVERS = re.compile(r"\bfrom security\b|\bimport security\b|\bAXROSS_[A-Z_]+")

PYPROJECT = f'''[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[project]
name = "supply-chain-gate"
version = "{VERSION}"
description = "Reviewed baselines for every pinned dependency: PyPI, OSV, minimum age, provenance, typosquatting, content, YARA, capa"
readme = "README.md"
license = {{text = "Apache-2.0"}}
requires-python = ">=3.11"
dependencies = []          # the gate is standard library only; the scanners run in a venv of their own

[project.scripts]
supply-chain-gate = "{PACKAGE}.supply_chain_gate:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
{PACKAGE} = ["*.txt", "yara_rules/*.yar"]
'''

EXAMPLE_CONFIG = '''# supply-chain-gate.toml - put it in the project's root (the gate reads ./supply-chain-gate.toml,
# or the file named with --config). Paths are relative to this file.

root = "."
# The hash-pinned locks the project installs from (pip-compile / uv pip compile --generate-hashes).
locks = ["requirements.txt"]
# The scanners' own lock (copied from this project's requirements-scan-tools.txt): checked too.
scanner_lock = "requirements-scan-tools.txt"
# Files that must not configure another package index (dependency confusion).
index_config = ["pyproject.toml"]
# The reviewed baseline, one JSON file per package - commit it.
baseline_dir = "supply_chain_baseline"
# Downloaded archives, by SHA-256 (SUPPLY_CHAIN_GATE_CACHE overrides it).
cache_dir = ".supply-chain-cache"
# Reviewed security fixes younger than min_age_days: "NAME VERSION REASON" per line.
young_exceptions = "young-release-exceptions.txt"
min_age_days = 14
user_agent = "my-project-supply-chain-gate/1"
'''

README_HEAD = '''# supply-chain-gate

No dependency reaches your build unless it was reviewed and nothing about it changed since.
The gate checks every pin of your hash-pinned locks against PyPI, OSV, a minimum age, PEP 740
provenance, a typosquatting list, the content of the files themselves (nothing is executed),
YARA rules for malicious packages and capa on native binaries - and against a **baseline**
you commit: one JSON file per package with every reviewed version, who reviewed it and why
its findings are acceptable. Anything new fails until it is reviewed.

It was written for [axross](https://github.com/c0decave/axross), which runs it before every
release build; this is the same code as a project of its own.

## Quick start

```sh
pip install .                                   # the gate: standard library only
cp supply-chain-gate.example.toml /path/to/project/supply-chain-gate.toml   # and edit it
cp requirements-scan-tools.txt /path/to/project/

# the scanners, in a venv of their own (Python 3.12), from their hash-pinned lock
python3.12 -m venv scan-venv
scan-venv/bin/pip install --require-hashes --only-binary=:all: -r requirements-scan-tools.txt

cd /path/to/project
supply-chain-gate status                        # which pins have no reviewed baseline
supply-chain-gate survey survey/ --scan-python ../scan-venv/bin/python
#   read survey/NAME==VERSION.todo.json: every finding, YARA hit, native binary, attestation;
#   write verdicts.json: {"NAME==VERSION": "what was checked and why it is acceptable", ...}
supply-chain-gate accept-survey survey/ verdicts.json --by YOUR-NAME
supply-chain-gate check                         # standard-library stage (PyPI, OSV, age, names)
supply-chain-gate check --scan-python ../scan-venv/bin/python --report report/   # the full gate
```

In CI or a release script: run `check` (and `check --scan-python`) before installing anything,
and stop on a non-zero exit (0 clean, 1 a problem, 2 the gate could not run).
`verify-env --python VENV/bin/python --lock LOCK` checks an installed venv against its lock.

## Commands

| Command | What |
|---|---|
| `check [--scan-python PY] [--report DIR]` | the gate over every pin |
| `status` | which pins are not (or no longer) reviewed |
| `review NAME==VERSION --scan-python PY` | everything about one pin, the source diff against the reviewed version |
| `accept NAME==VERSION --by WHO --note TEXT --scan-python PY` | write one baseline entry |
| `survey DIR --scan-python PY`, `accept-survey DIR VERDICTS.json --by WHO` | many pins at once |
| `deep-scan --scan-python PY [--budget-minutes N]` | capa on every binary without a size limit (night runs) |
| `accept-deep NAME==VERSION MEMBER --by WHO --note TEXT` | accept a deep-scan alarm |
| `verify-env --python PY --lock LOCK ...` | an installed venv is exactly its locks |
| `check-system PACKAGES.json [--accept]` | Debian / AlmaLinux packages (OSV), for builds that bundle them |
| `top-packages` | refresh the typosquatting reference (hugovk/top-pypi-packages) |

## Settings

`supply-chain-gate.toml` (see `supply-chain-gate.example.toml`): `root`, `locks`, `scanner_lock`,
`index_config`, `baseline_dir`, `cache_dir`, `young_exceptions`, `build_from_source`,
`min_age_days`, `user_agent`, `capa_rules`, `capa_sigs`, `top_packages` (the last three default to
the pinned files shipped with the gate). Environment: `SUPPLY_CHAIN_GATE_CACHE` (download cache),
`SUPPLY_CHAIN_GATE_SCAN_WORKERS`, `SUPPLY_CHAIN_GATE_CAPA_WORKERS`, `SUPPLY_CHAIN_GATE_CAPA_MAX_MB`,
`SUPPLY_CHAIN_GATE_CAPA_MEMORY_MB`.

Network: pypi.org and files.pythonhosted.org, api.osv.dev, github.com (the pinned capa rules and
signatures, once). Without OSV the gate fails closed.

'''

README_TAIL = '''
## Tests

```sh
python -m pytest tests            # offline: crafted malicious archives, a fake PyPI and OSV
SUPPLY_CHAIN_GATE_TEST_SCAN_PYTHON=scan-venv/bin/python python -m pytest tests   # with the real scanners
```

## Licence

Apache-2.0, as axross.
'''


def _section(doc: str, heading: str) -> str:
    start = doc.index(f"## {heading}")
    end = doc.find("\n## ", start + 3)
    return doc[start:end if end != -1 else len(doc)].rstrip() + "\n"


def rewrite(name: str, text: str) -> str:
    for old, new, required in REWRITES.get(name, []):
        if required and old not in text:
            raise SystemExit(f"export: {name} no longer contains {old!r} - update REWRITES")
        text = text.replace(old, new)
    left = sorted(set(LEFTOVERS.findall(text)))
    if left:
        raise SystemExit(f"export: {name} still refers to axross: {', '.join(left)}")
    return text


def export(out: Path) -> Path:
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"export: {out} is not empty")
    pkg = out / "src" / PACKAGE
    (pkg / "yara_rules").mkdir(parents=True)
    (out / "tests").mkdir()
    for name, src in MODULES.items():
        (pkg / name).write_text(rewrite(name, (ROOT / src).read_text(encoding="utf-8")), encoding="utf-8")
    for name, src in DATA.items():
        shutil.copyfile(ROOT / src, pkg / name)
    for rule in sorted((ROOT / "security" / "yara_rules").glob("*.yar")):
        shutil.copyfile(rule, pkg / "yara_rules" / rule.name)
    (pkg / "__init__.py").write_text('"""The supply-chain gate (see README.md)."""\n', encoding="utf-8")
    (pkg / "__main__.py").write_text(
        f"import sys\n\nfrom {PACKAGE}.supply_chain_gate import main\n\nsys.exit(main())\n", encoding="utf-8")
    for name, src in TOP_FILES.items():
        shutil.copyfile(ROOT / src, out / name)
    for name, src in TESTS.items():
        (out / "tests" / name).write_text(rewrite(name, (ROOT / src).read_text(encoding="utf-8")), encoding="utf-8")
    (out / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (out / "supply-chain-gate.example.toml").write_text(EXAMPLE_CONFIG, encoding="utf-8")
    doc = (ROOT / "docs" / "SUPPLY_CHAIN_GATE.md").read_text(encoding="utf-8")
    method = _section(doc, "What a pin has to pass")
    for old, new in (("build/young-release-exceptions.txt", "the young-release exceptions file"),
                     ("`build/capa-", "`src/supply_chain_gate/capa-"), ("`security/", "`src/supply_chain_gate/"),
                     ("(`security/", "(`src/supply_chain_gate/"), ("axross's own", "the gate's own")):
        method = method.replace(old, new)
    (out / "README.md").write_text(README_HEAD + method + README_TAIL, encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", type=Path, help="an empty or new folder")
    args = ap.parse_args(argv)
    out = export(args.out)
    print(f"supply-chain-gate written to {out}: cd {out} && python -m pytest tests && pip install .")
    return 0


if __name__ == "__main__":
    sys.exit(main())
