#!/usr/bin/env python3
"""Check that a release names one version and one MCP server everywhere:
``check_mcp_release.py VERSION``.

The release tag (``vVERSION``), ``axross/_version.py``, ``server.json`` (the
entry in the official MCP registry: its version, the PyPI package's version
and the Docker image's tag) must agree, and the server's name must be the
one the registry checks on both packages - the ``mcp-name:`` line of the
axross-headless-mcp README (scripts/export_standalone.py) and the
``io.modelcontextprotocol.server.name`` label of Dockerfile.mcp. Exit 1 with
every disagreement named; .github/workflows/mcp-release.yml runs it before
anything is built or published, tests/test_mcp_release.py on every commit
(without VERSION: against axross/_version.py).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "io.github.c0decave/axross-headless-mcp"
PYPI_PACKAGE = "axross-headless-mcp"
IMAGE = "ghcr.io/c0decave/axross-headless-mcp"
REPOSITORY = "https://github.com/c0decave/axross-headless-mcp"
#: The registry schema server.json is written against (the publisher checks
#: it), and the registry's limit for the description.
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
MAX_DESCRIPTION = 100


def _label_instructions(dockerfile: str) -> list[str]:
    """The LABEL instructions of *dockerfile*, continuation lines joined and
    comments left out (a commented-out LABEL is no label)."""
    lines = [line for line in dockerfile.splitlines() if not line.lstrip().startswith("#")]
    joined = re.sub(r"\\\s*\n", " ", "\n".join(lines))
    return [line.strip() for line in joined.splitlines()
            if re.match(r"\s*LABEL\s", line, re.IGNORECASE)]


def source_version(root: Path = ROOT) -> str:
    text = (root / "axross" / "_version.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    if not match:
        raise SystemExit("no __version__ in axross/_version.py")
    return match.group(1)


def problems(version: str, root: Path = ROOT) -> list[str]:
    """Every way the release files disagree with *version* and the name."""
    out: list[str] = []
    if source_version(root) != version:
        out.append(f"axross/_version.py says {source_version(root)}, the release is {version}")
    try:
        server = json.loads((root / "server.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return out + [f"server.json is not readable JSON: {exc}"]
    if not isinstance(server, dict):
        return out + ["server.json is not a JSON object"]
    if server.get("$schema") != SCHEMA:
        out.append(f"server.json's $schema is {server.get('$schema')!r}, not {SCHEMA!r}")
    description = server.get("description")
    if not isinstance(description, str) or not description.strip() \
            or len(description) > MAX_DESCRIPTION:
        out.append(f"server.json needs a description of 1 to {MAX_DESCRIPTION} characters")
    # The registry entry links the project's own repository (where the
    # package and image are built), not axross's.
    repository = server.get("repository")
    if not isinstance(repository, dict) or repository.get("url") != REPOSITORY \
            or repository.get("source") != "github":
        out.append(f"server.json's repository must be {{\"url\": \"{REPOSITORY}\", "
                   "\"source\": \"github\"}")
    # The server's own serverInfo.websiteUrl says the same.
    try:
        source = (root / "core" / "mcp_server.py").read_text(encoding="utf-8")
    except OSError:
        source = ""
    website = re.findall(r'^SERVER_WEBSITE = "([^"]*)"', source, re.MULTILINE)
    if website != [server.get("websiteUrl")]:
        out.append(f"core/mcp_server.py's SERVER_WEBSITE is {website}, server.json's "
                   f"websiteUrl {server.get('websiteUrl')!r}: they must agree")
    if server.get("websiteUrl") != REPOSITORY:
        out.append(f"server.json's websiteUrl is {server.get('websiteUrl')!r}, not "
                   f"{REPOSITORY!r}")
    if server.get("name") != SERVER_NAME:
        out.append(f"server.json name is {server.get('name')!r}, not {SERVER_NAME!r}")
    if server.get("version") != version:
        out.append(f"server.json version is {server.get('version')!r}, not {version!r}")
    packages = server.get("packages")
    if not isinstance(packages, list):
        packages = []
        out.append("server.json has no packages list")
    pypi = [p for p in packages if isinstance(p, dict) and p.get("registryType") == "pypi"]
    oci = [p for p in packages if isinstance(p, dict) and p.get("registryType") == "oci"]
    if len(pypi) != 1 or len(oci) != 1 or len(packages) != 2:
        out.append(f"server.json must list exactly one pypi and one oci package "
                   f"(has {len(pypi)} pypi, {len(oci)} oci, {len(packages)} in all)")
    for package in pypi[:1]:
        if package.get("identifier") != PYPI_PACKAGE:
            out.append(f"server.json's pypi package is {package.get('identifier')!r}, "
                       f"not {PYPI_PACKAGE!r}")
        if package.get("version") != version:
            out.append(f"server.json's pypi package is version {package.get('version')!r}, "
                       f"not {version!r}")
        if package.get("registryBaseUrl") != "https://pypi.org":
            out.append("server.json's pypi package must name registryBaseUrl https://pypi.org")
    for package in oci[:1]:
        if package.get("identifier") != f"{IMAGE}:{version}":
            out.append(f"server.json's oci package is {package.get('identifier')!r}, "
                       f"not '{IMAGE}:{version}'")
    for package in pypi[:1] + oci[:1]:
        if package.get("transport") != {"type": "stdio"}:
            out.append(f"server.json's {package.get('registryType')} package must have "
                       "transport {\"type\": \"stdio\"}")
    # The markers, as the registry reads them: the label's exact value and
    # the README line's exact name - not a substring of something else.
    dockerfile = (root / "Dockerfile.mcp").read_text(encoding="utf-8")
    labels = [value for instruction in _label_instructions(dockerfile)
              for value in re.findall(r'io\.modelcontextprotocol\.server\.name="([^"]*)"',
                                      instruction)]
    if labels != [SERVER_NAME]:
        out.append(f"Dockerfile.mcp must carry exactly one LABEL io.modelcontextprotocol."
                   f'server.name="{SERVER_NAME}" (has {labels})')
    exporter = (root / "scripts" / "export_standalone.py").read_text(encoding="utf-8")
    markers = re.findall(r"<!-- mcp-name: (\S+) -->", exporter)
    if markers != [SERVER_NAME]:
        out.append(f"the axross-headless-mcp README (scripts/export_standalone.py) must carry "
                   f"exactly '<!-- mcp-name: {SERVER_NAME} -->' (has {markers})")
    return out


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    version = args[0] if args else source_version()
    found = problems(version)
    for problem in found:
        print(f"check_mcp_release: {problem}", file=sys.stderr)
    if not found:
        print(f"MCP release {version}: tag, axross/_version.py, server.json, "
              "Dockerfile.mcp and the axross-headless-mcp README agree")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
