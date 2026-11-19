"""Every release ships the headless MCP server too: the PyPI package
axross-headless-mcp, the image ghcr.io/c0decave/axross-headless-mcp and the entry
io.github.c0decave/axross-headless-mcp in the official MCP registry (server.json).

Held here: server.json names this version (its own, the PyPI package's
and the image tag) - a version bump that forgets it fails at once, not on
the release tag; the registry's ownership markers are where it looks (the
axross-headless-mcp README's ``mcp-name:`` line, the image's
``io.modelcontextprotocol.server.name`` label); the release workflow builds
and pushes the image with its own GITHUB_TOKEN and publishes through
GitHub OIDC, with nothing but its token and a pinned, checksummed
mcp-publisher; and the CI job that runs the MCP path without PyQt6.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_mcp_release",
                                               ROOT / "scripts" / "check_mcp_release.py")
CHECK = importlib.util.module_from_spec(_spec)
sys.modules["check_mcp_release"] = CHECK
_spec.loader.exec_module(CHECK)

SERVER = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
RELEASE = yaml.safe_load((ROOT / ".github" / "workflows" / "mcp-release.yml").read_text(
    encoding="utf-8"))
RELEASE_TEXT = (ROOT / ".github" / "workflows" / "mcp-release.yml").read_text(encoding="utf-8")
APP = yaml.safe_load((ROOT / ".github" / "workflows" / "python-app.yml").read_text(
    encoding="utf-8"))


def _runs(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


# --- server.json --------------------------------------------------------------------


def test_happy_server_json_names_this_release():
    from axross._version import __version__

    assert CHECK.problems(__version__) == []
    assert SERVER["version"] == __version__
    packages = {p["registryType"]: p for p in SERVER["packages"]}
    assert packages["pypi"]["version"] == __version__
    assert packages["oci"]["identifier"] == f"ghcr.io/c0decave/axross-headless-mcp:{__version__}"


def test_happy_server_json_has_what_the_registry_demands():
    assert SERVER["$schema"].startswith("https://static.modelcontextprotocol.io/schemas/")
    assert SERVER["name"] == "io.github.c0decave/axross-headless-mcp"
    assert re.fullmatch(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+", SERVER["name"])
    assert 1 <= len(SERVER["description"]) <= 100  # the schema's maxLength
    for package in SERVER["packages"]:
        assert package["transport"] == {"type": "stdio"}
    pypi = next(p for p in SERVER["packages"] if p["registryType"] == "pypi")
    assert pypi["identifier"] == "axross-headless-mcp" and pypi["registryBaseUrl"] == "https://pypi.org"
    # The OCI entry starts the stdio server rooted at the mounted folder.
    oci = next(p for p in SERVER["packages"] if p["registryType"] == "oci")
    assert [a.get("value") for a in oci["packageArguments"]] == ["--mcp-server", "/data"]


def test_happy_the_ownership_markers_name_the_server():
    dockerfile = (ROOT / "Dockerfile.mcp").read_text(encoding="utf-8")
    assert f'LABEL io.modelcontextprotocol.server.name="{SERVER["name"]}"' in dockerfile
    exporter = (ROOT / "scripts" / "export_standalone.py").read_text(encoding="utf-8")
    assert f'readme_marker="<!-- mcp-name: {SERVER["name"]} -->"' in exporter


def test_sad_a_version_bump_without_server_json_is_named(tmp_path):
    for rel in ("server.json", "Dockerfile.mcp", "scripts/export_standalone.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "axross").mkdir()
    (tmp_path / "axross" / "_version.py").write_text('__version__ = "9.9.9"\n')
    found = CHECK.problems("9.9.9", tmp_path)
    assert any("server.json version" in p for p in found)
    assert any("pypi package is version" in p for p in found)
    assert any("oci package" in p for p in found)
    assert CHECK.main(["0.0.1"]) == 1


# --- the release workflow -----------------------------------------------------------


def test_happy_the_release_runs_on_version_tags_and_checks_the_version_first():
    assert RELEASE[True]["push"]["tags"] == ["v*.*.*"]  # yaml reads "on" as True
    assert "scripts/check_mcp_release.py" in _runs(RELEASE["jobs"]["check"])
    assert RELEASE["jobs"]["image"]["needs"] == "check"
    assert set(RELEASE["jobs"]["registry"]["needs"]) == {"check", "image"}


def test_happy_the_image_is_pushed_with_the_workflows_own_token():
    image = RELEASE["jobs"]["image"]
    assert image["permissions"] == {"contents": "read", "packages": "write"}
    runs = _runs(image)
    assert "docker build -f Dockerfile.mcp" in runs
    assert '"$IMAGE:$VERSION"' in runs and '"$IMAGE:latest"' in runs
    assert image["env"]["IMAGE"] == "ghcr.io/c0decave/axross-headless-mcp"
    assert "--password-stdin" in runs
    assert "secrets.GITHUB_TOKEN" in json.dumps(image)
    # Smoke before push: label, initialize + tools/list, no PyQt6.
    assert runs.index("io.modelcontextprotocol.server.name") < runs.index("docker push")


def test_happy_the_registry_entry_goes_out_through_oidc_with_a_pinned_publisher():
    registry = RELEASE["jobs"]["registry"]
    assert registry["permissions"] == {"contents": "read", "id-token": "write"}
    runs = _runs(registry)
    assert "./mcp-publisher login github-oidc" in runs
    assert "./mcp-publisher publish server.json" in runs
    assert "sha256sum -c" in runs
    assert re.fullmatch(r"\d+\.\d+\.\d+", registry["env"]["PUBLISHER_VERSION"])
    assert re.fullmatch(r"[0-9a-f]{64}", registry["env"]["PUBLISHER_SHA256"])
    assert "releases/latest" not in runs  # pinned, never "whatever is newest"
    assert "pypi.org/pypi/axross-headless-mcp/$VERSION/json" in runs


def test_sad_no_stored_secret_but_the_workflows_own_token():
    secrets = set(re.findall(r"secrets\.([A-Za-z_]+)", RELEASE_TEXT))
    assert secrets == {"GITHUB_TOKEN"}
    assert RELEASE["permissions"] == {"contents": "read"}
    # Only the image job may write packages, only the registry job mint an OIDC token.
    for name, job in RELEASE["jobs"].items():
        perms = job.get("permissions", {})
        assert ("packages" in perms) == (name == "image")
        assert ("id-token" in perms) == (name == "registry")


# --- the CI job without Qt ----------------------------------------------------------


def test_happy_ci_runs_the_mcp_path_where_pyqt6_does_not_exist():
    job = APP["jobs"]["mcp-headless"]
    runs = _runs(job)
    assert "python scripts/export_standalone.py mcp" in runs
    assert "find_spec('PyQt6') is not None" in runs
    assert "tests/test_mcp_without_qt.py" in runs
    assert "twine check --strict" in runs
    assert "PyQt6" not in (ROOT / "dev-requirements.txt").read_text(encoding="utf-8")
