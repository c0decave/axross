"""The Linux release build in CI: .github/workflows/cross-platform.yml, job
``linux``, runs scripts/build_dist.sh - the builder machine's script,
unchanged - and uploads its dist/<version>/ as the artifact
``axross-linux-dist``, which scripts/assemble_release.py takes from ``--ci``.
A release then needs no builder machine, only the maintainer's key, which
CI never sees (docs/PACKAGING.md, "Release flow").
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "cross-platform.yml"
BUILD_DIST = REPO / "scripts" / "build_dist.sh"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

import assemble_release as AR  # noqa: E402


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _job(name: str = "linux") -> dict:
    return _workflow()["jobs"][name]


def _runs(job: dict) -> list[str]:
    return [" ".join(step["run"].split()) for step in job["steps"] if "run" in step]


def _index(job: dict, predicate) -> int:
    hits = [i for i, step in enumerate(job["steps"]) if predicate(step)]
    assert hits, "no such step"
    return hits[0]


def _uploads(job: dict) -> list[dict]:
    return [s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]


def _build_step(job: dict) -> str:
    builds = [r for r in _runs(job) if "scripts/build_dist.sh" in r]
    assert len(builds) == 1, builds
    return builds[0]


def _out_dir(job: dict) -> str:
    match = re.search(r"--out (\S+)", _build_step(job))
    assert match, "the build names its output folder"
    return match.group(1)


# -- happy -----------------------------------------------------------------------------


def test_happy_the_linux_job_runs_on_tags_ci_branches_and_by_hand() -> None:
    workflow = _workflow()
    on = workflow.get("on", workflow.get(True))  # YAML 1.1 reads a bare `on` as True
    assert "v*" in on["push"]["tags"] and "ci/**" in on["push"]["branches"]
    assert "workflow_dispatch" in on
    job = _job()
    assert job["needs"] == "smoke"  # as the bundle job: only after the smoke tests
    condition = job["if"]
    assert "startsWith(github.ref, 'refs/tags/v')" in condition
    assert "startsWith(github.ref, 'refs/heads/ci/')" in condition
    # not on every push to main or pull request: the build takes hours
    assert "refs/heads/main" not in condition and "pull_request" not in condition


def test_happy_it_runs_build_dist_sh_unchanged_with_both_glibc_variants() -> None:
    """The same target systems as the builder: build_dist.sh's own
    defaults - AlmaLinux 9 (glibc 2.34) and Debian 12 (glibc 2.36), each
    built against only its own packages (build/sysroot/<system>.txt) - and
    every flavour, tool, the packs, wheel and sdist."""
    build = _build_step(_job())
    for option in ("--variants", "--flavors", "--only", "--standalone", "--lock-tools"):
        assert option not in build, option
    script = BUILD_DIST.read_text(encoding="utf-8")
    assert 'VARIANTS="almalinux9,debian12"' in script
    assert 'FLAVORS="base,slim,full"' in script
    assert 'STANDALONE="media-player,system-info"' in script
    assert "almalinux9) echo 2.34 ;; debian12) echo 2.36 ;;" in script
    for variant in ("almalinux9", "debian12"):
        assert (REPO / "build" / "sysroot" / f"{variant}.txt").is_file()
    # no other image or container builds the Linux release
    job = _job()
    assert "container" not in job
    assert not any(re.search(r"\b(docker|podman)\b", r) for r in _runs(job))
    assert job["runs-on"].startswith("ubuntu-")  # Debian-based: gpgv, dpkg-deb


def test_happy_it_keeps_the_supply_chain_gate() -> None:
    """build_dist.sh runs the gate before it builds anything, with no switch
    to skip it; the job adds no pip install of its own and fetches uv only
    against a pinned SHA-256."""
    script = BUILD_DIST.read_text(encoding="utf-8")
    assert script.index("gate check --report") < script.index("uv python install")
    assert "--no-gate" not in script and "SKIP_GATE" not in script
    job = _job()
    runs = _runs(job)
    assert not any("pip install" in r or "pip3 install" in r for r in runs)
    uv = next(r for r in runs if "astral-sh/uv/releases/download" in r)
    assert '$UV_SHA256 $RUNNER_TEMP/uv.tar.gz" | sha256sum --check --strict' in uv
    assert re.fullmatch(r"[0-9a-f]{64}", job["env"]["UV_SHA256"])
    assert re.fullmatch(r"\d+\.\d+\.\d+", job["env"]["UV_VERSION"])
    assert uv.index("sha256sum --check") < uv.index("tar -xzf")


def test_happy_it_uploads_the_dist_folder_as_axross_linux_dist() -> None:
    job = _job()
    release = [u for u in _uploads(job) if u["with"]["name"] == AR.CI_LINUX]
    assert len(release) == 1
    upload = release[0]
    assert "if" not in upload  # only a green build: a failed step stops before it
    assert upload["with"]["path"].rstrip("/") == _out_dir(job).rstrip("/")
    assert upload["with"]["if-no-files-found"] == "error"
    # after the build, the native components and the assemble check
    position = job["steps"].index(upload)
    for needle in ("scripts/build_dist.sh", "native_inventory.py", "--check",
                   "scripts/assemble_release.py"):
        assert _index(job, lambda s, n=needle: n in s.get("run", "")) < position, needle


def test_happy_the_artifact_carries_what_assemble_release_reads() -> None:
    """NATIVE-COMPONENTS.md (the release notes) is written into the uploaded
    folder; assemble_release.py runs on that folder in the job itself."""
    job = _job()
    out = _out_dir(job).rstrip("/")
    notes = next(r for r in _runs(job) if "--notes" in r)
    assert f"--notes {out}/NATIVE-COMPONENTS.md" in notes
    assert f"{out}/glibc-2.34/axross-full" in notes and f"{out}/glibc-2.34/axross-slim" in notes
    assemble = next(r for r in _runs(job) if "scripts/assemble_release.py" in r)
    assert f"--dist {out}" in assemble
    assert "--key" not in assemble and "--require-all" not in assemble
    # the regenerated THIRD_PARTY_LICENSES.md is a diagnostic of a failed check only
    others = [u for u in _uploads(job) if u["with"]["name"] != AR.CI_LINUX]
    assert others and all("failure()" in u["if"] for u in others)
    assert all(not u["with"]["name"].startswith(AR.CI_LINUX) for u in others)


def test_happy_the_host_check_runs_on_the_downloaded_artifact_and_uploads_nothing() -> None:
    """docs/PACKAGING.md step 6: the binaries against a current host - in a
    job of its own, as pytest and PyQt6 come from PyPI unpinned there."""
    job = _job("linux-host-check")
    assert job["needs"] == "linux"
    assert sorted(job["strategy"]["matrix"]["flavor"]) == ["base", "full", "slim"]
    download = [s for s in job["steps"] if s.get("uses", "").startswith(
        "actions/download-artifact@")]
    assert len(download) == 1 and download[0]["with"]["name"] == AR.CI_LINUX
    test = next(s for s in job["steps"] if "test_frozen_binary_host_e2e.py" in s.get("run", ""))
    assert test["env"]["AXROSS_FROZEN_BINARY"].endswith(
        "/glibc-2.34/axross-${{ matrix.flavor }}")
    assert "chmod +x" in test["run"]  # an artifact keeps no file mode
    assert not _uploads(job)


def test_happy_the_assembler_knows_the_artifact_name() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert f"name: {AR.CI_LINUX}\n" in text
    assert not AR._CI_ARTIFACT.fullmatch(AR.CI_LINUX)  # never taken for a bundle artifact


# -- sad: no secret, no key ------------------------------------------------------------


def test_sad_no_secret_and_no_release_key_anywhere_in_the_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    for needle in ("secrets.", "release-key", "release-identity-terms", "sign_release",
                   "--key", "SHA256SUMS.sig", "id-token", "PYPI", "TWINE", "GH_TOKEN",
                   "GITHUB_TOKEN"):
        assert needle not in text, needle
    assert _workflow()["permissions"] == {"contents": "read"}
    for name in ("linux", "linux-host-check"):
        job = _job(name)
        assert "permissions" not in job and "secrets" not in job, name
        checkout = next(s for s in job["steps"] if s.get("uses", "").startswith(
            "actions/checkout@"))
        assert checkout["with"]["persist-credentials"] is False, name


def test_sad_no_build_from_an_untrusted_ref() -> None:
    """A pull request (a fork's code) never reaches the build job."""
    condition = _job()["if"]
    assert "github.head_ref" not in condition and "pull_request" not in condition


def test_sad_every_action_is_pinned_to_a_commit() -> None:
    for name, job in _workflow()["jobs"].items():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]), \
                    (name, step["uses"])


# -- edge ------------------------------------------------------------------------------


def test_edge_the_work_folder_is_on_disk_and_the_job_fits_a_hosted_runner() -> None:
    """build_dist.sh's venvs, sysroots and PyInstaller scratch are many GB:
    on a disk folder, never a tmpfs; and within GitHub's 6 hours."""
    job = _job()
    assert '--work "$AXROSS_DIST_WORK"' in _build_step(job)
    assert any("AXROSS_DIST_WORK=" in r and "$GITHUB_ENV" in r for r in _runs(job))
    assert 60 < job["timeout-minutes"] <= 360


def test_edge_build_info_names_the_ci_run() -> None:
    script = BUILD_DIST.read_text(encoding="utf-8")
    assert '"${GITHUB_ACTIONS:-}" == "true"' in script
    assert "${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}" \
        in script


def test_edge_the_release_flow_documents_both_ways() -> None:
    text = (REPO / "docs" / "PACKAGING.md").read_text(encoding="utf-8")
    flow = text[text.index("## Release flow"):text.index("## Self-update: what a release")]
    assert AR.CI_LINUX in flow
    assert f'gh run download "$RUN" -n {AR.CI_LINUX} -D "dist/$VERSION"' in flow
    assert "scripts/build_dist.sh" in flow  # the builder machine stays an alternative


def test_happy_a_failed_build_leaves_its_last_lines_as_an_annotation() -> None:
    # the logs live where a sandboxed maintainer cannot reach them; the API's
    # annotations are what is left to see why a step stopped
    job = _job()
    logged = [s for s in job["steps"] if "build_dist.log" in s.get("run", "")
              and "ci_annotate" not in s.get("run", "")]
    assert len(logged) >= 4  # the build, both inventory steps, assemble_release
    for step in logged:
        assert "pipefail" in step["run"] and "tee" in step["run"], step["name"]
    last = _index(job, lambda s: "ci_annotate.py" in s.get("run", "")
                  and "build_dist.log" in s.get("run", ""))
    assert job["steps"][last].get("if") == "failure()"
    for step in logged:  # every logged step runs before the annotation
        assert job["steps"].index(step) < last


def test_happy_native_inventory_runs_with_the_bundle_venv_s_pyinstaller() -> None:
    # it reads the binaries with PyInstaller's archive reader; the runner's
    # python3 has no PyInstaller (the fourth CI build stopped there)
    runs = [r for r in _runs(_job()) if "native_inventory.py" in r]
    assert len(runs) == 3
    for run in runs:
        assert '"$AXROSS_DIST_WORK/venv/bin/python" -I scripts/native_inventory.py' in run
        assert "python3 -I scripts/native_inventory.py" not in run


def test_happy_a_drifted_licenses_file_is_shown_as_annotations() -> None:
    job = _job()
    write = _index(job, lambda s: "--write" in s.get("run", "") and "native_inventory" in s.get("run", ""))
    run = job["steps"][write]["run"]
    assert "git diff" in run and "ci_annotate.py" in run and "--head" in run


def test_happy_the_builder_has_debian_s_archive_keys() -> None:
    # sysroot_fetch.py verifies debian12's Release file with gpgv against
    # /usr/share/keyrings; an Ubuntu runner has none (the second CI build
    # stopped there: "no Debian archive keyring")
    runs = "\n".join(_runs(_job()))
    assert "debian-archive-keyring" in runs
    tools = _index(_job(), lambda s: "debian-archive-keyring" in s.get("run", ""))
    build = _index(_job(), lambda s: "build_dist.sh --out" in s.get("run", ""))
    assert tools < build
