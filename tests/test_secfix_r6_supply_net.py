"""Round-6 security, supply chain and network servers:

* L1 - a self-update checked the packs it carries along against one
  SHA256SUMS and the new binary against another one fetched later: the two
  may name different pack-manifest issues (an earlier signed issue served
  to the pack check). The binary's signed SHA256SUMS must now name the
  issue the carried packs were checked against.
* L3 - the MCP HTTP server's per-IP rate cap ran before the bearer check,
  so unauthenticated requests from 127.0.0.1 (any local user, a web page's
  <img>) used up the token holder's budget. The token is checked first;
  requests without it draw from a small budget of their own.
* L4 - one file name with a control character or bytes that are not UTF-8
  made the reverse-WebDAV PROPFIND / HTML index and the reverse-S3 listing
  malformed or dropped the connection, for every client.
* L5 - a planted mcp-discover ``crossref.json`` turned a listed server into
  an install of any registry package: a cached verdict now has to name the
  entry's own repository (or a Docker Hub image of its name).
* L6 - ``cargo install``, ``go install``, ``mvn exec:java`` were taken as
  commands that run as they are; they fetch and run code.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import sys
import threading
import time
import xml.dom.minidom
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import self_update as SU  # noqa: E402
from test_packs_at_once_and_reissue import _reissue, release  # noqa: E402, F401 - a fixture

# -- L1: the carried packs' issue and the binary's SHA256SUMS -------------------------

BINARY = b"the new axross binary"


def _sums(issue: int, version: str = "9.9.9") -> bytes:
    return (f"{SU.RELEASE_LINE_PREFIX}{version}\n# axross-packs-issue {issue}\n"
            f"{hashlib.sha256(BINARY).hexdigest()}  axross-base\n").encode()


def _update_with(monkeypatch, tmp_path, carried_issue, signed_issue):
    exe = tmp_path / "axross"
    exe.write_bytes(b"old")
    exe.chmod(0o755)
    inst = SU.Install(frozen=True, flavor="base", asset="axross-base", executable=exe,
                      platform="linux", machine="x86_64")
    url = "https://github.com/c0decave/axross/releases/download/v9.9.9/axross-base"
    rel = SU.Release("9.9.9", "v9.9.9", "", "", (SU.Asset("axross-base", url, len(BINARY)),))
    fetched = []

    def fake_fetch(u, *, sink=None, **kw):
        fetched.append(u)
        if sink is not None:
            sink(BINARY)
        return len(BINARY)

    monkeypatch.setattr(SU, "_carry_packs",
                        lambda *a, **k: SU.CarriedPacks(["x.whl"], [], carried_issue))
    monkeypatch.setattr(SU, "_signed_sums", lambda release, opener: _sums(signed_issue))
    monkeypatch.setattr(SU, "fetch", fake_fetch)
    result = SU.update(rel, inst, opener=object(), current="9.9.8")
    return result, fetched, exe


def test_sad_binary_sums_naming_another_packs_issue_refuse_the_update(monkeypatch, tmp_path):
    with pytest.raises(SU.SignatureError, match="issue 0.*issue 1|changed during the update"):
        _update_with(monkeypatch, tmp_path, carried_issue=0, signed_issue=1)
    assert (tmp_path / "axross").read_bytes() == b"old"


def test_happy_the_same_issue_updates(monkeypatch, tmp_path):
    result, fetched, exe = _update_with(monkeypatch, tmp_path, carried_issue=1, signed_issue=1)
    assert result.replaced and exe.read_bytes() == BINARY and fetched


def test_edge_no_packs_carried_checks_no_issue(monkeypatch, tmp_path):
    result, _fetched, exe = _update_with(monkeypatch, tmp_path, carried_issue=None,
                                         signed_issue=7)
    assert result.replaced and exe.read_bytes() == BINARY


def test_happy_carry_reports_the_issue_it_checked(release, tmp_path, monkeypatch):
    (tmp_path / "9.9.8").mkdir()
    (tmp_path / "9.9.8" / "installed.json").write_text(
        json.dumps({"units": ["extra:a"], "manifest": {}}))
    _reissue(release)                                     # issue 1
    monkeypatch.setattr(SU, "fetch",
                        lambda url, **kw: release["fetch"](url, kw["max_bytes"], kw.get("hosts")))
    carried = SU._carry_packs(release["release"], object(), current="9.9.8", root=tmp_path,
                              verify=release["verify"])
    assert carried.blobs and carried.issue == 1


# -- L3: the token before the per-IP cap ------------------------------------------------

INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "t", "version": "1"}}}).encode()


@pytest.fixture
def mcp_server(tmp_path, monkeypatch):
    from core import mcp_http as MH
    from core.local_fs import LocalFS

    monkeypatch.setattr(MH, "DEFAULT_HTTP_UNAUTH_BURST", 3, raising=False)
    monkeypatch.setattr(MH, "DEFAULT_HTTP_UNAUTH_REFILL_PER_SEC", 0.001, raising=False)
    cfg = MH.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0, root=str(tmp_path),
                              http_ip_burst=5, http_ip_refill_per_sec=0.001)
    srv = MH.build_server(cfg)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _status(srv, method, path, headers, body=None) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def _authed(srv) -> int:
    return _status(srv, "POST", "/messages",
                   {"Authorization": f"Bearer {srv.auth_token}",
                    "Content-Type": "application/json"}, INIT)


def test_sad_unauthenticated_flood_does_not_starve_the_token_holder(mcp_server):
    assert mcp_server.auth_token
    for _ in range(12):                                   # > the token holder's burst of 5
        _status(mcp_server, "GET", "/x.png", {"Sec-Fetch-Mode": "no-cors"})
    assert _authed(mcp_server) == 200


def test_happy_unauthenticated_requests_have_their_own_small_budget(mcp_server):
    codes = [_status(mcp_server, "GET", "/x.png", {}) for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert codes[3:] == [429, 429]


def test_edge_authenticated_requests_still_meet_their_cap(mcp_server):
    codes = [_authed(mcp_server) for _ in range(7)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]


# -- L4: reverse-serve listings with any file name -----------------------------------------

ODD = [b"a\x01b", b"bad\xffname", b"e\x1b[31m"]


@pytest.fixture
def odd_tree(tmp_path):
    root = tmp_path / "root"
    (root / "b").mkdir(parents=True)
    (root / "b" / "plain.txt").write_bytes(b"1")
    for name in ODD:
        with open(os.path.join(os.fsencode(root / "b"), name), "wb") as fh:
            fh.write(b"x")
    return str(root)


def _serve(kind, root):
    from core import reverse_serve as RS
    from core.local_fs import LocalFS

    fn = RS.serve_s3 if kind == "s3" else RS.serve_webdav
    return fn(LocalFS(), bind="127.0.0.1", port=0, root_path=root)


def _get(srv, method, path, extra=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    try:
        conn.request(method, path, headers={"Authorization": "Bearer " + srv.auth_token,
                                            "Host": "127.0.0.1", **(extra or {})})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def test_sad_propfind_answers_well_formed_for_odd_names(odd_tree):
    srv = _serve("webdav", odd_tree)
    try:
        status, body = _get(srv, "PROPFIND", "/b", {"Depth": "1"})
    finally:
        srv.shutdown()
    assert status == 207
    dom = xml.dom.minidom.parseString(body)
    hrefs = [n.firstChild.data for n in dom.getElementsByTagNameNS("DAV:", "href")]
    assert "/b/a%01b" in hrefs and "/b/bad%FFname" in hrefs and "/b/plain.txt" in hrefs
    names = [n.firstChild.data for n in dom.getElementsByTagNameNS("DAV:", "displayname")
             if n.firstChild]
    assert "plain.txt" in names and not any("\x01" in n for n in names)


def test_sad_html_index_lists_odd_names_escaped(odd_tree):
    srv = _serve("webdav", odd_tree)
    try:
        status, body = _get(srv, "GET", "/b/")
    finally:
        srv.shutdown()
    assert status == 200
    text = body.decode("utf-8")
    assert "href='a%01b'" in text and "href='bad%FFname'" in text
    assert "\x01" not in text and "\x1b" not in text


def test_sad_s3_listing_stays_well_formed_and_url_encoding_carries_odd_keys(odd_tree):
    srv = _serve("s3", odd_tree)
    try:
        plain = _get(srv, "GET", "/b?list-type=2")
        encoded = _get(srv, "GET", "/b?list-type=2&encoding-type=url")
        delim = _get(srv, "GET", "/b?list-type=2&delimiter=/")
    finally:
        srv.shutdown()
    for status, body in (plain, encoded, delim):
        assert status == 200
        xml.dom.minidom.parseString(body)
    keys = [n.firstChild.data for n in
            xml.dom.minidom.parseString(plain[1]).getElementsByTagName("Key")]
    assert keys == ["plain.txt"]
    keys = [n.firstChild.data for n in
            xml.dom.minidom.parseString(encoded[1]).getElementsByTagName("Key")]
    assert sorted(keys) == sorted(["a%01b", "bad%FFname", "e%1B%5B31m", "plain.txt"])
    assert b"<EncodingType>url</EncodingType>" in encoded[1]


def test_edge_xml_escape_never_emits_what_xml_cannot_carry():
    from core import reverse_serve as RS

    out = RS._xml_escape("a\x01b\udcff<")
    assert out == "a�b�&lt;"
    xml.dom.minidom.parseString(f"<k>{out}</k>".encode())


# -- L5: a planted crossref.json -------------------------------------------------------------

def _discover(tmp_path):
    import dataclasses

    from core import mcp_catalog as M
    from core import mcp_discover as D

    entry = M.CatalogEntry(id="discover:someone/harmless-mcp", name="harmless",
                           title="Harmless MCP", category="x", source="discover",
                           repository="https://github.com/someone/harmless-mcp")
    entry = dataclasses.replace(entry, xref="unchecked")
    return D.DiscoverSource(opener=None, cache_dir=tmp_path), entry


def _plant(tmp_path, entry, repo_url):
    item = {"server": {"name": "io.github.x/x-mcp", "repository": {"url": repo_url},
                       "packages": [{"registryType": "npm", "identifier": "evil-mcp-pkg",
                                     "version": "6.6.6", "transport": {"type": "stdio"}}]}}
    (tmp_path / "crossref.json").write_text(json.dumps(
        {entry.id.lower(): {"xref": "mcpregistry", "t": time.time(), "item": item}}))


def test_sad_planted_crossref_of_another_repository_is_ignored(tmp_path):
    src, entry = _discover(tmp_path)
    _plant(tmp_path, entry, "https://github.com/evil/evil-mcp")
    out = src.apply_verdict(entry)
    assert out.xref == "unchecked" and out.identifier != "evil-mcp-pkg"


def test_happy_crossref_of_the_entrys_own_repository_applies(tmp_path):
    src, entry = _discover(tmp_path)
    _plant(tmp_path, entry, "https://github.com/someone/harmless-mcp")
    out = src.apply_verdict(entry)
    assert out.xref == "mcpregistry" and out.identifier == "evil-mcp-pkg"
    assert out.repository == entry.repository


def test_edge_planted_docker_hub_verdict_must_name_the_server(tmp_path):
    src, entry = _discover(tmp_path)
    (tmp_path / "crossref.json").write_text(json.dumps(
        {entry.id.lower(): {"xref": "dockerhub", "t": time.time(), "hub": "postgres"}}))
    assert src.apply_verdict(entry).xref == "unchecked"
    from core import mcp_discover as D

    assert D._hub_name_fits("harmless", "harmless-mcp", "")
    assert not D._hub_name_fits("postgres", "harmless-mcp", "")
    assert not D._hub_name_fits("../evil", "harmless-mcp", "")


# -- L6: build tools fetch and run code ------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["cargo", "install", "some-mcp"],
    ["cargo", "run", "--release"],
    ["go", "install", "example.com/srv@latest"],
    ["go", "build", "./cmd/srv"],
    ["mvn", "exec:java"],
    ["./mvnw", "exec:java"],
    ["gradle", "run"],
    ["env", "FOO=1", "cargo", "install", "x"],
    ["strace", "-f", "cargo", "run"],
])
def test_sad_build_tools_are_downloading_runners(argv):
    from core.mcp_runner import downloading_runner

    plan = downloading_runner(argv)
    assert plan is not None and not plan.convertible and "not converted" in plan.why_not


def test_happy_a_program_on_disk_still_runs_as_is():
    from core.mcp_runner import downloading_runner

    assert downloading_runner(["/opt/srv/bin/server", "--stdio"]) is None
