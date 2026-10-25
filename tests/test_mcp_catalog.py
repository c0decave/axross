"""The MCP server catalog (core.mcp_catalog): the shipped catalog, user
catalog files, the live sources (Docker Hub's curated ``mcp`` namespace and
the official MCP Registry) and the validation every entry passes.

Registry answers are untrusted data: the fixtures under tests/fixtures/mcp
are trimmed real answers (2026-10-25), the hostile ones are made here."""

from __future__ import annotations

import http.server
import io
import json
import socketserver
import sys
import threading
import time
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mcp_catalog as M  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mcp"


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class _Response(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {"Content-Type": "application/json"}

    def read1(self, n=-1):
        return self.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeOpener:
    """Answers by URL substring; records every URL asked for."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.urls: list[str] = []

    def open(self, request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        self.urls.append(url)
        for needle, answer in self.routes.items():
            if needle in url:
                if isinstance(answer, Exception):
                    raise answer
                return _Response(answer)
        raise urllib.error.HTTPError(url, 404, "not found", {}, None)


def _catalog(*entries, **top) -> dict:
    return {"schema": M.SCHEMA, "version": M.VERSION, "title": "t", "entries": list(entries),
            **top}


def _oci(**kw) -> dict:
    entry = {"id": "x", "name": "x", "title": "X", "description": "d", "category": "Testing",
             "kind": "oci", "image": "docker.io/mcp/x", "tag": "latest",
             "digest": "sha256:" + "a" * 64}
    entry.update(kw)
    return entry


# -- happy ----------------------------------------------------------------------------


def test_happy_the_shipped_catalog_is_valid_and_pinned():
    entries, warnings = M.load_builtin()
    assert warnings == []
    names = {e.name for e in entries}
    assert {"git", "filesystem", "fetch", "sqlite", "memory", "sequentialthinking", "time",
            "everything"} <= names
    categories = {e.category for e in entries}
    assert {"Files & Dev", "Web & Data", "Knowledge & Reasoning", "Testing",
            "Security"} <= categories
    for e in entries:
        assert e.kind == "oci" and e.installable, e.name
        assert e.identifier.startswith("docker.io/mcp/"), e.identifier
        assert len(e.digest) == 71 and e.digest.startswith("sha256:"), e.name
        assert e.image_ref == f"{e.identifier}@{e.digest}"
        assert e.repository.startswith("https://") and e.license, e.name
        assert e.source == "builtin"
    assert next(e for e in entries if e.name == "fetch").network == "full"
    fs = next(e for e in entries if e.name == "filesystem")
    assert fs.mounts[0].target == "/projects/{name}" and fs.mounts[0].repeat
    assert fs.args == ("/projects",)
    shodan = next(e for e in entries if e.name == "shodan")
    assert shodan.env[0].secret and shodan.env[0].required


def test_happy_a_user_catalog_file_is_read(tmp_path):
    path = tmp_path / "mine.json"
    path.write_text(json.dumps(_catalog(_oci(id="a", name="alpha", tags=["one", "two"]))))
    entries, warnings = M.load_catalog_file(path, source="file:mine")
    assert warnings == []
    (entry,) = entries
    assert (entry.name, entry.tags, entry.source) == ("alpha", ("one", "two"), "file:mine")


def test_happy_search_filters_by_text_category_and_tag():
    entries, _ = M.load_builtin()
    assert [e.name for e in entries if e.matches("timezone")] == ["time"]
    assert {e.name for e in entries if e.matches("", category="Security")} >= {"vuln-nist"}
    assert [e.name for e in entries if e.matches("", tag="sql")] == ["sqlite"]
    assert all(e.matches("") for e in entries)


def test_happy_docker_hub_namespace_search(monkeypatch):
    opener = FakeOpener({"/v2/repositories/mcp/?": _fixture("hub_list_time.json")})
    result = M.DockerHubSource(opener=opener).search("time")
    assert result.error == ""
    names = [e.name for e in result.entries]
    assert "time" in names
    assert "signatures" not in names  # cosign signatures, not a server image
    entry = next(e for e in result.entries if e.name == "time")
    assert (entry.kind, entry.identifier, entry.tag, entry.digest) == (
        "oci", "docker.io/mcp/time", "latest", "")
    assert entry.installable and entry.source == "dockerhub"
    assert entry.category == "Machine learning & AI"
    assert "name=time" in opener.urls[0] and opener.urls[0].startswith("https://hub.docker.com/")


def test_happy_docker_hub_details_and_digest():
    opener = FakeOpener({
        "/v2/repositories/mcp/time/tags/latest": _fixture("hub_tag_time.json"),
        "/v2/repositories/mcp/time/": _fixture("hub_repo_time.json"),
    })
    source = M.DockerHubSource(opener=opener)
    entry = M.CatalogEntry(id="dockerhub:mcp/time", name="time", title="time", kind="oci",
                           identifier="docker.io/mcp/time", tag="latest", source="dockerhub")
    detailed = source.details(entry)
    assert detailed.repository == "https://github.com/modelcontextprotocol/servers"
    assert detailed.license == "MIT License"
    pinned = source.resolve(detailed)
    assert pinned.digest == ("sha256:9c46a918633fb474bf8035e3ee90ebac6bcf2b18ccb00679ac4c179cba0eb"
                             "fcf")


def test_happy_mcp_registry_search_maps_package_types():
    opener = FakeOpener({"/v0.1/servers?": _fixture("registry_time.json")})
    result = M.McpRegistrySource(opener=opener, max_pages=1).search("time")
    assert result.error == ""
    by_id = {e.id: e for e in result.entries}
    npm = by_id["mcpregistry:io.github.KatoMato65/time-mcp"]
    assert (npm.kind, npm.identifier, npm.version, npm.installable) == (
        "npm", "@katomato65/time-mcp", "1.0.2", True)
    pypi = by_id["mcpregistry:io.github.Shakargy/devtime"]
    assert (pypi.kind, pypi.identifier, pypi.version) == ("pypi", "devtime-ei", "0.7.0")
    oci = by_id["mcpregistry:com.formatho/runtime"]
    assert (oci.kind, oci.identifier, oci.tag) == ("oci", "docker.io/formatho/formatho-runtime",
                                                   "0.3.0")
    remote = by_id["mcpregistry:ai.b77/time"]
    assert (remote.kind, remote.url, remote.bearer) == ("remote", "https://time.b77.ai/mcp", False)
    smithery = by_id["mcpregistry:ai.smithery/arjunkmrm-time"]
    assert smithery.kind == "remote" and smithery.bearer
    anyfetch = by_id["mcpregistry:io.github.aliasmode/anyfetch"]
    assert anyfetch.kind == "npm"  # its mcpb package is passed over for one axross runs
    q = opener.urls[0]
    assert q.startswith("https://registry.modelcontextprotocol.io/v0.1/servers?")
    assert "search=time" in q and "version=latest" in q


def test_happy_sources_from_settings_and_their_switches(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(_catalog(_oci())))
    sources = M.CatalogSources.from_dict(
        {"builtin": True, "dockerhub": False, "mcpregistry": True, "extra": [str(path)]})
    ids = [s.id for s in sources.sources()]
    assert ids == ["builtin", "mcpregistry", f"file:{path}"]
    assert M.CatalogSources.from_dict(sources.to_dict()) == sources


def test_happy_search_all_collects_every_source(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(_catalog(_oci(name="mine", id="mine"))))
    opener = FakeOpener({"hub.docker.com": _fixture("hub_list_time.json"),
                         "registry.modelcontextprotocol.io": _fixture("registry_time.json")})
    sources = M.CatalogSources(extra=(str(path),)).sources(opener=opener)
    results = M.search_all(sources, "")
    assert [r.source for r in results] == ["builtin", "dockerhub", "mcpregistry", f"file:{path}"]
    assert all(r.error == "" for r in results)
    assert any(e.name == "mine" for e in results[-1].entries)


# -- sad ------------------------------------------------------------------------------


@pytest.mark.parametrize("data, why", [
    ([], "an object"),
    ({"schema": "other", "version": 1, "entries": []}, "schema"),
    ({"schema": M.SCHEMA, "version": 99, "entries": []}, "version"),
    ({"schema": M.SCHEMA, "version": 1, "entries": "x"}, "entries"),
    ({"schema": M.SCHEMA, "version": 1, "entries": [{}] * (M.MAX_ENTRIES + 1)}, "entries"),
])
def test_sad_a_broken_catalog_is_refused_with_a_reason(data, why):
    with pytest.raises(M.CatalogError, match=why):
        M.parse_catalog(data, source="file:x")


@pytest.mark.parametrize("entry, why", [
    (_oci(digest=""), "digest"),
    (_oci(digest="sha256:abc"), "digest"),
    (_oci(image="-oevil"), "image"),
    (_oci(image="docker.io/mcp/x --privileged"), "image"),
    (_oci(kind="exe"), "kind"),
    (_oci(name="../etc"), "name"),
    (_oci(network="host"), "network"),
    (_oci(hosts=["nohost"], network="allowlist"), "host"),
    (_oci(env=[{"name": "LD_PRELOAD=x"}]), "environment"),
    (_oci(env=[{"name": "A", "default": "two\nlines"}]), "environment"),
    (_oci(mounts=[{"target": "relative"}]), "mount"),
    (_oci(mounts=[{"target": "/a:/b"}]), "mount"),
    (_oci(args=["ok", 5]), "arguments"),
    ({"id": "n", "name": "n", "kind": "npm", "package": "-g", "version": "1.0.0"}, "package"),
    ({"id": "n", "name": "n", "kind": "npm", "package": "ok", "version": "^1.0.0"}, "version"),
    ({"id": "p", "name": "p", "kind": "pypi", "package": "ok", "version": "--pre"}, "version"),
    ({"id": "r", "name": "r", "kind": "remote", "url": "http://plain.example/mcp"}, "https"),
])
def test_sad_a_bad_entry_is_skipped_with_a_warning(entry, why):
    entries, warnings = M.parse_catalog(_catalog(entry, _oci(id="ok", name="ok")),
                                        source="file:x")
    assert [e.name for e in entries] == ["ok"]
    assert len(warnings) == 1 and why in warnings[0], warnings


def test_sad_an_oversized_or_broken_file_is_refused(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (M.MAX_CATALOG_BYTES + 1))
    with pytest.raises(M.CatalogError, match="larger than"):
        M.load_catalog_file(big, source="file:big")
    broken = tmp_path / "broken.json"
    broken.write_text("{nope")
    with pytest.raises(M.CatalogError, match="JSON"):
        M.load_catalog_file(broken, source="file:broken")
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100000 + "]" * 100000)
    with pytest.raises(M.CatalogError):
        M.load_catalog_file(deep, source="file:deep")
    with pytest.raises(M.CatalogError, match="cannot read"):
        M.load_catalog_file(tmp_path / "missing.json", source="file:missing")


def test_sad_a_source_that_fails_reports_and_the_rest_go_on(tmp_path):
    opener = FakeOpener({"hub.docker.com": urllib.error.URLError("no route"),
                         "registry.modelcontextprotocol.io": b"<html>not json</html>"})
    results = M.search_all(M.CatalogSources().sources(opener=opener), "time")
    by = {r.source: r for r in results}
    assert by["builtin"].error == "" and by["builtin"].entries
    assert "no route" in by["dockerhub"].error
    assert "JSON" in by["mcpregistry"].error


def test_sad_a_hanging_registry_times_out():
    class Slow(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.2)

        def log_message(self, *args):
            pass

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Slow)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        start = time.monotonic()
        with pytest.raises(M.CatalogError, match="within"):
            M.http_get_json(f"http://127.0.0.1:{server.server_address[1]}/x", timeout=1.0,
                            allow_http=True)
        assert time.monotonic() - start < 5
    finally:
        server.shutdown()
        server.server_close()


def test_sad_a_registry_answer_too_large_is_refused():
    opener = FakeOpener({"x": b"[" + b"1," * (M.MAX_ANSWER_BYTES // 2) + b"1]"})
    with pytest.raises(M.CatalogError, match="larger than"):
        M.http_get_json("https://x.example/x", opener=opener)


def test_sad_redirects_and_plain_http_are_refused():
    with pytest.raises(M.CatalogError, match="https"):
        M.http_get_json("http://example.com/x")
    err = urllib.error.HTTPError("https://x/", 302, "redirect", {"Location": "https://e/"}, None)
    with pytest.raises(M.CatalogError, match="302"):
        M.http_get_json("https://x.example/", opener=FakeOpener({"x.example": err}))


def test_sad_user_sources_must_be_absolute_paths_or_https():
    sources = M.CatalogSources.from_dict(
        {"extra": ["relative.json", "http://plain/c.json", "https://ok.example/c.json",
                   "/abs/c.json", 5, "/abs/c.json"]})
    assert sources.extra == ("https://ok.example/c.json", "/abs/c.json")
    assert M.CatalogSources.problems_of("relative.json")
    assert M.CatalogSources.problems_of("http://plain/c.json")
    assert not M.CatalogSources.problems_of("/abs/c.json")


# -- edge -----------------------------------------------------------------------------


def test_edge_hostile_text_is_cleaned_and_bounded():
    entry = _oci(title="A\u202eevil\x1b[31m", description="x" * 50000,
                 repository="javascript:alert(1)", license="L" * 500)
    (e,), _ = M.parse_catalog(_catalog(entry), source="file:x")
    assert "\u202e" not in e.title and "\x1b" not in e.title
    assert len(e.description) <= M.MAX_DESCRIPTION
    assert e.repository == ""
    assert len(e.license) <= M.MAX_SHORT


def test_edge_registry_entries_with_hostile_fields_are_cleaned():
    hostile = {"servers": [
        {"server": {"name": "io.evil/" + "x" * 300, "description": "d", "version": "1"},
         "_meta": {}},
        {"server": {"name": "io.evil/args", "description": "\x00bad\u202e", "version": "1",
                    "packages": [{"registryType": "npm", "identifier": "ok-pkg",
                                  "version": "1.0.0", "transport": {"type": "stdio"},
                                  "runtimeArguments": [{"type": "named", "name": "--privileged"}],
                                  "packageArguments": [
                                      {"type": "named", "name": "--port", "value": "8080"},
                                      {"type": "positional", "value": "x\ny"},
                                      {"type": "positional", "valueHint": "{needs_input}",
                                       "isRequired": True}],
                                  "environmentVariables": [
                                      {"name": "TOKEN", "isSecret": True, "isRequired": True},
                                      {"name": "BAD NAME"}]}]},
         "_meta": {"io.modelcontextprotocol.registry/official": {
             "status": "active", "updatedAt": "2026-10-01T00:00:00Z"}}},
        {"server": {"name": "io.gone/x", "description": "d", "version": "1",
                    "packages": [{"registryType": "npm", "identifier": "a", "version": "1",
                                  "transport": {"type": "stdio"}}]},
         "_meta": {"io.modelcontextprotocol.registry/official": {"status": "deleted"}}},
        {"server": {"name": "io.npm/other", "description": "d", "version": "1",
                    "packages": [{"registryType": "npm", "identifier": "a", "version": "1.0.0",
                                  "registryBaseUrl": "https://npm.evil.example",
                                  "transport": {"type": "stdio"}}]}, "_meta": {}},
        {"server": {"name": "io.only/mcpb", "description": "d", "version": "1",
                    "packages": [{"registryType": "mcpb", "identifier": "https://x/a.mcpb",
                                  "transport": {"type": "stdio"}}]}, "_meta": {}},
        {"server": {"name": "io.only/sse", "description": "d", "version": "1",
                    "remotes": [{"type": "sse", "url": "https://x.example/sse"}]}, "_meta": {}},
        "not a dict",
    ], "metadata": {"count": 7}}
    result = M.McpRegistrySource(opener=FakeOpener({"/v0.1/servers": json.dumps(hostile).encode()}),
                                 max_pages=1).search("x")
    by = {e.id.split(":", 1)[1]: e for e in result.entries}
    assert "io.gone/x" not in by
    args = by["io.evil/args"]
    assert "\x00" not in args.description and "\u202e" not in args.description
    assert args.args == ("--port", "8080")  # no runtime arguments, no multi-line value
    assert [(s.name, s.secret, s.required) for s in args.env] == [("TOKEN", True, True)]
    assert "argument" in args.notes
    assert not by["io.npm/other"].installable and "registry" in by["io.npm/other"].why_not
    assert by["io.only/mcpb"].kind == "mcpb" and "mcpb" in by["io.only/mcpb"].why_not
    assert not by["io.only/sse"].installable and "sse" in by["io.only/sse"].why_not
    assert all(len(e.name) <= 32 for e in result.entries)


def test_edge_registry_pages_follow_the_cursor_but_stop_at_the_bound():
    pages = []

    class Paged(FakeOpener):
        def open(self, request, timeout=None):
            url = request.full_url
            pages.append(url)
            body = {"servers": [], "metadata": {"count": 0, "nextCursor": f"c{len(pages)}"}}
            return _Response(json.dumps(body).encode())

    M.McpRegistrySource(opener=Paged({}), max_pages=3).search("time")
    assert len(pages) == 3
    assert "cursor=c1" in pages[1] and "cursor=c2" in pages[2]


def test_edge_server_names_are_made_valid():
    assert M.server_name("io.github.someone/My Server!") == "My-Server"
    assert M.server_name("x" * 80) == "x" * 32
    assert M.server_name("///") == "server"


def test_edge_an_empty_catalog_and_unknown_keys_are_fine():
    entries, warnings = M.parse_catalog(_catalog(), source="file:x")
    assert entries == [] and warnings == []
    entries, warnings = M.parse_catalog(_catalog(_oci(future_field={"a": 1})), source="file:x")
    assert len(entries) == 1 and warnings == []


def test_edge_duplicate_entry_ids_keep_the_first():
    entries, warnings = M.parse_catalog(_catalog(_oci(id="a", name="one"), _oci(id="a",
                                                                                name="two")),
                                        source="file:x")
    assert [e.name for e in entries] == ["one"]
    assert "twice" in warnings[0]


def test_edge_a_cancelled_search_stops_between_pages():
    cancel = threading.Event()

    class Cancelling(FakeOpener):
        def open(self, request, timeout=None):
            cancel.set()
            body = {"servers": [], "metadata": {"count": 0, "nextCursor": "next"}}
            return _Response(json.dumps(body).encode())

    result = M.McpRegistrySource(opener=Cancelling({}), max_pages=5).search("t", cancel=cancel)
    assert result.error == "cancelled"
