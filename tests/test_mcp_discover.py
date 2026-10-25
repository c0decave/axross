"""Discover (core.mcp_discover): curated awesome-lists of MCP servers, parsed
from their README as untrusted text, cross-referenced against the MCP
Registry and Docker Hub's ``mcp`` namespace - installable only through
those, otherwise "link only".

The R00T-Kim list (CC0) ships as a snapshot in resources/mcp; the wong2
list (MIT) is only read live, so its fixture here is written by hand in
its format. The registry answer in tests/fixtures/mcp is a real one
(2026-10-25)."""

from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mcp_catalog as M  # noqa: E402
from core import mcp_discover as D  # noqa: E402
from tests.test_mcp_catalog import FakeOpener  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mcp"
R00T = D.LISTS[0]
WONG2 = D.LISTS[1]

WONG2_STYLE = """# Awesome MCP Servers

## Sponsors

<div align="center"><a href="https://sponsor.example/">Sponsor</a></div>

## Reference Servers

- **[Time](https://github.com/modelcontextprotocol/servers/blob/main/src/time)** - Time and \
timezone conversion capabilities
- **[Fetch](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch)** - Web content \
fetching

## Community Servers

- **[Firecrawl](https://github.com/mendableai/firecrawl-mcp-server)** - Extract web data with \
[Firecrawl](https://firecrawl.dev)
- **[Find-A-Domain](https://findadomain.dev/mcp)** - not on GitHub

## Clients

- **[mcp-cli](https://github.com/wong2/mcp-cli)** a cli inspector for MCP servers

## Frameworks

- **[LiteMCP](https://github.com/wong2/litemcp)** - A TypeScript framework
"""

HOSTILE = """## <script>alert(1)</script>Evil ‮Category

- [**Script**](javascript:alert(1)) - runs code
- [**Data**](data:text/html,<b>x</b>) - a data URL
- [**Plain http**](http://github.com/evil/plain) - not https
- [**Lookalike**](https://github.com.evil.example/evil/x) - not GitHub
- [**Userinfo**](https://user@github.com/evil/x) - credentials in the URL
- [**Port**](https://github.com:8443/evil/x) - another port
- [**Org page**](https://github.com/orgs/evil) - no repository
- [**Good ‮name<img src=x onerror=alert(1)>**](https://github.com/good/repo.git) - \
<b>bold</b> text\x1b[31m with [a link](javascript:alert(2)) and ![img](https://x/i.png)
- [**Twice**](https://github.com/good/repo) - the same repository again
"""


def _readme_opener(*, r00t: bytes | Exception | None = None,
                   wong2: bytes | Exception | None = None, **routes) -> FakeOpener:
    table = dict(routes)
    if r00t is not None:
        table[R00T.url] = r00t
    if wong2 is not None:
        table[WONG2.url] = wong2
    return FakeOpener(table)


def _snapshot_text() -> str:
    return json.loads(D.snapshot_path(R00T).read_text(encoding="utf-8"))["readme"]


def _source(tmp_path, opener, **kw) -> D.DiscoverSource:
    return D.DiscoverSource(opener=opener, cache_dir=tmp_path / "cache", **kw)


# -- happy ----------------------------------------------------------------------------


def test_happy_the_shipped_snapshot_parses_into_categorised_github_entries():
    meta = json.loads(D.snapshot_path(R00T).read_text(encoding="utf-8"))
    assert meta["license"] == "CC0-1.0" and len(meta["commit"]) == 40
    assert meta["source"].endswith(f"/{meta['commit']}/README.md")
    entries, warnings = D.parse_readme(meta["readme"], listed_in=R00T.title)
    assert len(entries) >= 90, len(entries)
    categories = {e.category for e in entries}
    assert {"Reconnaissance & OSINT", "Vulnerability Research & Analysis",
            "Cryptography & Cracking"} <= categories
    assert not any("Framework" in c or "Contributing" in c for c in categories)
    nmap = next(e for e in entries if e.title == "Nmap MCP")
    assert nmap.repository == "https://github.com/vorotaai/nmap-mcp"
    assert nmap.category == "Reconnaissance & OSINT" and nmap.description.startswith("Run Nmap")
    assert nmap.id == "discover:vorotaai/nmap-mcp" and nmap.source == "discover"
    assert nmap.kind == "link" and not nmap.installable and nmap.xref == "unchecked"
    assert nmap.listed_in == R00T.title
    for e in entries:
        assert D.github_repo(e.repository) and e.repository.startswith("https://github.com/")
    fetch = next(e for e in entries if e.repository.endswith("/src/fetch"))
    assert fetch.repository == "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch"
    assert fetch.id == "discover:modelcontextprotocol/servers/src/fetch" and fetch.name == "fetch"


def test_happy_a_wong2_style_list_is_parsed_and_clients_are_left_out():
    entries, warnings = D.parse_readme(WONG2_STYLE, listed_in=WONG2.title)
    by = {e.title: e for e in entries}
    assert set(by) == {"Time", "Fetch", "Firecrawl"}
    assert by["Time"].repository == (
        "https://github.com/modelcontextprotocol/servers/blob/main/src/time")
    assert by["Time"].category == "Reference Servers"
    assert by["Firecrawl"].description == "Extract web data with Firecrawl"
    # Two folders of one repository are two servers.
    assert by["Fetch"].id == "discover:modelcontextprotocol/servers/src/fetch" != by["Time"].id
    assert any("Find-A-Domain" in w and "GitHub" in w for w in warnings)


def test_happy_the_source_reads_both_lists_and_filters_by_text(tmp_path):
    opener = _readme_opener(r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode())
    source = _source(tmp_path, opener)
    result = source.search("")
    assert result.error == "" and (result.source, result.title) == ("discover", "Discover")
    lists = {name for e in result.entries for name in e.listed_in.split(", ")}
    assert lists == {R00T.title, WONG2.title}
    both = [e for e in result.entries if e.listed_in == f"{R00T.title}, {WONG2.title}"]
    assert both  # the reference servers are in both lists, shown once
    assert all(e.xref == "unchecked" for e in result.entries)
    hits = source.search("shodan").entries
    assert hits and all("shodan" in (e.title + e.description).lower() for e in hits)
    assert [u for u in opener.urls if "raw.githubusercontent.com" in u] == [R00T.url, WONG2.url]


def test_happy_crossref_registry_and_docker_hub_or_link_only(tmp_path):
    hub_search = {"count": 1, "results": [
        {"name": "nmap", "namespace": "mcp", "description": "Nmap in a box",
         "is_private": False, "media_types": ["application/vnd.oci.image.index.v1+json"]}]}
    hub_repo = {"name": "nmap", "namespace": "mcp",
                "full_description": "**Repository**|https://github.com/vorotaai/nmap-mcp\n"}
    opener = _readme_opener(
        r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode(),
        **{"search=BurtTheCoder": (FIXTURES / "registry_burtthecoder.json").read_bytes(),
           "registry.modelcontextprotocol.io": b'{"servers": [], "metadata": {"count": 0}}',
           "/v2/repositories/mcp/?": json.dumps(hub_search).encode(),
           "/v2/repositories/mcp/nmap/tags/latest": json.dumps(
               {"digest": "sha256:" + "b" * 64}).encode(),
           "/v2/repositories/mcp/nmap/": json.dumps(hub_repo).encode()})
    source = _source(tmp_path, opener)
    entries = {e.id: e for e in source.search("").entries}
    shodan = source.check(entries["discover:BurtTheCoder/mcp-shodan"])
    assert shodan.installable and shodan.xref == "mcpregistry" and shodan.via == "MCP Registry"
    assert (shodan.kind, shodan.identifier, shodan.version) == (
        "npm", "@burtthecoder/mcp-shodan", "1.0.22")
    assert shodan.id == "discover:BurtTheCoder/mcp-shodan" and shodan.source == "discover"
    assert shodan.category == "Reconnaissance & OSINT" and shodan.title == "Shodan MCP"
    nmap = source.check(entries["discover:vorotaai/nmap-mcp"])
    assert nmap.installable and nmap.xref == "dockerhub" and nmap.via == "Docker Hub (mcp/*)"
    assert nmap.identifier == "docker.io/mcp/nmap" and nmap.digest == ""
    assert source.resolve(nmap).digest == "sha256:" + "b" * 64
    zoom = source.check(entries["discover:zoomeye-ai/mcp_zoomeye"])
    assert zoom.xref == "link" and not zoom.installable and zoom.kind == "link"
    assert "link only" in zoom.why_not


def test_happy_parsed_lists_and_verdicts_are_cached_until_the_ttl(tmp_path):
    clock = [1000.0]
    opener = _readme_opener(r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode(),
                            **{"registry.modelcontextprotocol.io":
                               b'{"servers": [], "metadata": {"count": 0}}',
                               "hub.docker.com": b'{"count": 0, "results": []}'})
    first = _source(tmp_path, opener, now=lambda: clock[0])
    entry = next(e for e in first.search("").entries if e.id == "discover:vorotaai/nmap-mcp")
    assert first.check(entry).xref == "link"
    asked = len(opener.urls)
    offline = FakeOpener({"": OSError("offline")})
    second = _source(tmp_path, offline, now=lambda: clock[0] + 60)
    again = {e.id: e for e in second.search("").entries}
    assert offline.urls == []  # from the cache, nothing asked
    assert again["discover:vorotaai/nmap-mcp"].xref == "link"
    clock[0] += D.TTL + 1
    third = _source(tmp_path, opener, now=lambda: clock[0])
    third.search("")
    assert len(opener.urls) > asked  # stale: read again
    asked = len(opener.urls)
    third.refresh()
    third.search("")
    assert len(opener.urls) == asked + 2  # Refresh reads both lists again


def test_happy_offline_the_snapshot_is_used_and_says_its_commit(tmp_path):
    opener = _readme_opener(r00t=OSError("no route"), wong2=OSError("no route"))
    result = _source(tmp_path, opener).search("")
    assert result.error == ""
    assert {e.listed_in for e in result.entries} == {R00T.title}
    assert len(result.entries) >= 90
    text = " ".join(result.notes)
    assert "snapshot" in text and "28f9c0f" in text and "no route" in text
    assert WONG2.title in text and "could not be read" in text
    assert not any("snapshot" in w for w in result.warnings)


def test_happy_crossref_all_reports_progress_and_skips_checked(tmp_path):
    opener = _readme_opener(r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode(),
                            **{"registry.modelcontextprotocol.io":
                               b'{"servers": [], "metadata": {"count": 0}}',
                               "hub.docker.com": b'{"count": 0, "results": []}'})
    source = _source(tmp_path, opener)
    entries = source.search("").entries[:5]
    seen = []
    done = source.crossref_all(entries, on_entry=seen.append)
    assert sorted(e.id for e in seen) == sorted(e.id for e in entries) and done == 5
    assert all(e.xref == "link" for e in seen)
    asked = len(opener.urls)
    assert source.crossref_all([seen[0]], on_entry=seen.append) == 0
    assert len(opener.urls) == asked


# -- sad ------------------------------------------------------------------------------


def test_sad_a_hostile_readme_gives_plain_text_and_only_github_repositories():
    entries, warnings = D.parse_readme(HOSTILE, listed_in="evil")
    assert [e.repository for e in entries] == ["https://github.com/good/repo"]
    (good,) = entries
    for text in (good.title, good.description, good.category):
        assert "<" not in text and "‮" not in text and "\x1b" not in text
        assert "javascript" not in text and "http" not in text
    assert good.title == "Good name"
    assert good.description == "bold text[31m with a link and img"
    assert good.category == "Evil Category"
    assert len(warnings) >= 7  # every refused link is named, the duplicate too
    assert any("twice" in w for w in warnings)


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "data:text/html,x", "http://github.com/a/b",
    "https://github.com.evil.example/a/b", "https://user@github.com/a/b",
    "https://github.com:8443/a/b", "https://github.com/orgs/a", "https://github.com/a",
    "https://github.com/-a/b", "https://github.com/a/..", "https://gist.github.com/a/b",
    "https://github.com/a/b c", "https://github.com/a/b‮", "", None, 5,
    "https://github.com/" + "a" * 50 + "/b",
])
def test_sad_only_https_github_repositories_are_accepted(url):
    assert D.github_repo(url) == ""


def test_sad_an_oversized_readme_is_refused_and_the_snapshot_steps_in(tmp_path):
    big = b"- [**x**](https://github.com/a/b) - y\n" * (D.MAX_README_BYTES // 30)
    opener = _readme_opener(r00t=big, wong2=big)
    result = _source(tmp_path, opener).search("")
    assert result.error == ""
    assert {e.listed_in for e in result.entries} == {R00T.title}  # the snapshot
    assert sum("larger than" in n for n in result.notes) == 2


def test_sad_broken_markdown_does_not_break_the_parser():
    broken = ("## [unclosed\n- [**a**(https://github.com/a/b)\n- [**b**](https://github.com/a/b\n"
              "- [[[[**c**]]]](https://github.com/c/d) - nested\n- " + "[" * 100000 + "\n"
              "\x00\xff� garbage\n" + "- [**e**](https://github.com/e/f) - " + "x" * 50000
              + "\n")
    entries, _warnings = D.parse_readme(broken, listed_in="broken")
    assert "https://github.com/e/f" in {e.repository for e in entries}
    assert all(len(e.description) <= M.MAX_DESCRIPTION for e in entries)


def test_sad_a_failing_registry_leaves_the_entry_unchecked_not_link_only(tmp_path):
    opener = _readme_opener(r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode(),
                            **{"registry.modelcontextprotocol.io": OSError("down"),
                               "hub.docker.com": b'{"count": 0, "results": []}'})
    source = _source(tmp_path, opener)
    entry = next(e for e in source.search("").entries if e.id == "discover:vorotaai/nmap-mcp")
    checked = source.check(entry)
    assert checked.xref == "unchecked" and "down" in checked.notes
    assert not checked.installable


def test_sad_a_docker_hub_image_of_another_repository_is_not_offered(tmp_path):
    hub_search = {"count": 1, "results": [{"name": "shodan", "namespace": "mcp",
                                           "description": "Shodan", "is_private": False}]}
    hub_repo = {"full_description": "**Repository**|https://github.com/Cyreslab-AI/shodan\n"}
    lookalike = json.loads((FIXTURES / "registry_burtthecoder.json").read_text())
    lookalike["servers"][0]["server"]["repository"]["url"] = (
        "https://github.com/BurtTheCoder/mcp-shodan-evil")
    opener = _readme_opener(
        r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode(),
        **{"registry.modelcontextprotocol.io": json.dumps(lookalike).encode(),
           "/v2/repositories/mcp/?": json.dumps(hub_search).encode(),
           "/v2/repositories/mcp/shodan/": json.dumps(hub_repo).encode()})
    source = _source(tmp_path, opener)
    entry = next(e for e in source.search("").entries
                 if e.id == "discover:BurtTheCoder/mcp-shodan")
    checked = source.check(entry)
    assert checked.xref == "link" and not checked.installable


def test_sad_the_request_budget_bounds_a_crossref_run(tmp_path):
    opener = _readme_opener(r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode(),
                            **{"registry.modelcontextprotocol.io":
                               b'{"servers": [], "metadata": {"count": 0}}',
                               "hub.docker.com": b'{"count": 0, "results": []}'})
    source = _source(tmp_path, opener)
    entries = source.search("").entries
    before = len(opener.urls)
    done = source.crossref_all(entries, on_entry=lambda e: None, budget=6, workers=1)
    assert len(opener.urls) - before <= 6 + 2  # at most one entry's requests over
    assert done < len(entries)


def test_sad_a_cancelled_crossref_stops(tmp_path):
    opener = _readme_opener(r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode(),
                            **{"registry.modelcontextprotocol.io":
                               b'{"servers": [], "metadata": {"count": 0}}',
                               "hub.docker.com": b'{"count": 0, "results": []}'})
    source = _source(tmp_path, opener)
    entries = source.search("").entries
    cancel = threading.Event()
    seen = []

    def on_entry(entry):
        seen.append(entry)
        cancel.set()

    source.crossref_all(entries, on_entry=on_entry, cancel=cancel)
    assert 1 <= len(seen) <= 4  # the ones already running end, no new one starts


# -- edge -----------------------------------------------------------------------------


def test_edge_a_broken_cache_is_ignored(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    for name in ("list-r00t-kim.json", "list-wong2.json", "crossref.json"):
        (cache / name).write_text("{broken")
    opener = _readme_opener(r00t=_snapshot_text().encode(), wong2=WONG2_STYLE.encode())
    result = D.DiscoverSource(opener=opener, cache_dir=cache).search("")
    assert result.error == "" and len(result.entries) >= 90


def test_edge_the_same_repository_in_both_lists_is_shown_once():
    both = "## A\n- [**x**](https://github.com/o/r) - one\n"
    other = "## B\n- **[y](https://github.com/O/R)** - two\n"
    merged = D.merge_lists([D.parse_readme(both, listed_in="L1")[0],
                            D.parse_readme(other, listed_in="L2")[0]])
    (entry,) = merged
    assert entry.listed_in == "L1, L2" and entry.description == "one"


def test_edge_github_urls_are_made_canonical():
    assert D.github_repo("https://github.com/a/b.git") == "https://github.com/a/b"
    assert D.github_repo("https://www.github.com/a/b/") == "https://github.com/a/b"
    assert D.github_repo("https://github.com/a/b/tree/main/src/x#readme") == (
        "https://github.com/a/b")
    assert D.github_repo("https://github.com/a-1/b_c.d") == "https://github.com/a-1/b_c.d"
    assert D.github_location("https://github.com/a/b/tree/main/src/x") == (
        "https://github.com/a/b", "tree/main/src/x")
    assert D.github_location("https://github.com/a/b/blob/v1.0/src/../x") == (
        "https://github.com/a/b", "")
    assert D.github_location("https://github.com/a/b/issues") == ("https://github.com/a/b", "")


def test_edge_entries_are_bounded():
    many = "## C\n" + "".join(f"- [**n{i}**](https://github.com/o/r{i}) - d\n"
                              for i in range(D.MAX_LIST_ENTRIES + 50))
    entries, warnings = D.parse_readme(many, listed_in="many")
    assert len(entries) == D.MAX_LIST_ENTRIES
    assert any("at most" in w for w in warnings)


def test_edge_discover_is_a_switchable_source_on_by_default():
    assert M.CatalogSources().discover is True
    ids = [s.id for s in M.CatalogSources().sources()]
    assert "discover" in ids
    off = M.CatalogSources.from_dict({"discover": False})
    assert "discover" not in [s.id for s in off.sources()]
    assert M.CatalogSources.from_dict(off.to_dict()) == off


# -- live -----------------------------------------------------------------------------


def _online(host: str) -> bool:
    try:
        socket.create_connection((host, 443), timeout=5).close()
        return True
    except OSError:
        return False


def test_live_the_real_list_and_the_real_registry(tmp_path):
    if not (_online("raw.githubusercontent.com") and _online("registry.modelcontextprotocol.io")):
        pytest.skip("offline")
    source = D.DiscoverSource(cache_dir=tmp_path / "cache", lists=(R00T,))
    result = source.search("")
    assert result.error == "" and result.notes == [], result
    assert len(result.entries) >= 50
    shodan = next((e for e in result.entries if e.id == "discover:BurtTheCoder/mcp-shodan"),
                  None)
    if shodan is None:
        pytest.skip("the list no longer names BurtTheCoder/mcp-shodan")
    checked = source.check(shodan)
    assert checked.xref == "mcpregistry" and checked.installable, checked
    assert checked.kind == "npm" and checked.identifier == "@burtthecoder/mcp-shodan"


def test_edge_a_title_heading_never_hides_the_list():
    text = "# Awesome MCP Resources\n\n## Tools\n- [**t**](https://github.com/o/t) - d\n"
    (entry,), _ = D.parse_readme(text, listed_in="x")
    assert entry.category == "Tools"


def test_edge_tooltips_keep_their_lines_as_text():
    from ui.mcp_catalog_dialog import plain_tooltip

    assert plain_tooltip("a <b>\nc") == "<qt>a &lt;b&gt;<br>c</qt>"
    assert plain_tooltip("") == ""
