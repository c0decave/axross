"""Fuzz: the PAC interpreter against hostile PAC files.

A PAC file is fetched from the network. Loading and evaluating it must end
in a result or a PacError (proxy_settings turns that into "no answer" and
fails closed) - never another exception class, and never a hang.
"""

from __future__ import annotations

import sys
import time
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402

from core import pac  # noqa: E402

CORPUS = [
    b"""function FindProxyForURL(url, host) {
    host = host.toLowerCase();
    if (isPlainHostName(host) || dnsDomainIs(host, ".corp.local")) return "DIRECT";
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
    if (url.substring(0, 6) == "https:") return "PROXY a.example:3128; PROXY b.example:3128";
    if (shExpMatch(url, "ftp://*")) return "SOCKS5 socks.example:1080";
    return "PROXY proxy.example:8080; DIRECT";
}""",
    b"""var list = ["a", "b", "c"];
function FindProxyForURL(url, host) {
    var n = 0;
    for (var i = 0; i < list.length; i++) { n += list[i].length; }
    while (n > 0) { n--; }
    var parts = host.split(".");
    return parts.length > 2 ? "HTTPS h.example:443" : "SOCKS s.example:1080";
}""",
    b"""function helper(x) { return x.charAt(0) + x.indexOf("x") + x.replace("a", "b"); }
function FindProxyForURL(url, host) {
    if (weekdayRange("MON", "FRI") && timeRange(8, 18)) return "PROXY w.example:80";
    if (dateRange("JAN", "DEC")) return 'PROXY "\\x41\\n" :81';
    return helper(host) === "q" ? "DIRECT" : "PROXY [::1]:8080";
}""",
]


def _resolver(host):
    return "10.1.2.3"


def _load_and_find(src: str):
    script = pac.load_pac(src, resolver=_resolver, my_ip=lambda: "10.0.0.1", now=time.localtime)
    return script.find("https://www.example.com/", "www.example.com")


def _contract(src: str, ctx: str):
    result = check_contract(lambda: _load_and_find(src), (pac.PacError,), timeout=20.0, context=ctx)
    if not isinstance(result, pac.PacError):
        assert result and all(isinstance(d, pac.PacDirective) for d in result)
        for d in result:
            assert d.kind == "direct" or 1 <= d.port <= 65535
    return result


def test_happy_corpus_evaluates():
    for src in CORPUS:
        assert not isinstance(_contract(src.decode(), "corpus"), pac.PacError)


@pytest.mark.parametrize(
    "src",
    [
        'function FindProxyForURL(u, h) { return "PROXY a:\u00b2"; }',  # superscript digit port
        'function FindProxyForURL(u, h) { return "PROXY a:\u0663"; }',  # Arabic-Indic digit
        'function FindProxyForURL(u, h) { return "PROXY a:99999999999999999999"; }',
        'function FindProxyForURL(u, h) { return "PROXY :80"; }',
        'function FindProxyForURL(u, h) { return 42; }',
        'function FindProxyForURL(u, h) { return ""; }',
        'function FindProxyForURL(u, h) { return "BOGUS x:1"; }',
        "function FindProxyForURL(u, h) { return h.substring(-5, 1e309); }",
        "function FindProxyForURL(u, h) { return [1,2][99]; }",
        "function FindProxyForURL(u, h) { return undefinedName; }",
        "function FindProxyForURL(u, h) { return 1 / 0 + 'x' % 0; }",
        "function FindProxyForURL(u, h) { while (true) {} }",
        "function FindProxyForURL(u, h) { return FindProxyForURL(u, h); }",
        "function FindProxyForURL(u, h) { var s = 'x'; for (;;) { s = s + s; } }",
        "function FindProxyForURL(u, h) { return h.split('').join(h); }",
        "function FindProxyForURL(u, h) { return isInNet(h, 'x', 'y'); }",
        "function FindProxyForURL(u, h) { return dateRange(1,2,3,4,5,6,7); }",
        "function FindProxyForURL(u, h) { return timeRange('a', 'b'); }",
        "function FindProxyForURL(u, h) { return weekdayRange(); }",
        "function FindProxyForURL(u, h) { return convert_addr('1.2.3'); }",
        "function FindProxyForURL(u, h) { return h.charAt('x').toUpperCase(1,2,3); }",
        "function FindProxyForURL(u, h) { return new Date(); }",
        "function FindProxyForURL(u, h) { return typeof h; }",
        "function FindProxyForURL(u, h) { return",
        "function FindProxyForURL(",
        "function",
        "\x00\xff",
        "/* unterminated",
        '"unterminated string',
        "function FindProxyForURL(u, h) { return " + "(" * 5000 + "1" + ")" * 5000 + "; }",
        "function FindProxyForURL(u, h) { return " + "!" * 20000 + "1; }",
        "function FindProxyForURL(u, h) { return " + "[" * 5000 + "]" * 5000 + "; }",
        "function FindProxyForURL(u, h) { " + "if (1) {" * 3000 + "}" * 3000 + " }",
        "function FindProxyForURL(u, h) { return 'a' " + "+ 'a' " * 50000 + "; }",
        "var x = 1; x();",
        "function FindProxyForURL(u, h) { return h[0][0][0][0]; }",
        "function FindProxyForURL(u, h) { return null.length; }",
        "function FindProxyForURL(u, h) { return h.length.length; }",
        "function FindProxyForURL(u, h) { h++; return h--; }",
        "function FindProxyForURL(u, h) { 1 = 2; }",
        "function FindProxyForURL(u, h) { return 1e400 * -1e400; }",
        "function FindProxyForURL(u, h) { return '\\x'; }",
        "function FindProxyForURL(u, h) { return h.substring(1e300); }",
        "function FindProxyForURL(u, h) { return 'x'.charAt(1e300); }",
        "function FindProxyForURL(u, h) { return [].length - 'a'; }",
    ],
    ids=lambda s: f"len{len(s)}-{zlib.crc32(s.encode()):08x}" if len(s) > 60 else None,
)
def test_sad_hostile_scripts_end_in_result_or_pac_error(src):
    _contract(src, repr(src[:80]))


def test_fuzz_pac_source_mutants():
    n = 0
    for n, payload in enumerate(mutants(CORPUS, seed=0xAC01, per_entry=iterations(250))):
        _contract(payload.decode("utf-8", "replace"), f"PAC mutant #{n}: {payload[:160]!r}")
    assert n > 0


def test_fuzz_parse_result_mutants():
    corpus = [b"PROXY a.example:8080; SOCKS5 [::1]:1080; HTTPS h:443; DIRECT"]
    for payload in mutants(corpus, seed=0xAC02, per_entry=iterations(600)):
        text = payload.decode("utf-8", "replace")
        result = check_contract(lambda: pac.parse_result(text), (pac.PacError,), context=repr(text))
        if not isinstance(result, pac.PacError):
            assert all(d.kind == "direct" or 1 <= d.port <= 65535 for d in result)
