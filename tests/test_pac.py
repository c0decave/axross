"""PAC evaluation: the restricted interpreter and its helper functions."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import pac  # noqa: E402

CORP = """
// typical corporate PAC
function FindProxyForURL(url, host) {
    host = host.toLowerCase();
    if (isPlainHostName(host) || dnsDomainIs(host, ".corp.local")) {
        return "DIRECT";
    }
    if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
        shExpMatch(host, "*.internal.example.com")) {
        return "DIRECT";
    }
    if (url.substring(0, 6) == "https:") {
        return "PROXY secure-proxy.corp.example:3128; PROXY backup.corp.example:3128";
    }
    if (shExpMatch(url, "ftp://*")) return "SOCKS5 socks.corp.example:1080";
    return "PROXY proxy.corp.example:8080; DIRECT";
}
"""


def _find(src: str, url: str, host: str, **kw):
    return pac.PacScript(src, **kw).find(url, host)


class ResultParsingTest(unittest.TestCase):
    def test_all_directive_kinds(self) -> None:
        res = pac.parse_result("PROXY a:80; HTTPS b:443; SOCKS c:1; SOCKS4 d:2; SOCKS5 e:3; DIRECT")
        self.assertEqual(
            [(d.kind, d.host, d.port) for d in res],
            [
                ("http", "a", 80),
                ("https", "b", 443),
                ("socks4", "c", 1),
                ("socks4", "d", 2),
                ("socks5", "e", 3),
                ("direct", "", 0),
            ],
        )

    def test_case_and_whitespace(self) -> None:
        self.assertEqual(pac.parse_result("  proxy  p:3128 ;direct")[0].host, "p")

    def test_ipv6_proxy_host(self) -> None:
        self.assertEqual(pac.parse_result("PROXY [2001:db8::1]:3128")[0].host, "2001:db8::1")

    def test_bad_results(self) -> None:
        for bad in (
            "",
            ";",
            "PROXY",
            "PROXY nohostport",
            "PROXY h:0",
            "PROXY h:99999",
            "PROXY h:x",
            "TELEPORT h:1",
            None,
            5.0,
        ):
            with self.assertRaises(pac.PacError, msg=repr(bad)):
                pac.parse_result(bad)

    def test_port_with_non_ascii_digits_is_a_pac_error(self) -> None:
        # str.isdigit() accepts "²" (int() then raised ValueError past the
        # PacError contract) and "٣" (int() made it port 3).
        for bad in ("PROXY h:\u00b2", "PROXY h:8\u00b980", "PROXY h:\u0663", "SOCKS5 h:\uff18\uff10"):
            with self.assertRaises(pac.PacError, msg=repr(bad)):
                pac.parse_result(bad)

    def test_script_returning_a_superscript_port_is_a_pac_error(self) -> None:
        src = 'function FindProxyForURL(u, h) { return "PROXY a:\u00b2"; }'
        with self.assertRaises(pac.PacError):
            _find(src, "http://x/", "x")

    def test_ascii_port_edges_still_parse(self) -> None:
        self.assertEqual(pac.parse_result("PROXY h:1")[0].port, 1)
        self.assertEqual(pac.parse_result("PROXY h:65535")[0].port, 65535)
        self.assertEqual(pac.parse_result("PROXY h:00080")[0].port, 80)


class CorporatePacTest(unittest.TestCase):
    def kinds(self, url, host):
        return [(d.kind, d.host, d.port) for d in _find(CORP, url, host, resolver=lambda h: None)]

    def test_plain_host_is_direct(self) -> None:
        self.assertEqual(self.kinds("http://intranet/", "intranet"), [("direct", "", 0)])

    def test_domain_suffix_is_direct(self) -> None:
        self.assertEqual(self.kinds("http://a.corp.local/", "A.CORP.LOCAL"), [("direct", "", 0)])

    def test_ip_range_via_literal_is_direct(self) -> None:
        self.assertEqual(self.kinds("http://10.2.3.4/", "10.2.3.4"), [("direct", "", 0)])

    def test_glob_is_direct(self) -> None:
        self.assertEqual(
            self.kinds("http://x.internal.example.com/", "x.internal.example.com"),
            [("direct", "", 0)],
        )

    def test_https_goes_to_the_secure_proxy_with_failover_list(self) -> None:
        self.assertEqual(
            self.kinds("https://example.org/", "example.org"),
            [("http", "secure-proxy.corp.example", 3128), ("http", "backup.corp.example", 3128)],
        )

    def test_ftp_via_socks5(self) -> None:
        self.assertEqual(
            self.kinds("ftp://files.example.org/", "files.example.org"),
            [("socks5", "socks.corp.example", 1080)],
        )

    def test_default_rule(self) -> None:
        self.assertEqual(
            self.kinds("http://example.org/", "example.org"),
            [("http", "proxy.corp.example", 8080), ("direct", "", 0)],
        )


class HelperFunctionTest(unittest.TestCase):
    def check(self, expr: str, **kw):
        src = f'function FindProxyForURL(url, host) {{ return ({expr}) ? "DIRECT" : "PROXY p:1"; }}'
        return _find(src, "http://h/", "h.example.com", **kw)[0].kind == "direct"

    def test_isPlainHostName(self) -> None:
        self.assertTrue(self.check('isPlainHostName("intranet")'))
        self.assertFalse(self.check('isPlainHostName("a.b")'))

    def test_dnsDomainIs(self) -> None:
        self.assertTrue(self.check('dnsDomainIs("www.netscape.com", ".netscape.com")'))
        self.assertFalse(self.check('dnsDomainIs("www.mcom.com", ".netscape.com")'))

    def test_localHostOrDomainIs(self) -> None:
        self.assertTrue(self.check('localHostOrDomainIs("www.netscape.com", "www.netscape.com")'))
        self.assertTrue(self.check('localHostOrDomainIs("www", "www.netscape.com")'))
        self.assertFalse(self.check('localHostOrDomainIs("www.mcom.com", "www.netscape.com")'))

    def test_dnsDomainLevels(self) -> None:
        self.assertTrue(self.check('dnsDomainLevels("www.netscape.com") == 2'))

    def test_shExpMatch(self) -> None:
        self.assertTrue(
            self.check('shExpMatch("http://home.netscape.com/people/ari/index.html", "*/ari/*")')
        )
        self.assertFalse(
            self.check(
                'shExpMatch("http://home.netscape.com/people/montulli/index.html", "*/ari/*")'
            )
        )
        self.assertTrue(self.check('shExpMatch("ABC", "a?c")'))

    def test_isInNet_with_literal_and_with_resolver(self) -> None:
        self.assertTrue(self.check('isInNet("198.95.249.79", "198.95.249.79", "255.255.255.255")'))
        self.assertFalse(self.check('isInNet("1.2.3.4", "10.0.0.0", "255.0.0.0")'))
        self.assertTrue(
            self.check('isInNet("host.x", "10.0.0.0", "255.0.0.0")', resolver=lambda h: "10.9.9.9")
        )
        self.assertFalse(
            self.check('isInNet("host.x", "10.0.0.0", "255.0.0.0")', resolver=lambda h: None)
        )

    def test_dnsResolve_isResolvable_myIpAddress(self) -> None:
        self.assertTrue(self.check('dnsResolve("a.b") == "9.9.9.9"', resolver=lambda h: "9.9.9.9"))
        self.assertTrue(self.check('isResolvable("a.b")', resolver=lambda h: "1.1.1.1"))
        self.assertFalse(self.check('isResolvable("a.b")', resolver=lambda h: None))
        self.assertTrue(self.check('myIpAddress() == "192.0.2.7"', my_ip=lambda: "192.0.2.7"))

    def test_time_functions_use_the_injected_clock(self) -> None:
        # Wednesday 2026-03-04 10:30:15
        fixed = time.struct_time((2026, 3, 4, 10, 30, 15, 2, 63, 0))
        kw = {"now": lambda: fixed}
        self.assertTrue(self.check('weekdayRange("MON", "FRI")', **kw))
        self.assertFalse(self.check('weekdayRange("SAT", "SUN")', **kw))
        self.assertTrue(self.check("timeRange(8, 18)", **kw))
        self.assertFalse(self.check("timeRange(18, 23)", **kw))
        self.assertTrue(self.check('dateRange("MAR")', **kw))
        self.assertFalse(self.check('dateRange("JUN", "AUG")', **kw))
        self.assertTrue(self.check("dateRange(1, 10)", **kw))


class LanguageSubsetTest(unittest.TestCase):
    def run_pac(self, body: str, url="http://h.example.com/p?q=1", host="h.example.com"):
        src = f"function FindProxyForURL(url, host) {{ {body} }}"
        return pac.PacScript(src, resolver=lambda h: None).find(url, host)

    def test_var_if_else_and_comparison(self) -> None:
        r = self.run_pac(
            'var x = 3; if (x > 2 && x < 5) { return "PROXY a:1"; } else { return "DIRECT"; }'
        )
        self.assertEqual(r[0].host, "a")

    def test_ternary_and_logic(self) -> None:
        r = self.run_pac('return (host == "h.example.com" || false) ? "PROXY t:1" : "DIRECT";')
        self.assertEqual(r[0].host, "t")

    def test_string_methods(self) -> None:
        r = self.run_pac(
            'var d = host.substring(host.indexOf(".") + 1); '
            'if (d == "example.com" && host.charAt(0) == "h" && url.length > 5) '
            'return "PROXY ok:1"; '
            'return "DIRECT";'
        )
        self.assertEqual(r[0].host, "ok")

    def test_split_and_array_index(self) -> None:
        r = self.run_pac('var parts = host.split("."); return "PROXY " + parts[0] + ":1";')
        self.assertEqual(r[0].host, "h")

    def test_for_loop_over_array_of_domains(self) -> None:
        body = (
            'var bypass = ["a.com", "example.com", "b.com"]; '
            "for (var i = 0; i < bypass.length; i++) { "
            '  if (dnsDomainIs(host, bypass[i])) { return "DIRECT"; } } '
            'return "PROXY p:1";'
        )
        self.assertEqual(self.run_pac(body)[0].kind, "direct")

    def test_while_and_increment(self) -> None:
        r = self.run_pac('var i = 0; while (i < 5) { i++; } return "PROXY n" + i + ":1";')
        self.assertEqual(r[0].host, "n5")

    def test_nested_functions_and_globals(self) -> None:
        src = """
        var PROXY_A = "PROXY ga:1";
        function pick(h) { if (h == "h.example.com") { return PROXY_A; } return "DIRECT"; }
        function FindProxyForURL(url, host) { return pick(host); }
        """
        self.assertEqual(
            pac.PacScript(src).find("http://h.example.com/", "h.example.com")[0].host, "ga"
        )

    def test_parameter_shadows_global(self) -> None:
        src = """
        var x = "DIRECT";
        function f(x) { return x; }
        function FindProxyForURL(url, host) { return f("PROXY p:1"); }
        """
        self.assertEqual(pac.PacScript(src).find("u", "h")[0].kind, "http")

    def test_comments_everywhere(self) -> None:
        src = """/* header */ function FindProxyForURL(url, host) { // c
            return /* mid */ "DIRECT"; /* tail */ }"""
        self.assertEqual(pac.PacScript(src).find("u", "h")[0].kind, "direct")

    def test_string_escapes(self) -> None:
        r = self.run_pac(r'return "PROXY a\x62c:1";')
        self.assertEqual(r[0].host, "abc")

    def test_typeof_and_undefined_variable_guard(self) -> None:
        r = self.run_pac(
            'if (typeof nothing == "undefined") { return "DIRECT"; } return "PROXY p:1";'
        )
        self.assertEqual(r[0].kind, "direct")

    def test_number_semantics(self) -> None:
        r = self.run_pac(
            'if (1 + 2 * 3 == 7 && 10 % 4 == 2 && "5" == 5) return "DIRECT"; return "PROXY p:1";'
        )
        self.assertEqual(r[0].kind, "direct")


class FailClosedTest(unittest.TestCase):
    def assertPacError(self, src: str, url="http://h/", host="h") -> None:
        with self.assertRaises(pac.PacError):
            pac.PacScript(src).find(url, host)

    def test_missing_entry_point(self) -> None:
        with self.assertRaises(pac.PacError):
            pac.PacScript("function other() { return 'DIRECT'; }")

    def test_unsupported_syntax(self) -> None:
        for body in (
            "return /a.*b/.test(host) ? 'DIRECT' : 'PROXY p:1';",
            "eval('1');",
            "return new Date().getHours();",
            "return this.x;",
            "var o = {a: 1}; return 'DIRECT';",
            "return host.constructor;",
            "return `x`;",
        ):
            self.assertPacError(f"function FindProxyForURL(url, host) {{ {body} }}")

    def test_unknown_function_and_variable(self) -> None:
        self.assertPacError("function FindProxyForURL(u, h) { return nope(); }")
        self.assertPacError("function FindProxyForURL(u, h) { return nope; }")

    def test_infinite_loop_hits_the_step_limit(self) -> None:
        self.assertPacError("function FindProxyForURL(u, h) { while (true) {} return 'DIRECT'; }")

    def test_runaway_recursion(self) -> None:
        self.assertPacError(
            "function f() { return f(); } function FindProxyForURL(u, h) { return f(); }"
        )

    def test_string_bomb(self) -> None:
        self.assertPacError(
            "function FindProxyForURL(u, h) { var s = 'aaaaaaaaaa'; "
            "for (var i = 0; i < 40; i++) { s = s + s; } return s; }"
        )

    def test_non_string_result(self) -> None:
        self.assertPacError("function FindProxyForURL(u, h) { return 5; }")
        self.assertPacError("function FindProxyForURL(u, h) { }")

    def test_garbage_result(self) -> None:
        self.assertPacError("function FindProxyForURL(u, h) { return 'banana'; }")

    def test_oversized_script(self) -> None:
        with self.assertRaises(pac.PacError):
            pac.PacScript(" " * (pac.MAX_SOURCE + 1))

    def test_syntax_errors(self) -> None:
        for src in (
            "function FindProxyForURL(u, h) { return ; ",
            "function (",
            "var = 3;",
            "function FindProxyForURL(u, h) { if }",
        ):
            with self.assertRaises(pac.PacError, msg=src):
                pac.PacScript(src)

    def test_python_attribute_access_is_impossible(self) -> None:
        for body in (
            "return host.__class__;",
            "return host.__len__();",
            "return url['__class__'];",
        ):
            self.assertPacError(f"function FindProxyForURL(url, host) {{ {body} }}")


if __name__ == "__main__":
    unittest.main()
