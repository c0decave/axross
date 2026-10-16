"""LLM profiles for the Analysis dock: stored without keys, keys in the keyring,
remote endpoints recognised."""

from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import llm_profiles as LP  # noqa: E402


class ProfileStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "cfg" / "llm.json"

    def test_happy_round_trip_without_the_key(self) -> None:
        s = LP.LLMSettings(
            profiles=[
                LP.LLMProfile(name="local", provider="ollama", model="qwen3:8b"),
                LP.LLMProfile(name="lab", provider="openai", endpoint="https://llm.example.org/v1"),
            ],
            active="lab",
        )
        s.save(self.path)
        raw = self.path.read_text()
        self.assertNotIn("api_key", raw)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        back = LP.LLMSettings.load(self.path)
        self.assertEqual(back, s)
        self.assertEqual(back.active_profile().name, "lab")

    def test_sad_a_broken_file_gives_defaults(self) -> None:
        self.path.parent.mkdir(parents=True)
        for content in ("{not json", "[]", '{"profiles": "x"}', '{"profiles": [{"name": 3}]}'):
            with self.subTest(content=content):
                self.path.write_text(content)
                s = LP.LLMSettings.load(self.path)
                self.assertEqual(s.profiles, [])
                self.assertIsNone(s.active_profile())

    def test_sad_invalid_profiles_are_dropped_on_load(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(
            json.dumps(
                {
                    "profiles": [
                        {"name": "ok", "provider": "ollama"},
                        {"name": "ok", "provider": "ollama"},  # duplicate
                        {"name": "", "provider": "ollama"},  # blank
                        {"name": "bad", "provider": "telnet"},  # unknown provider
                        {"name": "ftp", "provider": "openai", "endpoint": "ftp://x"},  # not http(s)
                        {"name": "t", "provider": "lmstudio", "temperature": "hot"},  # wrong type
                    ],
                    "active": "missing",
                }
            )
        )
        s = LP.LLMSettings.load(self.path)
        self.assertEqual([p.name for p in s.profiles], ["ok", "t"])
        self.assertEqual(s.profiles[1].temperature, LP.LLMProfile.temperature)
        self.assertIsNone(s.active_profile())

    def _copies(self) -> list[Path]:
        return sorted(self.path.parent.glob("llm.json.unreadable-*"))

    def test_sad_saving_over_an_unreadable_file_keeps_a_copy_of_it(self) -> None:
        """load() gives no profiles for a file it cannot read; the next save
        must not erase the profiles that file held."""
        self.path.parent.mkdir(parents=True)
        for content in (
            b'{"profiles": [{"name": "work", "provider": "ollama"}], "active": "wo',
            b'{"profiles": [{"name": "w\xff"}]}',
            b"[]",
            b'{"profiles": "x"}',
        ):
            with self.subTest(content=content):
                for old in self._copies():
                    old.unlink()
                self.path.write_bytes(content)
                s = LP.LLMSettings.load(self.path)
                s.profiles.append(LP.LLMProfile(name="new"))
                s.save(self.path)
                self.assertEqual([c.read_bytes() for c in self._copies()], [content])
                self.assertEqual(
                    [p.name for p in LP.LLMSettings.load(self.path).profiles], ["new"]
                )

    def test_sad_saving_after_dropping_invalid_profiles_keeps_a_copy(self) -> None:
        self.path.parent.mkdir(parents=True)
        raw = json.dumps(
            {"profiles": [{"name": "ok"}, {"name": "future", "provider": "newprov"}]}
        ).encode()
        self.path.write_bytes(raw)
        s = LP.LLMSettings.load(self.path)
        self.assertEqual([p.name for p in s.profiles], ["ok"])
        s.save(self.path)
        self.assertEqual([c.read_bytes() for c in self._copies()], [raw])
        # The saved file is complete now: the next save keeps no further copy.
        LP.LLMSettings.load(self.path).save(self.path)
        self.assertEqual(len(self._copies()), 1)

    def test_sad_no_save_when_the_unreadable_file_cannot_be_kept(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b'{"profiles": [')
        s = LP.LLMSettings.load(self.path)
        with mock.patch.object(LP, "keep_unreadable_copy", return_value=False):
            with self.assertRaises(OSError):
                s.save(self.path)
        self.assertEqual(self.path.read_bytes(), b'{"profiles": [')

    def test_edge_a_missing_or_complete_file_keeps_no_copy(self) -> None:
        s = LP.LLMSettings.load(self.path)
        s.profiles.append(LP.LLMProfile(name="a"))
        s.save(self.path)
        LP.LLMSettings.load(self.path).save(self.path)
        self.assertEqual(self._copies(), [])

    def test_edge_validate_names_the_problem(self) -> None:
        self.assertEqual(LP.LLMProfile(name="x", provider="ollama").problems(), [])
        self.assertTrue(LP.LLMProfile(name=" ", provider="ollama").problems())
        self.assertTrue(LP.LLMProfile(name="x", provider="nope").problems())
        self.assertTrue(
            LP.LLMProfile(name="x", provider="openai", endpoint="javascript:x").problems()
        )
        self.assertTrue(LP.LLMProfile(name="x", provider="openai", timeout=0).problems())


class EndpointTest(unittest.TestCase):
    def test_happy_provider_defaults_match_sift(self) -> None:
        try:
            from sift import config as SC
        except ImportError:
            self.skipTest("sift is not installed")
        for provider in LP.PROVIDERS:
            with self.subTest(provider=provider):
                self.assertEqual(
                    LP.LLMProfile(name="x", provider=provider).resolved_endpoint(),
                    SC.Config(provider=provider).resolved_endpoint(),
                )

    def test_happy_local_endpoints_are_not_remote(self) -> None:
        for url in (
            "http://localhost:11434",
            "http://127.0.0.1:1234/v1",
            "http://[::1]:8080/v1",
            "http://192.168.1.20:11434",
            "http://10.0.0.5",
            "http://172.16.3.4:1234",
        ):
            with self.subTest(url=url):
                self.assertFalse(LP.is_remote_endpoint(url))

    def test_sad_public_and_unknown_hosts_are_remote(self) -> None:
        for url in (
            "https://api.openai.com/v1",
            "http://8.8.8.8:11434",
            "https://llm.example.org",
            "http://gpu-box:11434",
            "not a url",
            "",
        ):
            with self.subTest(url=url):
                self.assertTrue(LP.is_remote_endpoint(url))


class ReviewFixesTest(unittest.TestCase):
    def test_sad_special_purpose_ranges_that_are_not_this_network_are_remote(self) -> None:
        for url in (
            "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]:11434",  # Teredo
            "http://[2001:db8::1]",
            "http://192.0.0.8",
            "http://198.18.0.5",
            "http://100.64.0.1",
            "http://[::ffff:8.8.8.8]",
        ):
            with self.subTest(url=url):
                self.assertTrue(LP.is_remote_endpoint(url))

    def test_happy_lan_and_link_local_stay_local(self) -> None:
        for url in (
            "http://[fd12:3456::1]:11434",
            "http://[fe80::1]",
            "http://169.254.1.1",
            "http://[::ffff:192.168.1.5]",
            "http://[::1]:8080",
        ):
            with self.subTest(url=url):
                self.assertFalse(LP.is_remote_endpoint(url))

    def test_sad_consent_belongs_to_the_host_not_the_profile(self) -> None:
        p = LP.LLMProfile(name="r", provider="openai", endpoint="https://lab.example.org/v1")
        self.assertTrue(p.needs_consent())
        p.consent()
        self.assertFalse(p.needs_consent())
        p.endpoint = "https://api.other.example/v1"
        self.assertTrue(p.needs_consent())

    def test_edge_a_local_endpoint_needs_no_consent_and_old_flags_are_ignored(self) -> None:
        self.assertFalse(LP.LLMProfile(name="l", endpoint="http://127.0.0.1:11434").needs_consent())
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm.json"
            path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "r",
                                "provider": "openai",
                                "endpoint": "https://x.example",
                                "remote_confirmed": True,
                            }
                        ]
                    }
                )
            )
            self.assertTrue(LP.LLMSettings.load(path).profiles[0].needs_consent())


class KeyringTest(unittest.TestCase):
    def test_happy_the_key_goes_to_the_keyring_under_its_own_entry(self) -> None:
        stored = {}
        with (
            mock.patch(
                "core.credentials.store_password",
                side_effect=lambda n, v: stored.update({n: v}) or True,
            ),
            mock.patch("core.credentials.get_password", side_effect=lambda n: stored.get(n)),
        ):
            self.assertTrue(LP.store_api_key("lab", "sk-test"))
            self.assertEqual(LP.get_api_key("lab"), "sk-test")
        self.assertEqual(list(stored), ["llm-profile:lab:api-key"])

    def test_sad_no_keyring_means_no_key(self) -> None:
        with mock.patch("core.credentials.get_password", return_value=None):
            self.assertEqual(LP.get_api_key("lab"), "")


class WorkerRequestTest(unittest.TestCase):
    def test_happy_the_request_names_the_server_and_carries_the_key(self) -> None:
        p = LP.LLMProfile(name="lab", provider="lmstudio", model="m", timeout=30.0)
        req = LP.worker_request(p, "sk-1")
        self.assertEqual(
            req,
            {
                "provider": "lmstudio",
                "endpoint": "http://localhost:1234/v1",
                "model": "m",
                "api_key": "sk-1",
                "temperature": 0.2,
                "timeout": 30.0,
                "max_output_tokens": 2000,
                "allow_model_load": False,
            },
        )

    def test_edge_no_profile_fields_beyond_what_the_worker_reads(self) -> None:
        req = LP.worker_request(LP.LLMProfile(name="x", confirmed_origin="h"), "")
        self.assertNotIn("confirmed_origin", req)
        self.assertNotIn("name", req)


def _env_without_proxies(**extra: str) -> dict:
    import os

    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    env.update(extra)
    return env


class ProxyConsentTest(unittest.TestCase):
    """urllib sends a request to the proxy of the environment: that is where
    the file goes, so a proxied endpoint is remote, whatever its host."""

    def _patch(self, **env: str):
        patcher = mock.patch.dict("os.environ", _env_without_proxies(**env), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_happy_localhost_without_a_proxy_stays_local(self) -> None:
        self._patch()
        p = LP.LLMProfile(name="l", endpoint="http://localhost:11434")
        self.assertFalse(p.is_remote())
        self.assertFalse(p.needs_consent())
        self.assertEqual(p.host(), "localhost")

    def test_sad_localhost_through_a_proxy_is_remote_and_names_the_proxy(self) -> None:
        self._patch(http_proxy="http://user:hunter2@proxy.example:3128")
        p = LP.LLMProfile(name="l", endpoint="http://localhost:11434")
        self.assertTrue(p.is_remote())
        self.assertTrue(p.needs_consent())
        self.assertIn("proxy.example:3128", p.host())
        self.assertIn("localhost", p.host())
        self.assertNotIn("hunter2", p.host())
        p.consent()
        self.assertNotIn("hunter2", p.confirmed_origin)
        self.assertFalse(p.needs_consent())

    def test_sad_consent_through_one_proxy_does_not_cover_another(self) -> None:
        self._patch(http_proxy="http://proxy.example:3128")
        p = LP.LLMProfile(name="l", endpoint="http://localhost:11434")
        p.consent()
        self._patch(http_proxy="http://other-proxy.example:8080")
        self.assertTrue(p.needs_consent())
        self._patch()  # and no proxy at all: local again
        self.assertFalse(p.needs_consent())

    def test_edge_no_proxy_and_the_scheme_decide(self) -> None:
        for env in (
            {"http_proxy": "http://proxy.example:3128", "no_proxy": "localhost"},
            {"http_proxy": "http://proxy.example:3128", "no_proxy": "*"},
            {"https_proxy": "http://proxy.example:3128"},  # an http endpoint
        ):
            with self.subTest(env=env):
                self._patch(**env)
                p = LP.LLMProfile(name="l", endpoint="http://localhost:11434")
                self.assertFalse(p.is_remote())
        self._patch(https_proxy="http://proxy.example:3128")
        self.assertTrue(LP.LLMProfile(name="l", endpoint="https://127.0.0.1:8443/v1").is_remote())


class MalformedEndpointTest(unittest.TestCase):
    def test_sad_a_malformed_url_is_a_problem_not_an_exception(self) -> None:
        for endpoint in ("http://[::1:1234/v1", "http://host:99999/v1", "http://h:port/v1"):
            with self.subTest(endpoint=endpoint):
                p = LP.LLMProfile(name="x", provider="openai", endpoint=endpoint)
                self.assertIn("the endpoint is not an http(s) URL", p.problems())
                self.assertTrue(p.needs_consent())  # never a silent "local"

    def test_happy_load_keeps_the_valid_profiles_beside_a_malformed_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm.json"
            path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {"name": "good", "provider": "ollama"},
                            {"name": "bad", "provider": "openai", "endpoint": "http://[::1:1234/v1"},
                        ],
                        "active": "good",
                    }
                )
            )
            s = LP.LLMSettings.load(path)
        self.assertEqual([p.name for p in s.profiles], ["good"])
        self.assertEqual(s.active_profile().name, "good")


class OriginConsentTest(unittest.TestCase):
    """Consent is for scheme, host and port: the same host over plain HTTP or
    on another port is another place to send the file."""

    def setUp(self) -> None:
        patcher = mock.patch.dict("os.environ", _env_without_proxies(), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_happy_consent_covers_the_same_origin_written_differently(self) -> None:
        p = LP.LLMProfile(name="r", provider="openai", endpoint="https://lab.example.org/v1")
        p.consent()
        self.assertEqual(p.confirmed_origin, "https://lab.example.org:443")
        p.endpoint = "https://LAB.example.org:443/v2"
        self.assertFalse(p.needs_consent())

    def test_sad_another_scheme_or_port_asks_again(self) -> None:
        p = LP.LLMProfile(name="r", provider="openai", endpoint="https://lab.example.org/v1")
        p.consent()
        for endpoint in ("http://lab.example.org/v1", "https://lab.example.org:8443/v1"):
            with self.subTest(endpoint=endpoint):
                p.endpoint = endpoint
                self.assertTrue(p.needs_consent())

    def test_edge_an_empty_host_always_asks_and_old_host_only_consent_is_not_enough(self) -> None:
        p = LP.LLMProfile(name="r", provider="openai", endpoint="http:///evil.example/v1")
        p.consent()
        self.assertTrue(p.needs_consent())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "llm.json"
            path.write_text(
                json.dumps(
                    {
                        "profiles": [
                            {
                                "name": "r",
                                "provider": "openai",
                                "endpoint": "https://lab.example.org/v1",
                                "confirmed_host": "lab.example.org",
                            }
                        ]
                    }
                )
            )
            self.assertTrue(LP.LLMSettings.load(path).profiles[0].needs_consent())


if __name__ == "__main__":
    unittest.main()
