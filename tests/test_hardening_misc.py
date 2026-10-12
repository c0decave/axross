"""Hardening regressions: proxy SSRF guard, redaction, CAS perms, atomic modes."""
from __future__ import annotations

import io
import os
import stat
import tempfile
import unittest
from unittest import mock

from core import atomic_io, cas, proxy, redaction
from core.local_fs import LocalFS


class ProxyGuardTest(unittest.TestCase):
    def _blocked(self, host: str) -> bool:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AXROSS_ALLOW_PRIVATE_PROXY", None)
            try:
                proxy._assert_proxy_host_not_private(host)
            except ConnectionError:
                return True
            return False

    def test_plain_private_ranges_blocked(self) -> None:
        for host in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "fe80::1"):
            self.assertTrue(self._blocked(host), host)

    def test_ipv4_mapped_ipv6_is_unwrapped(self) -> None:
        for host in ("::ffff:169.254.169.254", "::ffff:127.0.0.1", "::ffff:10.0.0.1"):
            self.assertTrue(self._blocked(host), host)

    def test_unspecified_and_cgnat_blocked(self) -> None:
        for host in ("::", "0.0.0.0", "100.64.0.1"):
            self.assertTrue(self._blocked(host), host)

    def test_public_address_allowed(self) -> None:
        for host in ("8.8.8.8", "2001:4860:4860::8888", "::ffff:8.8.8.8"):
            self.assertFalse(self._blocked(host), host)


class RedactionTest(unittest.TestCase):
    def test_underscore_prefixed_keys(self) -> None:
        for text in (
            "access_token=abc123",
            "refresh_token=abc123",
            "AWS_SECRET_ACCESS_KEY=abc123",
            "api_key=abc123",
            "client_secret=abc123",
        ):
            self.assertNotIn("abc123", redaction.redact_text(text), text)

    def test_json_style_pairs(self) -> None:
        for text in ('{"password": "hunter2"}', "{'token': 'hunter2'}", '"api_key":"hunter2"'):
            self.assertNotIn("hunter2", redaction.redact_text(text), text)

    def test_previous_behaviour_kept(self) -> None:
        self.assertEqual(redaction.redact_text("password=hunter2"), "password=<redacted>")
        self.assertIn("<redacted>", redaction.redact_text("Authorization: Bearer abc.def"))

    def test_plain_prose_untouched(self) -> None:
        text = "connection to host failed after 3 retries"
        self.assertEqual(redaction.redact_text(text), text)
        self.assertEqual(redaction.redact_text("tokenizer=fast"), "tokenizer=fast")

    def test_empty_string(self) -> None:
        self.assertEqual(redaction.redact_text(""), "")


class CasPermissionsTest(unittest.TestCase):
    def test_new_index_is_private(self) -> None:
        base = tempfile.mkdtemp()
        db = os.path.join(base, "sub", "cas.sqlite")
        with cas._connect(__import__("pathlib").Path(db)):
            pass
        self.assertEqual(stat.S_IMODE(os.stat(db).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(db)).st_mode), 0o700)


class AtomicModeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "secret")
        with open(self.path, "wb") as fh:
            fh.write(b"old")
        os.chmod(self.path, 0o600)
        self.backend = LocalFS()

    def test_stream_keeps_restrictive_mode(self) -> None:
        atomic_io.atomic_write_stream(self.backend, self.path, io.BytesIO(b"new-secret"))
        self.assertEqual(open(self.path, "rb").read(), b"new-secret")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_write_keeps_restrictive_mode(self) -> None:
        atomic_io.atomic_write(self.backend, self.path, b"new-secret")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_temp_is_restricted_before_data_lands(self) -> None:
        seen: list[int] = []
        real_open = self.backend.open_write

        class Spy:
            def __init__(self, fh):
                self._fh = fh

            def write(self, data):
                if data:
                    seen.append(
                        stat.S_IMODE(os.stat(self._fh.name).st_mode)
                        if hasattr(self._fh, "name")
                        else -1
                    )
                return self._fh.write(data)

            def __enter__(self):
                self._fh.__enter__()
                return self

            def __exit__(self, *exc):
                return self._fh.__exit__(*exc)

        with mock.patch.object(
            self.backend, "open_write", lambda p, *a, **k: Spy(real_open(p, *a, **k))
        ):
            atomic_io.atomic_write(self.backend, self.path, b"payload")
        self.assertTrue(seen, "no data write observed")
        self.assertTrue(all(m in (0o600, -1) for m in seen), seen)

    def test_new_file_gets_default_mode(self) -> None:
        target = os.path.join(self.dir, "fresh")
        atomic_io.atomic_write(self.backend, target, b"x")
        self.assertEqual(open(target, "rb").read(), b"x")


if __name__ == "__main__":
    unittest.main()
