"""``redact_text`` hides the credential of every Authorization scheme.

Before: the generic header pattern replaced only the first token after
``Authorization:``, so ``Proxy-Authorization: NTLM <token>`` became
``Proxy-Authorization: <redacted> <token>`` -- the scheme name was hidden
and the token was kept. The same held for Negotiate, Digest and
AWS4-HMAC-SHA256. ``--password x`` at the very start of a string, Cookie
headers and PEM private-key blocks were not redacted at all.

The real paths: an HTTP backend error that echoes request headers
(``onedrive_client`` puts ``resp.text[:500]`` into the ``OSError``) lands
in ``DiagnosticReport.to_text`` and in the operation journal's ``error``
field, both of which rely on ``redact_text``.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import diagnostics  # noqa: E402
from core import operation_journal as OJ  # noqa: E402
from core.redaction import redact, redact_text  # noqa: E402

NTLM = "TlRMTVNTUAADAAAAGAAYAEgAAAAYABgAYAAAAAAAAAB4AAAA"
SPNEGO = "YIIGhgYGKwYBBQUCoIIGejCCBnagMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAg"
DIGEST_RESPONSE = "6629fae49393a05397450978507c4ef1"
AWS_SIG = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
AWS_KEY_ID = "AKIDEXAMPLE"
PEM_BODY = "MIIEpAIBAAKCAQEA7bq98ExampleKeyMaterialOnly"
# Split so the source holds no literal key header for leak scanners to flag.
RSA_KEY_HEADER = "-----BEGIN RSA " "PRIVATE KEY-----"


class AuthorizationSchemeTest(unittest.TestCase):
    def test_happy_ntlm_proxy_authorization_token_is_hidden(self) -> None:
        out = redact_text(f"Proxy-Authorization: NTLM {NTLM}")
        self.assertNotIn(NTLM, out)
        self.assertIn("Proxy-Authorization", out)
        self.assertIn("NTLM", out)  # the scheme stays readable for diagnosis

    def test_happy_negotiate_digest_and_aws4_credentials_are_hidden(self) -> None:
        cases = {
            f"Authorization: Negotiate {SPNEGO}": SPNEGO,
            (
                'Authorization: Digest username="bob", realm="r", nonce="n", '
                f'uri="/", response="{DIGEST_RESPONSE}"'
            ): DIGEST_RESPONSE,
            (
                f"Authorization: AWS4-HMAC-SHA256 Credential={AWS_KEY_ID}/20150830/"
                f"us-east-1/iam/aws4_request, SignedHeaders=host, Signature={AWS_SIG}"
            ): AWS_KEY_ID,
        }
        for text, secret in cases.items():
            self.assertNotIn(secret, redact_text(text), text)

    def test_happy_quoted_header_in_a_dict_repr_is_hidden(self) -> None:
        text = str({"Authorization": f"Negotiate {SPNEGO}", "Host": "example.org"})
        out = redact_text(text)
        self.assertNotIn(SPNEGO, out)
        self.assertIn("example.org", out)  # the next field survives

    def test_happy_basic_and_bearer_keep_their_previous_shape(self) -> None:
        self.assertEqual(
            redact_text("Proxy-Authorization: Basic dXNlcjpwYXNz"),
            "Proxy-Authorization: Basic <redacted>",
        )
        self.assertEqual(
            redact_text("Authorization: Bearer abc.def"), "Authorization: Bearer <redacted>"
        )

    def test_sad_prose_mentioning_authorization_is_untouched(self) -> None:
        text = "authorization failed for user bob"
        self.assertEqual(redact_text(text), text)

    def test_edge_header_value_stops_at_the_line_end(self) -> None:
        out = redact_text(f"Authorization: NTLM {NTLM}\r\nHost: example.org\r\n")
        self.assertNotIn(NTLM, out)
        self.assertIn("Host: example.org", out)

    def test_edge_no_space_after_colon(self) -> None:
        self.assertNotIn(NTLM, redact_text(f"Authorization:NTLM {NTLM}"))


class CookieTest(unittest.TestCase):
    def test_happy_cookie_and_set_cookie_values_are_hidden(self) -> None:
        for text in (
            "Cookie: session=abcdef123456; theme=dark",
            "Set-Cookie: SID=abcdef123456; Path=/",
        ):
            out = redact_text(text)
            self.assertNotIn("abcdef123456", out, text)
            self.assertIn("ookie", out)

    def test_sad_word_cookies_in_prose_is_untouched(self) -> None:
        text = "cookies_enabled is off; see the cookie jar docs"
        self.assertEqual(redact_text(text), text)

    def test_edge_cookie_header_stops_at_the_line_end(self) -> None:
        out = redact_text("Cookie: a=abcdef123456\nHost: example.org")
        self.assertNotIn("abcdef123456", out)
        self.assertIn("Host: example.org", out)


class CliOptionTest(unittest.TestCase):
    def test_happy_password_option_at_the_very_start(self) -> None:
        self.assertNotIn("hunter2", redact_text("--password hunter2 --user bob"))
        self.assertNotIn("hunter2", redact_text("--token=hunter2"))

    def test_sad_option_in_the_middle_still_redacted(self) -> None:
        self.assertEqual(redact_text("cmd --password hunter2"), "cmd --password <redacted>")

    def test_edge_option_name_without_value_is_untouched(self) -> None:
        self.assertEqual(redact_text("--password"), "--password")


class PemBlockTest(unittest.TestCase):
    def test_happy_private_key_block_is_hidden(self) -> None:
        kinds = ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
        for kind in kinds:
            text = f"key:\n-----BEGIN {kind}-----\n{PEM_BODY}\nabc==\n-----END {kind}-----\nafter"
            out = redact_text(text)
            self.assertNotIn(PEM_BODY, out, kind)
            self.assertIn(f"-----BEGIN {kind}-----", out)
            self.assertIn("after", out)

    def test_sad_public_certificate_is_untouched(self) -> None:
        text = f"-----BEGIN CERTIFICATE-----\n{PEM_BODY}\n-----END CERTIFICATE-----"
        self.assertEqual(redact_text(text), text)

    def test_edge_truncated_block_without_end_marker(self) -> None:
        out = redact_text(f"{RSA_KEY_HEADER}\n{PEM_BODY}")
        self.assertNotIn(PEM_BODY, out)


class RealPathTest(unittest.TestCase):
    """The leak reaches a screen or a file through these callers."""

    def _echoing_error(self) -> OSError:
        # Shape of onedrive_client.py: f"Graph API GET {url} failed ({code}): {resp.text[:500]}"
        body = f"debug: Proxy-Authorization: NTLM {NTLM}\nCookie: s=abcdef123456"
        return OSError(f"Graph API GET https://graph.example/x failed (407): {body}")

    def test_happy_diagnostics_report_hides_the_token(self) -> None:
        err = self._echoing_error()

        class Backend:
            name = "fake"

            def home(self):
                return "/"

            def list_dir(self, path):
                raise err

            def stat(self, path):
                raise err

        text = diagnostics.diagnose_backend(Backend()).to_text()
        self.assertIn("FAIL", text)
        self.assertNotIn(NTLM, text)
        self.assertNotIn("abcdef123456", text)

    def test_happy_journal_error_field_hides_the_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            OJ.append_event(
                OJ.JournalEvent(
                    operation_id="op1",
                    phase="end",
                    operation="copy",
                    status="error",
                    error=str(self._echoing_error()),
                ),
                journal_path=path,
            )
            raw = path.read_text(encoding="utf-8")
        self.assertNotIn(NTLM, raw)
        self.assertNotIn("abcdef123456", raw)
        self.assertEqual(json.loads(raw)["operation_id"], "op1")

    def test_edge_nested_structure_is_redacted_too(self) -> None:
        out = redact({"details": [f"Authorization: Negotiate {SPNEGO}"]})
        self.assertNotIn(SPNEGO, str(out))


if __name__ == "__main__":
    unittest.main()
