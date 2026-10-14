"""Redaction costs nothing for text that cannot hold a secret.

Measured before: ``redact`` of one journal event took ~180 µs; every
event is redacted twice (file line and log line), and a 1 000-file trash
writes several events per file. Each key ran 2 x 28 substring scans plus
a ``re.sub``; each value ran six regex passes even when it was ``""``.

Every pattern in ``redact_text`` needs whitespace, ``:`` or ``=`` to
match, so text without any of them is returned unchanged. Key verdicts
depend only on the key text and are cached. ``log_event`` skips the
redaction when its logger would drop the line anyway.

The reference functions below are verbatim copies of the code before the
change; the corpus test holds new == old.
"""

from __future__ import annotations

import logging
import random
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import redaction as R  # noqa: E402
from core import structured_log as SL  # noqa: E402


# --- verbatim reference (before the change) --------------------------------
def _old_is_sensitive_key(key: object) -> bool:
    text = str(key).strip().lower().replace("-", "_")
    compact = re.sub(r"[^a-z0-9]", "", text)
    return (
        text in R.SENSITIVE_KEYS
        or compact in R._COMPACT_SENSITIVE_KEYS
        or any(part in text for part in R.SENSITIVE_KEYS)
        or any(part in compact for part in R._COMPACT_SENSITIVE_KEYS)
    )


def _old_redact_text(value: str) -> str:
    text = R._AUTH_TOKEN_RE.sub(lambda m: f"{m.group(1)} <redacted>", value)
    text = R._GENERIC_AUTH_HEADER_RE.sub("Authorization: <redacted>", text)
    urls: list[str] = []

    def replace_url(match):
        url = match.group(0)
        suffix = ""
        while url and url[-1] in R._TRAILING_URL_PUNCT:
            suffix = url[-1] + suffix
            url = url[:-1]
        urls.append(R.redact_url(url) + suffix)
        return f"__AXROSS_REDACTED_URL_{len(urls) - 1}__"

    text = R._URL_RE.sub(replace_url, text)
    text = R._ASSIGNMENT_RE.sub(R._redact_assignment, text)
    text = R._CLI_SECRET_OPTION_RE.sub(lambda m: f"{m.group(1)}<redacted>", text)
    text = R._SSHPASS_RE.sub(lambda m: f"{m.group(1)}<redacted>", text)
    for idx, url in enumerate(urls):
        text = text.replace(f"__AXROSS_REDACTED_URL_{idx}__", url)
    return text


# --- corpus ------------------------------------------------------------------
_FIXED = [
    "",
    "~/Documents/file_name_12.txt",
    "~/My Documents/file name.txt",
    "password=hunter2",
    "PASSWORD:hunter2",
    "my_api_key='a b c'",
    '{"token": "abc"}',
    "Authorization: Bearer abc.def",
    "authorization:xyz",
    "Basic\tZm9vOmJhcg==",
    "ssh -o ProxyCommand=nc --password s3cret host",
    "sshpass -p hunter2 ssh host",
    "https://user:pw@host/p?sig=abc&x=1.",
    "s3://bucket/key?X-Amz-Signature=deadbeef",
    "tokenizer=fast",
    "no break space",  # unicode whitespace still scanned
    "full：width＝signs",  # look-alikes of ':' / '=' are not the ASCII ones
    "line\nbreak password=x",
    "Bearer",
    "key" * 50,
]
_ALPHABET = "abcPWtokenseigBarBearer/_.-:= \t\n'\"&;,}@? K"
_KEYS = [
    "operation_id", "phase", "source", "dest", "bytes_done", "details",
    "password", "Proxy-Password", "AWS_SECRET_ACCESS_KEY", "x-amz-signature",
    "SAS Token", "tokenizer", "", " sig ", "Key", 7, None, ("a", "b"),
]


def _corpus() -> list[str]:
    rng = random.Random(1234)
    out = list(_FIXED)
    for _ in range(3000):
        out.append("".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 40))))
    return out


class EquivalenceTest(unittest.TestCase):
    def test_happy_redact_text_equals_the_old_function(self) -> None:
        for text in _corpus():
            self.assertEqual(R.redact_text(text), _old_redact_text(text), repr(text))

    def test_happy_key_verdicts_equal_the_old_function(self) -> None:
        rng = random.Random(99)
        keys = list(_KEYS) + [
            "".join(rng.choice("abcdefgiknoprstwyz_- ") for _ in range(rng.randint(0, 20)))
            for _ in range(2000)
        ]
        for key in keys + keys:  # second pass hits the cache
            self.assertEqual(R._is_sensitive_key(key), _old_is_sensitive_key(key), repr(key))

    def test_happy_nested_redact_is_unchanged_in_shape_and_content(self) -> None:
        value = {
            "operation_id": "abc",
            "source": "/a b/c",
            "details": {"password": "x", "names": ["a", "token=1"], "n": 3},
            "proxy-password": "y",
        }
        self.assertEqual(
            R.redact(value),
            {
                "operation_id": "abc",
                "source": "/a b/c",
                "details": {"password": "<redacted>", "names": ["a", "token=<redacted>"], "n": 3},
                "proxy-password": "<redacted>",
            },
        )


class CostTest(unittest.TestCase):
    def test_happy_plain_text_runs_no_regex_pass(self) -> None:
        boom = mock.Mock(sub=mock.Mock(side_effect=AssertionError("regex pass ran")))
        with mock.patch.multiple(
            R,
            _AUTH_TOKEN_RE=boom,
            _GENERIC_AUTH_HEADER_RE=boom,
            _URL_RE=boom,
            _ASSIGNMENT_RE=boom,
            _CLI_SECRET_OPTION_RE=boom,
            _SSHPASS_RE=boom,
        ):
            self.assertEqual(R.redact_text("/srv/data/file_1.txt"), "/srv/data/file_1.txt")
            self.assertEqual(R.redact_text(""), "")

    def test_sad_text_with_a_separator_is_still_scanned(self) -> None:
        self.assertEqual(R.redact_text("token=abc"), "token=<redacted>")
        self.assertEqual(R.redact_text("x Bearer abc"), "x Bearer <redacted>")

    def test_edge_a_repeated_key_is_decided_once(self) -> None:
        R._is_sensitive_key("operation_id")
        with mock.patch.object(R.re, "sub", side_effect=AssertionError("recomputed")):
            self.assertFalse(R._is_sensitive_key("operation_id"))

    def test_edge_disabled_log_level_skips_redaction(self) -> None:
        logger = logging.getLogger("test.redaction.fastpath")
        logger.setLevel(logging.WARNING)
        with mock.patch.object(SL, "redact", side_effect=AssertionError("redacted")):
            SL.log_event(logger, logging.INFO, "operation_start", source="/a")

    def test_sad_enabled_log_level_still_redacts(self) -> None:
        logger = logging.getLogger("test.redaction.fastpath.on")
        logger.setLevel(logging.DEBUG)
        with self.assertLogs(logger, logging.INFO) as cm:
            SL.log_event(logger, logging.INFO, "operation_start", password="hunter2", b="c")
        self.assertEqual(cm.records[0].getMessage(), "event=operation_start b='c' password='<redacted>'")


if __name__ == "__main__":
    unittest.main()
