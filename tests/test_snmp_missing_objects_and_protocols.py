"""SNMP: a GET of an object the agent does not have, and v3 protocol names
(review round 2).

* An agent answers a GET of a missing OID with the varbind value
  noSuchObject / noSuchInstance (SNMPv2c, RFC 3416) and error-status 0:
  snmp_get returned it as a value ("No Such Object currently exists at
  this OID") - a success. It is FileNotFoundError now.
* An unknown auth or priv protocol name ("sha256" before it was known, a
  typo) silently fell back to SHA-1 / AES-128: the login then failed with
  a puzzling "wrong digest", or - worse - a weaker protocol than asked
  for was used. Unknown names are refused; SHA-2 and AES-192/256 known.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("pysnmp")

from snmp_fuzz_agent import FakeAgent, P  # noqa: E402

from core import snmp_helpers as SH  # noqa: E402


@pytest.fixture
def agent():
    a = FakeAgent()
    yield a
    a.close()


@pytest.mark.parametrize("value", [P.NoSuchObject(""), P.NoSuchInstance(""), P.EndOfMibView("")])
def test_sad_missing_object_is_not_found(agent, value) -> None:
    agent.value = value
    with pytest.raises(FileNotFoundError):
        SH.snmp_get("127.0.0.1", "1.3.6.1.2.1.1.1.0", port=agent.port, timeout=1.0, retries=0)


def test_happy_get_still_returns_a_value(agent) -> None:
    var = SH.snmp_get("127.0.0.1", "1.3.6.1.2.1.1.1.0", port=agent.port, timeout=1.0, retries=0)
    assert var.value == "fuzz agent"


@pytest.mark.parametrize("auth, priv", [("sha265", "aes"), ("sha", "aes512"), ("none?", "aes")])
def test_sad_unknown_protocol_names_are_refused(auth, priv) -> None:
    with pytest.raises(ValueError):
        SH._build_auth(None, "u", "authkey12", "privkey12", auth, priv)


@pytest.mark.parametrize(
    "auth, priv",
    [("SHA", "AES"), ("md5", "des"), ("sha256", "aes256"), ("sha512", "aes192"), (None, None)],
)
def test_happy_known_protocol_names(auth, priv) -> None:
    SH._build_auth(None, "u", "authkey12", "privkey12", auth, priv)
