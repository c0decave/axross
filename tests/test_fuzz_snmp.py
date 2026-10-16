"""Fuzz: snmp_get / snmp_walk (pysnmp) against a hostile SNMP agent.

The fake agent decodes each request, builds a matching v2c response and
then mutates its BER bytes: malformed BER, lying lengths, wrong types,
wrong request ids, non-increasing walk OIDs. snmp_helpers documents
OSError; nothing else may escape, and a broken agent must time out.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutate  # noqa: E402

pytest.importorskip("pysnmp")

from snmp_fuzz_agent import FakeAgent, P  # noqa: E402

from core import snmp_helpers as SH  # noqa: E402


@pytest.fixture
def agent():
    a = FakeAgent()
    yield a
    a.close()


def _get(agent):
    return check_contract(
        lambda: SH.snmp_get(
            "127.0.0.1", "1.3.6.1.2.1.1.1.0", port=agent.port, timeout=0.3, retries=0
        ),
        (OSError,),
        timeout=20.0,
    )


def _walk(agent, max_vars=50):
    return check_contract(
        lambda: SH.snmp_walk(
            "127.0.0.1", "1.3.6.1.2.1.1", port=agent.port, timeout=0.3, retries=0, max_vars=max_vars
        ),
        (OSError,),
        timeout=30.0,
    )


def test_happy_get(agent):
    var = _get(agent)
    assert var.value == "fuzz agent" and var.oid == "1.3.6.1.2.1.1.1.0"


@pytest.mark.parametrize(
    "value",
    [
        P.OctetString(b"\xff\xfe\x00 binary"),
        P.OctetString(b"x" * 60000),
        P.Integer(-(2**31)),
        P.Counter64(2**64 - 1),
        P.IpAddress(b"\x7f\x00\x00\x01"),
        P.ObjectIdentifier("1.3.6.1.4.1.99999.1.2.3.4.5.6.7.8.9"),
        P.Null(),
    ],
)
def test_sad_odd_value_types(agent, value):
    agent.value = value
    var = _get(agent)
    assert isinstance(var, OSError) or isinstance(var.value, str)


@pytest.mark.parametrize(
    "mangle",
    [
        lambda b: b"",
        lambda b: b[: len(b) // 2],  # truncated BER
        lambda b: b"\x30\x84\xff\xff\xff\xff" + b[2:],  # absurd outer length
        lambda b: b"\xff" * 64,
        lambda b: b + b"\x00" * 10,  # trailing garbage
        lambda b: None,  # silence
    ],
    ids=["empty", "truncated", "huge-length", "garbage", "trailing", "silence"],
)
def test_sad_malformed_ber(agent, mangle):
    agent.mangle = mangle
    assert isinstance(_get(agent), OSError)


def test_edge_walk_with_non_increasing_oids_terminates(agent):
    agent.walk_oids = ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.2.0"]
    result = _walk(agent)
    assert isinstance(result, OSError) or len(result) <= 50


def test_edge_endless_walk_is_capped(agent):
    agent.walk_oids = [f"1.3.6.1.2.1.1.{i}.0" for i in range(1, 500)]
    result = _walk(agent, max_vars=20)
    assert isinstance(result, OSError) or len(result) == 20


def test_fuzz_response_mutants(agent):
    rng = random.Random(0x5A)
    for _ in range(iterations(10)):
        agent.mangle = lambda b, r=random.Random(rng.random()): mutate(b, r)
        _get(agent)
