"""An SNMP value whose type disagrees with the MIB does not crash.

pysnmp formats a varbind through the MIB: sysDescr (1.3.6.1.2.1.1.1.0) is
a DisplayString, so an agent answering it with an Integer or Counter64
made ``value.prettyPrint()`` in snmp_helpers._to_var raise AttributeError
("'DisplayString' object has no attribute 'getNamedValues'") or TypeError
("'int' object is not iterable") out of snmp_get / snmp_walk, whose
documented error is OSError (found by tests/test_fuzz_snmp.py).
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

SYSDESCR = "1.3.6.1.2.1.1.1.0"


@pytest.fixture
def agent():
    a = FakeAgent()
    yield a
    a.close()


def _get(agent):
    return SH.snmp_get("127.0.0.1", SYSDESCR, port=agent.port, timeout=0.5, retries=0)


def test_happy_display_string(agent):
    assert _get(agent).value == "fuzz agent"


@pytest.mark.parametrize(
    "value, shown",
    [(P.Integer(-(2**31)), "-2147483648"), (P.Counter64(2**64 - 1), "18446744073709551615")],
    ids=["integer", "counter64"],
)
def test_sad_mistyped_value_is_returned_as_text(agent, value, shown):
    agent.value = value
    var = _get(agent)
    assert isinstance(var.value, str) and shown in var.value


def test_edge_walk_with_mistyped_values(agent):
    agent.value = P.Integer(7)
    agent.walk_oids = [SYSDESCR, "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.2.1.0"]
    out = SH.snmp_walk("127.0.0.1", "1.3.6.1.2.1.1", port=agent.port, timeout=0.5, retries=0)
    assert [v.value for v in out][:1] == ["7"]
