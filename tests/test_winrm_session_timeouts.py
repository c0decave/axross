"""A WinRM session can be created with its own default timeouts.

``WinRMSession`` passed ``operation_timeout_sec=60`` to ``winrm.Session``
but no ``read_timeout_sec``, whose pywinrm default is 30. pywinrm refuses
that pair (winrm/protocol.py: "read_timeout_sec must exceed
operation_timeout_sec") with a ``WinRMError`` - not one of the exceptions
the constructor translated - so every WinRM connection failed before a
single packet was sent.

No network: constructing the session does not connect.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("winrm")
from core import winrm_client as WC  # noqa: E402


def _protocol(s: "WC.WinRMSession"):
    return s._session.protocol


def test_happy_default_session_is_created():
    s = WC.WinRMSession("127.0.0.1", "u", "p", port=5985, use_https=False)
    p = _protocol(s)
    assert p.read_timeout_sec > p.operation_timeout_sec == 60


@pytest.mark.parametrize("op_timeout", [1, 30, 300])
def test_edge_any_operation_timeout_gets_a_longer_read_timeout(op_timeout):
    s = WC.WinRMSession(
        "127.0.0.1", "u", "p", port=5985, use_https=False, operation_timeout_sec=op_timeout
    )
    p = _protocol(s)
    assert p.read_timeout_sec > p.operation_timeout_sec == op_timeout


def test_sad_invalid_timeout_is_an_oserror():
    with pytest.raises(OSError):
        WC.WinRMSession("127.0.0.1", "u", "p", port=5985, use_https=False, operation_timeout_sec=0)
