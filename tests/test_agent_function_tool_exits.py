"""An extension's agent tool that exits or raises oddly is an error for the
model, never the end of the run.

Measured before: FunctionTool.call caught ``Exception`` only. A tool calling
``sys.exit()`` (or raising asyncio's CancelledError) let it out of the agent
loop, and the Agent dock's run thread, which caught ``Exception`` too, ended
without reporting: the tab stayed busy for good. A tool error whose
``str()`` raises did the same.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agent import FunctionTool  # noqa: E402


class _Odd(Exception):
    def __init__(self):
        pass

    def __str__(self):
        return self.msg


def _tool(handler) -> FunctionTool:
    return FunctionTool(name="t", description="d", schema={"type": "object"}, handler=handler)


@pytest.mark.parametrize("exc", [SystemExit(3), asyncio.CancelledError(), _Odd()])
def test_sad_an_odd_failure_is_an_error_for_the_model(exc):
    def handler(args):
        raise exc

    status, text = _tool(handler).call({})
    assert status == "error"
    assert type(exc).__name__ in text


def test_edge_ctrl_c_stays_the_users():
    def handler(args):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _tool(handler).call({})


def test_happy_a_value_goes_to_the_model():
    assert _tool(lambda args: {"a": 1}).call({}) == ("ok", '{"a": 1}')
