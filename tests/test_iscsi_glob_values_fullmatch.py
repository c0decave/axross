"""iSCSI: an IQN or portal address with a trailing newline is not globbed.

core.iscsi_client checks the target IQN and the portal IP against
``^[...]+$`` before they go into a ``sudo sh -c`` glob of the node-config
files. ``re.match`` with ``$`` accepts a trailing newline ("$" matches
before a final "\\n"), so "10.0.0.1\\n" passed the check and a newline
reached the shell command line. The values come from line-based parsing,
so no exploitable path was found - the check is a full match now anyway.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import iscsi_client as IC  # noqa: E402


def _client(iqn: str, ip: str):
    cls = next(v for v in vars(IC).values()
               if isinstance(v, type) and hasattr(v, "_node_config_paths"))
    client = cls.__new__(cls)
    client._target_iqn = iqn
    client._portal_ip = ip
    return client


def test_sad_a_trailing_newline_in_the_iqn_is_refused():
    assert _client("iqn.2026-11.example:disk\n", "10.0.0.1")._node_config_paths() == []


def test_sad_a_trailing_newline_in_the_portal_is_refused():
    assert _client("iqn.2026-11.example:disk", "10.0.0.1\n")._node_config_paths() == []


def test_happy_plain_values_still_pass_the_check():
    assert IC._IQN_SAFE.fullmatch("iqn.2026-11.example:disk-1_a")
    assert IC._IP_SAFE.fullmatch("fe80::1") and IC._IP_SAFE.fullmatch("10.0.0.1")
