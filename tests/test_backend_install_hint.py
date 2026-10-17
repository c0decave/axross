"""An unavailable backend names what to install - never a made-up extra.

GUI end-to-end run: the "Public: Apache SVN" profile answered "Backend
'Subversion (read-only)' is not available. Install it with: pip install
axross[svn]". pyproject.toml has no svn extra - the backend needs the
system svn binary. load_backend_class() fell back to the protocol id as
the extra name for every backend without one: rsync, nfs, iscsi, svn,
rsh and mtp all depend on system commands. They now carry an install
hint naming those commands.
"""

from __future__ import annotations

import dataclasses
import re
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import backend_registry as R  # noqa: E402

EXTRAS = set(
    tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]
)


@pytest.fixture
def unavailable():
    R.init_registry()

    def make(protocol_id):
        R.register(dataclasses.replace(R.get(protocol_id), available=False))
        with pytest.raises(ImportError) as exc:
            R.load_backend_class(protocol_id)
        return str(exc.value)

    yield make
    R.init_registry()


# --- happy ----------------------------------------------------------------


def test_happy_a_pip_backend_names_its_extra(unavailable):
    assert "pip install axross[s3]" in unavailable("s3")


def test_happy_svn_names_the_svn_command(unavailable):
    message = unavailable("svn")
    assert "pip install" not in message
    assert "svn" in message.split("not available", 1)[1]


# --- sad ------------------------------------------------------------------


def test_sad_every_required_extra_exists_in_pyproject():
    R.init_registry()
    missing = {
        b.protocol_id: b.required_extra
        for b in R.all_backends()
        if b.required_extra and b.required_extra not in EXTRAS
    }
    assert not missing


def test_sad_no_backend_hint_names_an_extra_pyproject_lacks(unavailable):
    R.init_registry()
    for info in R.all_backends():
        message = unavailable(info.protocol_id)
        for extra in re.findall(r"axross\[([^\]]+)\]", message):
            assert extra in EXTRAS, (info.protocol_id, message)


# --- edge -----------------------------------------------------------------


@pytest.mark.parametrize(
    "protocol_id, command",
    [
        ("rsync", "rsync"),
        ("nfs", "mount"),
        ("iscsi", "iscsiadm"),
        ("rsh", "rsh"),
        ("mtp", "jmtpfs"),
    ],
)
def test_edge_system_command_backends_name_their_commands(unavailable, protocol_id, command):
    message = unavailable(protocol_id)
    assert command in message and "pip install" not in message
