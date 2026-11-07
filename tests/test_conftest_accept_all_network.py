"""The lab counts as unreachable on a network that accepts every connection.

Behind a proxy that accepts each connection, ``create_connection`` to the
podman lab always succeeded: the lab tests ran against a lab that was not
there, an SMB login hung on its error box and an xdist worker aborted
(tests/conftest.py). Checked here with the decision functions themselves.
"""

from __future__ import annotations

import os
import socket

import pytest

from tests import conftest


def test_lab_addresses_are_recognised():
    assert conftest._in_lab(("10.99.0.31", 445))
    assert conftest._in_lab(("10.99.1.2", 22))
    assert not conftest._in_lab(("10.9.9.9", 445))
    assert not conftest._in_lab(("127.0.0.1", 80))
    assert not conftest._in_lab(("lab.example", 80))  # names are left alone
    assert not conftest._in_lab(("/run/x.sock",))


def test_the_decision_is_made_once_and_handed_to_the_workers(monkeypatch):
    monkeypatch.setenv("AXROSS_TEST_ACCEPT_ALL_NET", "1")
    assert conftest._network_accepts_everything() is True
    monkeypatch.setenv("AXROSS_TEST_ACCEPT_ALL_NET", "0")
    assert conftest._network_accepts_everything() is False


@pytest.mark.skipif(os.environ.get("AXROSS_TEST_ACCEPT_ALL_NET") != "1"
                    or os.environ.get("AXROSS_TEST_LAB") == "1",
                    reason="only on a network that accepts every connection")
def test_on_such_a_network_the_lab_is_refused():
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("10.99.0.31", 445), timeout=0.5)
    with socket.socket() as sock:
        assert sock.connect_ex(("10.99.0.31", 445)) != 0
