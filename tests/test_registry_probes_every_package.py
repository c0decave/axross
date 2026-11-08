"""A backend shows as available only when every package it imports is
there: gdrive also needs google_auth_oauthlib, onedrive / sharepoint also
requests, git also urllib3. Each probe checked one package, so a missing
second one passed the probe and failed at connect with an ImportError.
"""

from __future__ import annotations

import pytest

from core import backend_registry


@pytest.mark.parametrize(
    "protocol, needed",
    [
        ("gdrive", {"googleapiclient", "google_auth_oauthlib"}),
        ("onedrive", {"msal", "requests"}),
        ("sharepoint", {"msal", "requests"}),
        ("git", {"dulwich", "urllib3"}),
    ],
)
def test_sad_the_probe_names_every_package(protocol, needed):
    info = backend_registry.get(protocol)
    probe = info._availability
    assert needed <= set(probe.modules)


def test_edge_a_missing_second_package_makes_the_backend_unavailable(monkeypatch):
    probe = backend_registry._check_available("json", "axross_no_such_package_xyz")
    assert probe() is False
    assert backend_registry._check_available("json", "os")() is True
