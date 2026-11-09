"""Exchange retries a request the server turned away as busy - boundedly.

exchangelib's default retry policy is FailFast: ErrorServerBusy (EWS
throttling, with its BackOffMilliseconds), HTTP 503 and a dropped
connection fail the request at once, and with it a whole folder copy.
The session now hands exchangelib a FaultTolerance policy - for an
explicit server through its Configuration, for autodiscover through the
Configuration exchangelib reads the policy from - bounded by
EXCHANGE_RETRY_MAX_WAIT instead of the library's one hour.

exchangelib is not installed here: a fake module stands in for it.
"""

from __future__ import annotations

import sys
import types

import pytest

from core import exchange_client as EX


class _FaultTolerance:
    def __init__(self, max_wait: int = 3600) -> None:
        self.max_wait = max_wait


class _Configuration:
    made: list = []

    def __init__(self, **kw) -> None:
        self.kw = kw
        _Configuration.made.append(self)


class _Account:
    made: list = []

    def __init__(self, **kw) -> None:
        self.kw = kw
        self.protocol = types.SimpleNamespace()
        _Account.made.append(self)


@pytest.fixture
def fake_lib(monkeypatch):
    lib = types.ModuleType("exchangelib")
    lib.FaultTolerance = _FaultTolerance
    monkeypatch.setitem(sys.modules, "exchangelib", lib)
    _Configuration.made, _Account.made = [], []
    monkeypatch.setattr(EX, "EXCHANGELIB_AVAILABLE", True)
    monkeypatch.setattr(EX, "Configuration", _Configuration)
    monkeypatch.setattr(EX, "Account", _Account)
    monkeypatch.setattr(EX, "Credentials", lambda user, password: ("creds", user))
    monkeypatch.setattr(EX, "DELEGATE", "delegate")
    return lib


def test_happy_an_explicit_server_gets_a_bounded_fault_tolerance(fake_lib):
    EX.ExchangeSession("a@example.com", "a", "pw", server="mail.example.com",
                       autodiscover=False)
    (config,) = _Configuration.made
    policy = config.kw["retry_policy"]
    assert isinstance(policy, _FaultTolerance)
    assert policy.max_wait == EX.EXCHANGE_RETRY_MAX_WAIT
    assert config.kw["server"] == "mail.example.com"
    assert _Account.made[0].kw["config"] is config


def test_happy_autodiscover_gets_the_policy_through_a_configuration(fake_lib):
    EX.ExchangeSession("a@example.com", "a", "pw", autodiscover=True)
    (account,) = _Account.made
    assert account.kw["autodiscover"] is True
    assert account.kw["credentials"] == ("creds", "a")
    policy = account.kw["config"].kw["retry_policy"]
    assert isinstance(policy, _FaultTolerance)
    assert account.kw["config"].kw["credentials"] == ("creds", "a")


def test_sad_an_exchangelib_without_fault_tolerance_keeps_its_default(fake_lib):
    del fake_lib.FaultTolerance
    EX.ExchangeSession("a@example.com", "a", "pw", server="mail.example.com",
                       autodiscover=False)
    assert "retry_policy" not in _Configuration.made[0].kw
    EX.ExchangeSession("a@example.com", "a", "pw", autodiscover=True)
    assert "config" not in _Account.made[-1].kw


def test_edge_the_wait_is_bounded_well_below_an_hour():
    assert 10 <= EX.EXCHANGE_RETRY_MAX_WAIT <= 300
