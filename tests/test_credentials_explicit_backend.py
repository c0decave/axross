"""An explicitly chosen keyring backend is never swapped for another.

credentials replaced an unusable backend (null, fail, chainer) with
SecretService or KWallet. That is right when nothing was configured, but
PYTHON_KEYRING_BACKEND is how a user - and this test suite - says "this
backend and no other": with the null backend set, a test run on a desktop
with a reachable SecretService still reached the real keyring.
"""

from __future__ import annotations

from unittest import mock

import pytest

from core import credentials as C


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(C, "_keyring_checked", False)
    monkeypatch.setattr(C, "_keyring_usable", False)
    swap = mock.Mock(return_value=True)
    monkeypatch.setattr(C, "_try_set_real_backend", swap)
    return swap


def test_happy_an_explicit_null_backend_is_kept(fresh, monkeypatch) -> None:
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
    C._ensure_non_interactive_keyring()
    fresh.assert_not_called()
    assert C._keyring_usable is False


def test_sad_without_an_explicit_choice_an_unusable_backend_is_still_replaced(
    fresh, monkeypatch
) -> None:
    pytest.importorskip("keyring")
    import keyring
    from keyring.backends import null

    monkeypatch.delenv("PYTHON_KEYRING_BACKEND", raising=False)
    monkeypatch.setattr(keyring, "get_keyring", lambda: null.Keyring())
    C._ensure_non_interactive_keyring()
    fresh.assert_called_once()


def test_edge_a_blank_variable_is_no_explicit_choice(fresh, monkeypatch) -> None:
    pytest.importorskip("keyring")
    import keyring
    from keyring.backends import null

    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "  ")
    monkeypatch.setattr(keyring, "get_keyring", lambda: null.Keyring())
    C._ensure_non_interactive_keyring()
    fresh.assert_called_once()
