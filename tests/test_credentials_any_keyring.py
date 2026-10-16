"""Saved passwords work with any non-interactive keyring backend.

Checked in a disposable container with keyring + keyrings.alt and two
stand-in third-party backends (like keyring-pass):

* one third-party backend as the default: stored, read, deleted - fine;
* two viable backends: keyring picks its ChainerBackend (priority 10).
  axross refused every chainer and looked only for SecretService/KWallet,
  so passwords were not saved although the chain's first backend works.
  Now the chain's highest-priority usable backend is used directly - the
  one keyring itself would write to first;
* keyrings.alt's EncryptedKeyring counted as usable, but asks for a
  master password with getpass on the terminal ("Please set a password
  for your new keyring:") - invisible behind the GUI. It is treated like
  the other backends that cannot work non-interactively;
* PlaintextKeyring stays refused (passwords in a clear-text file).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

keyring = pytest.importorskip("keyring")
from keyring.backend import KeyringBackend  # noqa: E402
from keyring.backends import chainer  # noqa: E402

from core import credentials as C  # noqa: E402


class _Memory(KeyringBackend):
    priority = 5

    def __init__(self):
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


class VaultHigh(_Memory):
    priority = 5


class VaultLow(_Memory):
    priority = 4


def _named(module, name, base=_Memory):
    return type(name, (base,), {"__module__": module})


@pytest.fixture
def fresh(monkeypatch):
    # Read before the variable goes: an uninitialised keyring would
    # otherwise probe the host's real backends and leave them behind.
    previous = keyring.get_keyring()
    monkeypatch.delenv("PYTHON_KEYRING_BACKEND", raising=False)
    monkeypatch.setattr(C, "_keyring_checked", False)
    monkeypatch.setattr(C, "_try_set_real_backend", lambda: False)
    yield monkeypatch
    keyring.set_keyring(previous)
    C._keyring_checked = False


def _use_chain(monkeypatch, *backends):
    monkeypatch.setattr(keyring.backend, "get_all_keyring", lambda: list(backends))
    keyring.set_keyring(chainer.ChainerBackend())


# --- happy ----------------------------------------------------------------


def test_happy_a_single_third_party_backend_saves(fresh):
    vault = VaultHigh()
    keyring.set_keyring(vault)
    assert C.is_keyring_available()
    assert C.store_password("p", "s3cret") and C.get_password("p") == "s3cret"


def test_happy_a_chain_uses_its_first_usable_backend(fresh):
    high, low = VaultHigh(), VaultLow()
    _use_chain(fresh, low, high)
    assert C.is_keyring_available()
    assert C.store_password("p", "s3cret")
    assert high.store and not low.store  # the highest priority, as keyring would
    assert C.get_password("p") == "s3cret"


# --- sad ------------------------------------------------------------------


def test_sad_a_chain_of_unusable_backends_stays_unusable(fresh):
    from keyring.backends import fail

    _use_chain(fresh, fail.Keyring())
    assert not C.is_keyring_available()


@pytest.mark.parametrize(
    "module, name",
    [("keyrings.alt.file", "EncryptedKeyring"), ("keyrings.alt.file", "PlaintextKeyring")],
)
def test_sad_interactive_or_plaintext_backends_are_not_used(fresh, module, name):
    keyring.set_keyring(_named(module, name)())
    assert not C.is_keyring_available()


# --- edge -----------------------------------------------------------------


def test_edge_a_chain_skips_an_interactive_backend_for_the_next(fresh):
    prompting = _named("keyrings.alt.file", "EncryptedKeyring", VaultHigh)()
    low = VaultLow()
    _use_chain(fresh, prompting, low)
    assert C.is_keyring_available()
    C.store_password("p", "x")
    assert low.store and not prompting.store
