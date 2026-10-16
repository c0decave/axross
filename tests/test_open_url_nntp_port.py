"""open_url("nntp://host/") talks plain NNTP on port 119.

Checking a Gmane article download through the scripting API:
open_url("nntp://news.gmane.io/") timed out on port 563. open_url set
the registry's default port (563, NNTPS) first; the nntp branch's
setdefault("port", 119) then changed nothing, so plain NNTP went to
the TLS port without TLS. The scheme's own port now comes first; an
explicit port in the URL or as an argument still wins.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import scripting  # noqa: E402


@pytest.fixture
def made(monkeypatch):
    seen = []

    class Fake:
        def __init__(self, **kw):
            seen.append(kw)

    import core.backend_registry as R

    real = R.load_backend_class
    monkeypatch.setattr(R, "load_backend_class", lambda pid: Fake if pid == "nntp" else real(pid))
    return seen


# --- happy ----------------------------------------------------------------


def test_happy_nntp_is_plain_on_119(made):
    scripting.open_url("nntp://news.example.org/")
    assert made[-1]["port"] == 119 and made[-1]["use_tls"] is False


def test_happy_nntps_is_tls_on_563(made):
    scripting.open_url("nntps://news.example.org/")
    assert made[-1]["port"] == 563 and made[-1]["use_tls"] is True


# --- sad ------------------------------------------------------------------


def test_sad_an_explicit_url_port_wins(made):
    scripting.open_url("nntp://news.example.org:1119/")
    assert made[-1]["port"] == 1119 and made[-1]["use_tls"] is False


# --- edge -----------------------------------------------------------------


def test_edge_a_port_argument_wins(made):
    scripting.open_url("nntp://news.example.org/", port=2119)
    assert made[-1]["port"] == 2119


def test_edge_nntp_plus_ssl_is_tls_on_563(made):
    scripting.open_url("nntp+ssl://news.example.org/")
    assert made[-1]["port"] == 563 and made[-1]["use_tls"] is True
