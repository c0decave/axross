"""Exchange: every attachment of a message gets a name of its own
(review round 2).

The numbering gave ``[a.pdf, a.pdf, a.1.pdf]`` the names ``a.pdf,
a.1.pdf, a.1.pdf``: two entries of one name, and the third attachment
could not be read (open_read refused the ambiguous name, stat gave the
first). A number is skipped when the name is taken already.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.exchange_client import ExchangeSession  # noqa: E402


@pytest.mark.parametrize(
    "names",
    [["a.pdf", "a.pdf", "a.1.pdf"], ["noext", "noext", "noext.1"], ["x.1.txt", "x.txt", "x.txt"]],
)
def test_sad_names_never_collide(names) -> None:
    atts = [NS(name=n) for n in names]
    got = [ExchangeSession._unique_attachment_name(atts, a) for a in atts]
    assert len(set(got)) == len(got), got


def test_happy_first_keeps_its_name() -> None:
    atts = [NS(name="r.pdf"), NS(name="r.pdf")]
    assert [ExchangeSession._unique_attachment_name(atts, a) for a in atts] == ["r.pdf", "r.1.pdf"]
