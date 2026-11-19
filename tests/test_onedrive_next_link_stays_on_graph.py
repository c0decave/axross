"""OneDrive: a paging link that leaves Graph never gets the bearer token.

Protocol review (round 1): ``_pages`` followed every ``@odata.nextLink``
with ``_graph_get``, which always adds ``Authorization: Bearer``. A
hostile or broken answer (a proxy, a compromised tenant app answering
for Graph) naming ``http://evil.example/...`` got the token - in clear
text on http. Only https links on Graph's own host are followed now.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fake_onedrive  # noqa: E402
from fake_onedrive import Resp  # noqa: E402


class _Hostile(fake_onedrive.FakeGraph):
    next_link = "http://evil.example/steal"

    def get(self, url, headers=None, **kw):
        if "evil.example" in url or "graph.microsoft.com.evil" in url:
            self.leaked = (url, (headers or {}).get("Authorization"))
            return Resp(200, {"value": []})
        r = super().get(url, headers=headers, **kw)
        if "/children" in url:
            body = r.json()
            body["@odata.nextLink"] = self.next_link
            return Resp(200, body)
        return r


@pytest.mark.parametrize("link", [
    "http://evil.example/steal",
    "https://evil.example/v1.0/me/drive",
    "https://graph.microsoft.com.evil.example/v1.0/x",
    "http://graph.microsoft.com/v1.0/me/drive/root/children?$skiptoken=2",
])
def test_sad_foreign_next_link_is_refused_without_the_token(link):
    g = _Hostile()
    g.next_link = link
    od = fake_onedrive.make_session(g)
    od.mkdir("/a")
    with pytest.raises(OSError, match="paging link"):
        od.list_dir("/")
    assert getattr(g, "leaked", None) is None


def test_happy_graph_pages_are_followed():
    g = fake_onedrive.FakeGraph()
    od = fake_onedrive.make_session(g)
    for i in range(fake_onedrive.PAGE + 3):
        od.mkdir(f"/d{i}")
    assert len(od.list_dir("/")) == fake_onedrive.PAGE + 3
