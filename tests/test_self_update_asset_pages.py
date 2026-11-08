"""The update check reads a release's assets past the first 100.

Found by the round 3 release review: a release with its packs carries about
160 pack wheels besides the binaries, and parse_release kept only the first
100 assets of GitHub's answer - with SHA256SUMS or a binary past that, every
installed binary refused (or never saw) the update. The rest is now read
from the release's asset pages, at an address built from the repository and
the release id, bounded in pages and in assets.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import self_update as SU  # noqa: E402

TAG = "v9.9.9"


def _asset(name: str) -> dict:
    return {"name": name, "size": 10, "digest": "",
            "browser_download_url": f"https://github.com/{SU.REPOSITORY}/releases/download/{TAG}/{name}"}


def _release(n_first: int) -> dict:
    return {"tag_name": TAG, "id": 4242, "draft": False, "prerelease": False,
            "html_url": f"{SU.RELEASES_PREFIX}tag/{TAG}", "body": "notes",
            "assets": [_asset(f"pack-{i:03d}.whl") for i in range(n_first)]}


def _serve(monkeypatch, latest: dict, pages: dict, seen: list):
    def fake_fetch(url, **kwargs):
        seen.append(url)
        if url == SU.LATEST_URL:
            return json.dumps(latest).encode()
        if url in pages:
            page = pages[url]
            if isinstance(page, Exception):
                raise page
            return json.dumps(page).encode()
        raise SU.UpdateError(f"unexpected {url}")
    monkeypatch.setattr(SU, "fetch", fake_fetch)


def _page_url(n: int) -> str:
    return (f"https://api.github.com/repos/{SU.REPOSITORY}/releases/4242/assets"
            f"?per_page={SU.ASSETS_PAGE}&page={n}")


def test_sad_sha256sums_past_the_first_100_assets_is_found(monkeypatch):
    seen: list = []
    page2 = [_asset(f"pack-{i:03d}.whl") for i in range(100, 159)] + [_asset("SHA256SUMS")]
    _serve(monkeypatch, _release(100), {_page_url(2): page2}, seen)
    result = SU.check("1.0.0", opener=object())
    names = [a.name for a in result.release.assets]
    assert "SHA256SUMS" in names and len(names) == 160
    assert seen == [SU.LATEST_URL, _page_url(2)]  # stops at the short page


def test_happy_a_small_release_makes_one_request(monkeypatch):
    seen: list = []
    _serve(monkeypatch, _release(20), {}, seen)
    SU.check("1.0.0", opener=object())
    assert seen == [SU.LATEST_URL]


def test_edge_the_pages_stop_at_max_assets(monkeypatch):
    seen: list = []
    full = [_asset("x.whl")] * SU.ASSETS_PAGE
    pages = {_page_url(n): full for n in range(2, 20)}
    _serve(monkeypatch, _release(100), pages, seen)
    result = SU.check("1.0.0", opener=object())
    assert len(seen) == SU.MAX_ASSETS // SU.ASSETS_PAGE
    assert len(result.release.assets) <= SU.MAX_ASSETS


def test_sad_a_failed_page_keeps_what_was_read(monkeypatch):
    seen: list = []
    _serve(monkeypatch, _release(100), {_page_url(2): SU.UpdateError("reset")}, seen)
    result = SU.check("1.0.0", opener=object())
    assert len(result.release.assets) == 100


def test_sad_an_id_that_is_no_number_reads_no_further(monkeypatch):
    seen: list = []
    latest = _release(100)
    latest["id"] = "../../evil"
    _serve(monkeypatch, latest, {}, seen)
    SU.check("1.0.0", opener=object())
    assert seen == [SU.LATEST_URL]
