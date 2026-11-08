"""The update check reads every asset of a release, and each one once.

Found by the round 3 release review: parse_release kept only the first 100
assets of GitHub's answer. GitHub's answer to releases/latest carries every
asset (sorted by name, ignoring case; the final release review measured it),
so the asset pages are read only when the answer looks cut off at one full
page (exactly ASSETS_PAGE assets): the round 3 fix read page 2 of any answer
of 100 or more and listed 80 of a release's 180 assets twice. The pages are
read at an address built from the repository and the release id, bounded in
pages and in assets; an asset listed twice is kept once.
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import self_update as SU  # noqa: E402

TAG = "v9.9.9"
_IDS = itertools.count(1000)


def _asset(name: str, asset_id: int | None = None) -> dict:
    return {"name": name, "size": 10, "digest": "", "id": asset_id or next(_IDS),
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
    pages = {_page_url(n): [_asset(f"p{n}-{i:03d}.whl") for i in range(SU.ASSETS_PAGE)]
             for n in range(2, 20)}
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


def test_happy_an_answer_with_every_asset_makes_no_further_request(monkeypatch):
    """What GitHub sends: all 180 assets of a release with its packs in the
    first answer. The old code read page 2 as well and listed 80 twice."""
    seen: list = []
    latest = _release(179)
    latest["assets"].append(_asset("SHA256SUMS"))
    page2 = [_asset(f"pack-{i:03d}.whl") for i in range(100, 179)] + [_asset("SHA256SUMS")]
    _serve(monkeypatch, latest, {_page_url(2): page2}, seen)
    result = SU.check("1.0.0", opener=object())
    names = [a.name for a in result.release.assets]
    assert seen == [SU.LATEST_URL]
    assert len(names) == 180 and len(set(names)) == 180 and "SHA256SUMS" in names


def test_sad_assets_listed_twice_are_kept_once(monkeypatch):
    """A page that repeats assets of the first answer (or of itself) adds
    nothing twice - by id, and by name under another id."""
    seen: list = []
    first = _release(100)
    page2 = [first["assets"][5], _asset("pack-007.whl", asset_id=1),   # again: same id / name
             _asset("SHA256SUMS", asset_id=7), _asset("SHA256SUMS", asset_id=7)]
    _serve(monkeypatch, first, {_page_url(2): page2}, seen)
    result = SU.check("1.0.0", opener=object())
    names = [a.name for a in result.release.assets]
    assert len(names) == len(set(names)) == 101 and names[-1] == "SHA256SUMS"
    assert seen == [SU.LATEST_URL, _page_url(2)]


def test_edge_a_page_of_nothing_new_ends_the_reading(monkeypatch):
    seen: list = []
    first = _release(100)
    pages = {_page_url(n): list(first["assets"]) for n in range(2, 6)}
    _serve(monkeypatch, first, pages, seen)
    result = SU.check("1.0.0", opener=object())
    assert len(result.release.assets) == 100
    assert seen == [SU.LATEST_URL, _page_url(2)]


def test_sad_parse_release_keeps_a_name_listed_twice_once():
    data = _release(3)
    data["assets"].append(_asset("pack-001.whl", asset_id=99))
    assert [a.name for a in SU.parse_release(data).assets] == [
        "pack-000.whl", "pack-001.whl", "pack-002.whl"]


def test_sad_a_latest_release_that_is_no_version_says_so(monkeypatch):
    """A release published as "Latest" under another tag (the tour videos'
    tour-videos-1, published without --latest=false) stops every check;
    the message says why and where the releases are."""
    seen: list = []
    latest = _release(3)
    latest["tag_name"] = "tour-videos-1"
    latest["html_url"] = f"{SU.RELEASES_PREFIX}tag/tour-videos-1"
    _serve(monkeypatch, latest, {}, seen)
    with pytest.raises(SU.UpdateError) as info:
        SU.check("1.0.0", opener=object())
    text = str(info.value)
    assert "'tour-videos-1'" in text and "not an axross version" in text
    assert SU.RELEASES_PREFIX in text
