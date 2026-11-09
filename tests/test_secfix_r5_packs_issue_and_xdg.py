"""Round-5 security, packs and XDG paths:

* an earlier signed pack-manifest issue was accepted on a fresh install
  (and where a self-update brings the packs along): the floor is now the
  issue this build shipped with (core.packs.SHIPPED_ISSUES) or the highest
  one ever seen signed here (``issues-seen.json``, kept beside the version
  folders - removing the units or the folder does not forget it);
* core.packs did not check the signed ``# axross-release`` line of
  SHA256SUMS (another release's signed sums under this tag were taken) nor
  GitHub's API digests, as core.self_update does;
* a relative XDG_DATA_HOME put the packs - which go on sys.path - under the
  current directory (the XDG spec says to ignore a relative one); the same
  for the update cache and the other XDG reads (core.xdg_dirs);
* a wheel member ``pkg/C:evil.py`` passed the unpack check (a drive path on
  Windows).

The release fakes are those of tests/test_packs_at_once_and_reissue.py."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import packs as P  # noqa: E402
from core import self_update as SU  # noqa: E402
from test_packs_at_once_and_reissue import (  # noqa: E402, F401 - release is a fixture
    VERSION,
    _install,
    _opts,
    _reissue,
    release,
)


def _resign(release, text: str) -> None:
    """Replace the release's SHA256SUMS by *text*, validly signed."""
    data = text.encode()
    release["files"][SU.SUMS_NAME] = data
    release["files"][SU.SIG_NAME] = release["key"].sign(data)
    release["release"] = SU.Release(VERSION, f"v{VERSION}", "", "", tuple(
        SU.Asset(n, f"https://github.com/c0decave/axross/releases/download/v{VERSION}/{n}", len(d))
        for n, d in release["files"].items()))


def _sums_text(release) -> str:
    return release["files"][SU.SUMS_NAME].decode()


# -- issue floor ------------------------------------------------------------------

def test_happy_an_install_records_the_issue_seen(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    assert json.loads((tmp_path / P.ISSUES_SEEN).read_text()) == {VERSION: 0}
    _reissue(release)                                     # issue 1
    rel, _stale = P.check_reissued(VERSION, **_opts(release, tmp_path))
    P.update(rel, **_opts(release, tmp_path))
    assert P.issue_floor(VERSION, tmp_path) == 1


def test_sad_a_fresh_install_refuses_an_issue_older_than_the_shipped_one(release, tmp_path,
                                                                         monkeypatch):
    monkeypatch.setattr(P, "SHIPPED_ISSUES", {VERSION: 1}, raising=False)
    with pytest.raises(P.PackError, match="older than issue 1"):
        _install(release, ["extra:a"], tmp_path)          # issue 0, re-uploaded
    assert not (tmp_path / VERSION / "installed.json").exists()


def test_sad_the_issue_seen_survives_removing_the_version_folder(release, tmp_path):
    first = (dict(release["files"]), release["release"])
    _reissue(release)                                     # the fix: issue 1
    _install(release, ["extra:a"], tmp_path)
    shutil.rmtree(tmp_path / VERSION)                     # units removed, folder pruned
    release["files"], release["release"] = first          # issue 0 uploaded again
    with pytest.raises(P.PackError, match="older than issue 1"):
        _install(release, ["extra:a"], tmp_path)


def test_sad_a_self_update_does_not_carry_packs_to_an_older_issue(release, tmp_path):
    first = (dict(release["files"]), release["release"])
    _reissue(release)
    P.install_available(release["release"], ["extra:a"], **_opts(release, tmp_path))
    shutil.rmtree(tmp_path / VERSION)
    release["files"], release["release"] = first
    with pytest.raises(P.PackError, match="older than issue 1"):
        P.install_available(release["release"], ["extra:a"], **_opts(release, tmp_path))


# -- the signed release line and the API digests ---------------------------------------

def test_sad_sums_signed_for_another_release_are_refused(release, tmp_path):
    text = _sums_text(release).replace(f"{SU.RELEASE_LINE_PREFIX}{VERSION}",
                                       f"{SU.RELEASE_LINE_PREFIX}0.0.1")
    _resign(release, text)
    with pytest.raises(P.PackError, match="is for axross 0.0.1"):
        _install(release, ["extra:a"], tmp_path)


def test_sad_sums_without_a_release_line_are_refused(release, tmp_path):
    text = "".join(line + "\n" for line in _sums_text(release).splitlines()
                   if not line.startswith(SU.RELEASE_LINE_PREFIX))
    _resign(release, text)
    with pytest.raises(P.PackError, match="no version"):
        _install(release, ["extra:a"], tmp_path)


def test_sad_a_wrong_api_digest_is_refused(release, tmp_path):
    rel = release["release"]
    release["release"] = SU.Release(rel.version, rel.tag, rel.page_url, rel.notes, tuple(
        SU.Asset(a.name, a.url, a.size, "0" * 64 if a.name == SU.SUMS_NAME else "")
        for a in rel.assets))
    with pytest.raises(P.PackError, match="GitHub's digest"):
        _install(release, ["extra:a"], tmp_path)


def test_edge_matching_api_digests_are_accepted(release, tmp_path):
    rel = release["release"]
    release["release"] = SU.Release(rel.version, rel.tag, rel.page_url, rel.notes, tuple(
        SU.Asset(a.name, a.url, a.size, hashlib.sha256(release["files"][a.name]).hexdigest())
        for a in rel.assets))
    assert _install(release, ["extra:a"], tmp_path)


# -- XDG paths ------------------------------------------------------------------------

def test_edge_a_relative_xdg_data_home_is_ignored(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", "rel-data")
    monkeypatch.setenv("XDG_CACHE_HOME", "rel-cache")
    monkeypatch.setenv("XDG_STATE_HOME", "rel-state")
    assert P.packs_root() == tmp_path / "home" / ".local" / "share" / "axross" / "packs"
    assert SU.cache_dir() == tmp_path / "home" / ".cache" / "axross" / "update"
    from core import chat_servers, voice_models
    from core.xdg_dirs import base_dir

    assert chat_servers.cache_dir().is_absolute()
    assert voice_models.data_dir() == tmp_path / "home" / ".local" / "share" / "axross" / "voice"
    assert base_dir("XDG_STATE_HOME") == tmp_path / "home" / ".local" / "state"


def test_happy_an_absolute_xdg_data_home_is_used(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    assert P.packs_root() == tmp_path / "data" / "axross" / "packs"
    assert SU.cache_dir() == tmp_path / "cache" / "axross" / "update"


# -- unpack ---------------------------------------------------------------------------

@pytest.mark.parametrize("member", ["pkg/C:evil.py", "pkg/D:/evil.py", "pkg/mod.py:stream"])
def test_sad_a_member_with_a_colon_anywhere_is_refused(tmp_path, member):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, b"x = 1\n")
    blob = tmp_path / "w-1.0-py3-none-any.whl"
    blob.write_bytes(buf.getvalue())
    with pytest.raises(P.PackError, match="leaves its folder"):
        P._unpack(blob, tmp_path / "dest")
    assert not (tmp_path / "dest").exists()
