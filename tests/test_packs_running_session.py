"""core.packs / core.self_update: the folders of the running session, the
packs of a newer version, a unit a new release dropped, and the pack
downloads' time limit.

What was wrong (review round 2):

* "Update packs" deleted the blob folders the running session has on
  sys.path (``_drop_unused`` and an in-place ``rmtree`` of a blob
  re-issued under its name), although the window says the update is used
  from the next start: a late import in that session failed.
* ``prune()`` at the start deleted every other version's packs - also the
  newer version's, which a self-update installs before it replaces the
  binary. The old binary started again (the update waits in ~/.cache, a
  rollback to ``.previous``) wiped them.
* A self-update was refused for good when the new release no longer had
  an installed unit (dropped or renamed): ``needed_blobs`` raised.
* Every pack blob had a hard 600 s deadline, however steadily it arrived.

The fakes are those of tests/test_packs_at_once_and_reissue.py."""

from __future__ import annotations

import importlib
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import packs as P  # noqa: E402
from core import self_update as SU  # noqa: E402
from test_packs_at_once_and_reissue import (  # noqa: E402, F401 - release is a fixture
    ALPHA,
    ALPHA_FIXED,
    NATIVE,
    SHARED,
    VERSION,
    _forget,
    _install,
    _opts,
    publish,
    release,
    wheel,
)


def _fixed() -> bytes:
    return wheel("alpha", {"alpha_pk/__init__.py": "VALUE = 'fixed'\n"})


def _reissue(r, name: str) -> None:
    publish(r, {name: _fixed(), SHARED: r["files"][SHARED], NATIVE: r["files"][NATIVE]})


# -- "Update packs" and Remove keep what the running session imports from ------------


@pytest.mark.parametrize("renamed", [True, False], ids=["new-file-name", "same-file-name"])
def test_sad_update_packs_keeps_the_folders_the_running_session_uses(release, tmp_path, renamed):
    """The folders put on sys.path at the start stay, with their content,
    until the next start; that start uses the new blob and removes the old."""
    _install(release, ["extra:a"], tmp_path)
    session = []
    P.activate(VERSION, tmp_path, session)                 # as at the start
    before = {p: (Path(p) / "alpha_pk" / "__init__.py").read_text()
              for p in session if Path(p).name == ALPHA}
    assert before
    _reissue(release, ALPHA_FIXED if renamed else ALPHA)
    P.update(release["release"], **_opts(release, tmp_path))
    assert all(os.path.isdir(p) for p in session), "a folder of the running session was deleted"
    for p, text in before.items():
        assert (Path(p) / "alpha_pk" / "__init__.py").read_text() == text
    # The session still imports from its folders.
    sys.path[:0] = session
    try:
        _forget("alpha_pk")
        importlib.invalidate_caches()
        assert importlib.import_module("alpha_pk").VALUE == "alpha"
    finally:
        for p in session:
            sys.path.remove(p)
        _forget("alpha_pk")
    # The next start: the new blob is used, the old folder goes.
    nxt = []
    P.activate(VERSION, tmp_path, nxt)
    P.prune(VERSION, tmp_path)
    assert all(os.path.isdir(p) for p in nxt)
    assert not any(os.path.isdir(p) for p in before)
    alpha = next(Path(p) for p in nxt if Path(p).name.startswith("alpha"))
    assert "fixed" in (alpha / "alpha_pk" / "__init__.py").read_text()
    assert P.check_reissued(VERSION, **_opts(release, tmp_path))[1] == []


def test_sad_remove_keeps_the_folder_until_the_next_start(release, tmp_path):
    """Remove said "restart axross" but deleted the folder the session uses."""
    _install(release, ["extra:a"], tmp_path)
    folder = tmp_path / VERSION
    assert P.remove(VERSION, "extra:a", tmp_path) == [ALPHA, SHARED]
    assert (folder / ALPHA).is_dir() and (folder / SHARED).is_dir()
    assert P.installed(VERSION, tmp_path) == []
    assert sorted(P.prune(VERSION, tmp_path)) == [f"{VERSION}/{ALPHA}", f"{VERSION}/{SHARED}"]
    assert not (folder / ALPHA).exists() and not (folder / SHARED).exists()


def test_edge_a_unit_added_again_before_the_restart_keeps_its_folder(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    P.remove(VERSION, "extra:a", tmp_path)
    assert _install(release, ["extra:a"], tmp_path) == []       # still there: nothing fetched
    assert P.prune(VERSION, tmp_path) == []                       # and not retired any more
    assert (tmp_path / VERSION / ALPHA).is_dir()


# -- prune at the start --------------------------------------------------------------


def test_sad_prune_by_an_older_binary_keeps_the_newer_versions_packs(release, tmp_path):
    """packs/<new>/ is installed by the update before the binary is
    replaced; the old binary started once more must not delete it."""
    _install(release, ["extra:a"], tmp_path)                    # packs/9.9.9 (the newer version)
    (tmp_path / "1.0.0").mkdir()                                  # an older version's
    (tmp_path / "not-a-version").mkdir()
    gone = P.prune("5.0.0", tmp_path)                             # the binary of 5.0.0 starts
    assert gone == ["1.0.0"]
    assert P.installed(VERSION, tmp_path) == ["extra:a"]
    assert (tmp_path / VERSION / ALPHA).is_dir()
    assert (tmp_path / "not-a-version").is_dir()


# -- a self-update and a unit the new release does not have ---------------------------


def _carry(r, root, monkeypatch, cancel=None):
    monkeypatch.setattr(SU, "fetch", lambda url, **kw: r["fetch"](url, kw["max_bytes"], kw.get("hosts")))
    return SU._carry_packs(r["release"], object(), cancel=cancel, current="9.9.8", root=root,
                           verify=r["verify"])


def _installed_for_running(root: Path, units: list[str]) -> None:
    import json

    (root / "9.9.8").mkdir(parents=True)
    (root / "9.9.8" / "installed.json").write_text(json.dumps({"units": units, "manifest": {}}))


def test_sad_a_unit_the_new_release_dropped_does_not_refuse_the_update(release, tmp_path,
                                                                        monkeypatch):
    """The units the new release has come along; the others are named."""
    import test_packs_at_once_and_reissue as T

    _installed_for_running(tmp_path, ["extra:a", "extra:n", "extension:c"])
    monkeypatch.setattr(T, "UNITS", [u for u in T.UNITS if u.name != "extra:a"])
    publish(release, {k: release["files"][k] for k in (ALPHA, SHARED, NATIVE)})
    carried = _carry(release, tmp_path, monkeypatch)
    # extension:c needs extra:a, which is gone: it cannot come along either.
    assert sorted(carried.dropped) == ["extension:c", "extra:a"]
    assert sorted(carried.blobs) == [NATIVE, SHARED]
    assert P.installed(VERSION, tmp_path) == ["extra:n"]


def test_happy_the_update_result_and_window_name_the_dropped_units(tmp_path, monkeypatch):
    exe = tmp_path / "axross"
    exe.write_bytes(b"old")
    inst = SU.Install(frozen=True, flavor="base", asset="axross-base", executable=exe,
                      platform="linux", machine="x86_64")
    rel = SU.Release("9.9.9", "v9.9.9", "", "", ())
    monkeypatch.setattr(SU, "_carry_packs", lambda *a, **k: SU.CarriedPacks([], ["extra:n"]))
    monkeypatch.setattr(SU, "_writable", lambda folder: True)
    monkeypatch.setattr(SU, "download", lambda *a, **k: "downloaded")
    monkeypatch.setattr(SU, "install", lambda downloaded, i: SU.Installed(
        exe, exe.with_name("axross.previous"), True, "", "", "9.9.9"))
    result = SU.update(rel, inst, opener=object())
    assert result.dropped_units == ("extra:n",)
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from ui.update_ui import UpdateController

    message = UpdateController._finished_message(result)
    assert "extra:n" in message and "not brought along" in message


# -- the pack downloads' time limit ------------------------------------------------------


def test_sad_pack_blobs_have_no_overall_deadline_but_can_be_cancelled(release, tmp_path,
                                                                     monkeypatch):
    """Like the binary's download: a timeout per read, a cancel between
    reads - no 600 s for a blob of hundreds of MiB."""
    seen = []

    def fake_fetch(url, **kw):
        seen.append(kw)
        return release["fetch"](url, kw["max_bytes"], kw.get("hosts"))

    _installed_for_running(tmp_path, ["extra:a"])
    cancel = threading.Event()
    monkeypatch.setattr(SU, "fetch", fake_fetch)
    SU._carry_packs(release["release"], object(), cancel=cancel, current="9.9.8", root=tmp_path,
                    verify=release["verify"])
    assert seen and all(kw.get("deadline") is None for kw in seen)
    assert all(kw.get("cancel") is cancel for kw in seen)
    seen.clear()
    monkeypatch.setattr(SU, "build_opener", lambda: object())
    P.Fetcher(cancel=cancel)(release["release"].asset(SHARED).url, 10_000)
    assert seen[0].get("deadline") is None and seen[0].get("cancel") is cancel
