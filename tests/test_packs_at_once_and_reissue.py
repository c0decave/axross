"""core.packs / ui.packs_dialog / ui.features_dialog: a pack of pure Python
is used at once (sys.path, the import caches, the Features window, the
backends, bundled extensions that could not load), a native one waits for
the restart; a re-issued release manifest (same version, a pack fixed) is
found and "Update packs" fetches it through the same signature and hash
checks as Add - a re-issue with a bad signature, or one the signed sums do
not name, is refused and leaves the installed packs as they were.

The fakes are those of tests/test_packs.py: a test Ed25519 key, a release
of fake wheels served by a fake fetcher; here the fetcher also answers the
GitHub API and the release can be re-issued under the same version."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import packs as P  # noqa: E402
from core import self_update as SU  # noqa: E402
from core.units import Unit  # noqa: E402

VERSION = "9.9.9"
ALPHA = "alpha-1.0-py3-none-any.whl"
ALPHA_FIXED = "alpha-1.0.post1-py3-none-any.whl"
SHARED = "shared-1.0-py2.py3-none-any.whl"
NATIVE = "native-1.0-cp311-cp311-manylinux_2_34_x86_64.whl"
UNITS = [Unit("extra:a", "extra", "a", ("a",), (), frozenset({"alpha", "shared"})),
         Unit("extra:n", "extra", "n", ("n",), (), frozenset({"native", "shared"})),
         Unit("extension:c", "extension", "c", ("a",), ("extra:a",), frozenset())]


def wheel(name: str, files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for path, data in files.items():
            z.writestr(path, data)
        z.writestr(f"{name}-1.0.dist-info/METADATA", f"Name: {name}\nVersion: 1.0\n")
    return buf.getvalue()


def _key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw)).decode()
    return key, pub


def publish(state: dict, blobs: dict, *, key=None, sums_from: dict | None = None) -> None:
    """(Re-)issue the release *VERSION* with *blobs*: a new manifest, new
    SHA256SUMS, signed with *key* (the release key unless given). With
    *sums_from*, SHA256SUMS and its signature stay those of that earlier
    issue (a manifest swapped without being signed)."""
    wheels = {n.split("-")[0]: (n, hashlib.sha256(d).hexdigest(), len(d), f"https://files.pythonhosted.org/x/{n}")
              for n, d in blobs.items()}
    files = dict(blobs)
    files[P.manifest_name(VERSION)] = json.dumps(P.build_manifest(VERSION, "linux-x86_64", wheels, UNITS)).encode()
    if sums_from is not None:
        files[SU.SUMS_NAME], files[SU.SIG_NAME] = sums_from[SU.SUMS_NAME], sums_from[SU.SIG_NAME]
    else:
        sums = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(files.items())).encode()
        files[SU.SUMS_NAME] = sums
        files[SU.SIG_NAME] = (key or state["key"]).sign(sums)
    state["files"] = files
    state["release"] = SU.Release(VERSION, f"v{VERSION}", "", "", tuple(
        SU.Asset(n, f"https://github.com/c0decave/axross/releases/download/v{VERSION}/{n}", len(d))
        for n, d in files.items()))


@pytest.fixture
def release():
    key, pub = _key()
    state = {"key": key, "fetched": []}
    publish(state, {
        ALPHA: wheel("alpha", {"alpha_pk/__init__.py": "VALUE = 'alpha'\n"}),
        SHARED: wheel("shared", {"shared_pk/__init__.py": "X = 1\n"}),
        NATIVE: wheel("native", {"native_pk/__init__.py": "N = 1\n"}),
    })

    def get(url, max_bytes, hosts):
        state["fetched"].append(url)
        if "api.github.com" in url:
            return json.dumps({"tag_name": f"v{VERSION}", "body": "", "draft": False, "prerelease": False,
                               "html_url": f"https://github.com/c0decave/axross/releases/tag/v{VERSION}",
                               "assets": [{"name": a.name, "size": a.size, "browser_download_url": a.url}
                                          for a in state["release"].assets]}).encode()
        name = url.rsplit("/", 1)[1]
        if "pythonhosted" in url:
            raise OSError("404")
        data = state["files"][name]
        if len(data) > max_bytes:
            raise OSError("too large")
        return data
    state["fetch"] = P.Fetcher(get)
    state["verify"] = lambda data, sig: SU.verify_signature(data, sig, keys=(pub,))
    return state


def _opts(r, root) -> dict:
    return {"fetch": r["fetch"], "root": root, "verify": r["verify"]}


def _install(r, units, root):
    return P.install(r["release"], units, **_opts(r, root))


def _forget(*modules):
    for m in modules:
        sys.modules.pop(m, None)


@pytest.fixture
def app():
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _wait(app, cond, timeout=10.0) -> bool:
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.02)
    return bool(cond())


# -- at once: core ---------------------------------------------------------------------


def test_happy_a_pure_python_unit_is_usable_without_a_restart(release, tmp_path):
    _install(release, ["extension:c"], tmp_path)                 # needs extra:a: alpha + shared
    path = []
    added, waiting = P.activate_now(VERSION, ["extension:c"], tmp_path, path)
    assert waiting == []
    assert sorted(Path(p).name for p in added) == [ALPHA, SHARED] and path == added
    sys.path[:0] = path
    try:
        import alpha_pk

        assert alpha_pk.VALUE == "alpha"
    finally:
        for p in path:
            sys.path.remove(p)
        _forget("alpha_pk")


def test_happy_pure_python_wheel_names():
    assert P.is_pure_python(ALPHA) and P.is_pure_python(SHARED)
    assert not P.is_pure_python(NATIVE)
    assert not P.is_pure_python("x-1.0-py3-abi3-any.whl")
    assert not P.is_pure_python("x-1.0-py3-none-linux_x86_64.whl")
    assert not P.is_pure_python("x-1.0.tar.gz") and not P.is_pure_python("x-none-any.whl")


def test_edge_a_unit_with_a_native_wheel_waits_for_the_restart(release, tmp_path):
    _install(release, ["extra:n"], tmp_path)
    path = []
    added, waiting = P.activate_now(VERSION, ["extra:n"], tmp_path, path)
    assert (added, waiting, path) == ([], [NATIVE], [])           # not half: shared stays off too
    # since the start on the path (activate), the native wheel holds nothing back
    path.append(str(tmp_path / VERSION / NATIVE))
    added, waiting = P.activate_now(VERSION, ["extra:n"], tmp_path, path)
    assert waiting == [] and [Path(p).name for p in added] == [SHARED]


def test_sad_activate_now_refuses_a_blob_whose_marker_does_not_match(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    (tmp_path / VERSION / ALPHA / ".axross-sha256").write_text("0" * 64 + "\n")
    path = []
    with pytest.raises(P.PackError, match="does not match"):
        P.activate_now(VERSION, ["extra:a"], tmp_path, path)
    assert path == []


# -- at once: the Packs window ---------------------------------------------------------


class _Host:
    """A fake ui.extension_host.ExtensionHost."""

    def __init__(self, errors):
        self.errors, self.loaded, self.retried = dict(errors), [], []

    def loaded_ids(self):
        return list(self.loaded)

    def error(self, ext_id):
        return self.errors.get(ext_id, "")

    def retry(self, ext_id):
        self.retried.append(ext_id)
        self.loaded.append(ext_id)
        return True


def _packs_dialog(app, release, root, parent=None, path=None):
    from ui.packs_dialog import PacksDialog

    dlg = PacksDialog(parent, version=VERSION, path=path, **_opts(release, root))
    assert _wait(app, lambda: dlg.table.rowCount() == len(UNITS)), dlg.status.text()
    return dlg


def _add(app, dlg, unit):
    rows = {dlg.table.item(r, 0).data(256): r for r in range(dlg.table.rowCount())}
    dlg.table.clearSelection()
    dlg.table.selectRow(rows[unit])
    dlg.add_selected()
    assert _wait(app, lambda: "Added" in dlg.status.text() or "Not added" in dlg.status.text())
    return rows


def test_happy_the_packs_window_says_ready_to_use_and_refreshes_what_lists_features(
        app, release, tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QWidget

    from core import extensions as EX
    from core import features as F

    refreshed = []
    monkeypatch.setattr(F, "refresh_availability", lambda: refreshed.append(1))
    monkeypatch.setattr(EX, "safe_mode", lambda: False)
    monkeypatch.setattr(EX, "enabled_ids", lambda: {"bundled:c", "bundled:hung", "bundled:fine", "user:mine"})
    monkeypatch.setattr(EX, "suspended_ids", lambda: {"bundled:hung"})
    window = QWidget()
    window.extension_host = _Host({"bundled:c": "ModuleNotFoundError: alpha_pk",
                                   "bundled:hung": "not loaded: an earlier start stopped",
                                   "user:mine": "ModuleNotFoundError: x"})
    window.extension_host.loaded.append("bundled:fine")
    path = []
    dlg = _packs_dialog(app, release, tmp_path, parent=window, path=path)
    seen = []
    dlg.activated.connect(seen.append)
    _add(app, dlg, "extension:c")
    assert "ready to use" in dlg.status.text() and "estart" not in dlg.status.text()
    assert sorted(Path(p).name for p in path) == [ALPHA, SHARED]
    assert seen == [["extension:c"]] and refreshed == [1]
    assert window.extension_host.retried == ["bundled:c"]      # not the suspended one, not user ones
    dlg.close()


def test_edge_the_packs_window_keeps_the_restart_for_a_native_unit(app, release, tmp_path, monkeypatch):
    from core import features as F

    refreshed = []
    monkeypatch.setattr(F, "refresh_availability", lambda: refreshed.append(1))
    path = []
    dlg = _packs_dialog(app, release, tmp_path, path=path)
    seen = []
    dlg.activated.connect(seen.append)
    _add(app, dlg, "extra:n")
    text = dlg.status.text()
    assert "restart axross" in text and NATIVE in text and "ready to use" not in text
    assert path == [] and seen == [] and refreshed == []
    assert P.installed(VERSION, tmp_path) == ["extra:n"]       # installed, used at the next start
    dlg.close()


def test_edge_removing_a_unit_says_it_needs_a_restart(app, release, tmp_path):
    dlg = _packs_dialog(app, release, tmp_path, path=[])
    rows = _add(app, dlg, "extra:a")
    dlg.table.clearSelection()
    dlg.table.selectRow(rows["extra:a"])
    dlg.remove_selected()
    assert P.installed(VERSION, tmp_path) == []
    assert "restart axross" in dlg.status.text()
    dlg.close()


# -- re-issued manifest: core ----------------------------------------------------------


def _fixed_alpha() -> bytes:
    return wheel("alpha", {"alpha_pk/__init__.py": "VALUE = 'fixed'\n"})


def _reissue(release, *, renamed=True, **kw):
    blobs = {n: d for n, d in release["files"].items() if n.endswith(".whl")}
    blobs.pop(ALPHA)
    blobs[ALPHA_FIXED if renamed else ALPHA] = _fixed_alpha()
    publish(release, blobs, **kw)


def test_happy_a_reissued_manifest_is_found_and_updated(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    _reissue(release)
    rel, stale = P.check_reissued(VERSION, **_opts(release, tmp_path))
    assert stale == ["extra:a"] and rel.version == VERSION
    done = P.update(rel, **_opts(release, tmp_path))
    assert done == [ALPHA_FIXED]                                  # shared is the same file: kept
    folder = tmp_path / VERSION
    assert not (folder / ALPHA).exists()                          # the old blob went
    assert P.check_reissued(VERSION, **_opts(release, tmp_path))[1] == []
    path = []
    P.activate(VERSION, tmp_path, path)
    assert sorted(Path(p).name for p in path) == [ALPHA_FIXED, SHARED]
    sys.path[:0] = path
    try:
        import alpha_pk

        assert alpha_pk.VALUE == "fixed"
    finally:
        for p in path:
            sys.path.remove(p)
        _forget("alpha_pk")


def test_happy_a_blob_reissued_under_the_same_name_is_replaced(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    _reissue(release, renamed=False)
    rel, stale = P.check_reissued(VERSION, **_opts(release, tmp_path))
    assert stale == ["extra:a"]
    assert P.update(rel, **_opts(release, tmp_path)) == [ALPHA]
    assert "fixed" in (tmp_path / VERSION / ALPHA / "alpha_pk" / "__init__.py").read_text()


def test_edge_no_reissue_and_no_packs_offer_nothing(release, tmp_path):
    assert P.check_reissued(VERSION, **_opts(release, tmp_path)) == (None, [])
    assert release["fetched"] == []                               # nothing installed: no request
    _install(release, ["extra:a"], tmp_path)
    assert P.check_reissued(VERSION, **_opts(release, tmp_path))[1] == []
    assert P.stale_units(VERSION, {"units": {}, "blobs": {}}, tmp_path) == []   # a unit gone: nothing to fetch


def test_sad_a_reissued_manifest_with_a_bad_signature_is_refused(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    old = release["release"]
    other, _pub = _key()
    _reissue(release, key=other)                                  # signed, but not by the release key
    with pytest.raises(SU.SignatureError):
        P.check_reissued(VERSION, **_opts(release, tmp_path))
    with pytest.raises(SU.SignatureError):
        P.update(release["release"], **_opts(release, tmp_path))
    with pytest.raises(SU.SignatureError):
        P.update(old, **_opts(release, tmp_path))
    folder = tmp_path / VERSION
    assert (folder / ALPHA).is_dir() and not (folder / ALPHA_FIXED).exists()
    assert "VALUE = 'alpha'" in (folder / ALPHA / "alpha_pk" / "__init__.py").read_text()


def test_sad_a_reissued_manifest_the_signed_sums_do_not_name_is_refused(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    first = dict(release["files"])
    _reissue(release, sums_from=first)                            # the manifest swapped, the sums not
    with pytest.raises(P.PackError, match="differs from the signed"):
        P.check_reissued(VERSION, **_opts(release, tmp_path))
    with pytest.raises(P.PackError, match="differs from the signed"):
        P.update(release["release"], **_opts(release, tmp_path))
    assert not (tmp_path / VERSION / ALPHA_FIXED).exists()


def test_sad_a_reissued_blob_with_a_wrong_hash_is_refused_and_the_old_one_stays(release, tmp_path):
    _install(release, ["extra:a"], tmp_path)
    _reissue(release)
    rel, stale = P.check_reissued(VERSION, **_opts(release, tmp_path))
    release["files"][ALPHA_FIXED] = release["files"][ALPHA_FIXED][:-1] + b"X"
    with pytest.raises(P.PackError, match="could not be fetched"):
        P.update(rel, **_opts(release, tmp_path))
    folder = tmp_path / VERSION
    assert (folder / ALPHA).is_dir() and not (folder / ALPHA_FIXED).exists()
    assert P.installed(VERSION, tmp_path) == ["extra:a"]


# -- re-issued manifest: the Features window -------------------------------------------


@pytest.fixture
def features(app, monkeypatch):
    from PyQt6.QtCore import QEvent

    from core import features as F

    monkeypatch.setattr(F, "collect", lambda: [])
    monkeypatch.setattr(F, "is_frozen", lambda: True)
    monkeypatch.setattr(SU, "start_check_allowed", lambda environ=None: (True, ""))
    made = []

    def open_(release, root):
        from ui.features_dialog import FeaturesDialog

        dlg = FeaturesDialog(runner=lambda *a: None, version=VERSION, packs=_opts(release, root))
        made.append(dlg)
        return dlg
    yield open_
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    app.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_happy_the_features_window_offers_and_runs_update_packs(app, release, tmp_path, features):
    _install(release, ["extra:a"], tmp_path)
    _reissue(release)
    dlg = features(release, tmp_path)
    assert _wait(app, lambda: not dlg.update_packs_button.isHidden()), dlg.status.text()
    assert "extra:a" in dlg.status.text()
    dlg.update_packs_button.click()
    assert _wait(app, lambda: "Packs updated" in dlg.status.text()), dlg.status.text()
    assert dlg.update_packs_button.isHidden() and "Restart axross" in dlg.status.text()
    assert (tmp_path / VERSION / ALPHA_FIXED).is_dir()


def test_edge_the_features_window_offers_nothing_when_not_reissued(app, release, tmp_path, features):
    _install(release, ["extra:a"], tmp_path)
    release["fetched"].clear()
    dlg = features(release, tmp_path)
    assert _wait(app, lambda: any("api.github.com" in u for u in release["fetched"]))
    assert _wait(app, lambda: release["fetched"][-1].endswith(P.manifest_name(VERSION)))
    for _ in range(20):
        app.processEvents()
        time.sleep(0.01)
    assert dlg.update_packs_button.isHidden()


def test_edge_the_features_window_does_not_ask_when_checks_are_off(app, release, tmp_path, features,
                                                                   monkeypatch):
    monkeypatch.setattr(SU, "start_check_allowed", lambda environ=None: (False, "AXROSS_NO_UPDATE_CHECK is set"))
    _install(release, ["extra:a"], tmp_path)
    _reissue(release)
    release["fetched"].clear()
    dlg = features(release, tmp_path)
    for _ in range(20):
        app.processEvents()
        time.sleep(0.01)
    assert release["fetched"] == [] and dlg.update_packs_button.isHidden()


def test_sad_the_features_window_offers_nothing_for_a_badly_signed_reissue(app, release, tmp_path, features):
    _install(release, ["extra:a"], tmp_path)
    other, _pub = _key()
    _reissue(release, key=other)
    release["fetched"].clear()
    dlg = features(release, tmp_path)
    assert _wait(app, lambda: any(u.endswith(SU.SIG_NAME) for u in release["fetched"]))
    for _ in range(30):
        app.processEvents()
        time.sleep(0.01)
    assert dlg.update_packs_button.isHidden() and dlg._packs_release is None
    assert not (tmp_path / VERSION / ALPHA_FIXED).exists()
